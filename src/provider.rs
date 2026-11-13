//! AcmeService — the owner of `acme.yaml`.
//!
//! Holds an [`ArcSwapOption`] snapshot of [`crate::config::AcmeConfig`];
//! consumers (renewal task, cleanup task, gRPC ACME endpoint) resolve this
//! from the registry and pull the snapshot on demand. Congif reads the file:
//! it is prepared before boot and in the reload batch, applied here through
//! `configure`, and followed through `ConfigObserver` when the source is
//! watched. An absent file is the "ACME off" declaration: the snapshot is
//! `None`; no HTTP-01 contribution is installed.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use claviron::runtime::congif::{
    self, ConfigFile, ConfigObserver, Configurable,
};
use claviron::runtime::registry::{Component, Reloadable, priority};
use claviron::runtime::{AppState, Register};
use tracing::info;

use crate::AcmeError;
use crate::clients::OrderChallenge;
use crate::config::{AcmeConfig, ChallengeMethod};
use crate::dns01::{Dns01, TxtPublisher};

/// What the ACME configuration file is called in the config directory.
pub const CONFIG_FILE: &str = "acme.yaml";

pub struct AcmeProvider {
    config_path: PathBuf,
    snapshot: ArcSwapOption<AcmeConfig>,
    txt_publisher: Option<Arc<dyn TxtPublisher>>,
    #[cfg(feature = "http-0")]
    pub(crate) http01:
        std::sync::Mutex<Option<Arc<crate::http01::Http01Layer>>>,
    worker: bool,
}

impl AcmeProvider {
    pub fn empty(config_path: PathBuf) -> Self {
        Self {
            config_path,
            snapshot: ArcSwapOption::empty(),
            txt_publisher: None,
            #[cfg(feature = "http-0")]
            http01: std::sync::Mutex::default(),
            worker: false,
        }
    }

    pub fn snapshot(&self) -> Option<Arc<AcmeConfig>> {
        self.snapshot.load_full()
    }

    pub fn order_challenge<'a>(
        &'a self,
        config: &'a AcmeConfig,
    ) -> Result<OrderChallenge<'a>, AcmeError> {
        match config.method {
            None | Some(ChallengeMethod::Http0) => {
                Ok(OrderChallenge::Http01(config.challenges_dir()))
            }
            Some(ChallengeMethod::Dns01) => {
                let publisher = self
                    .txt_publisher
                    .as_deref()
                    .ok_or(AcmeError::MissingTxtPublisher)?;
                let dns = Dns01::new(publisher, config.dns_visibility()?);
                let dns = if config.pre_validation {
                    dns.with_system_resolver()?
                } else {
                    dns
                };
                Ok(OrderChallenge::Dns01(dns))
            }
        }
    }

    fn apply(
        &self,
        config: &Option<AcmeConfig>,
    ) {
        #[cfg(feature = "http-0")]
        let mut prepared =
            self.http01.lock().expect("HTTP-01 preparation poisoned");
        #[cfg(feature = "http-0")]
        {
            *prepared = None;
        }
        match config {
            Some(cfg) => {
                self.snapshot.store(Some(Arc::new(cfg.clone())));
                if self.worker {
                    tracing::debug!(
                        "📦 AcmeService applied {}",
                        self.config_path.display()
                    );
                } else {
                    info!(
                        "📦 AcmeService applied {}",
                        self.config_path.display()
                    );
                }
            }
            None => {
                self.snapshot.store(None);
                tracing::debug!(
                    path = %self.config_path.display(),
                    "acme.yaml not found; AcmeService running empty"
                );
            }
        }
    }
}

/// Register ACME configuration and its optional native route contribution.
impl Register<AppState> for AcmeProvider {
    fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
        #[cfg(not(feature = "http-0"))]
        let registry = state.registry_ref();
        state.bind_config_environment::<Self>()?;
        let provider = Arc::new(AcmeProvider {
            worker: state.is_worker(),
            txt_publisher: state
                .registry_ref()
                .resolve_dyn::<dyn TxtPublisher>(),
            ..AcmeProvider::empty(state.config_dir().join(CONFIG_FILE))
        });
        #[cfg(feature = "http-0")]
        {
            let hosts = state
                .registry_ref()
                .resolve::<claviron::edge::HostAppRegistry>()
                .ok_or_else(|| {
                    claviron::runtime::registry::Error::msg(
                        "HostAppRegistry not registered",
                    )
                })?;
            // TODO: compose non-serving integrations when Edge supports multiple interceptors.
            hosts.bind_non_serving_interception_with(
                crate::http01::prepare_non_serving,
            )?;
            claviron::edge::register_routable(state, provider)?;
        }
        #[cfg(not(feature = "http-0"))]
        registry.register(provider)?;
        Ok(())
    }
}

#[async_trait]
impl Component<AppState> for AcmeProvider {
    type Deps = ();

    fn name(&self) -> &'static str {
        "AcmeService"
    }

    fn as_reloadable(&self) -> Option<&dyn Reloadable<AppState>> {
        Some(self)
    }

    fn as_configurable(&self) -> Option<&dyn congif::ConfigRegistration> {
        Some(self)
    }
}

#[async_trait]
impl Configurable for AcmeProvider {
    /// The document, or `None` for no document: ACME is opt-in by file.
    type Config = Option<AcmeConfig>;

    fn source(&self) -> ConfigFile {
        ConfigFile::yaml(&self.config_path)
    }

    fn absent_source(&self) -> Option<Option<AcmeConfig>> {
        Some(None)
    }

    fn as_config_observer(
        &self
    ) -> Option<&dyn ConfigObserver<Config = Self::Config>> {
        Some(self)
    }

    async fn configure(
        &self,
        config: &Option<AcmeConfig>,
    ) -> congif::Result<()> {
        self.apply(config);
        Ok(())
    }

    fn validate_config(
        &self,
        config: &Self::Config,
    ) -> congif::Result<()> {
        if let Some(config) = config {
            self.order_challenge(config)
                .map_err(|error| congif::Error::msg(error.to_string()))?;
        }
        if config
            .as_ref()
            .is_some_and(|config| config.method == Some(ChallengeMethod::Http0))
            && !cfg!(feature = "http-0")
        {
            return Err(congif::Error::msg(
                "acme.method http-0 requires the http-0 feature",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl ConfigObserver for AcmeProvider {
    async fn config_changed(
        &self,
        config: &Option<AcmeConfig>,
    ) -> congif::Result<()> {
        self.apply(config);
        Ok(())
    }
}

#[async_trait]
impl Reloadable<AppState> for AcmeProvider {
    fn priority(&self) -> Option<u8> {
        Some(priority::EARLY)
    }

    async fn reload(
        &self,
        state: &AppState,
    ) -> claviron::runtime::registry::Result<()> {
        let config = state.config_reader().snapshot::<Self>()?;
        self.apply(&config);
        Ok(())
    }
}

pub fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
    <AcmeProvider as Register<AppState>>::register(state)
}
