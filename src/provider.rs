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
use claviron::orbit::ClientAdmissionProvider;
use claviron::runtime::congif::{
    self, ConfigFile, ConfigObserver, Configurable,
};
use claviron::runtime::registry::{Component, Reloadable, priority};
use claviron::runtime::{AppState, Register, registry};

use crate::AcmeError;
use crate::clients::OrderChallenge;
use crate::config::{AcmeConfig, ChallengeMethod};
#[cfg(feature = "dns-01")]
use crate::methods::dns01::{Dns01, TxtPublisher};
#[cfg(feature = "tls-alpn-01")]
use crate::methods::tlsalpn01;

/// What the ACME configuration file is called in the config directory.
pub const CONFIG_FILE: &str = "acme.yaml";

pub struct AcmeProvider {
    config_path: PathBuf,
    snapshot: ArcSwapOption<AcmeConfig>,
    #[cfg(feature = "dns-01")]
    txt_publisher: Option<Arc<dyn TxtPublisher>>,
    #[cfg(feature = "tls-alpn-01")]
    tls_alpn_publisher: Option<Arc<dyn tlsalpn01::Publisher>>,
    /// A listener `register_local` opted in, answering the configured id.
    #[cfg(feature = "tls-alpn-01")]
    tls_alpn_answer: Option<Arc<tlsalpn01::Answer>>,
    #[cfg(feature = "http-0")]
    pub(crate) http01:
        std::sync::Mutex<Option<Arc<crate::methods::http01::Http01Layer>>>,
    /// The fleet's client admission table, where the application registered
    /// it; `http.pool.scope: fleet` needs it.
    admission: Option<Arc<ClientAdmissionProvider>>,
    /// This process's client to the CA, kept while `http:` is unchanged.
    client: std::sync::Mutex<
        Option<(
            claviron::clients::HttpClientConfig,
            crate::clients::AcmeClient,
        )>,
    >,
    worker: bool,
}

impl AcmeProvider {
    pub fn empty(config_path: PathBuf) -> Self {
        Self {
            config_path,
            snapshot: ArcSwapOption::empty(),
            #[cfg(feature = "dns-01")]
            txt_publisher: None,
            #[cfg(feature = "tls-alpn-01")]
            tls_alpn_publisher: None,
            #[cfg(feature = "tls-alpn-01")]
            tls_alpn_answer: None,
            #[cfg(feature = "http-0")]
            http01: std::sync::Mutex::default(),
            admission: None,
            client: std::sync::Mutex::default(),
            worker: false,
        }
    }

    pub fn snapshot(&self) -> Option<Arc<AcmeConfig>> {
        self.snapshot.load_full()
    }

    /// This process's client to the CA, as `acme.yaml`'s `http:` declares it;
    /// `None` while ACME is off.
    pub fn client(&self) -> Option<crate::clients::AcmeClient> {
        self.client
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(|(_, client)| client.clone())
    }

    /// Keep the client while `http:` is unchanged, so its pool and admission
    /// carry across a reload that touched something else.
    fn apply_client(
        &self,
        config: Option<&AcmeConfig>,
    ) {
        let mut client =
            self.client.lock().unwrap_or_else(|error| error.into_inner());
        let Some(config) = config else {
            *client = None;
            return;
        };
        if client.as_ref().is_some_and(|(http, _)| *http == config.http) {
            return;
        }
        match crate::clients::AcmeClient::new(
            self.admission.clone(),
            &config.http,
        ) {
            Ok(built) => *client = Some((config.http.clone(), built)),
            // Validation refused this before it was applied.
            Err(error) => {
                tracing::error!(%error, "ACME HTTP client not rebuilt")
            }
        }
    }

    /// Resolve an explicit order method, else the one `acme.method` chose.
    /// Nothing chooses one implicitly.
    pub fn order_challenge<'a>(
        &'a self,
        config: &'a AcmeConfig,
        method: Option<ChallengeMethod>,
    ) -> Result<OrderChallenge<'a>, AcmeError> {
        match method.or(config.method) {
            None => Err(
                "acme.method is not set: choose http-0, dns-01 or tls-alpn-01"
                    .into(),
            ),
            Some(ChallengeMethod::Http0) if !cfg!(feature = "http-0") => {
                Err("ACME HTTP-01 requires the http-0 feature".into())
            }
            Some(ChallengeMethod::Http0) => {
                Ok(OrderChallenge::Http01(config.challenges_dir()))
            }
            Some(ChallengeMethod::Dns01) => {
                #[cfg(feature = "dns-01")]
                {
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
                    Ok(OrderChallenge::Dns01(Box::new(dns)))
                }
                #[cfg(not(feature = "dns-01"))]
                Err("ACME DNS-01 requires the dns-01 feature".into())
            }
            Some(ChallengeMethod::TlsAlpn01) => {
                #[cfg(feature = "tls-alpn-01")]
                {
                    self.tls_alpn_publisher.as_deref()
                        .map(|publisher| OrderChallenge::TlsAlpn01 {
                            publisher,
                            alpn: config.tls_alpn(),
                        })
                        .ok_or_else(|| "TLS-ALPN-01 requires a registered challenge publisher".into())
                }
                #[cfg(not(feature = "tls-alpn-01"))]
                Err("acme.method tls-alpn-01 requires the tls-alpn-01 feature"
                    .into())
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
        self.apply_client(config.as_ref());
        match config {
            Some(cfg) => {
                self.snapshot.store(Some(Arc::new(cfg.clone())));
                if self.worker {
                    tracing::debug!(
                        "📦 AcmeService applied {}",
                        self.config_path.display()
                    );
                } else {
                    tracing::info!(
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
    fn register(state: &AppState) -> registry::Result<()> {
        #[cfg(not(feature = "http-0"))]
        let registry = state.registry_ref();
        state.bind_config_environment::<Self>()?;
        let provider = Arc::new(AcmeProvider {
            worker: state.is_worker(),
            #[cfg(feature = "dns-01")]
            txt_publisher: state
                .registry_ref()
                .resolve_dyn::<dyn TxtPublisher>(),
            #[cfg(feature = "tls-alpn-01")]
            tls_alpn_publisher: state
                .registry_ref()
                .resolve_dyn::<dyn tlsalpn01::Publisher>(),
            #[cfg(feature = "tls-alpn-01")]
            tls_alpn_answer: state
                .registry_ref()
                .resolve::<tlsalpn01::Answer>(),
            admission: state
                .registry_ref()
                .resolve::<claviron::orbit::ClientAdmissionProvider>(),
            ..AcmeProvider::empty(state.config_dir().join(CONFIG_FILE))
        });
        #[cfg(feature = "http-0")]
        {
            let hosts = state
                .registry_ref()
                .resolve::<claviron::edge::HostAppRegistry>()
                .ok_or_else(|| {
                    registry::Error::msg("HostAppRegistry not registered")
                })?;
            // TODO: compose non-serving integrations when Edge supports multiple interceptors.
            hosts.bind_non_serving_interception_with(
                crate::methods::http01::prepare_non_serving,
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
        // A listener opted into TLS-ALPN-01 answers the id this names.
        #[cfg(feature = "tls-alpn-01")]
        if let (Some(answer), Some(config)) = (&self.tls_alpn_answer, config) {
            answer.answer(config.tls_alpn()).map_err(congif::Error::msg)?;
        }
        self.apply(config);
        Ok(())
    }

    fn validate_config(
        &self,
        config: &Self::Config,
    ) -> congif::Result<()> {
        if let Some(config) = config {
            self.order_challenge(config, None)
                .map_err(|error| congif::Error::msg(error.to_string()))?;
            crate::clients::AcmeClient::new(
                self.admission.clone(),
                &config.http,
            )
            .map_err(|error| congif::Error::msg(error.to_string()))?;
            #[cfg(feature = "tls-alpn-01")]
            if let Some(answer) = &self.tls_alpn_answer {
                answer.check(config.tls_alpn()).map_err(congif::Error::msg)?;
            }
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
    ) -> registry::Result<()> {
        let config = state.config_reader().snapshot::<Self>()?;
        self.apply(&config);
        Ok(())
    }
}

pub fn register(state: &AppState) -> registry::Result<()> {
    <AcmeProvider as Register<AppState>>::register(state)
}
