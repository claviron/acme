use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock, RwLock};

use claviron::runtime::{AppState, registry};
use claviron::ssl::Sni;
use claviron_tls::handshake::{AlpnProfile, AlpnProfiles};
use rustls::{ServerConfig, server::ClientHello};

use super::{Publication, PublishError, Publisher};

type Challenges = RwLock<HashMap<Sni, Arc<ServerConfig>>>;

struct Local {
    listener: String,
    challenges: Arc<Challenges>,
}

/// The listener's profile, answering the ALPN id `acme.yaml` names.
struct LocalProfile {
    local: Arc<Local>,
    protocols: Box<[Box<[u8]>]>,
}

/// A listener opted in by [`register_local`], answering once `acme.yaml` is
/// applied and names its ALPN id.
pub(crate) struct Answer {
    local: Arc<Local>,
    profiles: Arc<AlpnProfiles>,
    answering: OnceLock<Box<[u8]>>,
}

impl Answer {
    /// Answer `alpn` on the listener. The id is registered once, when the
    /// configuration is first applied; a later change takes a restart.
    pub(crate) fn answer(
        &self,
        alpn: &[u8],
    ) -> Result<(), String> {
        if let Some(answering) = self.answering.get() {
            return Self::unchanged(answering, alpn);
        }
        let profile = LocalProfile {
            local: self.local.clone(),
            protocols: Box::new([Box::from(alpn)]),
        };
        self.profiles
            .register(Arc::new(profile))
            .map_err(|conflict| conflict.to_string())?;
        let _ = self.answering.set(Box::from(alpn));
        Ok(())
    }

    /// Whether a configuration about to be applied keeps the id answered.
    pub(crate) fn check(
        &self,
        alpn: &[u8],
    ) -> Result<(), String> {
        match self.answering.get() {
            Some(answering) => Self::unchanged(answering, alpn),
            None => Ok(()),
        }
    }

    fn unchanged(
        answering: &[u8],
        alpn: &[u8],
    ) -> Result<(), String> {
        if answering == alpn {
            Ok(())
        } else {
            Err("tls-alpn-01.alpn changed; a new ALPN id takes a restart"
                .into())
        }
    }
}

/// Opt a standalone application's named TCP TLS listener into TLS-ALPN-01.
/// Call before registering ACME. Supervised applications can bind their own
/// publisher and ALPN profile with cross-process publication.
pub fn register_local(
    state: &AppState,
    listener: impl Into<String>,
) -> registry::Result<()> {
    if !state.is_standalone() || state.worker_count() != 0 {
        return Err(registry::Error::msg(
            "TLS-ALPN-01 requires a fleet-aware publisher in supervised mode",
        ));
    }
    let listener = listener.into();
    if listener.is_empty() {
        return Err(registry::Error::msg(
            "TLS-ALPN-01 requires a named TCP TLS listener",
        ));
    }
    let registry = state.registry_ref();
    let profiles = registry.resolve::<AlpnProfiles>().ok_or_else(|| {
        registry::Error::msg("TLS-ALPN-01 requires the Edge's ALPN profiles")
    })?;
    let local = Arc::new(Local { listener, challenges: Arc::default() });
    registry.insert(local.clone())?;
    registry.bind_dyn::<dyn Publisher, Local>(|local| local)?;
    // The profile is registered when ACME's configuration names its id.
    registry.insert(Arc::new(Answer {
        local,
        profiles,
        answering: OnceLock::new(),
    }))?;
    Ok(())
}

impl AlpnProfile for LocalProfile {
    fn protocols(&self) -> &[Box<[u8]>] {
        &self.protocols
    }

    fn handshake(
        &self,
        listener: &str,
        hello: &ClientHello<'_>,
    ) -> io::Result<Option<Arc<ServerConfig>>> {
        self.local.handshake(listener, hello, &self.protocols[0])
    }
}

impl Local {
    /// The challenge for `hello` when it reached this listener offering
    /// `alpn` alone, as RFC 8737 has the CA connect.
    fn handshake(
        &self,
        listener: &str,
        hello: &ClientHello<'_>,
        alpn: &[u8],
    ) -> io::Result<Option<Arc<ServerConfig>>> {
        if listener != self.listener {
            return Ok(None);
        }
        let Some(mut offered) = hello.alpn() else { return Ok(None) };
        if offered.next() != Some(alpn) || offered.next().is_some() {
            return Ok(None);
        }
        let name =
            hello.server_name().and_then(|name| name.parse::<Sni>().ok());
        let config = name
            .and_then(|name| self.challenges.read().ok()?.get(&name).cloned());
        config.map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "No active TLS-ALPN-01 challenge",
            )
        })
    }
}

#[async_trait::async_trait]
impl Publisher for Local {
    async fn publish(
        &self,
        name: &Sni,
        config: Arc<ServerConfig>,
    ) -> Result<Box<dyn Publication>, PublishError> {
        use std::collections::hash_map::Entry;

        let mut challenges = self
            .challenges
            .write()
            .map_err(|_| "TLS-ALPN-01 store poisoned")?;
        let Entry::Vacant(entry) = challenges.entry(name.clone()) else {
            return Err(format!(
                "TLS-ALPN-01 challenge already active for {name}"
            )
            .into());
        };
        entry.insert(config);
        Ok(Box::new(Active {
            challenges: self.challenges.clone(),
            name: name.clone(),
        }))
    }
}

struct Active {
    challenges: Arc<Challenges>,
    name: Sni,
}

impl Publication for Active {}

impl Drop for Active {
    fn drop(&mut self) {
        if let Ok(mut challenges) = self.challenges.write() {
            challenges.remove(&self.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::io::Cursor;

    fn select(
        local: &Local,
        listener: &str,
        sni: &'static str,
        alpns: &[&[u8]],
    ) -> io::Result<Option<Arc<ServerConfig>>> {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            claviron_tls::policy::provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        config.alpn_protocols =
            alpns.iter().map(|alpn| alpn.to_vec()).collect();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(sni).unwrap(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        let mut acceptor = rustls::server::Acceptor::default();
        acceptor.read_tls(&mut Cursor::new(bytes)).unwrap();
        let hello = acceptor.accept().unwrap().unwrap();
        local.handshake(listener, &hello.client_hello(), ID)
    }

    const ID: &[u8] = b"acme-tls/1";

    #[test]
    fn the_listener_answers_the_configured_id_until_a_restart() {
        let profiles = Arc::new(AlpnProfiles::default());
        let answer = Answer {
            local: Arc::new(Local {
                listener: "public".into(),
                challenges: Arc::default(),
            }),
            profiles: profiles.clone(),
            answering: OnceLock::new(),
        };
        answer.answer(b"example-acme/1").unwrap();
        // Registered under the configured id: a second claim conflicts.
        let claim = LocalProfile {
            local: answer.local.clone(),
            protocols: Box::new([Box::from(&b"example-acme/1"[..])]),
        };
        assert!(profiles.register(Arc::new(claim)).is_err());
        answer.answer(b"example-acme/1").unwrap();
        assert!(answer.check(b"acme-tls/1").is_err());
        assert!(answer.check(b"example-acme/1").is_ok());
    }

    #[tokio::test]
    async fn challenge_requires_its_listener_sni_and_solo_alpn() {
        let local =
            Local { listener: "public".into(), challenges: Arc::default() };
        let name = "example.test".parse().unwrap();
        let config =
            super::super::challenge_config(&name, "token.thumbprint", ID)
                .unwrap();
        let active = local.publish(&name, config.clone()).await.unwrap();
        assert!(Arc::ptr_eq(
            &config,
            &select(&local, "public", "example.test", &[ID]).unwrap().unwrap()
        ));
        assert!(local.publish(&name, config).await.is_err());
        assert!(
            select(&local, "other", "example.test", &[ID]).unwrap().is_none()
        );
        assert!(
            select(&local, "public", "example.test", &[b"h2", ID])
                .unwrap()
                .is_none()
        );
        assert!(select(&local, "public", "other.test", &[ID]).is_err());
        drop(active);
        assert!(select(&local, "public", "example.test", &[ID]).is_err());
    }
}
