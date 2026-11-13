use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};

use claviron::runtime::{AppState, registry};
use claviron::ssl::Sni;
use claviron_tls::handshake::HandshakeSelector;
use rustls::{ServerConfig, server::ClientHello};

use super::{ALPN, Publication, PublishError, Publisher};

type Challenges = RwLock<HashMap<Sni, Arc<ServerConfig>>>;

struct Local {
    listener: String,
    challenges: Arc<Challenges>,
}

/// Opt a standalone application's named TCP TLS listener into TLS-ALPN-01.
/// Call before registering ACME. Supervised applications can bind their own
/// publisher and selector with cross-process publication.
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
    registry
        .insert(Arc::new(Local { listener, challenges: Arc::default() }))?;
    registry.bind_dyn::<dyn Publisher, Local>(|local| local)?;
    registry.bind_dyn::<dyn HandshakeSelector, Local>(|local| local)?;
    Ok(())
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
        local.select(listener, &hello.client_hello())
    }

    #[tokio::test]
    async fn challenge_requires_its_listener_sni_and_solo_alpn() {
        let local =
            Local { listener: "public".into(), challenges: Arc::default() };
        let name = "example.test".parse().unwrap();
        let config =
            super::super::challenge_config(&name, "token.thumbprint").unwrap();
        let active = local.publish(&name, config.clone()).await.unwrap();
        assert!(Arc::ptr_eq(
            &config,
            &select(&local, "public", "example.test", &[ALPN])
                .unwrap()
                .unwrap()
        ));
        assert!(local.publish(&name, config).await.is_err());
        assert!(
            select(&local, "other", "example.test", &[ALPN]).unwrap().is_none()
        );
        assert!(
            select(&local, "public", "example.test", &[b"h2", ALPN])
                .unwrap()
                .is_none()
        );
        assert!(select(&local, "public", "other.test", &[ALPN]).is_err());
        drop(active);
        assert!(select(&local, "public", "example.test", &[ALPN]).is_err());
    }
}

impl HandshakeSelector for Local {
    fn select(
        &self,
        listener: &str,
        hello: &ClientHello<'_>,
    ) -> io::Result<Option<Arc<ServerConfig>>> {
        if listener != self.listener {
            return Ok(None);
        }
        let Some(mut offered) = hello.alpn() else { return Ok(None) };
        if offered.next() != Some(ALPN) || offered.next().is_some() {
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
