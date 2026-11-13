//! TLS-ALPN-01 proof generation and publication (RFC 8737).

use std::sync::Arc;

use async_trait::async_trait;
use claviron::ssl::Sni;
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use sha2::{Digest, Sha256};

use crate::AcmeError;

pub const ALPN: &[u8] = b"acme-tls/1";

pub type PublishError = Box<dyn std::error::Error + Send + Sync>;

/// Owns one active proof. Dropping it withdraws the proof.
pub trait Publication: Send + Sync {}

/// Make a challenge config visible to the accepting TCP listeners. Return
/// only when all relevant processes can serve it. The returned guard owns
/// withdrawal on completion and cancellation.
#[async_trait]
pub trait Publisher: Send + Sync {
    async fn publish(
        &self,
        name: &Sni,
        config: Arc<ServerConfig>,
    ) -> Result<Box<dyn Publication>, PublishError>;
}

pub(crate) fn challenge_config(
    name: &Sni,
    key_authorization: &str,
) -> Result<Arc<ServerConfig>, AcmeError> {
    fn error(error: impl std::fmt::Display) -> AcmeError {
        AcmeError::from(format!("TLS-ALPN-01 certificate: {error}"))
    }

    let key = rcgen::KeyPair::generate().map_err(error)?;
    let mut params =
        rcgen::CertificateParams::new(vec![name.to_string()]).map_err(error)?;
    params.custom_extensions.push(rcgen::CustomExtension::new_acme_identifier(
        &Sha256::digest(key_authorization),
    ));
    let certificate = params.self_signed(&key).map_err(error)?;
    let provider = Arc::new(claviron_tls::policy::provider());
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        )))
        .map_err(error)?;
    // The certificate and key were generated together. rustls' ordinary
    // certificate parser rejects the critical ACME extension by design.
    let certified_key =
        CertifiedKey::new(vec![certificate.der().clone()], signing_key);
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&claviron_tls::policy::versions())
        .map_err(error)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.session_storage =
        Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

mod local;
pub use local::register_local;
