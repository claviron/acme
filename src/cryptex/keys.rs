use base64ct::LineEnding;
use claviron::ssl::Algorithm;
use getrandom::fill as getrandom_fill;
use p256::pkcs8::EncodePrivateKey;
use p256::{FieldBytes, SecretKey};

use crate::AcmeError;
use crate::cryptex::jwk::AcmeJwk;

pub(crate) fn generate_acme_key() -> Result<String, AcmeError> {
    // Generate 32 bytes from OS CSPRNG and derive a valid P-256 secret key
    let mut seed = [0u8; 32];
    getrandom_fill(&mut seed)
        .map_err(|e| AcmeError::SignRequest(format!("OS RNG error: {e}")))?;

    // Convert to FieldBytes and build SecretKey (retry unlikely errors by bubbling up)
    let fb = FieldBytes::try_from(&seed[..])
        .map_err(|_| AcmeError::SignRequest("invalid seed length".into()))?;
    let sk = SecretKey::from_bytes(&fb)
        .map_err(|_| AcmeError::SignRequest("invalid P-256 scalar".into()))?;

    // Export as PKCS#8 PEM (UTF-8 String)
    let pem = sk.to_pkcs8_pem(LineEnding::LF)?.to_string();
    Ok(pem)
}

/// Generate a fresh ACME key (PEM) **and** its corresponding JWK fields.
pub(crate) fn generate_acme_key_with_jwk(
    algorithm: &Algorithm
) -> Result<(String, AcmeJwk), AcmeError> {
    match algorithm {
        Algorithm::ES256 => {
            let pem = generate_acme_key()?;
            let jwk = AcmeJwk::from_pem(pem.as_bytes())?;
            Ok((pem, jwk))
        }
        Algorithm::RS256 => {
            use aws_lc_rs::encoding::AsDer;
            let key = aws_lc_rs::rsa::KeyPair::generate(
                aws_lc_rs::rsa::KeySize::Rsa2048,
            )
            .map_err(|e| {
                AcmeError::SignRequest(format!(
                    "RSA key generation failed: {e}"
                ))
            })?;
            let der = key.as_der().map_err(|e| {
                AcmeError::SignRequest(format!("RSA key encoding failed: {e}"))
            })?;
            let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", der.as_ref()));
            let jwk = AcmeJwk::from_pem(pem.as_bytes())?;
            Ok((pem, jwk))
        }
        _ => Err(AcmeError::UnsupportedAlgorithm(*algorithm)),
    }
}
