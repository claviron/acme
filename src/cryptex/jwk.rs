use std::collections::BTreeMap;

use claviron::helpers::base64::base64_encode;
pub(crate) use claviron::ssl::Algorithm;
use p256::SecretKey;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};

use crate::AcmeError;

/// JSON Web Key — the public half of the account key, as embedded in
/// every ACME JWS protected header.
///
/// Two ACME request shapes:
/// 1. **`newAccount`** — the account isn't registered yet, so the
///    server has no `kid` for it. The full `jwk` block goes into the
///    JWS protected header (the *only* time it does). After the
///    server creates the account, the `Location` header gives back
///    a `kid` URL.
/// 2. **Every subsequent request** — `kid` (= account URL) replaces
///    `jwk` in the header. The server already has the public key,
///    so we don't repeat it.
///
/// Only the public coordinates (`x`, `y` for EC; `n`, `e` for RSA)
/// are serialised. The matching private
/// scalar lives in the account key PEM and never enters this struct.
///
/// Key generation and signing support `EC` / `P-256` and `RSA` / `RS256`.
/// Persisted metadata is validated against the private key before use.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AcmeJwk {
    pub kty: String, // "EC"
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub crv: String, // "P-256"
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub x: String, // base64url without padding
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub y: String, // base64url without padding
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub n: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub e: String,
}

impl AcmeJwk {
    /// JWS alg to use with this JWK in ACME protected headers
    pub fn alg(&self) -> Algorithm {
        match (self.kty.as_str(), self.crv.as_str()) {
            ("RSA", _) => Algorithm::RS256,
            ("EC", "P-256") => Algorithm::ES256,
            ("OKP", "Ed25519") => Algorithm::EdDSA,
            _ => Algorithm::ES256, // sensible default for our current keygen
        }
    }

    /// Required public members in RFC 7638 canonical (lexicographic) order.
    pub fn to_map(&self) -> BTreeMap<String, String> {
        if self.kty == "RSA" {
            return BTreeMap::from([
                ("e".into(), self.e.clone()),
                ("kty".into(), self.kty.clone()),
                ("n".into(), self.n.clone()),
            ]);
        }
        BTreeMap::from([
            ("kty".to_string(), self.kty.clone()),
            ("crv".to_string(), self.crv.clone()),
            ("x".to_string(), self.x.clone()),
            ("y".to_string(), self.y.clone()),
        ])
    }

    /// Construct an AcmeJwk directly from a PKCS#8 PEM private key slice
    pub fn from_pem(private_key_pem: &[u8]) -> Result<Self, AcmeError> {
        let pem_str = std::str::from_utf8(private_key_pem)?;
        if let Ok(key) = super::signing::rsa_key(pem_str) {
            use aws_lc_rs::signature::KeyPair as _;
            let public = aws_lc_rs::rsa::PublicKeyComponents::<Vec<u8>>::from(
                key.public_key(),
            );
            return Ok(Self {
                kty: "RSA".into(),
                n: base64_encode(&public.n),
                e: base64_encode(&public.e),
                ..Self::default()
            });
        }
        let sk = SecretKey::from_pkcs8_pem(pem_str)
            .or_else(|_| SecretKey::from_sec1_pem(pem_str))
            .map_err(|e| {
                AcmeError::Jwk(format!(
                    "invalid or unsupported account private key: {e}"
                ))
            })?;
        // Build signing/verifying key to extract public point
        let signing_key =
            SigningKey::from_bytes(&sk.to_bytes()).map_err(|e| {
                AcmeError::Jwk(format!("invalid EC account key: {e}"))
            })?;
        let vk = signing_key.verifying_key();
        let ep = vk.to_sec1_point(false); // uncompressed
        let x = ep
            .x()
            .ok_or_else(|| AcmeError::Jwk("missing x coordinate".into()))?;
        let y = ep
            .y()
            .ok_or_else(|| AcmeError::Jwk("missing y coordinate".into()))?;
        Ok(AcmeJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: base64_encode(x.as_slice()),
            y: base64_encode(y.as_slice()),
            ..Self::default()
        })
    }

    /// Return the requested field as an Option<&str>, e.g. `jwk.get("kty")`
    pub fn get(
        &self,
        field: &str,
    ) -> Option<&str> {
        match field {
            "kty" => Some(&self.kty),
            "crv" => Some(&self.crv),
            "x" => Some(&self.x),
            "y" => Some(&self.y),
            "n" => Some(&self.n),
            "e" => Some(&self.e),
            _ => None,
        }
    }

    /// Persisted metadata must describe the actual signing key, not a config default.
    pub(crate) fn validate_key(
        &self,
        pem: &str,
        algorithm: Algorithm,
    ) -> Result<(), AcmeError> {
        let actual = Self::from_pem(pem.as_bytes())?;
        if actual.alg() != algorithm || actual.to_map() != self.to_map() {
            return Err(AcmeError::Jwk(
                "account algorithm/JWK does not match its private key".into(),
            ));
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for AcmeJwk {
    type Error = AcmeError;

    fn try_from(pem: &[u8]) -> Result<Self, Self::Error> {
        Self::from_pem(pem)
    }
}
