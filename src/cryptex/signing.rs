use claviron::helpers::base64::{base64_decode, base64_encode};
use p256::SecretKey;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::AcmeError;
use crate::cryptex::jwk::AcmeJwk;

// key_pem will include BEGIM END headers to detect algorithm
pub(crate) fn sign_payload(
    pem_str: &str,
    protected_b64: &str,
    payload_b64: &str,
) -> Result<String, AcmeError> {
    let protected =
        base64_decode(protected_b64).map_err(AcmeError::SignRequest)?;
    let protected: serde_json::Value = serde_json::from_slice(&protected)?;
    let actual = AcmeJwk::from_pem(pem_str.as_bytes())?;
    let expected = match actual.alg() {
        claviron::ssl::Algorithm::RS256 => "RS256",
        _ => "ES256",
    };
    if protected.get("alg").and_then(serde_json::Value::as_str)
        != Some(expected)
    {
        return Err(AcmeError::SignRequest(
            "protected algorithm does not match account key".into(),
        ));
    }
    if expected == "RS256" {
        let key = rsa_key(pem_str)?;
        let mut signature = vec![0; key.public_modulus_len()];
        key.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            format!("{protected_b64}.{payload_b64}").as_bytes(),
            &mut signature,
        )
        .map_err(|e| {
            AcmeError::SignRequest(format!("RSA signing failed: {e}"))
        })?;
        return Ok(base64_encode(&signature));
    }
    // Try PKCS#8 first, fall back to SEC1 (traditional EC key)
    let sk: SecretKey = SecretKey::from_pkcs8_pem(pem_str).or_else(|e| {
        SecretKey::from_sec1_pem(pem_str).map_err(|_| {
            AcmeError::SignRequest(format!("invalid EC account key PEM: {e}"))
        })
    })?;

    let signing_key = SigningKey::from_bytes(&sk.to_bytes()).map_err(|e| {
        AcmeError::SignRequest(format!("invalid EC account key: {e}"))
    })?;
    let to_sign = format!("{}.{}", protected_b64, payload_b64);
    let sig: Signature = signing_key.sign(to_sign.as_bytes());
    // ES256 requires raw r||s (64 bytes) base64url without padding
    Ok(base64_encode(sig.to_bytes().as_slice()))
}

pub(super) fn rsa_key(pem: &str) -> Result<aws_lc_rs::rsa::KeyPair, AcmeError> {
    let pem = pem::parse(pem).map_err(|e| {
        AcmeError::SignRequest(format!("invalid account PEM: {e}"))
    })?;
    let key = match pem.tag() {
        "PRIVATE KEY" => aws_lc_rs::rsa::KeyPair::from_pkcs8(pem.contents()),
        "RSA PRIVATE KEY" => aws_lc_rs::rsa::KeyPair::from_der(pem.contents()),
        _ => {
            return Err(AcmeError::SignRequest(
                "not an RSA private key".into(),
            ));
        }
    };
    key.map_err(|e| {
        AcmeError::SignRequest(format!("invalid RSA account key: {e}"))
    })
}

pub(crate) fn thumbprint(jwk: &AcmeJwk) -> Result<String, AcmeError> {
    let map = jwk.to_map();
    let jwk_json = json!(map).to_string();
    let digest = Sha256::digest(jwk_json.as_bytes());
    Ok(base64_encode(&digest))
}
