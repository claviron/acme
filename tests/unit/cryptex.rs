use aws_lc_rs::signature::KeyPair as _;
use claviron::helpers::base64::{base64_decode, base64_encode};
use claviron::ssl::Algorithm;

use super::jwk::AcmeJwk;
use super::keys::generate_acme_key_with_jwk;
use super::signing::{sign_payload, thumbprint};

#[test]
fn rsa_account_signs_standard_rs256_and_preserves_metadata() {
    let (pem, jwk) = generate_acme_key_with_jwk(&Algorithm::RS256).unwrap();
    assert_eq!(jwk.alg(), Algorithm::RS256);
    assert_eq!(jwk.to_map().len(), 3);
    assert_eq!(jwk.e, "AQAB");
    assert_eq!(base64_decode(&jwk.n).unwrap().len(), 256);
    let stored = serde_json::to_value(&jwk).unwrap();
    assert!(stored.get("d").is_none());
    assert!(stored.get("crv").is_none());
    let loaded: AcmeJwk = serde_json::from_value(stored).unwrap();
    loaded.validate_key(&pem, Algorithm::RS256).unwrap();
    assert!(loaded.validate_key(&pem, Algorithm::ES256).is_err());
    let protected = base64_encode(br#"{"alg":"RS256","kid":"https://ca.example/acct/1","nonce":"nonce","url":"https://ca.example/order"}"#);
    for payload in [base64_encode(br#"{"identifiers":[]}"#), String::new()] {
        let signature =
            base64_decode(&sign_payload(&pem, &protected, &payload).unwrap())
                .unwrap();
        let key = super::signing::rsa_key(&pem).unwrap();
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            key.public_key().as_ref(),
        )
        .verify(format!("{protected}.{payload}").as_bytes(), &signature)
        .unwrap();
    }
    let wrong_header = base64_encode(br#"{"alg":"ES256"}"#);
    assert!(sign_payload(&pem, &wrong_header, "").is_err());
    let pkcs8 = pem::parse(&pem).unwrap();
    let info = pkcs8::PrivateKeyInfoRef::try_from(pkcs8.contents()).unwrap();
    let pkcs1 = pem::encode(&pem::Pem::new(
        "RSA PRIVATE KEY",
        info.private_key.as_bytes(),
    ));
    assert_eq!(
        AcmeJwk::from_pem(pkcs1.as_bytes()).unwrap().to_map(),
        jwk.to_map()
    );
    assert_eq!(
        sign_payload(&pem, &protected, "").unwrap(),
        sign_payload(&pkcs1, &protected, "").unwrap()
    );
    let mut wrong_jwk = loaded;
    wrong_jwk.n = "invalid".into();
    assert!(wrong_jwk.validate_key(&pem, Algorithm::RS256).is_err());
}

#[test]
fn saved_rsa_account_ignores_new_account_es256_default() {
    use crate::account::{ACCOUNT_FILE_NAME, ACCOUNT_KEY_FILE_NAME, Account};
    let root = tempfile::tempdir().unwrap();
    let config: crate::AcmeConfig = serde_yaml::from_str(&format!(
        r#"
base_dir: {}
account: imported
challenges_dir: {}/challenges
production_url: https://ca.example/directory
staging_url: https://staging.example/directory
organization:
  name: Claviron
  unit: Trust
  email: certs@example.test
pre-validation: false
renew_before: 30
algorithm: ES256
"#,
        root.path().display(),
        root.path().display()
    ))
    .unwrap();
    let (pem, jwk) = generate_acme_key_with_jwk(&Algorithm::RS256).unwrap();
    let mut account =
        Account::with_config(&config, &crate::AcmeMode::Production, "imported");
    account.alg = Algorithm::RS256;
    account.jwk = jwk;
    account.url = "https://ca.example/acct/original".into();
    let dir = config.account_dir("imported", &crate::AcmeMode::Production);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(ACCOUNT_KEY_FILE_NAME), &pem).unwrap();
    std::fs::write(
        dir.join(ACCOUNT_FILE_NAME),
        serde_json::to_vec(&account).unwrap(),
    )
    .unwrap();
    let loaded =
        Account::load(&config, &crate::AcmeMode::Production, "imported")
            .unwrap();
    assert_eq!(loaded.alg, Algorithm::RS256);
    assert_eq!(loaded.private_key(), pem);
    assert_eq!(loaded.url, "https://ca.example/acct/original");
}

#[test]
fn ec_account_still_uses_raw_es256_signatures() {
    use p256::SecretKey;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    let (pem, jwk) = generate_acme_key_with_jwk(&Algorithm::ES256).unwrap();
    jwk.validate_key(&pem, Algorithm::ES256).unwrap();
    assert_eq!(jwk.to_map().len(), 4);
    let protected = base64_encode(br#"{"alg":"ES256"}"#);
    let signature =
        base64_decode(&sign_payload(&pem, &protected, "").unwrap()).unwrap();
    assert_eq!(signature.len(), 64);
    let secret = SecretKey::from_pkcs8_pem(&pem).unwrap();
    let key = SigningKey::from_bytes(&secret.to_bytes()).unwrap();
    key.verifying_key()
        .verify(
            format!("{protected}.").as_bytes(),
            &Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    assert!(
        sign_payload(&pem, &base64_encode(br#"{"alg":"RS256"}"#), "").is_err()
    );
}

#[test]
fn rsa_thumbprint_uses_only_canonical_public_members() {
    use sha2::{Digest, Sha256};
    let jwk: AcmeJwk =
        serde_json::from_str(r#"{"n":"modulus","kty":"RSA","e":"AQAB"}"#)
            .unwrap();
    let expected = base64_encode(&Sha256::digest(
        br#"{"e":"AQAB","kty":"RSA","n":"modulus"}"#,
    ));
    assert_eq!(thumbprint(&jwk).unwrap(), expected);
}

#[test]
fn unsupported_algorithms_and_invalid_keys_fail_closed() {
    assert!(generate_acme_key_with_jwk(&Algorithm::ES384).is_err());
    assert!(generate_acme_key_with_jwk(&Algorithm::EdDSA).is_err());
    assert!(AcmeJwk::from_pem(b"invalid key").is_err());
}
