use claviron::helpers::base64::base64_encode;
use reqwest::header::ACCEPT;
use serde_json::{Value, json};
use tracing::debug;

use crate::AcmeError;
use crate::clients::AcmeClient;
use crate::clients::http::checked_response;
use crate::cryptex::jwk;
use crate::cryptex::signing::sign_payload;

/// One-shot client for the **account creation** leg of ACME (RFC 8555 §7.3).
///
/// Three round-trips:
/// 1. `GET <base>/directory` — discover `newNonce` and `newAccount` URLs.
/// 2. `HEAD newNonce` — pull a fresh `Replay-Nonce` to seed the JWS.
/// 3. `POST newAccount` — JWS-signed registration. `jwk` lives in the
///    protected header (no `kid` yet — the account doesn't exist), and
///    the response `Location` header is the freshly assigned account URL
///    that becomes the `kid` for every subsequent request.
///
/// `register_account` consumes `self` because creation is one-shot —
/// after it succeeds, the caller persists the returned URL into an
/// `Account` and from then on uses [`super::CertClient`] (which signs
/// with `kid`, not `jwk`).
pub struct AccountClient {
    client: AcmeClient,
    base_url: String,
}

impl AccountClient {
    pub fn with_client(
        client: AcmeClient,
        base_url: &str,
    ) -> AccountClient {
        Self { client, base_url: base_url.to_string() }
    }

    pub(crate) async fn register_account(
        self,
        pem_key: &str,
        jwk: &jwk::AcmeJwk,
    ) -> Result<String, AcmeError> {
        let base_url = format!("{}/directory", self.base_url);

        let directory_response = self
            .client
            .get(&base_url)
            .header(ACCEPT, "application/json")
            .send()
            .await?;

        let directory_response = checked_response(directory_response).await?;
        let directory_json: Value = directory_response.json().await?;

        let new_nonce_url = directory_json["newNonce"]
            .as_str()
            .ok_or("newNonce URL not found in directory")?
            .to_string();

        let new_account_url = directory_json["newAccount"]
            .as_str()
            .ok_or("newAccount URL not found in directory")?
            .to_string();

        debug!("Registering new account at url {}", &new_account_url);

        let payload = json!({
            "termsOfServiceAgreed": true
        });

        let response = self
            .send_signed_request(
                &new_account_url,
                &new_nonce_url,
                Some(&payload),
                pem_key,
                jwk,
            )
            .await?;
        let location = response
            .headers()
            .get("Location")
            .ok_or(AcmeError::MissingLocationHeader)?;
        let account_url = location.to_str()?;
        debug!("Account registered at url {}", account_url);
        Ok(account_url.to_string())
    }

    async fn send_signed_request(
        &self,
        url: &str,
        new_nonce_url: &str,
        payload: Option<&Value>,
        key_pem: &str,
        jwk: &jwk::AcmeJwk,
    ) -> Result<reqwest::Response, AcmeError> {
        let nonce_resp = self.client.head(new_nonce_url).send().await?;
        let nonce_resp = checked_response(nonce_resp).await?;
        let nonce_hdr = nonce_resp
            .headers()
            .get("Replay-Nonce")
            .or_else(|| nonce_resp.headers().get("replay-nonce"))
            .ok_or("Replay-Nonce header not found")?;
        let nonce = nonce_hdr.to_str()?;

        // We already have the AcmeJwk; convert it to a map for JSON
        let jwk_value = jwk.to_map();

        // Choose alg directly from JWK helper (no manual matching here)
        let alg = match jwk.alg() {
            jwk::Algorithm::RS256 => "RS256",
            jwk::Algorithm::ES256 => "ES256",
            jwk::Algorithm::ES384 => "ES384",
            jwk::Algorithm::EdDSA => "EdDSA",
        };

        let protected = json!({
            "alg": alg,
            "nonce": nonce,
            "url": url,
            "jwk": jwk_value
        });

        // Base64URL-encode protected header (no padding) per JWS
        let protected_b64 = base64_encode(&serde_json::to_vec(&protected)?);

        // ACME POST-as-GET: payload may be empty
        let payload_b64 = match payload {
            Some(p) => base64_encode(p.to_string().as_bytes()),
            None => String::new(),
        };

        let signature = sign_payload(key_pem, &protected_b64, &payload_b64)?;

        let body = json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature
        });

        let body_str = serde_json::to_string(&body)?;
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .header(ACCEPT, "application/json")
            .body(body_str)
            .send()
            .await?;

        checked_response(response).await
    }
}
