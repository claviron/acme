use std::path::Path;
use std::time::{Duration, Instant};

use claviron::helpers::base64::base64_encode;
use claviron::ssl::{Algorithm, Aliases, KeyString};
use serde_json::json;
use tokio::time::sleep;
use tracing::{debug, error};
use url::Url;

use crate::AcmeError;
use crate::clients::AcmeClient;
use crate::clients::challenge::Challenge;
use crate::clients::http::checked_response;
use crate::cryptex::jwk::AcmeJwk;
use crate::cryptex::signing::{sign_payload, thumbprint};

/// Long-lived client for the **certificate order** legs of ACME
/// (RFC 8555 §7.4 and §8). Holds the account's signing key plus the
/// account URL (the JWS `kid`); reused across many cert orders.
///
/// One call to [`request_certificate`](Self::request_certificate)
/// drives the full RFC 8555 order state machine end-to-end:
///
/// 1. `POST newOrder` with the SNI list → returns an order URL plus
///    one `authorization` URL per identifier.
/// 2. For each authorization: pick the `http-01` challenge, write
///    `<token>` → `<token>.<jwk_thumbprint>` to the challenges
///    directory, then `POST` the challenge URL to ask the CA to
///    validate.
/// 3. Poll the challenge status (capped backoff, 90s overall
///    deadline) until `valid` or `invalid`.
/// 4. Once all authorizations are valid: poll the order until
///    `ready`, then `POST finalize` with the base64url CSR.
/// 5. Poll the order until `valid`, then `GET certificate` URL to
///    fetch the issued PEM chain.
///
/// `challenge_dir` must be a path the **public-facing claviron-hyper
/// listener** serves under `/.well-known/acme-challenge/` — that's
/// the cooperation contract between this crate and the cleartext
/// listener that handles port-80 traffic. CAs reach the challenge
/// files via plaintext HTTP, so port 80 must be open for ACME to
/// work end-to-end.
///
/// The function returns the full PEM chain (leaf + intermediates) on
/// success; persistence is the caller's job — file-based path writes
/// to disk via `actions::certificate`, DB-backed path writes via
/// `actions::database`.
pub struct CertClient {
    client: AcmeClient,
    key: String,
    base_url: String,
    account_url: String,
}

impl CertClient {
    pub fn with_client(
        client: AcmeClient,
        key: &str,
        account_url: &str,
    ) -> Result<Self, AcmeError> {
        let url = Url::parse(account_url).map_err(|error| {
            AcmeError::ClientCreationFailed(format!(
                "Invalid ACME account URL: {error}"
            ))
        })?;
        if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
            return Err(AcmeError::ClientCreationFailed(
                "ACME account URL must use HTTP or HTTPS and include a host"
                    .into(),
            ));
        }
        // Let URL serialization preserve non-default ports and bracketed IPv6
        // authorities while keeping the original account URL for the JWS kid.
        let base_url = url.origin().ascii_serialization();

        Ok(Self {
            client,
            key: key.to_string(),
            base_url,
            account_url: account_url.to_string(),
        })
    }

    pub async fn request_certificate(
        &self,
        p_csr_der: &[u8],
        jwk: &AcmeJwk,
        challenge_dir: impl AsRef<Path>,
    ) -> Result<String, AcmeError> {
        let alg = jwk.alg();
        // NOTE: we reuse `alg` for all ACME calls in this flow to avoid recomputation

        let new_order_url = format!("{}/acme/new-order", self.base_url);

        debug!("Creating new order at URL: {}", new_order_url);

        let aliases = Aliases::from_csr_der(p_csr_der)?;

        // debug!("Sni Hosts: {:?}", &aliases);

        // Create a new order with only SNI (DNS) entries; skip IPs or unsupported types
        let identifiers: Vec<_> = aliases
            .iter()
            .filter(|d| d.is_sni())
            .map(|d| json!({"type": "dns", "value": d.key_str()}))
            .collect();

        debug!("Creating new order with identifiers: {:?}", identifiers);

        let order_resp = self
            .send_signed_request(
                new_order_url.as_str(),
                Some(&json!({"identifiers": identifiers})),
                &alg,
            )
            .await?;

        // Extract order status URL and authorization URLs
        let order_status_url = order_resp
            .headers()
            .get("Location")
            .ok_or("Order status URL not found in headers")?
            .to_str()?
            .to_string();

        let order_resp_text = order_resp.text().await?;
        let order: serde_json::Value = serde_json::from_str(&order_resp_text)?;

        let auth_urls = order["authorizations"]
            .as_array()
            .ok_or("Authorization URLs not found")?;

        // Validate each domain
        for auth_url in auth_urls {
            let auth_url =
                auth_url.as_str().ok_or("Invalid authorization URL")?;
            let auth_resp =
                self.send_signed_request(auth_url, None, &alg).await?;
            let auth_resp_text = auth_resp.text().await?;
            let auth: serde_json::Value =
                serde_json::from_str(&auth_resp_text)?;

            if auth["status"] == "valid" {
                debug!("Authorization is already valid, skipping challenge.");
                continue;
            }

            let challenge = auth["challenges"]
                .as_array()
                .ok_or("Challenges not found")?
                .iter()
                .find(|c| c["type"] == "http-01")
                .ok_or("HTTP-01 challenge not found")?;

            let token = challenge["token"]
                .as_str()
                .ok_or("Challenge Token not found in response")?;
            let key_authorization = format!("{}.{}", token, thumbprint(jwk)?);
            let _file = Challenge::create(
                challenge_dir.as_ref(),
                token,
                key_authorization,
            )
            .await?;

            debug!("Waiting for challenge to be validated");

            self.send_signed_request(
                challenge["url"].as_str().ok_or("Challenge URL not found")?,
                Some(&json!({})),
                &alg,
            )
            .await?;

            // Bound the validation wait with an overall deadline.
            // Compile-time default; promote to `AcmeConfig` if operator
            // tuning becomes necessary. Runtime env reads are not
            // allowed (claviron worker scrubs libc env post-boot).
            let max_secs: u64 = 90;
            let started = Instant::now();
            let mut backoff = Duration::from_secs(1);

            loop {
                let challenge_status_resp = self
                    .send_signed_request(
                        challenge["url"]
                            .as_str()
                            .ok_or("Challenge URL not found")?,
                        None,
                        &alg,
                    )
                    .await?;
                let challenge_status_text =
                    challenge_status_resp.text().await?;
                let challenge_status: serde_json::Value =
                    serde_json::from_str(&challenge_status_text)?;

                match challenge_status["status"].as_str() {
                    Some("valid") => break,
                    Some("invalid") => {
                        let err = challenge_status["error"].clone();
                        error!("challenge became invalid: {}", err);
                        return Err(AcmeError::InvalidOrderStatus);
                    }
                    _ => {}
                }

                if started.elapsed() > Duration::from_secs(max_secs) {
                    error!(
                        "challenge validation timed out after {}s (url: {})",
                        max_secs,
                        challenge["url"].as_str().unwrap_or("")
                    );
                    return Err(AcmeError::from(
                        "Challenge validation timeout",
                    ));
                }

                sleep(backoff).await;
                // simple exponential backoff, capped
                backoff = std::cmp::min(backoff * 2, Duration::from_secs(10));
            }
        }

        // Finalize the order and retrieve the certificate
        loop {
            debug!("checking order status");

            let order_status_resp =
                self.send_signed_request(&order_status_url, None, &alg).await?;
            let order_status: serde_json::Value =
                order_status_resp.json().await?;

            debug!("order status : {}", order_status["status"]);

            if order_status["status"] == "valid" {
                return if let Some(cert_url) =
                    order_status["certificate"].as_str()
                {
                    let cert_resp =
                        self.send_signed_request(cert_url, None, &alg).await?;
                    let cert_pem = cert_resp.text().await?;
                    Ok(cert_pem)
                } else {
                    Err(AcmeError::InvalidOrderStatus)
                };
            } else if order_status["status"] == "ready" {
                debug!("Order is ready, sending finalize request");
                let csr_base64 = base64_encode(p_csr_der);
                self.send_signed_request(
                    order["finalize"]
                        .as_str()
                        .ok_or("Finalize URL not found")?,
                    Some(&json!({"csr": csr_base64})),
                    &alg,
                )
                .await?;
                debug!("Finalize request completed, waiting for certificate");
            } else {
                // RFC 8555 order statuses: pending, ready, processing, valid, invalid
                match order_status["status"].as_str() {
                    Some("pending") | Some("processing") => {
                        // keep polling
                    }
                    Some("invalid") => {
                        let prob = order_status["error"].clone();
                        error!("order became invalid: {}", prob);
                        return Err(AcmeError::InvalidOrderStatus);
                    }
                    Some(other) => {
                        error!(
                            "unexpected order status: {} — full: {}",
                            other, order_status
                        );
                        return Err(AcmeError::InvalidOrderStatus);
                    }
                    None => {
                        error!(
                            "order status missing or not a string: {}",
                            order_status
                        );
                        return Err(AcmeError::InvalidOrderStatus);
                    }
                }
            }
            sleep_for(1).await;
        }
    }

    async fn send_signed_request(
        &self,
        url: &str,
        payload: Option<&serde_json::Value>,
        alg: &Algorithm,
    ) -> Result<reqwest::Response, AcmeError> {
        let payload64 = if let Some(payload) = payload {
            let json = serde_json::to_vec(payload)?;
            base64_encode(&json)
        } else {
            String::new()
        };

        let nonce_resp = self
            .client
            .head(format!("{}/acme/new-nonce", self.base_url))
            .send()
            .await?;
        let nonce_resp = checked_response(nonce_resp).await?;

        let nonce_hdr = nonce_resp
            .headers()
            .get("Replay-Nonce")
            .or_else(|| nonce_resp.headers().get("replay-nonce"))
            .ok_or("Replay nonce not found")?;
        let nonce = nonce_hdr.to_str()?;

        let alg_str = match alg {
            Algorithm::RS256 => "RS256",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::EdDSA => "EdDSA",
        };

        let protected = json!({
            "alg":  alg_str,
            "nonce": nonce,
            "url": url,
            "kid": &self.account_url
        });

        let protected64 = base64_encode(&serde_json::to_vec(&protected)?);

        let signature = sign_payload(&self.key, &protected64, &payload64)?;

        let request_body = json!({
            "protected": protected64,
            "payload": payload64,
            "signature": signature
        });

        let body_str = serde_json::to_string(&request_body)?;
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body_str)
            .send()
            .await?;

        checked_response(response).await
    }
}

/// Asynchronously sleeps for the specified number of seconds.
pub async fn sleep_for(seconds: u64) {
    sleep(Duration::from_secs(seconds)).await;
}

#[cfg(all(test, unix))]
#[path = "../../tests/unit/authority.rs"]
mod tests;
