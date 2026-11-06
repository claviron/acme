use std::time::Duration;

use http::HeaderMap;
use http::header::{ACCEPT, USER_AGENT};
use tracing::debug;

use crate::AcmeError;
use crate::clients::AcmeClient;

// Tunables for the ACME HTTP client. Hardcoded compile-time defaults
// — these are operator-tuning knobs, not secrets, and the values were
// already set as fallbacks when the previous env-based loader saw an
// unset variable. If a deployment needs to tune them, promote to
// `AcmeConfig` fields rather than re-introducing `std::env::var` —
// claviron's worker scrubs libc env post-boot, so request-time env
// reads are not allowed on the runtime hot path.
const ACME_USER_AGENT: &str = "Claviron-Acme-Client/0.1";
const ACME_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACME_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

fn build_http_client() -> Result<AcmeClient, AcmeError> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, ACME_USER_AGENT.parse().unwrap());
    headers.insert(ACCEPT, "application/json".parse().unwrap());

    let builder = AcmeClient::builder()
        // Allow both HTTP/1.1 and HTTP/2 for ACME (Let's Encrypt supports both)
        .connect_timeout(ACME_CONNECT_TIMEOUT)
        .timeout(ACME_REQUEST_TIMEOUT)
        .default_headers(headers)
        .pool_max_idle_per_host(2) // Minimal pooling
        .pool_idle_timeout(Duration::from_secs(30)) // Short timeout
        .tcp_keepalive(Some(Duration::from_secs(15))); // Short keepalive

    let client = builder.build()?;
    debug!("HTTP Acme client created");
    Ok(client)
}

pub(crate) fn acme_client() -> Result<AcmeClient, AcmeError> {
    debug!("Creating new HTTP client for ACME");
    build_http_client()
}

/// Check status before reading success headers or parsing a success payload.
/// Error bodies stay intact so callers retain ACME problem type, detail and
/// subproblems, including a non-JSON response from an upstream proxy.
pub(super) async fn checked_response(
    response: reqwest::Response
) -> Result<reqwest::Response, AcmeError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let mut url = response.url().clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let body = response.text().await.unwrap_or_else(|error| {
        format!("Failed to read ACME error response body: {error}")
    });
    Err(AcmeError::HttpResponse { status, url: url.to_string(), body })
}

#[cfg(all(test, unix))]
#[path = "../../tests/unit/response.rs"]
mod tests;
