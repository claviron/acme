use std::sync::Arc;

use async_trait::async_trait;
use claviron::clients::{
    ActiveRequestPolicy, AdmittedPool, ClientManager, HttpClientConfig,
};
use claviron::orbit::ClientAdmissionProvider;
use http::header::{ACCEPT, USER_AGENT};
use http::{HeaderMap, HeaderValue};
use tracing::debug;

use crate::AcmeError;

const ACME_USER_AGENT: &str = "Claviron-Acme-Client/0.1";

/// The key of ACME's fleet budget when its pool's scope is `fleet`.
const BUDGET: &str = "acme";

/// Builds one `reqwest` client with the declared timeouts per pool slot.
enum HttpManager {
    Declared {
        connect_timeout: std::time::Duration,
        request_timeout: std::time::Duration,
    },
    /// A test's own client, such as one routed to a scripted issuer.
    #[cfg(test)]
    Fixed(reqwest::Client),
}

/// Why a client could not be built.
#[derive(Debug, thiserror::Error)]
#[error("ACME HTTP client: {0}")]
pub struct ClientBuildError(String);

#[async_trait]
impl ClientManager for HttpManager {
    type Client = reqwest::Client;
    type Error = ClientBuildError;

    async fn create(&self) -> Result<reqwest::Client, ClientBuildError> {
        let (connect_timeout, request_timeout) = match self {
            Self::Declared { connect_timeout, request_timeout } => {
                (*connect_timeout, *request_timeout)
            }
            #[cfg(test)]
            Self::Fixed(client) => return Ok(client.clone()),
        };
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(ACME_USER_AGENT));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .map_err(|error| ClientBuildError(error.to_string()))
    }

    async fn recycle(
        &self,
        _client: &mut reqwest::Client,
    ) -> Result<(), ClientBuildError> {
        Ok(())
    }
}

/// ACME's outbound HTTP, as `acme.yaml`'s `http:` declares it: each request
/// is admitted by the pool, in this process or across the fleet.
#[derive(Clone)]
pub struct AcmeClient(Arc<AdmittedPool<HttpManager>>);

impl AcmeClient {
    /// `admission` is the fleet's table, which ACME registers; `scope: fleet`
    /// needs it.
    pub fn new(
        admission: Option<Arc<ClientAdmissionProvider>>,
        http: &HttpClientConfig,
    ) -> Result<Self, AcmeError> {
        http.validate()
            .map_err(|error| AcmeError::from(format!("acme http: {error}")))?;
        let manager = HttpManager::Declared {
            connect_timeout: http.connect_timeout,
            request_timeout: http.request_timeout,
        };
        let pool = AdmittedPool::new(admission, BUDGET, manager, &http.pool)
            .map_err(|error| AcmeError::from(format!("acme http: {error}")))?;
        debug!("ACME HTTP client pool created");
        Ok(Self(Arc::new(pool)))
    }

    /// ACME's default pool around a test's own client.
    #[cfg(test)]
    pub(crate) fn fixed(client: reqwest::Client) -> Self {
        let pool = AdmittedPool::new(
            None,
            BUDGET,
            HttpManager::Fixed(client),
            &crate::config::default_http().pool,
        )
        .expect("the default pool is valid");
        Self(Arc::new(pool))
    }

    /// Send one request with an admitted client. A client that could not
    /// reach the server is retired rather than handed to the next request.
    pub(crate) async fn send(
        &self,
        build: impl FnOnce(&reqwest::Client) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, AcmeError> {
        let lease =
            self.0.acquire(ActiveRequestPolicy::Preserve).await.map_err(
                |error| AcmeError::from(format!("acme http: {error}")),
            )?;
        match build(&lease).send().await {
            Ok(response) => Ok(response),
            Err(error) => {
                if error.is_connect() || error.is_timeout() {
                    lease.discard();
                }
                Err(error.into())
            }
        }
    }
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
