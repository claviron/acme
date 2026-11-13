//! Native HTTP-01 handling for admitted plain HTTP hosts.
//! Storage owns expiry and publication.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use claviron::edge::{
    Host, HostConfig, InterceptsNonServing, NonServingContext, Routable,
};
use claviron::http::{
    RouteBody, RouteResponse, ServiceResult, bytes_body, empty_body, err_status,
};
use claviron::pipeline::extension::RouteLayer;
use claviron::pipeline::factory::RouteProtocol;
use claviron::pipeline::layers::HostLayer;
use claviron::pipeline::plan::HostLayerBuilder;
use claviron::pipeline::{DispatchCall, HostHandlerResult, HostRequest};
use claviron::runtime::{AppState, registry};
use http::{Method, Request, Response, StatusCode, header};

use crate::{AcmeConfig, AcmeError, AcmeProvider};

// RFC 8555 fixes this path prefix; it is not an operator routing default.
const PREFIX: &str = "/.well-known/acme-challenge/";

/// Return live raw authorization bytes, or None for an absent/expired token.
/// Implementations own TTL, cache/database access and cross-worker visibility.
/// Bind an implementation with the runtime registry before host preparation.
#[async_trait]
pub trait Http01Storage: Send + Sync + 'static {
    async fn get(
        &self,
        token: &str,
    ) -> Result<Option<Bytes>, AcmeError>;
}

struct FileStorage(PathBuf);

#[async_trait]
impl Http01Storage for FileStorage {
    async fn get(
        &self,
        token: &str,
    ) -> Result<Option<Bytes>, AcmeError> {
        let path = self.0.join(token);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes.into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(AcmeError::io_error(
                "Failed to read HTTP-01 token",
                &path,
                error,
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum Selection {
    Pass,
    InvalidToken,
    InvalidMethod,
    Lookup { head: bool },
}

fn select(
    method: &Method,
    path: &str,
) -> Selection {
    let Some(token) = path.strip_prefix(PREFIX) else {
        return Selection::Pass;
    };
    if !crate::clients::valid_token(token) {
        return Selection::InvalidToken;
    }
    match *method {
        Method::GET => Selection::Lookup { head: false },
        Method::HEAD => Selection::Lookup { head: true },
        _ => Selection::InvalidMethod,
    }
}

fn invalid_method() -> RouteResponse {
    let mut response = err_status(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(header::ALLOW, http::HeaderValue::from_static("GET, HEAD"));
    response
}

fn storage(
    state: &AppState,
    config: &AcmeConfig,
) -> registry::Result<Arc<dyn Http01Storage>> {
    if let Some(storage) =
        state.registry_ref().resolve_dyn::<dyn Http01Storage>()
    {
        return Ok(storage);
    }
    if config.challenges_dir().as_os_str().is_empty() {
        return Err(registry::Error::msg(
            "HTTP-01 requires Http01Storage or challenges_dir",
        ));
    }
    Ok(Arc::new(FileStorage(config.challenges_dir().clone())))
}

pub struct Http01Layer {
    storage: Arc<dyn Http01Storage>,
}

impl From<Arc<dyn Http01Storage>> for Http01Layer {
    fn from(storage: Arc<dyn Http01Storage>) -> Self {
        Self { storage }
    }
}

impl RouteLayer for Http01Layer {
    fn prepare(
        &self,
        layer: &mut HostLayerBuilder,
    ) -> claviron::pipeline::Result<()> {
        let storage = self.storage.clone();
        layer.request(move |request: Request<RouteBody>| {
            let head_only = match select(request.method(), request.uri().path())
            {
                Selection::Pass => {
                    return DispatchCall::ready(ServiceResult::Unhandled(
                        request,
                    ));
                }
                Selection::InvalidToken => {
                    return DispatchCall::ready(ServiceResult::Handled(
                        err_status(StatusCode::FORBIDDEN),
                    ));
                }
                Selection::InvalidMethod => {
                    return DispatchCall::ready(ServiceResult::Handled(
                        invalid_method(),
                    ));
                }
                Selection::Lookup { head } => head,
            };
            let (head, body) = request.into_parts();
            drop(body);
            let storage = storage.clone();
            DispatchCall::new(async move {
                ServiceResult::Handled(
                    reply(storage.as_ref(), head.uri.path(), head_only).await,
                )
            })
        });
        Ok(())
    }
}

impl HostLayer for Http01Layer {
    fn prepare(
        self,
        layer: &mut HostLayerBuilder,
    ) -> claviron::pipeline::Result<()> {
        RouteLayer::prepare(&self, layer)
    }
}

async fn reply(
    storage: &dyn Http01Storage,
    path: &str,
    head: bool,
) -> RouteResponse {
    // Selection above established the prefix and the token alphabet.
    let token = &path[PREFIX.len()..];
    match storage.get(token).await {
        Ok(Some(bytes)) => {
            let length = bytes.len();
            let mut response = Response::new(if head {
                empty_body()
            } else {
                bytes_body(bytes)
            });
            response.headers_mut().insert(
                header::CONTENT_LENGTH,
                http::HeaderValue::from(length),
            );
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain"),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            response
        }
        Ok(None) => err_status(StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::warn!(%error, "HTTP-01 storage lookup failed");
            err_status(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

impl InterceptsNonServing for Http01Layer {
    fn intercept<'a>(
        &'a self,
        request: HostRequest,
        _context: NonServingContext<'a>,
    ) -> Pin<Box<dyn Future<Output = HostHandlerResult> + Send + 'a>> {
        let head_only =
            match select(&request.head().method, request.head().uri.path()) {
                Selection::Pass => {
                    return Box::pin(std::future::ready(
                        ServiceResult::Unhandled(request),
                    ));
                }
                Selection::InvalidToken => {
                    return Box::pin(std::future::ready(
                        ServiceResult::Handled(err_status(
                            StatusCode::FORBIDDEN,
                        )),
                    ));
                }
                Selection::InvalidMethod => {
                    return Box::pin(std::future::ready(
                        ServiceResult::Handled(invalid_method()),
                    ));
                }
                Selection::Lookup { head } => head,
            };
        let (head, body) = request.into_request().into_parts();
        drop(body);
        Box::pin(async move {
            ServiceResult::Handled(
                reply(self.storage.as_ref(), head.uri.path(), head_only).await,
            )
        })
    }
}

/// Prepare the optional HTTP-01 interceptor from staged configuration.
/// Called at plain-listener preparation. The returned trait object is public:
/// a downstream interceptor can call it and pass Unhandled to another owner.
/// `register` binds this factory automatically with the `http-0` feature.
pub fn prepare_non_serving(
    state: &AppState
) -> registry::Result<Option<Arc<dyn InterceptsNonServing>>> {
    let config = state.config_reader().snapshot::<AcmeProvider>()?;
    prepare_non_serving_config(state, config.as_ref().as_ref())
}

fn prepare_non_serving_config(
    state: &AppState,
    config: Option<&AcmeConfig>,
) -> registry::Result<Option<Arc<dyn InterceptsNonServing>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    if !config.serves_http01() {
        return Ok(None);
    }
    let layer = Http01Layer::from(storage(state, config)?);
    Ok(Some(Arc::new(layer)))
}

impl Routable for AcmeProvider {
    fn match_protocol(
        &self,
        protocol: RouteProtocol,
    ) -> bool {
        protocol == RouteProtocol::Http
    }

    fn match_host(
        &self,
        _key: &Host,
        _host: &HostConfig,
    ) -> bool {
        self.snapshot().is_some_and(|config| config.serves_http01())
    }

    fn layers(
        self: Arc<Self>,
        state: &AppState,
        _key: &Host,
        _host: Arc<HostConfig>,
    ) -> registry::Result<Vec<Arc<dyn RouteLayer>>> {
        let mut prepared =
            self.http01.lock().expect("HTTP-01 preparation poisoned");
        let Some(config) =
            self.snapshot().filter(|config| config.serves_http01())
        else {
            return Ok(Vec::new());
        };
        if prepared.is_none() {
            let storage = storage(state, &config)?;
            *prepared = Some(Arc::new(Http01Layer::from(storage)));
        }
        Ok(vec![prepared.as_ref().expect("prepared HTTP-01 layer").clone()])
    }
}

#[cfg(test)]
#[path = "../../tests/unit/http01.rs"]
mod tests;
