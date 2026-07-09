#![allow(dead_code)]

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;

use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::proxy::circuit::{CircuitBreakerRegistry, RetryConfig};
use crate::proxy::mtls::SpiffeAuthorizer;
use crate::proxy::router::ProxyRouter;
use crate::proxy::upstream::UpstreamPool;

/// HTTP reverse proxy listener that routes requests to backend services
/// based on the ProxyRouter configuration. Supports all HTTP methods,
/// headers, request bodies, circuit breaking, and retries.
#[derive(Clone)]
pub struct ProxyListener {
    router: ProxyRouter,
    upstream: UpstreamPool,
    authorizer: SpiffeAuthorizer,
    circuit_breakers: CircuitBreakerRegistry,
    retry_config: RetryConfig,
}

impl ProxyListener {
    pub fn new(router: ProxyRouter, upstream: UpstreamPool, authorizer: SpiffeAuthorizer) -> Self {
        Self {
            router,
            upstream,
            authorizer,
            circuit_breakers: CircuitBreakerRegistry::default(),
            retry_config: RetryConfig::default(),
        }
    }

    /// Configure circuit breaker and retry settings.
    pub fn with_resilience(
        mut self,
        circuit_breakers: CircuitBreakerRegistry,
        retry_config: RetryConfig,
    ) -> Self {
        self.circuit_breakers = circuit_breakers;
        self.retry_config = retry_config;
        self
    }

    /// Start the HTTP proxy listener on the given address.
    pub async fn start(self, bind_addr: SocketAddr) -> Result<(), std::io::Error> {
        let http_client = Client::builder(TokioExecutor::new()).build_http();

        let app = axum::Router::new()
            .route("/{*path}", any(proxy_handler))
            .route("/", any(proxy_handler))
            .with_state(ProxyState {
                router: self.router,
                upstream: self.upstream,
                authorizer: self.authorizer,
                client: http_client,
                circuit_breakers: self.circuit_breakers,
                retry_config: self.retry_config,
            });

        tracing::info!(addr = %bind_addr, "Proxy listener started");

        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app)
            .await
            .map_err(std::io::Error::other)?;

        Ok(())
    }
}

#[derive(Clone)]
struct ProxyState {
    router: ProxyRouter,
    upstream: UpstreamPool,
    authorizer: SpiffeAuthorizer,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    circuit_breakers: CircuitBreakerRegistry,
    retry_config: RetryConfig,
}

/// Returns true if the HTTP method is idempotent and safe to retry.
fn is_idempotent(method: &axum::http::Method) -> bool {
    use axum::http::Method;
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS
    )
}

/// Handle an incoming proxy request by forwarding it to the resolved upstream.
/// Preserves HTTP method, headers, and body. Applies circuit breaking and retries.
async fn proxy_handler(State(state): State<ProxyState>, req: Request) -> impl IntoResponse {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());
    let method = req.method().clone();

    // Collect original headers (excluding "host", which is set to the upstream)
    let mut original_headers = req.headers().clone();
    original_headers.remove("host");

    // Buffer the body so it can be replayed on retries
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Resolve route
    let resolved = match state.router.resolve(&host, &path).await {
        Some(r) => r,
        None => {
            tracing::debug!(host = %host, path = %path, "No route found");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // Check circuit breaker before attempting the request
    if !state
        .circuit_breakers
        .allow_request(&resolved.service_name)
        .await
    {
        tracing::warn!(
            service = %resolved.service_name,
            "Circuit breaker open — rejecting request"
        );
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    // Select upstream endpoint
    let endpoint = match state.upstream.next_endpoint(&resolved.service_name).await {
        Some(addr) => addr,
        None => {
            tracing::warn!(
                service = %resolved.service_name,
                "No healthy upstream available"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    // Forward the full request with retry logic
    let max_attempts = state.retry_config.max_retries + 1;
    let mut last_error = None;

    for attempt in 0..max_attempts {
        // Only retry idempotent methods after the first attempt
        if attempt > 0 && !is_idempotent(&method) {
            break;
        }

        if attempt > 0 {
            let delay = state.retry_config.delay_for_attempt(attempt - 1);
            tracing::debug!(
                service = %resolved.service_name,
                attempt,
                delay = ?delay,
                "Retrying upstream request"
            );
            tokio::time::sleep(delay).await;
        }

        match forward_request(
            &state.client,
            &ForwardParams {
                endpoint,
                host: &host,
                path: &path,
                query: &query,
                method: &method,
                headers: &original_headers,
                body: &body_bytes,
            },
        )
        .await
        {
            Ok(resp) => {
                state
                    .circuit_breakers
                    .record_success(&resolved.service_name)
                    .await;
                return resp.into_response();
            }
            Err(e) => {
                tracing::debug!(
                    endpoint = %endpoint,
                    attempt,
                    error = %e,
                    "Upstream request failed"
                );
                last_error = Some(e);
            }
        }
    }

    // All attempts failed — record failure for circuit breaker
    state
        .circuit_breakers
        .record_failure(&resolved.service_name)
        .await;
    state
        .upstream
        .mark_unhealthy(&resolved.service_name, endpoint)
        .await;

    tracing::error!(
        endpoint = %endpoint,
        error = ?last_error,
        "All upstream attempts failed"
    );
    StatusCode::BAD_GATEWAY.into_response()
}

/// Details of an upstream request to forward.
struct ForwardParams<'a> {
    endpoint: SocketAddr,
    host: &'a str,
    path: &'a str,
    query: &'a Option<String>,
    method: &'a axum::http::Method,
    headers: &'a axum::http::HeaderMap,
    body: &'a [u8],
}

/// Forward a request to an upstream endpoint, preserving the original
/// HTTP method, headers, and body.
async fn forward_request(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    params: &ForwardParams<'_>,
) -> Result<Response, hyper_util::client::legacy::Error> {
    let ForwardParams {
        endpoint,
        host,
        path,
        query,
        method,
        headers,
        body,
    } = params;
    let path_and_query = match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    let uri = Uri::builder()
        .scheme("http")
        .authority(endpoint.to_string())
        .path_and_query(path_and_query)
        .build()
        .expect("valid upstream URI");

    let mut builder = Request::builder().method(*method).uri(uri).header(
        "host",
        HeaderValue::from_str(host).unwrap_or_else(|_| HeaderValue::from_static("localhost")),
    );

    // Copy original headers (host was already removed by the caller)
    for (name, value) in *headers {
        builder = builder.header(name, value);
    }

    let upstream_req = builder
        .body(Body::from(axum::body::Bytes::copy_from_slice(body)))
        .expect("valid request body");

    client.request(upstream_req).await.map(|resp| {
        let (parts, body) = resp.into_parts();
        Response::from_parts(parts, Body::new(body))
    })
}
