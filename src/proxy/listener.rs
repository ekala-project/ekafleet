#![allow(dead_code)]

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;

use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};

use crate::proxy::circuit::{CircuitBreakerRegistry, RetryConfig};
use crate::proxy::ingress::{Ingress, RouteTable};
use crate::proxy::mtls::SpiffeAuthorizer;
use crate::proxy::router::ProxyRouter;
use crate::proxy::tls::IngressTls;
use crate::proxy::upstream::UpstreamPool;

/// HTTP reverse proxy listener that routes requests to backend services
/// based on the ProxyRouter configuration. Supports all HTTP methods,
/// headers, request bodies, circuit breaking, and retries.
#[derive(Clone)]
pub struct ProxyListener {
    router: ProxyRouter,
    upstream: UpstreamPool,
    routes: RouteTable,
    authorizer: SpiffeAuthorizer,
    circuit_breakers: CircuitBreakerRegistry,
    retry_config: RetryConfig,
    /// Port of the TLS listener, where plain-HTTP requests for TLS routes
    /// are redirected.
    https_port: Option<u16>,
}

/// What a request's connection tells about its client.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub client: SocketAddr,
    /// SPIFFE ID of a verified client certificate.
    pub spiffe_id: Option<String>,
    pub tls: bool,
}

/// How long a client may take to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl ProxyListener {
    pub fn new(router: ProxyRouter, upstream: UpstreamPool, authorizer: SpiffeAuthorizer) -> Self {
        Self {
            router,
            upstream,
            routes: RouteTable::default(),
            authorizer,
            circuit_breakers: CircuitBreakerRegistry::default(),
            retry_config: RetryConfig::default(),
            https_port: None,
        }
    }

    /// Serve the routes of `ingress`, with their options.
    pub fn for_ingress(ingress: &Ingress, authorizer: SpiffeAuthorizer) -> Self {
        let mut listener = Self::new(ingress.router.clone(), ingress.upstream.clone(), authorizer);
        listener.routes = ingress.routes.clone();
        listener
    }

    /// Redirect plain-HTTP requests for TLS routes to `port`.
    pub fn with_https_port(mut self, port: u16) -> Self {
        self.https_port = Some(port);
        self
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
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        self.serve(listener).await
    }

    fn app(self) -> axum::Router {
        let http_client = Client::builder(TokioExecutor::new()).build_http();
        axum::Router::new()
            .route("/{*path}", any(proxy_handler))
            .route("/", any(proxy_handler))
            .with_state(ProxyState {
                router: self.router,
                upstream: self.upstream,
                routes: self.routes,
                authorizer: self.authorizer,
                client: http_client,
                circuit_breakers: self.circuit_breakers,
                retry_config: self.retry_config,
                https_port: self.https_port,
            })
    }

    /// Serve plain-HTTP proxied traffic on `listener`.
    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<(), std::io::Error> {
        tracing::info!(addr = %listener.local_addr()?, "Proxy listener started");
        let app = self.app();
        loop {
            let Some((stream, client)) = accept(&listener).await else {
                continue;
            };
            let app = app.clone();
            tokio::spawn(serve_connection(
                TokioIo::new(stream),
                app,
                ConnInfo {
                    client,
                    spiffe_id: None,
                    tls: false,
                },
            ));
        }
    }

    /// Serve HTTPS proxied traffic on `listener`, with the certificates
    /// and client verification of `tls`.
    pub async fn serve_tls(
        self,
        listener: tokio::net::TcpListener,
        tls: IngressTls,
    ) -> Result<(), std::io::Error> {
        tracing::info!(addr = %listener.local_addr()?, "Proxy TLS listener started");
        let app = self.app();
        loop {
            let Some((stream, client)) = accept(&listener).await else {
                continue;
            };
            let app = app.clone();
            let acceptor = tls.acceptor();
            tokio::spawn(async move {
                let stream =
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            tracing::debug!(client = %client, error = %e, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            tracing::debug!(client = %client, "TLS handshake timed out");
                            return;
                        }
                    };
                let spiffe_id = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .and_then(|leaf| SpiffeAuthorizer::extract_spiffe_id_from_der(leaf));
                serve_connection(
                    TokioIo::new(stream),
                    app,
                    ConnInfo {
                        client,
                        spiffe_id,
                        tls: true,
                    },
                )
                .await;
            });
        }
    }
}

/// The next connection; `None` after a (logged) accept error.
async fn accept(listener: &tokio::net::TcpListener) -> Option<(tokio::net::TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok(accepted) => Some(accepted),
        Err(e) => {
            tracing::warn!(error = %e, "Proxy accept failed");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            None
        }
    }
}

/// Serve HTTP/1.1 or HTTP/2 on one connection, telling handlers `info`.
async fn serve_connection<I>(io: I, app: axum::Router, info: ConnInfo)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let client = info.client;
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let mut req = req.map(Body::new);
        req.extensions_mut().insert(info.clone());
        tower::ServiceExt::oneshot(app.clone(), req)
    });
    if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
    {
        tracing::debug!(client = %client, error = %e, "Proxy connection ended");
    }
}

#[derive(Clone)]
struct ProxyState {
    router: ProxyRouter,
    upstream: UpstreamPool,
    routes: RouteTable,
    authorizer: SpiffeAuthorizer,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    circuit_breakers: CircuitBreakerRegistry,
    retry_config: RetryConfig,
    https_port: Option<u16>,
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
    let conn = req.extensions().get::<ConnInfo>().cloned();
    let client_ip = conn
        .as_ref()
        .map_or(std::net::IpAddr::from([0, 0, 0, 0]), |c| c.client.ip());

    // Collect original headers (excluding "host", which is set to the upstream)
    let mut original_headers = req.headers().clone();
    original_headers.remove("host");
    if let Some(conn) = &conn {
        let forwarded = match original_headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            Some(previous) => format!("{previous}, {}", conn.client.ip()),
            None => conn.client.ip().to_string(),
        };
        if let Ok(value) = HeaderValue::from_str(&forwarded) {
            original_headers.insert("x-forwarded-for", value);
        }
        original_headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if conn.tls { "https" } else { "http" }),
        );
    }

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

    let options = state.routes.get(&resolved.service_name).await;
    if let Some(options) = &options {
        let tls = conn.as_ref().is_some_and(|c| c.tls);
        if options.tls
            && !tls
            && let Some(port) = state.https_port
        {
            return redirect_to_https(&host, port, &path, &query);
        }
        if !options.authorized(conn.as_ref().and_then(|c| c.spiffe_id.as_deref())) {
            tracing::debug!(route = %resolved.service_name, client = %client_ip, "Caller not allowed");
            return StatusCode::FORBIDDEN.into_response();
        }
        if !options.admit(client_ip).await {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }

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
    let picked = match &options {
        Some(options) => options.pick(&state.upstream, client_ip).await,
        None => state
            .upstream
            .next_endpoint(&resolved.service_name)
            .await
            .map(|endpoint| (resolved.service_name.clone(), endpoint)),
    };
    let (pool, endpoint) = match picked {
        Some(picked) => picked,
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
    state.upstream.mark_unhealthy(&pool, endpoint).await;

    tracing::error!(
        endpoint = %endpoint,
        error = ?last_error,
        "All upstream attempts failed"
    );
    StatusCode::BAD_GATEWAY.into_response()
}

/// A permanent redirect to the same URL over HTTPS on `port`.
fn redirect_to_https(host: &str, port: u16, path: &str, query: &Option<String>) -> Response {
    let host = super::router::host_without_port(host);
    let authority = match (host.contains(':'), port) {
        (true, 443) => format!("[{host}]"),
        (true, _) => format!("[{host}]:{port}"),
        (false, 443) => host.to_string(),
        (false, _) => format!("{host}:{port}"),
    };
    let location = match query {
        Some(q) => format!("https://{authority}{path}?{q}"),
        None => format!("https://{authority}{path}"),
    };
    match HeaderValue::from_str(&location) {
        Ok(location) => (
            StatusCode::PERMANENT_REDIRECT,
            [(axum::http::header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
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
