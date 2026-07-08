#![allow(dead_code)]

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;

use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::proxy::mtls::SpiffeAuthorizer;
use crate::proxy::router::ProxyRouter;
use crate::proxy::upstream::UpstreamPool;

/// HTTP reverse proxy listener that routes requests to backend services
/// based on the ProxyRouter configuration. Supports all HTTP methods,
/// headers, and request bodies.
#[derive(Clone)]
pub struct ProxyListener {
    router: ProxyRouter,
    upstream: UpstreamPool,
    authorizer: SpiffeAuthorizer,
}

impl ProxyListener {
    pub fn new(router: ProxyRouter, upstream: UpstreamPool, authorizer: SpiffeAuthorizer) -> Self {
        Self {
            router,
            upstream,
            authorizer,
        }
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
}

/// Handle an incoming proxy request by forwarding it to the resolved upstream.
/// Preserves HTTP method, headers, and body.
async fn proxy_handler(State(state): State<ProxyState>, req: Request) -> impl IntoResponse {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());

    // Resolve route
    let resolved = match state.router.resolve(&host, &path).await {
        Some(r) => r,
        None => {
            tracing::debug!(host = %host, path = %path, "No route found");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

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

    // Forward the full request to the upstream
    match forward_request(&state.client, endpoint, req, &query).await {
        Ok(resp) => resp.into_response(),
        Err(e) => {
            tracing::error!(
                endpoint = %endpoint,
                error = %e,
                "Upstream request failed"
            );
            state
                .upstream
                .mark_unhealthy(&resolved.service_name, endpoint)
                .await;
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Forward a request to an upstream endpoint, preserving method, headers, and body.
async fn forward_request(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    endpoint: SocketAddr,
    original: Request,
    query: &Option<String>,
) -> Result<Response, hyper_util::client::legacy::Error> {
    let (parts, body) = original.into_parts();

    // Build upstream URI
    let path_and_query = match query {
        Some(q) => format!("{}?{}", parts.uri.path(), q),
        None => parts.uri.path().to_string(),
    };
    let uri = Uri::builder()
        .scheme("http")
        .authority(endpoint.to_string())
        .path_and_query(path_and_query)
        .build()
        .expect("valid upstream URI");

    // Reconstruct the request with all original headers and body
    let mut upstream_req = Request::builder().method(parts.method).uri(uri);

    // Copy all headers, overriding Host to the upstream
    for (name, value) in &parts.headers {
        if name == "host" {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }
    upstream_req = upstream_req.header(
        "host",
        HeaderValue::from_str(&endpoint.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("localhost")),
    );

    let upstream_req = upstream_req.body(body).expect("valid request body");

    client.request(upstream_req).await.map(|resp| {
        let (parts, body) = resp.into_parts();
        Response::from_parts(parts, Body::new(body))
    })
}
