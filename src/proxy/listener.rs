#![allow(dead_code)]

use std::net::SocketAddr;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;

use crate::proxy::mtls::SpiffeAuthorizer;
use crate::proxy::router::ProxyRouter;
use crate::proxy::upstream::UpstreamPool;

/// HTTP reverse proxy listener that routes requests to backend services
/// based on the ProxyRouter configuration.
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
        let app = axum::Router::new()
            .route("/{*path}", any(proxy_handler))
            .route("/", any(proxy_handler))
            .with_state(ProxyState {
                router: self.router,
                upstream: self.upstream,
                authorizer: self.authorizer,
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
}

/// Handle an incoming proxy request.
async fn proxy_handler(State(state): State<ProxyState>, req: Request) -> impl IntoResponse {
    // Extract Host header and path
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = req.uri().path().to_string();

    // Resolve route
    let resolved = match state.router.resolve(&host, &path).await {
        Some(r) => r,
        None => {
            tracing::debug!(host = %host, path = %path, "No route found");
            return StatusCode::BAD_GATEWAY.into_response();
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

    // Forward the request via TCP
    match forward_request(endpoint, &host, &path).await {
        Ok(body) => (StatusCode::OK, body).into_response(),
        Err(e) => {
            tracing::error!(
                endpoint = %endpoint,
                error = %e,
                "Upstream request failed"
            );
            // Mark endpoint as unhealthy on failure
            state
                .upstream
                .mark_unhealthy(&resolved.service_name, endpoint)
                .await;
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Forward a request to an upstream endpoint.
async fn forward_request(
    endpoint: SocketAddr,
    host: &str,
    path: &str,
) -> Result<String, std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(endpoint).await?;

    // Reconstruct a simple HTTP/1.1 GET request
    let request_line = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request_line.as_bytes()).await?;
    stream.shutdown().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    // Extract body from HTTP response (after \r\n\r\n)
    let response_str = String::from_utf8_lossy(&response);
    let body = response_str
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();

    Ok(body)
}
