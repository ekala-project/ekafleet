//! Fetching service closures from the server's binary cache.
//!
//! Nix speaks HTTP to binary caches; the server only serves its cache over
//! the agent's authenticated gRPC connection. For each fetch the agent binds
//! a loopback HTTP bridge on a random port under an unguessable path prefix,
//! forwards narinfo and NAR requests to the server, and runs
//! `nix copy --from <bridge>` with the server's cache key as an extra trusted
//! public key. Nix downloads only missing paths and checks every one against
//! its signature and NAR hash; the bridge stops as soon as the copy ends.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio_util::sync::CancellationToken;

use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::{CacheNarInfoRequest, CacheNarRequest};

/// Default upper bound on one `nix copy` (override with
/// `EKAFLEET_NIX_COPY_TIMEOUT`, seconds).
const DEFAULT_COPY_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, thiserror::Error)]
pub enum ClosureError {
    #[error("the server did not send a binary cache key")]
    NoCacheKey,
    #[error("store path check failed: {0}")]
    Check(String),
    #[error("nix copy failed: {0}")]
    Copy(String),
    #[error("nix copy timed out after {0}s")]
    Timeout(u64),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Attaches the dev-mode bearer token, if any, to every request. Agents
/// with a node SVID authenticate by TLS client certificate instead.
#[derive(Clone)]
pub struct AgentAuth {
    pub bearer: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
}

impl tonic::service::Interceptor for AgentAuth {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(bearer) = &self.bearer {
            req.metadata_mut().insert("authorization", bearer.clone());
        }
        Ok(req)
    }
}

pub type AgentClient = FleetControlClient<
    tonic::service::interceptor::InterceptedService<tonic::transport::Channel, AgentAuth>,
>;

/// The paths in `paths` that are not valid in the local store.
pub async fn missing_paths(paths: &[String]) -> Result<Vec<String>, ClosureError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let output = tokio::process::Command::new("nix-store")
        .args(["--check-validity", "--print-invalid"])
        .args(paths)
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Err(ClosureError::Check(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

/// Make every path in `paths` (and its closure) valid locally, fetching
/// what is missing from the server's cache signed by `public_key`.
pub async fn ensure_closures(
    client: &AgentClient,
    paths: &[String],
    public_key: &str,
) -> Result<(), ClosureError> {
    let missing = missing_paths(paths).await?;
    if missing.is_empty() {
        return Ok(());
    }
    if public_key.is_empty() {
        return Err(ClosureError::NoCacheKey);
    }
    tracing::info!(
        paths = missing.len(),
        "Fetching service closures from the server"
    );

    let bridge = Bridge::start(client.clone()).await?;
    let timeout = std::env::var("EKAFLEET_NIX_COPY_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&s: &u64| s > 0)
        .map_or(DEFAULT_COPY_TIMEOUT, Duration::from_secs);
    let copy = tokio::process::Command::new("nix")
        .args(["--extra-experimental-features", "nix-command", "copy"])
        .args(["--from", &bridge.url])
        .args(["--extra-trusted-public-keys", public_key])
        .args(&missing)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let result = tokio::time::timeout(timeout, copy).await;
    bridge.stop();
    let output = result.map_err(|_| ClosureError::Timeout(timeout.as_secs()))??;
    if !output.status.success() {
        return Err(ClosureError::Copy(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    tracing::info!(paths = missing.len(), "Service closures fetched");
    Ok(())
}

/// A loopback HTTP binary cache that forwards to the server.
struct Bridge {
    url: String,
    stop: CancellationToken,
}

impl Bridge {
    async fn start(client: AgentClient) -> Result<Self, ClosureError> {
        let prefix = random_prefix();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}/{prefix}", listener.local_addr()?);
        let router = Router::new()
            .route(&format!("/{prefix}/nix-cache-info"), get(cache_info))
            .route(&format!("/{prefix}/{{file}}"), get(narinfo))
            .route(&format!("/{prefix}/nar/{{file}}"), get(nar))
            .with_state(client);
        let stop = CancellationToken::new();
        let shutdown = stop.clone();
        tokio::spawn(async move {
            let serve = axum::serve(listener, router)
                .with_graceful_shutdown(async move { shutdown.cancelled().await });
            if let Err(e) = serve.await {
                tracing::warn!(error = %e, "Binary cache bridge failed");
            }
        });
        Ok(Self { url, stop })
    }

    fn stop(self) {
        self.stop.cancel();
    }
}

/// 128 random bits, hex: the bridge only answers under this prefix, so
/// other local users cannot fetch through it while it runs.
fn random_prefix() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system randomness");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn cache_info() -> &'static str {
    "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n"
}

fn grpc_failure(status: &tonic::Status) -> Response {
    let code = match status.code() {
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => StatusCode::FORBIDDEN,
        _ => StatusCode::BAD_GATEWAY,
    };
    (code, status.message().to_string()).into_response()
}

async fn narinfo(State(mut client): State<AgentClient>, Path(file): Path<String>) -> Response {
    let Some(hash) = file.strip_suffix(".narinfo") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match client
        .cache_nar_info(CacheNarInfoRequest {
            hash_part: hash.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let resp = resp.into_inner();
            if resp.found {
                ([(header::CONTENT_TYPE, "text/x-nix-narinfo")], resp.narinfo).into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        Err(status) => grpc_failure(&status),
    }
}

async fn nar(State(mut client): State<AgentClient>, Path(file): Path<String>) -> Response {
    let Some(hash) = file.strip_suffix(".nar") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let stream = match client
        .cache_nar(CacheNarRequest {
            hash_part: hash.to_string(),
        })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(status) => return grpc_failure(&status),
    };
    use tokio_stream::StreamExt;
    let body = stream.map(|chunk| {
        chunk
            .map(|c| c.data)
            .map_err(|status| std::io::Error::other(status.message().to_string()))
    });
    Body::from_stream(body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_random_and_url_safe() {
        let (a, b) = (random_prefix(), random_prefix());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn nothing_to_fetch_needs_no_server_or_key() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let client = FleetControlClient::with_interceptor(channel, AgentAuth { bearer: None });
        ensure_closures(&client, &[], "").await.unwrap();
    }
}
