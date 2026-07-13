//! Standalone proxy daemon entry point.
//!
//! Runs the service mesh proxy as a separate process, isolated from
//! the privileged data-plane agent. Listens for HTTP traffic and
//! forwards to backend services via `UpstreamPool`.

use std::net::SocketAddr;
use std::path::PathBuf;

use super::circuit::CircuitBreakerRegistry;
use super::listener::ProxyListener;
use super::mtls::SpiffeAuthorizer;
use super::router::ProxyRouter;
use super::upstream::UpstreamPool;

/// Configuration for the standalone proxy daemon.
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub trust_domain: String,
    pub data_dir: PathBuf,
}

/// Run the standalone service mesh proxy daemon.
///
/// Initializes the L7 reverse proxy with an empty routing table and
/// upstream pool. The data-plane process pushes configuration updates
/// (routes, endpoints, policies) as services are deployed.
pub async fn run_standalone(config: ProxyConfig) -> anyhow::Result<()> {
    tracing::info!(
        listen = %config.listen,
        trust_domain = %config.trust_domain,
        data_dir = %config.data_dir.display(),
        "Starting standalone proxy daemon"
    );

    let upstream = UpstreamPool::new();
    let router = ProxyRouter::new();
    let authorizer = SpiffeAuthorizer::new(&config.trust_domain);
    let circuit_breakers = CircuitBreakerRegistry::default();

    let proxy = ProxyListener::new(router, upstream, authorizer)
        .with_resilience(circuit_breakers, Default::default());

    proxy.start(config.listen).await?;

    Ok(())
}
