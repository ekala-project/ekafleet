//! Standalone proxy daemon entry point.
//!
//! Runs the service mesh proxy as a separate process, isolated from
//! the privileged data-plane agent. Listens for HTTP traffic and
//! forwards it along the ingress routes the agent writes to the routes
//! file (see [`super::routes`]).

use std::net::SocketAddr;
use std::path::PathBuf;

use super::circuit::CircuitBreakerRegistry;
use super::ingress::Ingress;
use super::l4::TcpRoutes;
use super::listener::ProxyListener;
use super::mtls::SpiffeAuthorizer;
use super::tls::IngressTls;

/// Configuration for the standalone proxy daemon.
pub struct ProxyConfig {
    pub listen: SocketAddr,
    /// HTTPS listener for TLS routes.
    pub tls_listen: Option<SocketAddr>,
    pub trust_domain: String,
    pub data_dir: PathBuf,
    /// The ingress routes file the agent writes.
    pub routes_file: PathBuf,
    /// The route certificates the agent writes.
    pub tls_dir: PathBuf,
}

/// Run the standalone service mesh proxy daemon.
///
/// Serves the routes of the routes file, reloading it when it changes:
/// HTTP routes on `listen` (and TLS routes on `tls_listen`), TCP routes on
/// their own ports of `listen`'s address.
pub async fn run_standalone(config: ProxyConfig) -> anyhow::Result<()> {
    tracing::info!(
        listen = %config.listen,
        tls_listen = ?config.tls_listen,
        trust_domain = %config.trust_domain,
        data_dir = %config.data_dir.display(),
        routes_file = %config.routes_file.display(),
        "Starting standalone proxy daemon"
    );

    let tls = config.tls_listen.map(|_| IngressTls::new(&config.tls_dir));
    let ingress = Ingress {
        tcp: Some(TcpRoutes::new(config.listen.ip())),
        tls: tls.clone(),
        ..Default::default()
    };
    let authorizer = SpiffeAuthorizer::new(&config.trust_domain);
    super::routes::watch(
        config.routes_file,
        ingress.clone(),
        tokio_util::sync::CancellationToken::new(),
    );

    let mut proxy = ProxyListener::for_ingress(&ingress, authorizer)
        .with_resilience(CircuitBreakerRegistry::default(), Default::default());
    if let (Some(addr), Some(tls)) = (config.tls_listen, tls) {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        proxy = proxy.with_https_port(listener.local_addr()?.port());
        tokio::spawn(proxy.clone().serve_tls(listener, tls));
    }
    proxy.start(config.listen).await?;

    Ok(())
}
