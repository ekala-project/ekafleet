#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::proxy::upstream::UpstreamPool;

/// L4 TCP proxy that forwards raw TCP connections to upstream services.
/// Used for non-HTTP protocols (databases, gRPC, AMQP, custom TCP).
#[derive(Clone)]
pub struct L4Proxy {
    upstream: UpstreamPool,
    bindings: Arc<RwLock<HashMap<String, L4Binding>>>,
}

/// A single L4 proxy binding: listen address → service.
struct L4Binding {
    service_name: String,
    listen_addr: SocketAddr,
}

impl L4Proxy {
    pub fn new(upstream: UpstreamPool) -> Self {
        Self {
            upstream,
            bindings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a TCP proxy binding: connections to `listen_addr` are forwarded
    /// to an upstream endpoint for `service_name`.
    pub async fn bind(&self, name: &str, service_name: &str, listen_addr: SocketAddr) {
        let mut bindings = self.bindings.write().await;
        bindings.insert(
            name.to_string(),
            L4Binding {
                service_name: service_name.to_string(),
                listen_addr,
            },
        );
        tracing::info!(
            name = %name,
            service = %service_name,
            addr = %listen_addr,
            "L4 proxy binding registered"
        );
    }

    /// Start all registered L4 proxy listeners.
    /// Each binding spawns an independent accept loop.
    pub async fn start(&self) -> Result<(), std::io::Error> {
        let bindings = self.bindings.read().await;
        for (name, binding) in bindings.iter() {
            let listener = TcpListener::bind(binding.listen_addr).await?;
            let upstream = self.upstream.clone();
            let service_name = binding.service_name.clone();
            let binding_name = name.clone();

            tokio::spawn(async move {
                tracing::info!(
                    name = %binding_name,
                    addr = %listener.local_addr().unwrap(),
                    service = %service_name,
                    "L4 proxy listener started"
                );

                loop {
                    match listener.accept().await {
                        Ok((inbound, peer)) => {
                            let upstream = upstream.clone();
                            let svc = service_name.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_l4_connection(inbound, peer, &upstream, &svc).await
                                {
                                    tracing::debug!(
                                        peer = %peer,
                                        service = %svc,
                                        error = %e,
                                        "L4 proxy connection error"
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "L4 proxy accept error");
                        }
                    }
                }
            });
        }

        Ok(())
    }
}

/// Handle a single L4 connection by selecting an upstream and performing
/// bidirectional byte copying.
async fn handle_l4_connection(
    inbound: impl AsyncRead + AsyncWrite + Unpin,
    peer: SocketAddr,
    upstream: &UpstreamPool,
    service_name: &str,
) -> Result<(), std::io::Error> {
    let endpoint = upstream
        .next_endpoint(service_name)
        .await
        .ok_or_else(|| std::io::Error::other("no healthy upstream"))?;

    tracing::debug!(
        peer = %peer,
        upstream = %endpoint,
        service = %service_name,
        "L4 proxy connecting"
    );

    let outbound = tokio::net::TcpStream::connect(endpoint)
        .await
        .inspect_err(|_| {
            upstream.mark_unhealthy_sync(service_name, endpoint);
        })?;

    let (mut ri, mut wi) = tokio::io::split(inbound);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

    tokio::select! {
        r = client_to_server => {
            if let Err(e) = r {
                tracing::debug!(error = %e, "L4 client→server copy ended");
            }
        }
        r = server_to_client => {
            if let Err(e) = r {
                tracing::debug!(error = %e, "L4 server→client copy ended");
            }
        }
    }

    Ok(())
}
