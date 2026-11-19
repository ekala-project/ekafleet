//! Listeners of TCP ingress routes (`tcpPort`): each forwards connections
//! to a backend of its route, chosen like an HTTP request's.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::ingress::Ingress;
use super::routes::RoutesFile;

/// How long a backend may take to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Backends tried per connection.
const ATTEMPTS: usize = 3;

/// The listeners of TCP routes, on one address.
#[derive(Clone)]
pub struct TcpRoutes {
    ip: IpAddr,
    listening: Arc<Mutex<HashMap<u16, (SocketAddr, CancellationToken)>>>,
}

impl TcpRoutes {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            listening: Arc::default(),
        }
    }

    /// The addresses listened on, by route port.
    pub async fn listening(&self) -> HashMap<u16, SocketAddr> {
        let listening = self.listening.lock().await;
        listening.iter().map(|(p, (a, _))| (*p, *a)).collect()
    }

    /// Listen on exactly the ports of `routes`' TCP routes. A port that
    /// cannot be bound is logged and tried again on the next call.
    pub async fn sync(&self, routes: &RoutesFile, ingress: &Ingress) {
        let wanted: BTreeSet<u16> = routes.routes.iter().filter_map(|r| r.tcp_port).collect();
        let mut listening = self.listening.lock().await;
        listening.retain(|port, (_, stop)| {
            let keep = wanted.contains(port);
            if !keep {
                stop.cancel();
                tracing::info!(port, "TCP route listener stopped");
            }
            keep
        });
        for port in wanted {
            if listening.contains_key(&port) {
                continue;
            }
            let listener = match TcpListener::bind((self.ip, port)).await {
                Ok(listener) => listener,
                Err(e) => {
                    tracing::warn!(port, error = %e, "Cannot listen for a TCP route");
                    continue;
                }
            };
            let addr = listener.local_addr().unwrap_or((self.ip, port).into());
            let stop = CancellationToken::new();
            tokio::spawn(accept_loop(listener, port, ingress.clone(), stop.clone()));
            tracing::info!(port, addr = %addr, "TCP route listener started");
            listening.insert(port, (addr, stop));
        }
    }
}

async fn accept_loop(listener: TcpListener, port: u16, ingress: Ingress, stop: CancellationToken) {
    loop {
        let accepted = tokio::select! {
            _ = stop.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((inbound, client)) => {
                let ingress = ingress.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward(inbound, client, port, &ingress).await {
                        tracing::debug!(port, client = %client, error = %e, "TCP route connection ended");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(port, error = %e, "TCP route accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn forward(
    mut inbound: TcpStream,
    client: SocketAddr,
    port: u16,
    ingress: &Ingress,
) -> std::io::Result<()> {
    let (route, options) = ingress
        .routes
        .tcp(port)
        .await
        .ok_or_else(|| std::io::Error::other("no route"))?;
    for _ in 0..ATTEMPTS {
        let Some((pool, endpoint)) = options.pick(&ingress.upstream, client.ip()).await else {
            break;
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(endpoint)).await {
            Ok(Ok(mut outbound)) => {
                tracing::debug!(route = %route, client = %client, upstream = %endpoint, "TCP route connected");
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
                return Ok(());
            }
            Ok(Err(e)) => {
                tracing::debug!(route = %route, upstream = %endpoint, error = %e, "TCP backend refused");
            }
            Err(_) => {
                tracing::debug!(route = %route, upstream = %endpoint, "TCP backend timed out");
            }
        }
        ingress.upstream.mark_unhealthy(&pool, endpoint).await;
    }
    Err(std::io::Error::other(format!(
        "route {route}: no backend accepted"
    )))
}
