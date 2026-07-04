use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Backend pool management for the L7 proxy.
/// Tracks healthy endpoints for each service and provides
/// round-robin selection.
#[derive(Clone)]
pub struct UpstreamPool {
    inner: Arc<RwLock<PoolState>>,
}

struct PoolState {
    services: HashMap<String, ServicePool>,
}

struct ServicePool {
    endpoints: Vec<Endpoint>,
    next_index: usize,
}

#[derive(Debug, Clone)]
struct Endpoint {
    addr: SocketAddr,
    healthy: bool,
}

impl UpstreamPool {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PoolState {
                services: HashMap::new(),
            })),
        }
    }

    /// Update endpoints for a service.
    pub async fn update_endpoints(&self, service_name: &str, addrs: Vec<(SocketAddr, bool)>) {
        let mut state = self.inner.write().await;
        let pool = state
            .services
            .entry(service_name.to_string())
            .or_insert_with(|| ServicePool {
                endpoints: Vec::new(),
                next_index: 0,
            });

        pool.endpoints = addrs
            .into_iter()
            .map(|(addr, healthy)| Endpoint { addr, healthy })
            .collect();

        tracing::debug!(
            service = %service_name,
            endpoints = pool.endpoints.len(),
            healthy = pool.endpoints.iter().filter(|e| e.healthy).count(),
            "Upstream pool updated"
        );
    }

    /// Get the next healthy endpoint for a service (round-robin).
    pub async fn next_endpoint(&self, service_name: &str) -> Option<SocketAddr> {
        let mut state = self.inner.write().await;
        let pool = state.services.get_mut(service_name)?;

        let healthy: Vec<&Endpoint> = pool.endpoints.iter().filter(|e| e.healthy).collect();
        if healthy.is_empty() {
            return None;
        }

        let idx = pool.next_index % healthy.len();
        pool.next_index = pool.next_index.wrapping_add(1);
        Some(healthy[idx].addr)
    }

    /// Mark an endpoint as unhealthy.
    pub async fn mark_unhealthy(&self, service_name: &str, addr: SocketAddr) {
        let mut state = self.inner.write().await;
        if let Some(pool) = state.services.get_mut(service_name) {
            for endpoint in &mut pool.endpoints {
                if endpoint.addr == addr {
                    endpoint.healthy = false;
                    tracing::warn!(
                        service = %service_name,
                        endpoint = %addr,
                        "Upstream marked unhealthy"
                    );
                    break;
                }
            }
        }
    }

    /// Remove a service from the pool.
    pub async fn remove_service(&self, service_name: &str) {
        let mut state = self.inner.write().await;
        state.services.remove(service_name);
    }
}
