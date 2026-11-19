use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// How long an endpoint that failed a request is skipped.
pub const EJECT_FOR: Duration = Duration::from_secs(10);

/// Backend pool management for the L7 proxy.
/// Tracks healthy endpoints for each service and provides
/// round-robin selection. An endpoint that fails is ejected for
/// [`EJECT_FOR`], then tried again.
#[derive(Clone)]
pub struct UpstreamPool {
    inner: Arc<RwLock<PoolState>>,
}

struct PoolState {
    services: HashMap<String, ServicePool>,
}

struct ServicePool {
    endpoints: Vec<Endpoint>,
    next_index: AtomicUsize,
}

#[derive(Debug, Clone)]
struct Endpoint {
    addr: SocketAddr,
    healthy: bool,
    /// Skipped until then after a failure.
    ejected_until: Option<Instant>,
}

impl Endpoint {
    fn usable(&self, now: Instant) -> bool {
        self.healthy && self.ejected_until.is_none_or(|until| until <= now)
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
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
                next_index: AtomicUsize::new(0),
            });

        pool.endpoints = addrs
            .into_iter()
            .map(|(addr, healthy)| Endpoint {
                addr,
                healthy,
                ejected_until: None,
            })
            .collect();

        tracing::debug!(
            service = %service_name,
            endpoints = pool.endpoints.len(),
            healthy = pool.endpoints.iter().filter(|e| e.healthy).count(),
            "Upstream pool updated"
        );
    }

    /// Get the next healthy endpoint for a service (round-robin).
    /// Uses a read lock with atomic counter — concurrent callers are not serialized.
    pub async fn next_endpoint(&self, service_name: &str) -> Option<SocketAddr> {
        let state = self.inner.read().await;
        let pool = state.services.get(service_name)?;

        let now = Instant::now();
        let healthy: Vec<&Endpoint> = pool.endpoints.iter().filter(|e| e.usable(now)).collect();
        if healthy.is_empty() {
            return None;
        }

        let idx = pool.next_index.fetch_add(1, Ordering::Relaxed) % healthy.len();
        Some(healthy[idx].addr)
    }

    /// Eject an endpoint that failed for [`EJECT_FOR`].
    /// The endpoints of `service_name` that may take traffic now.
    pub async fn usable_endpoints(&self, service_name: &str) -> Vec<SocketAddr> {
        let state = self.inner.read().await;
        let now = Instant::now();
        state
            .services
            .get(service_name)
            .map_or_else(Vec::new, |pool| {
                pool.endpoints
                    .iter()
                    .filter(|e| e.usable(now))
                    .map(|e| e.addr)
                    .collect()
            })
    }

    pub async fn mark_unhealthy(&self, service_name: &str, addr: SocketAddr) {
        let mut state = self.inner.write().await;
        if let Some(pool) = state.services.get_mut(service_name) {
            for endpoint in &mut pool.endpoints {
                if endpoint.addr == addr {
                    endpoint.ejected_until = Some(Instant::now() + EJECT_FOR);
                    tracing::warn!(
                        service = %service_name,
                        endpoint = %addr,
                        ejected_for = ?EJECT_FOR,
                        "Upstream ejected"
                    );
                    break;
                }
            }
        }
    }

    /// Mark an endpoint as unhealthy (non-async version for use in sync closures).
    /// Spawns the async operation on the current runtime.
    pub fn mark_unhealthy_sync(&self, service_name: &str, addr: SocketAddr) {
        let pool = self.clone();
        let name = service_name.to_string();
        tokio::spawn(async move {
            pool.mark_unhealthy(&name, addr).await;
        });
    }

    /// Replace every pool: services not in `pools` are dropped. Endpoints
    /// that stay keep their ejection.
    pub async fn replace_all(&self, pools: HashMap<String, Vec<SocketAddr>>) {
        let mut state = self.inner.write().await;
        state.services.retain(|name, _| pools.contains_key(name));
        for (name, addrs) in pools {
            let pool = state.services.entry(name).or_insert_with(|| ServicePool {
                endpoints: Vec::new(),
                next_index: AtomicUsize::new(0),
            });
            let ejected: HashMap<SocketAddr, Instant> = pool
                .endpoints
                .iter()
                .filter_map(|e| e.ejected_until.map(|t| (e.addr, t)))
                .collect();
            pool.endpoints = addrs
                .into_iter()
                .map(|addr| Endpoint {
                    addr,
                    healthy: true,
                    ejected_until: ejected.get(&addr).copied(),
                })
                .collect();
        }
    }

    /// Remove a service from the pool.
    pub async fn remove_service(&self, service_name: &str) {
        let mut state = self.inner.write().await;
        state.services.remove(service_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn ejected_endpoints_are_skipped_then_retried() {
        let pool = UpstreamPool::new();
        pool.replace_all(HashMap::from([("web".into(), vec![addr(1), addr(2)])]))
            .await;
        pool.mark_unhealthy("web", addr(1)).await;
        for _ in 0..4 {
            assert_eq!(pool.next_endpoint("web").await, Some(addr(2)));
        }
        // Replacing keeps the ejection of endpoints that stay.
        pool.replace_all(HashMap::from([("web".into(), vec![addr(1), addr(3)])]))
            .await;
        for _ in 0..4 {
            assert_eq!(pool.next_endpoint("web").await, Some(addr(3)));
        }
        // Once the ejection lapses the endpoint is used again.
        {
            let mut state = pool.inner.write().await;
            let endpoint = &mut state.services.get_mut("web").unwrap().endpoints[0];
            endpoint.ejected_until = Some(Instant::now() - Duration::from_secs(1));
        }
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4 {
            seen.insert(pool.next_endpoint("web").await.unwrap());
        }
        assert_eq!(seen.len(), 2);
    }

    #[tokio::test]
    async fn replace_all_drops_absent_services() {
        let pool = UpstreamPool::new();
        pool.replace_all(HashMap::from([("a".into(), vec![addr(1)])]))
            .await;
        pool.replace_all(HashMap::from([("b".into(), vec![addr(2)])]))
            .await;
        assert_eq!(pool.next_endpoint("a").await, None);
        assert_eq!(pool.next_endpoint("b").await, Some(addr(2)));
    }
}
