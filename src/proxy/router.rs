use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// HTTP routing table built from service port contracts.
/// Maps hostnames/paths to backend service pools.
#[derive(Clone)]
pub struct ProxyRouter {
    inner: Arc<RwLock<RouterState>>,
}

struct RouterState {
    routes: Vec<Route>,
}

#[derive(Debug, Clone)]
struct Route {
    hostname: String,
    path_prefix: String,
    service_name: String,
    port: u16,
    /// Traffic weight for canary splitting (0-100)
    weight: u32,
}

impl Default for ProxyRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyRouter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RouterState { routes: Vec::new() })),
        }
    }

    /// Update routes from service port contracts.
    pub async fn update_routes(&self, services: &HashMap<String, Vec<PortRoute>>) {
        let mut state = self.inner.write().await;
        state.routes.clear();

        for (service_name, ports) in services {
            for port_route in ports {
                state.routes.push(Route {
                    hostname: port_route.hostname.clone(),
                    path_prefix: port_route.path_prefix.clone(),
                    service_name: service_name.clone(),
                    port: port_route.port,
                    weight: port_route.weight,
                });
            }
        }

        tracing::info!(routes = state.routes.len(), "Proxy routes updated");
    }

    /// Resolve a request to a backend service.
    pub async fn resolve(&self, hostname: &str, path: &str) -> Option<ResolvedRoute> {
        let state = self.inner.read().await;

        // Find matching routes, sorted by path specificity (longest prefix first)
        let mut matches: Vec<&Route> = state
            .routes
            .iter()
            .filter(|r| {
                (r.hostname == hostname || r.hostname == "*") && path.starts_with(&r.path_prefix)
            })
            .collect();

        matches.sort_by_key(|a| std::cmp::Reverse(a.path_prefix.len()));

        matches.first().map(|r| ResolvedRoute {
            service_name: r.service_name.clone(),
            port: r.port,
            weight: r.weight,
        })
    }

    /// Set traffic weight for canary splitting.
    pub async fn set_weight(&self, service_name: &str, weight: u32) {
        let mut state = self.inner.write().await;
        for route in &mut state.routes {
            if route.service_name == service_name {
                route.weight = weight;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortRoute {
    pub hostname: String,
    pub path_prefix: String,
    pub port: u16,
    pub weight: u32,
}

#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub service_name: String,
    pub port: u16,
    pub weight: u32,
}
