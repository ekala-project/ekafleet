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

    /// Resolve a request to a backend service. `hostname` is the Host
    /// header; any port is ignored and it matches case-insensitively.
    pub async fn resolve(&self, hostname: &str, path: &str) -> Option<ResolvedRoute> {
        let hostname = host_without_port(hostname).to_ascii_lowercase();
        let hostname = hostname.as_str();
        let state = self.inner.read().await;

        // Find matching routes, sorted by path specificity (longest prefix first)
        let mut matches: Vec<&Route> = state
            .routes
            .iter()
            .filter(|r| {
                (r.hostname == hostname || r.hostname == "*") && path.starts_with(&r.path_prefix)
            })
            .collect();

        // Longest prefix first; for equal prefixes an exact host beats `*`.
        matches.sort_by_key(|a| (std::cmp::Reverse(a.path_prefix.len()), a.hostname == "*"));

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

/// `host[:port]` or `[v6][:port]` → host.
fn host_without_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str, prefix: &str) -> Vec<PortRoute> {
        vec![PortRoute {
            hostname: host.into(),
            path_prefix: prefix.into(),
            port: 0,
            weight: 100,
        }]
    }

    #[tokio::test]
    async fn longest_prefix_wins_and_host_port_is_ignored() {
        let router = ProxyRouter::new();
        router
            .update_routes(&HashMap::from([
                ("site".to_string(), route("www.example.com", "/")),
                ("api".to_string(), route("www.example.com", "/api")),
                ("any".to_string(), route("*", "/")),
            ]))
            .await;
        let name = |host: &'static str, path: &'static str| {
            let router = router.clone();
            async move { router.resolve(host, path).await.map(|r| r.service_name) }
        };
        assert_eq!(name("www.example.com", "/").await.as_deref(), Some("site"));
        assert_eq!(
            name("WWW.example.com:8080", "/api/v1").await.as_deref(),
            Some("api")
        );
        assert_eq!(name("other.test", "/x").await.as_deref(), Some("any"));
    }

    #[test]
    fn ports_are_stripped_from_hosts() {
        assert_eq!(host_without_port("a.test:80"), "a.test");
        assert_eq!(host_without_port("a.test"), "a.test");
        assert_eq!(host_without_port("[::1]:80"), "::1");
        assert_eq!(host_without_port("[::1]"), "::1");
    }
}
