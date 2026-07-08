#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Registration for services that live outside the fleet (external databases,
/// SaaS endpoints, third-party APIs) so they participate in DNS discovery
/// and health checking.
#[derive(Clone)]
pub struct ExternalServiceRegistry {
    services: Arc<RwLock<HashMap<String, ExternalService>>>,
}

/// An external service registered in the fleet catalog.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExternalService {
    /// Service name (used in DNS: <name>.external.fleet.internal)
    pub name: String,
    /// Endpoint addresses (ip:port).
    pub addresses: Vec<String>,
    /// Optional health check URL (HTTP GET).
    pub health_check_url: Option<String>,
    /// Whether this service is currently healthy.
    pub healthy: bool,
}

impl Default for ExternalServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register an external service.
    pub async fn register(&self, service: ExternalService) {
        tracing::info!(name = %service.name, addrs = ?service.addresses, "External service registered");
        self.services
            .write()
            .await
            .insert(service.name.clone(), service);
    }

    /// Deregister an external service.
    pub async fn deregister(&self, name: &str) -> bool {
        self.services.write().await.remove(name).is_some()
    }

    /// Get all registered external services.
    pub async fn list(&self) -> Vec<ExternalService> {
        self.services.read().await.values().cloned().collect()
    }

    /// Look up addresses for an external service.
    pub async fn resolve(&self, name: &str) -> Option<Vec<String>> {
        let services = self.services.read().await;
        services
            .get(name)
            .filter(|s| s.healthy)
            .map(|s| s.addresses.clone())
    }

    /// Update health status for an external service.
    pub async fn set_healthy(&self, name: &str, healthy: bool) {
        if let Some(svc) = self.services.write().await.get_mut(name) {
            svc.healthy = healthy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_resolve() {
        let reg = ExternalServiceRegistry::new();
        reg.register(ExternalService {
            name: "external-db".into(),
            addresses: vec!["10.0.0.50:5432".into()],
            health_check_url: None,
            healthy: true,
        })
        .await;

        let addrs = reg.resolve("external-db").await;
        assert_eq!(addrs, Some(vec!["10.0.0.50:5432".to_string()]));

        // Unhealthy services don't resolve
        reg.set_healthy("external-db", false).await;
        assert!(reg.resolve("external-db").await.is_none());
    }
}
