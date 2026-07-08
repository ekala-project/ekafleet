#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Configuration for a federated peer cluster.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederatedCluster {
    /// Unique name for this peer cluster.
    pub name: String,
    /// gRPC address of the peer cluster's server.
    pub address: String,
    /// Trust domain of the peer cluster (for SPIFFE federation).
    pub trust_domain: String,
    /// CA certificate PEM for verifying the peer cluster.
    pub ca_cert_pem: Option<String>,
    /// Whether cross-cluster service discovery is enabled.
    #[serde(default = "default_true")]
    pub discovery_enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Manages federation with peer clusters for multi-region deployments.
#[derive(Clone)]
pub struct FederationRegistry {
    peers: Arc<RwLock<HashMap<String, FederatedCluster>>>,
    /// Cached service catalog from peer clusters.
    remote_services: Arc<RwLock<HashMap<String, Vec<RemoteService>>>>,
}

/// A service discovered from a federated peer cluster.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RemoteService {
    pub name: String,
    pub cluster: String,
    pub addresses: Vec<String>,
    pub healthy: bool,
}

impl Default for FederationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FederationRegistry {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            remote_services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a federated peer cluster.
    pub async fn add_peer(&self, cluster: FederatedCluster) {
        tracing::info!(
            name = %cluster.name,
            address = %cluster.address,
            trust_domain = %cluster.trust_domain,
            "Federated peer cluster registered"
        );
        self.peers
            .write()
            .await
            .insert(cluster.name.clone(), cluster);
    }

    /// Remove a federated peer cluster.
    pub async fn remove_peer(&self, name: &str) -> bool {
        let removed = self.peers.write().await.remove(name).is_some();
        if removed {
            self.remote_services.write().await.remove(name);
        }
        removed
    }

    /// Update the service catalog from a peer cluster.
    pub async fn update_remote_services(&self, cluster_name: &str, services: Vec<RemoteService>) {
        self.remote_services
            .write()
            .await
            .insert(cluster_name.to_string(), services);
    }

    /// Resolve a service across all federated clusters.
    /// Returns addresses from healthy remote instances if the service
    /// is not available locally.
    pub async fn resolve_federated(&self, service_name: &str) -> Vec<RemoteService> {
        let remote = self.remote_services.read().await;
        remote
            .values()
            .flatten()
            .filter(|s| s.name == service_name && s.healthy)
            .cloned()
            .collect()
    }

    /// List all peer clusters.
    pub async fn list_peers(&self) -> Vec<FederatedCluster> {
        self.peers.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_and_resolve() {
        let reg = FederationRegistry::new();
        reg.add_peer(FederatedCluster {
            name: "us-west".into(),
            address: "10.0.2.1:7400".into(),
            trust_domain: "us-west.fleet.internal".into(),
            ca_cert_pem: None,
            discovery_enabled: true,
        })
        .await;

        reg.update_remote_services(
            "us-west",
            vec![RemoteService {
                name: "api".into(),
                cluster: "us-west".into(),
                addresses: vec!["10.0.2.10:8080".into()],
                healthy: true,
            }],
        )
        .await;

        let resolved = reg.resolve_federated("api").await;
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].cluster, "us-west");
    }
}
