use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Service catalog propagated between agents via gossip.
/// Provides eventually-consistent service discovery that works
/// even when the server is unreachable. Entries are scoped by
/// namespace so services with the same name in different namespaces
/// resolve independently.
#[derive(Clone)]
pub struct ServiceCatalog {
    inner: Arc<RwLock<CatalogState>>,
}

struct CatalogState {
    /// (namespace, service_name) → list of nodes running it
    entries: HashMap<(String, String), Vec<CatalogEntry>>,
    /// Lamport clock for conflict resolution
    version: u64,
}

#[derive(Debug, Clone)]
struct CatalogEntry {
    node_id: String,
    address: String,
    port: u16,
    version: u64,
}

impl Default for ServiceCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceCatalog {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CatalogState {
                entries: HashMap::new(),
                version: 0,
            })),
        }
    }

    /// Register a local service in the catalog.
    pub async fn register(
        &self,
        namespace: &str,
        service_name: &str,
        node_id: &str,
        address: &str,
        port: u16,
    ) {
        let mut state = self.inner.write().await;
        state.version += 1;
        let version = state.version;

        let key = (namespace.to_string(), service_name.to_string());
        let entries = state.entries.entry(key).or_default();

        // Update existing or add new
        if let Some(entry) = entries.iter_mut().find(|e| e.node_id == node_id) {
            entry.address = address.to_string();
            entry.port = port;
            entry.version = version;
        } else {
            entries.push(CatalogEntry {
                node_id: node_id.to_string(),
                address: address.to_string(),
                port,
                version,
            });
        }
    }

    /// Deregister a service instance.
    pub async fn deregister(&self, namespace: &str, service_name: &str, node_id: &str) {
        let mut state = self.inner.write().await;
        let key = (namespace.to_string(), service_name.to_string());
        if let Some(entries) = state.entries.get_mut(&key) {
            entries.retain(|e| e.node_id != node_id);
        }
    }

    /// Look up endpoints for a service within a namespace.
    pub async fn lookup(&self, namespace: &str, service_name: &str) -> Vec<(String, String, u16)> {
        let state = self.inner.read().await;
        let key = (namespace.to_string(), service_name.to_string());
        state
            .entries
            .get(&key)
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| (e.node_id.clone(), e.address.clone(), e.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Merge remote catalog state (from gossip).
    /// Uses version numbers for conflict resolution (last-writer-wins).
    #[allow(clippy::type_complexity)]
    pub async fn merge(
        &self,
        remote_entries: HashMap<(String, String), Vec<(String, String, u16, u64)>>,
    ) {
        let mut state = self.inner.write().await;

        for (key, remote) in remote_entries {
            let local = state.entries.entry(key).or_default();

            for (node_id, address, port, version) in remote {
                if let Some(existing) = local.iter_mut().find(|e| e.node_id == node_id) {
                    if version > existing.version {
                        existing.address = address;
                        existing.port = port;
                        existing.version = version;
                    }
                } else {
                    local.push(CatalogEntry {
                        node_id,
                        address,
                        port,
                        version,
                    });
                }
            }
        }
    }

    /// Get all catalog data for gossip propagation.
    pub async fn snapshot(&self) -> HashMap<(String, String), Vec<(String, String, u16, u64)>> {
        let state = self.inner.read().await;
        state
            .entries
            .iter()
            .map(|(key, entries)| {
                let data = entries
                    .iter()
                    .map(|e| (e.node_id.clone(), e.address.clone(), e.port, e.version))
                    .collect();
                (key.clone(), data)
            })
            .collect()
    }
}
