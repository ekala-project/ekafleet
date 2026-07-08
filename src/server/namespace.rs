#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Namespace provides service-level isolation within a fleet.
/// Services, secrets, and RBAC policies are scoped to a namespace.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NamespaceConfig {
    /// Namespace name (e.g., "production", "staging", "team-alpha").
    pub name: String,
    /// Resource quotas for this namespace (optional).
    #[serde(default)]
    pub quota: Option<NamespaceQuota>,
    /// Labels for the namespace.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NamespaceQuota {
    #[serde(default, rename = "maxCpu")]
    pub max_cpu: Option<u64>,
    #[serde(default, rename = "maxMemory")]
    pub max_memory: Option<u64>,
    #[serde(default, rename = "maxServices")]
    pub max_services: Option<u32>,
}

/// Registry of namespaces in the fleet.
#[derive(Clone)]
pub struct NamespaceRegistry {
    namespaces: Arc<RwLock<HashMap<String, NamespaceConfig>>>,
}

impl Default for NamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceRegistry {
    pub fn new() -> Self {
        let mut initial = HashMap::new();
        initial.insert(
            "default".to_string(),
            NamespaceConfig {
                name: "default".to_string(),
                quota: None,
                labels: HashMap::new(),
            },
        );
        Self {
            namespaces: Arc::new(RwLock::new(initial)),
        }
    }

    pub async fn create(&self, config: NamespaceConfig) {
        tracing::info!(namespace = %config.name, "Namespace created");
        self.namespaces
            .write()
            .await
            .insert(config.name.clone(), config);
    }

    pub async fn delete(&self, name: &str) -> bool {
        if name == "default" {
            tracing::warn!("Cannot delete the default namespace");
            return false;
        }
        self.namespaces.write().await.remove(name).is_some()
    }

    pub async fn list(&self) -> Vec<NamespaceConfig> {
        self.namespaces.read().await.values().cloned().collect()
    }

    pub async fn exists(&self, name: &str) -> bool {
        self.namespaces.read().await.contains_key(name)
    }
}

/// Prefix a service name with its namespace for scoped DNS and secret paths.
pub fn scoped_name(namespace: &str, service_name: &str) -> String {
    if namespace == "default" {
        service_name.to_string()
    } else {
        format!("{namespace}/{service_name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_exists() {
        let reg = NamespaceRegistry::new();
        assert!(reg.exists("default").await);
        assert!(!reg.exists("staging").await);
    }

    #[tokio::test]
    async fn cannot_delete_default() {
        let reg = NamespaceRegistry::new();
        assert!(!reg.delete("default").await);
        assert!(reg.exists("default").await);
    }

    #[test]
    fn scoped_names() {
        assert_eq!(scoped_name("default", "api"), "api");
        assert_eq!(scoped_name("staging", "api"), "staging/api");
    }
}
