#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Versioned secret store that retains previous versions for rollback.
#[derive(Clone)]
pub struct VersionedSecretStore {
    /// secret_key → list of (version, encrypted_value) in ascending version order
    secrets: Arc<RwLock<HashMap<String, Vec<SecretVersion>>>>,
    /// Maximum number of versions to retain per secret.
    max_versions: usize,
}

#[derive(Debug, Clone)]
struct SecretVersion {
    version: u64,
    encrypted_value: Vec<u8>,
}

impl VersionedSecretStore {
    pub fn new(max_versions: usize) -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            max_versions,
        }
    }

    /// Store a new version of a secret.
    pub async fn put(&self, key: &str, version: u64, encrypted_value: Vec<u8>) {
        let mut secrets = self.secrets.write().await;
        let versions = secrets.entry(key.to_string()).or_default();

        // Don't store duplicates
        if versions.iter().any(|v| v.version == version) {
            return;
        }

        versions.push(SecretVersion {
            version,
            encrypted_value,
        });
        versions.sort_by_key(|v| v.version);

        // Trim old versions
        while versions.len() > self.max_versions {
            versions.remove(0);
        }
    }

    /// Get the current (latest) version of a secret.
    pub async fn get_current(&self, key: &str) -> Option<(u64, Vec<u8>)> {
        let secrets = self.secrets.read().await;
        secrets
            .get(key)
            .and_then(|versions| versions.last())
            .map(|v| (v.version, v.encrypted_value.clone()))
    }

    /// Get a specific version of a secret.
    pub async fn get_version(&self, key: &str, version: u64) -> Option<Vec<u8>> {
        let secrets = self.secrets.read().await;
        secrets
            .get(key)
            .and_then(|versions| versions.iter().find(|v| v.version == version))
            .map(|v| v.encrypted_value.clone())
    }

    /// Rollback a secret to a previous version by making it the new current.
    /// Returns the rolled-back version number, or None if version not found.
    pub async fn rollback(&self, key: &str, to_version: u64) -> Option<u64> {
        let mut secrets = self.secrets.write().await;
        let versions = secrets.get_mut(key)?;
        let target = versions.iter().find(|v| v.version == to_version)?;
        let value = target.encrypted_value.clone();

        // Create a new version with the old value
        let new_version = versions.last().map(|v| v.version + 1).unwrap_or(1);
        versions.push(SecretVersion {
            version: new_version,
            encrypted_value: value,
        });

        while versions.len() > self.max_versions {
            versions.remove(0);
        }

        tracing::info!(
            key = %key,
            from_version = to_version,
            new_version,
            "Secret rolled back"
        );

        Some(new_version)
    }

    /// List available versions for a secret.
    pub async fn list_versions(&self, key: &str) -> Vec<u64> {
        let secrets = self.secrets.read().await;
        secrets
            .get(key)
            .map(|versions| versions.iter().map(|v| v.version).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_and_get() {
        let store = VersionedSecretStore::new(5);
        store.put("db-pass", 1, b"secret1".to_vec()).await;
        store.put("db-pass", 2, b"secret2".to_vec()).await;

        let (version, value) = store.get_current("db-pass").await.unwrap();
        assert_eq!(version, 2);
        assert_eq!(value, b"secret2");

        let v1 = store.get_version("db-pass", 1).await.unwrap();
        assert_eq!(v1, b"secret1");
    }

    #[tokio::test]
    async fn rollback() {
        let store = VersionedSecretStore::new(5);
        store.put("key", 1, b"v1".to_vec()).await;
        store.put("key", 2, b"v2".to_vec()).await;

        let new_ver = store.rollback("key", 1).await.unwrap();
        assert_eq!(new_ver, 3);

        let (version, value) = store.get_current("key").await.unwrap();
        assert_eq!(version, 3);
        assert_eq!(value, b"v1"); // rolled back to v1 content
    }

    #[tokio::test]
    async fn respects_max_versions() {
        let store = VersionedSecretStore::new(3);
        for i in 1..=5 {
            store.put("key", i, format!("v{i}").into_bytes()).await;
        }

        let versions = store.list_versions("key").await;
        assert_eq!(versions, vec![3, 4, 5]); // oldest trimmed
    }
}
