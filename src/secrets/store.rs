use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Server-side encrypted secret storage.
/// Secrets are encrypted at rest and scoped to specific services.
#[derive(Clone)]
pub struct SecretStore {
    inner: Arc<RwLock<StoreState>>,
}

struct StoreState {
    /// service_name → secret_name → encrypted value + metadata
    secrets: HashMap<String, HashMap<String, SecretEntry>>,
}

#[derive(Clone)]
struct SecretEntry {
    encrypted_value: Vec<u8>,
    version: u64,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreState {
                secrets: HashMap::new(),
            })),
        }
    }

    /// Store or update a secret for a service.
    pub async fn put(&self, service_name: &str, secret_name: &str, value: &[u8]) -> u64 {
        let mut state = self.inner.write().await;
        let service_secrets = state.secrets.entry(service_name.to_string()).or_default();

        let version = service_secrets
            .get(secret_name)
            .map(|e| e.version + 1)
            .unwrap_or(1);

        // TODO: encrypt with fleet key before storing
        let encrypted = value.to_vec();

        service_secrets.insert(
            secret_name.to_string(),
            SecretEntry {
                encrypted_value: encrypted,
                version,
            },
        );

        tracing::info!(
            service = %service_name,
            secret = %secret_name,
            version,
            "Secret stored"
        );

        version
    }

    /// Get a secret for a service. Returns (encrypted_value, version).
    pub async fn get(&self, service_name: &str, secret_name: &str) -> Option<(Vec<u8>, u64)> {
        let state = self.inner.read().await;
        state
            .secrets
            .get(service_name)
            .and_then(|svc| svc.get(secret_name))
            .map(|e| (e.encrypted_value.clone(), e.version))
    }

    /// Delete a secret.
    pub async fn delete(&self, service_name: &str, secret_name: &str) -> bool {
        let mut state = self.inner.write().await;
        if let Some(svc) = state.secrets.get_mut(service_name) {
            svc.remove(secret_name).is_some()
        } else {
            false
        }
    }

    /// List all secrets for a service (names only).
    pub async fn list(&self, service_name: &str) -> Vec<(String, u64)> {
        let state = self.inner.read().await;
        state
            .secrets
            .get(service_name)
            .map(|svc| {
                svc.iter()
                    .map(|(name, entry)| (name.clone(), entry.version))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all secrets that should be pushed to a node for its assigned services.
    pub async fn secrets_for_services(
        &self,
        service_names: &[String],
    ) -> Vec<(String, String, Vec<u8>, u64)> {
        let state = self.inner.read().await;
        let mut result = Vec::new();

        for svc_name in service_names {
            if let Some(svc_secrets) = state.secrets.get(svc_name) {
                for (secret_name, entry) in svc_secrets {
                    result.push((
                        svc_name.clone(),
                        secret_name.clone(),
                        entry.encrypted_value.clone(),
                        entry.version,
                    ));
                }
            }
        }

        result
    }
}
