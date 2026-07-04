#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::RwLock;

use crate::agent::now_epoch;

/// Dynamic secrets engine for generating short-lived database credentials.
/// Inspired by Vault's dynamic secrets — generates unique credential material
/// per lease without actually connecting to databases.
#[derive(Clone)]
pub struct DynamicSecretsEngine {
    inner: Arc<RwLock<EngineState>>,
    rng: Arc<SystemRandom>,
}

struct EngineState {
    engines: HashMap<String, RegisteredEngine>,
    leases: HashMap<String, DynamicLease>,
    lease_counter: u64,
}

struct RegisteredEngine {
    name: String,
    connection_url: String,
}

#[derive(Debug, Clone)]
pub struct DynamicLease {
    pub service_name: String,
    pub secret_name: String,
    pub credentials: Credentials,
    pub expires_at: u64,
    pub lease_id: String,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DynamicSecretError {
    #[error("engine '{0}' not found")]
    EngineNotFound(String),
    #[error("lease '{0}' not found")]
    LeaseNotFound(String),
    #[error("random generation failed")]
    RngFailure,
}

impl Default for DynamicSecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicSecretsEngine {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(EngineState {
                engines: HashMap::new(),
                leases: HashMap::new(),
                lease_counter: 0,
            })),
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Register a database engine for dynamic credential generation.
    pub async fn register_engine(&self, engine_name: &str, connection_url: &str) {
        let mut state = self.inner.write().await;
        state.engines.insert(
            engine_name.to_string(),
            RegisteredEngine {
                name: engine_name.to_string(),
                connection_url: connection_url.to_string(),
            },
        );
        tracing::info!(engine = %engine_name, "Dynamic secrets engine registered");
    }

    /// Generate dynamic credentials for a service.
    /// Produces random username/password material (does not actually provision in DB).
    pub async fn generate_credentials(
        &self,
        engine: &str,
        role: &str,
        service_name: &str,
    ) -> Result<DynamicLease, DynamicSecretError> {
        let mut state = self.inner.write().await;

        if !state.engines.contains_key(engine) {
            return Err(DynamicSecretError::EngineNotFound(engine.to_string()));
        }

        state.lease_counter += 1;
        let lease_id = format!("{engine}/{role}/{}", state.lease_counter);

        let username = format!("v-{}-{}-{}", service_name, role, self.random_hex(8)?);
        let password = self.random_hex(32)?;

        let lease = DynamicLease {
            service_name: service_name.to_string(),
            secret_name: format!("{engine}/{role}"),
            credentials: Credentials { username, password },
            expires_at: now_epoch() + 3600, // 1 hour TTL
            lease_id: lease_id.clone(),
        };

        state.leases.insert(lease_id, lease.clone());

        tracing::info!(
            engine = %engine,
            role = %role,
            service = %service_name,
            lease = %lease.lease_id,
            "Dynamic credentials generated"
        );

        Ok(lease)
    }

    /// Revoke a dynamic lease (credentials should be deleted from DB).
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<(), DynamicSecretError> {
        let mut state = self.inner.write().await;
        if state.leases.remove(lease_id).is_some() {
            tracing::info!(lease = %lease_id, "Dynamic lease revoked");
            Ok(())
        } else {
            Err(DynamicSecretError::LeaseNotFound(lease_id.to_string()))
        }
    }

    /// List all active (non-expired) leases.
    pub async fn active_leases(&self) -> Vec<DynamicLease> {
        let state = self.inner.read().await;
        let now = now_epoch();
        state
            .leases
            .values()
            .filter(|l| l.expires_at > now)
            .cloned()
            .collect()
    }

    /// Generate a random hex string of the given byte length.
    fn random_hex(&self, byte_len: usize) -> Result<String, DynamicSecretError> {
        let mut bytes = vec![0u8; byte_len];
        self.rng
            .fill(&mut bytes)
            .map_err(|_| DynamicSecretError::RngFailure)?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_credentials_for_registered_engine() {
        let engine = DynamicSecretsEngine::new();
        engine
            .register_engine("postgres", "postgres://localhost/mydb")
            .await;

        let lease = engine
            .generate_credentials("postgres", "readonly", "my-service")
            .await
            .unwrap();

        assert!(lease.credentials.username.contains("my-service"));
        assert!(lease.credentials.username.contains("readonly"));
        assert!(!lease.credentials.password.is_empty());
        assert_eq!(lease.service_name, "my-service");
    }

    #[tokio::test]
    async fn generate_fails_for_unknown_engine() {
        let engine = DynamicSecretsEngine::new();

        let result = engine
            .generate_credentials("nonexistent", "role", "svc")
            .await;

        assert!(matches!(result, Err(DynamicSecretError::EngineNotFound(_))));
    }

    #[tokio::test]
    async fn revoke_lease_removes_it() {
        let engine = DynamicSecretsEngine::new();
        engine.register_engine("pg", "postgres://localhost").await;

        let lease = engine
            .generate_credentials("pg", "admin", "svc")
            .await
            .unwrap();

        assert_eq!(engine.active_leases().await.len(), 1);

        engine.revoke_lease(&lease.lease_id).await.unwrap();

        assert_eq!(engine.active_leases().await.len(), 0);
    }

    #[tokio::test]
    async fn revoke_nonexistent_lease_fails() {
        let engine = DynamicSecretsEngine::new();

        let result = engine.revoke_lease("no/such/lease").await;
        assert!(matches!(result, Err(DynamicSecretError::LeaseNotFound(_))));
    }

    #[tokio::test]
    async fn credentials_are_unique() {
        let engine = DynamicSecretsEngine::new();
        engine.register_engine("pg", "postgres://localhost").await;

        let l1 = engine
            .generate_credentials("pg", "role", "svc")
            .await
            .unwrap();
        let l2 = engine
            .generate_credentials("pg", "role", "svc")
            .await
            .unwrap();

        assert_ne!(l1.credentials.username, l2.credentials.username);
        assert_ne!(l1.credentials.password, l2.credentials.password);
        assert_ne!(l1.lease_id, l2.lease_id);
    }
}
