#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::RwLock;

use super::db_driver::{self, DbEngine};
use crate::agent::now_epoch;

/// Dynamic secrets engine for generating short-lived database credentials.
///
/// When a registered engine has a connection URL, credentials are provisioned
/// directly in the database (CREATE USER + GRANT). On revocation, the user
/// is dropped (DROP USER). When no database is reachable, credential material
/// is still generated for distribution via the secrets store.
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
    db_engine: DbEngine,
    /// Default database to grant access to
    default_database: String,
}

#[derive(Debug, Clone)]
pub struct DynamicLease {
    pub service_name: String,
    pub secret_name: String,
    pub credentials: Credentials,
    pub expires_at: u64,
    pub lease_id: String,
    /// Whether credentials were provisioned in the actual database
    pub provisioned: bool,
    /// The engine name (for revocation)
    engine_name: String,
    /// The connection URL (for revocation)
    connection_url: String,
    /// The detected DB engine type
    db_engine: DbEngine,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// Connection string the service should use (with embedded credentials)
    pub connection_url: Option<String>,
}

/// Duration of a dynamic lease.
#[derive(Debug, Clone, Copy)]
pub struct LeaseTtl {
    pub seconds: u64,
}

impl Default for LeaseTtl {
    fn default() -> Self {
        Self { seconds: 3600 } // 1 hour
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DynamicSecretError {
    #[error("engine '{0}' not found")]
    EngineNotFound(String),
    #[error("lease '{0}' not found")]
    LeaseNotFound(String),
    #[error("random generation failed")]
    RngFailure,
    #[error("database driver error: {0}")]
    DbDriver(#[from] db_driver::DbDriverError),
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
    ///
    /// The `connection_url` is used both to detect the engine type (postgres://,
    /// mysql://) and to connect for provisioning. The `default_database` is the
    /// database name used in GRANT statements.
    pub async fn register_engine(
        &self,
        engine_name: &str,
        connection_url: &str,
        default_database: &str,
    ) -> Result<(), DynamicSecretError> {
        let db_engine = db_driver::detect_engine(connection_url)?;

        let mut state = self.inner.write().await;
        state.engines.insert(
            engine_name.to_string(),
            RegisteredEngine {
                name: engine_name.to_string(),
                connection_url: connection_url.to_string(),
                db_engine,
                default_database: default_database.to_string(),
            },
        );

        tracing::info!(
            engine = %engine_name,
            db = %default_database,
            "Dynamic secrets engine registered"
        );
        Ok(())
    }

    /// Generate dynamic credentials for a service.
    ///
    /// 1. Generates random username and password
    /// 2. Connects to the database and provisions the user (CREATE ROLE/USER + GRANT)
    /// 3. Creates a lease for tracking and later revocation
    ///
    /// If the database is unreachable, credentials are still generated
    /// (marked as `provisioned: false`) so they can be retried.
    pub async fn generate_credentials(
        &self,
        engine: &str,
        role: &str,
        service_name: &str,
        ttl: Option<LeaseTtl>,
    ) -> Result<DynamicLease, DynamicSecretError> {
        let ttl = ttl.unwrap_or_default();
        let mut state = self.inner.write().await;

        let registered = state
            .engines
            .get(engine)
            .ok_or_else(|| DynamicSecretError::EngineNotFound(engine.to_string()))?;

        let connection_url = registered.connection_url.clone();
        let db_engine = registered.db_engine.clone();
        let default_database = registered.default_database.clone();

        state.lease_counter += 1;
        let lease_id = format!("{engine}/{role}/{}", state.lease_counter);

        let username = format!("v-{}-{}-{}", service_name, role, self.random_hex(4)?);
        let password = self.random_hex(32)?;

        // Build a role template from the role name
        let role_template = db_driver::parse_role(role, &default_database);

        // Drop the lock before doing I/O
        drop(state);

        // Attempt to provision in the actual database
        let provisioned = match db_driver::provision_credentials(
            &db_engine,
            &connection_url,
            &username,
            &password,
            &role_template,
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    engine = %engine,
                    user = %username,
                    database = %default_database,
                    "Credentials provisioned in database"
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    engine = %engine,
                    error = %e,
                    "Database provisioning failed — credentials generated but not active in DB"
                );
                false
            }
        };

        // Build a service-usable connection URL with the generated credentials
        let service_connection_url =
            build_service_url(&connection_url, &username, &password, &default_database);

        let lease = DynamicLease {
            service_name: service_name.to_string(),
            secret_name: format!("{engine}/{role}"),
            credentials: Credentials {
                username,
                password,
                connection_url: Some(service_connection_url),
            },
            expires_at: now_epoch() + ttl.seconds,
            lease_id: lease_id.clone(),
            provisioned,
            engine_name: engine.to_string(),
            connection_url: connection_url.clone(),
            db_engine,
        };

        let mut state = self.inner.write().await;
        state.leases.insert(lease_id, lease.clone());

        tracing::info!(
            engine = %engine,
            role = %role,
            service = %service_name,
            lease = %lease.lease_id,
            provisioned,
            "Dynamic lease created"
        );

        Ok(lease)
    }

    /// Revoke a dynamic lease.
    ///
    /// If the credentials were provisioned in the database, this also
    /// drops the user (terminates connections, revokes privileges, DROP USER).
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<(), DynamicSecretError> {
        let mut state = self.inner.write().await;
        let lease = state
            .leases
            .remove(lease_id)
            .ok_or_else(|| DynamicSecretError::LeaseNotFound(lease_id.to_string()))?;

        // Drop the lock before doing I/O
        drop(state);

        if lease.provisioned {
            match db_driver::revoke_credentials(
                &lease.db_engine,
                &lease.connection_url,
                &lease.credentials.username,
            )
            .await
            {
                Ok(()) => {
                    tracing::info!(
                        lease = %lease_id,
                        user = %lease.credentials.username,
                        "Database credentials revoked"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        lease = %lease_id,
                        user = %lease.credentials.username,
                        error = %e,
                        "Failed to revoke database credentials — user may still exist"
                    );
                    return Err(e.into());
                }
            }
        } else {
            tracing::info!(
                lease = %lease_id,
                "Lease revoked (credentials were not provisioned in DB)"
            );
        }

        Ok(())
    }

    /// Revoke all expired leases.
    ///
    /// This should be called periodically (e.g., every 60 seconds) to clean
    /// up expired credentials from databases.
    pub async fn revoke_expired(&self) -> Vec<(String, Result<(), DynamicSecretError>)> {
        let now = now_epoch();
        let expired_ids: Vec<String> = {
            let state = self.inner.read().await;
            state
                .leases
                .iter()
                .filter(|(_, l)| l.expires_at <= now)
                .map(|(id, _)| id.clone())
                .collect()
        };

        let mut results = Vec::new();
        for lease_id in expired_ids {
            let result = self.revoke_lease(&lease_id).await;
            results.push((lease_id, result));
        }
        results
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

    /// Retry provisioning for leases that failed database provisioning.
    pub async fn retry_unprovisioned(&self) -> Vec<(String, Result<(), DynamicSecretError>)> {
        let unprovisioned: Vec<DynamicLease> = {
            let state = self.inner.read().await;
            state
                .leases
                .values()
                .filter(|l| !l.provisioned && l.expires_at > now_epoch())
                .cloned()
                .collect()
        };

        let mut results = Vec::new();
        for lease in unprovisioned {
            let registered = {
                let state = self.inner.read().await;
                state.engines.get(&lease.engine_name).map(|e| {
                    (
                        e.connection_url.clone(),
                        e.db_engine.clone(),
                        e.default_database.clone(),
                    )
                })
            };

            if let Some((conn_url, db_engine, db_name)) = registered {
                let role_template = db_driver::parse_role(
                    lease.secret_name.split('/').nth(1).unwrap_or("readonly"),
                    &db_name,
                );
                let result = db_driver::provision_credentials(
                    &db_engine,
                    &conn_url,
                    &lease.credentials.username,
                    &lease.credentials.password,
                    &role_template,
                )
                .await;

                match &result {
                    Ok(()) => {
                        let mut state = self.inner.write().await;
                        if let Some(l) = state.leases.get_mut(&lease.lease_id) {
                            l.provisioned = true;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            lease = %lease.lease_id,
                            error = %e,
                            "Retry provisioning failed"
                        );
                    }
                }
                results.push((
                    lease.lease_id.clone(),
                    result.map_err(DynamicSecretError::from),
                ));
            }
        }
        results
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

/// Build a connection URL for the service with embedded credentials.
fn build_service_url(admin_url: &str, username: &str, password: &str, database: &str) -> String {
    // Parse the admin URL to extract host:port
    // Formats: postgres://admin:pass@host:port/admindb or mysql://admin:pass@host:port/admindb
    if let Some(rest) = admin_url
        .strip_prefix("postgres://")
        .or_else(|| admin_url.strip_prefix("postgresql://"))
    {
        let host_part = rest.rsplit('@').next().unwrap_or(rest);
        let host_port = host_part.split('/').next().unwrap_or(host_part);
        format!("postgres://{username}:{password}@{host_port}/{database}")
    } else if let Some(rest) = admin_url.strip_prefix("mysql://") {
        let host_part = rest.rsplit('@').next().unwrap_or(rest);
        let host_port = host_part.split('/').next().unwrap_or(host_part);
        format!("mysql://{username}:{password}@{host_port}/{database}")
    } else {
        format!("{admin_url}?user={username}&password={password}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_engine_detects_type() {
        let engine = DynamicSecretsEngine::new();
        engine
            .register_engine("pg", "postgres://admin:pass@localhost:5432/admin", "myapp")
            .await
            .unwrap();

        let state = engine.inner.read().await;
        assert!(matches!(state.engines["pg"].db_engine, DbEngine::Postgres));
    }

    #[tokio::test]
    async fn register_mysql_engine() {
        let engine = DynamicSecretsEngine::new();
        engine
            .register_engine("my", "mysql://root:pass@localhost:3306/admin", "myapp")
            .await
            .unwrap();

        let state = engine.inner.read().await;
        assert!(matches!(state.engines["my"].db_engine, DbEngine::Mysql));
    }

    #[tokio::test]
    async fn register_unsupported_engine_fails() {
        let engine = DynamicSecretsEngine::new();
        let result = engine
            .register_engine("sq", "sqlite:///tmp/db.sqlite", "myapp")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn generate_credentials_produces_unique_material() {
        let engine = DynamicSecretsEngine::new();
        engine
            .register_engine("pg", "postgres://admin:pass@localhost:5432/admin", "myapp")
            .await
            .unwrap();

        // Will fail to connect to DB but should still generate credentials
        let l1 = engine
            .generate_credentials("pg", "readonly", "my-service", None)
            .await
            .unwrap();
        let l2 = engine
            .generate_credentials("pg", "readonly", "my-service", None)
            .await
            .unwrap();

        assert_ne!(l1.credentials.username, l2.credentials.username);
        assert_ne!(l1.credentials.password, l2.credentials.password);
        assert_ne!(l1.lease_id, l2.lease_id);
        assert!(
            !l1.provisioned,
            "should not be provisioned when DB unreachable"
        );
    }

    #[tokio::test]
    async fn generate_credentials_includes_connection_url() {
        let engine = DynamicSecretsEngine::new();
        engine
            .register_engine(
                "pg",
                "postgres://admin:pass@db.example.com:5432/admin",
                "myapp",
            )
            .await
            .unwrap();

        let lease = engine
            .generate_credentials("pg", "rw", "my-service", None)
            .await
            .unwrap();

        let conn_url = lease.credentials.connection_url.unwrap();
        assert!(conn_url.starts_with("postgres://"));
        assert!(conn_url.contains("db.example.com:5432"));
        assert!(conn_url.contains("myapp"));
        assert!(conn_url.contains(&lease.credentials.username));
    }

    #[tokio::test]
    async fn generate_fails_for_unknown_engine() {
        let engine = DynamicSecretsEngine::new();
        let result = engine
            .generate_credentials("nonexistent", "role", "svc", None)
            .await;
        assert!(matches!(result, Err(DynamicSecretError::EngineNotFound(_))));
    }

    #[tokio::test]
    async fn revoke_lease_removes_it() {
        let engine = DynamicSecretsEngine::new();
        engine
            .register_engine("pg", "postgres://admin:pass@localhost:5432/admin", "myapp")
            .await
            .unwrap();

        let lease = engine
            .generate_credentials("pg", "admin", "svc", None)
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
    async fn custom_ttl() {
        let engine = DynamicSecretsEngine::new();
        engine
            .register_engine("pg", "postgres://admin:pass@localhost/db", "mydb")
            .await
            .unwrap();

        let lease = engine
            .generate_credentials("pg", "ro", "svc", Some(LeaseTtl { seconds: 300 }))
            .await
            .unwrap();

        let now = now_epoch();
        assert!(lease.expires_at >= now + 299);
        assert!(lease.expires_at <= now + 301);
    }

    #[test]
    fn build_service_url_postgres() {
        let url = build_service_url(
            "postgres://admin:secret@db.host:5432/admindb",
            "v-svc-ro-abc123",
            "randompass",
            "myapp",
        );
        assert_eq!(
            url,
            "postgres://v-svc-ro-abc123:randompass@db.host:5432/myapp"
        );
    }

    #[test]
    fn build_service_url_mysql() {
        let url = build_service_url(
            "mysql://root:pass@db.host:3306/admin",
            "v-svc-rw-def456",
            "pw",
            "myapp",
        );
        assert_eq!(url, "mysql://v-svc-rw-def456:pw@db.host:3306/myapp");
    }
}
