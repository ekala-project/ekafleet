use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Role-based access control for the fleet API.
/// Each token maps to a role that grants specific permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full access: deploy, drain, scale, manage tokens, read everything.
    Admin,
    /// Operational access: deploy, drain, scale, read everything.
    Operator,
    /// Read-only: status, services, capacity, logs, drift.
    Viewer,
}

/// Permissions that can be checked against a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read fleet status, services, capacity, drift, logs
    Read,
    /// Plan and apply deployments
    Deploy,
    /// Scale services
    Scale,
    /// Drain nodes
    Drain,
    /// Create/revoke tokens, manage RBAC
    ManageTokens,
    /// Stream control (agent connections)
    AgentConnect,
    /// Node attestation
    Attest,
}

impl Role {
    /// Check if this role grants the given permission.
    pub fn has_permission(&self, permission: Permission) -> bool {
        match self {
            Role::Admin => true,
            Role::Operator => matches!(
                permission,
                Permission::Read
                    | Permission::Deploy
                    | Permission::Scale
                    | Permission::Drain
                    | Permission::AgentConnect
                    | Permission::Attest
            ),
            Role::Viewer => matches!(permission, Permission::Read),
        }
    }
}

/// Metadata for a registered token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    role: Role,
    description: String,
    /// Unix timestamp when the token was created.
    created_at: u64,
    /// Optional Unix timestamp when the token expires. None = never expires.
    expires_at: Option<u64>,
}

impl TokenEntry {
    fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now >= exp
        } else {
            false
        }
    }
}

/// Token store that maps bearer tokens to roles with persistence.
#[derive(Clone)]
pub struct TokenStore {
    tokens: Arc<RwLock<HashMap<String, TokenEntry>>>,
    persist_path: Option<PathBuf>,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            persist_path: None,
        }
    }

    /// Create a token store that persists tokens to the given directory.
    pub fn with_persistence(data_dir: &Path) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            persist_path: Some(data_dir.join("tokens.json")),
        }
    }

    /// Load persisted tokens from disk. Expired tokens are discarded.
    pub async fn load(&self) -> anyhow::Result<()> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        if !path.exists() {
            return Ok(());
        }

        let data = tokio::fs::read_to_string(path).await?;
        let loaded: HashMap<String, TokenEntry> = serde_json::from_str(&data)?;

        let mut tokens = self.tokens.write().await;
        let mut count = 0;
        for (token, entry) in loaded {
            if !entry.is_expired() {
                tokens.insert(token, entry);
                count += 1;
            }
        }
        tracing::info!(count, "Loaded persisted ACL tokens");
        Ok(())
    }

    /// Persist current tokens to disk.
    async fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let tokens = self.tokens.read().await;
        match serde_json::to_string_pretty(&*tokens) {
            Ok(data) => {
                if let Err(e) = tokio::fs::write(path, data).await {
                    tracing::warn!(error = %e, "Failed to persist tokens");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize tokens");
            }
        }
    }

    /// Register a token with a role. The initial admin token is registered at startup.
    pub async fn register(&self, token: &str, role: Role, description: &str) {
        self.register_with_ttl(token, role, description, None).await;
    }

    /// Register a token with a role and optional TTL in seconds.
    pub async fn register_with_ttl(
        &self,
        token: &str,
        role: Role,
        description: &str,
        ttl_secs: Option<u64>,
    ) {
        let now = now_epoch();
        let entry = TokenEntry {
            role,
            description: description.to_string(),
            created_at: now,
            expires_at: ttl_secs.map(|ttl| now + ttl),
        };
        self.tokens
            .write()
            .await
            .insert(token.to_string(), entry);
        tracing::info!(role = ?role, description = %description, "Token registered");
        self.persist().await;
    }

    /// Get a reference to the inner token map for synchronous access (e.g., interceptors).
    /// The interceptor must check expiration separately via `is_valid_sync`.
    pub fn inner_ref(&self) -> &Arc<RwLock<HashMap<String, TokenEntry>>> {
        &self.tokens
    }

    /// Synchronous token validation for use in interceptors.
    /// Returns the role if the token exists and is not expired.
    pub fn authenticate_sync(
        tokens: &HashMap<String, TokenEntry>,
        token: &str,
    ) -> Option<Role> {
        let entry = tokens.get(token)?;
        if entry.is_expired() {
            None
        } else {
            Some(entry.role)
        }
    }

    /// Look up the role for a bearer token.
    pub async fn authenticate(&self, token: &str) -> Option<Role> {
        let store = self.tokens.read().await;
        Self::authenticate_sync(&store, token)
    }

    /// Revoke a token.
    pub async fn revoke(&self, token: &str) -> bool {
        let removed = self.tokens.write().await.remove(token).is_some();
        if removed {
            self.persist().await;
        }
        removed
    }

    /// List all tokens (returns description and role, not the token value itself).
    pub async fn list(&self) -> Vec<(String, Role)> {
        let tokens = self.tokens.read().await;
        tokens
            .values()
            .filter(|e| !e.is_expired())
            .map(|e| (e.description.clone(), e.role))
            .collect()
    }
}

/// Extract the bearer token from gRPC metadata or HTTP headers.
/// Returns the raw token value (without "Bearer " prefix).
pub fn extract_bearer_token(authorization: Option<&str>) -> Option<&str> {
    authorization.and_then(|v| v.strip_prefix("Bearer "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_all_permissions() {
        assert!(Role::Admin.has_permission(Permission::Read));
        assert!(Role::Admin.has_permission(Permission::Deploy));
        assert!(Role::Admin.has_permission(Permission::Scale));
        assert!(Role::Admin.has_permission(Permission::Drain));
        assert!(Role::Admin.has_permission(Permission::ManageTokens));
        assert!(Role::Admin.has_permission(Permission::AgentConnect));
        assert!(Role::Admin.has_permission(Permission::Attest));
    }

    #[test]
    fn operator_permissions() {
        assert!(Role::Operator.has_permission(Permission::Read));
        assert!(Role::Operator.has_permission(Permission::Deploy));
        assert!(Role::Operator.has_permission(Permission::Scale));
        assert!(Role::Operator.has_permission(Permission::Drain));
        assert!(!Role::Operator.has_permission(Permission::ManageTokens));
    }

    #[test]
    fn viewer_is_read_only() {
        assert!(Role::Viewer.has_permission(Permission::Read));
        assert!(!Role::Viewer.has_permission(Permission::Deploy));
        assert!(!Role::Viewer.has_permission(Permission::Scale));
        assert!(!Role::Viewer.has_permission(Permission::Drain));
        assert!(!Role::Viewer.has_permission(Permission::ManageTokens));
    }

    #[tokio::test]
    async fn token_store_authenticate() {
        let store = TokenStore::new();
        store
            .register("admin-tok", Role::Admin, "primary admin")
            .await;
        store
            .register("viewer-tok", Role::Viewer, "dashboard")
            .await;

        assert_eq!(store.authenticate("admin-tok").await, Some(Role::Admin));
        assert_eq!(store.authenticate("viewer-tok").await, Some(Role::Viewer));
        assert!(store.authenticate("unknown").await.is_none());
    }

    #[tokio::test]
    async fn token_store_revoke() {
        let store = TokenStore::new();
        store.register("tok", Role::Operator, "ci pipeline").await;
        assert!(store.revoke("tok").await);
        assert!(store.authenticate("tok").await.is_none());
        assert!(!store.revoke("tok").await);
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let store = TokenStore::new();
        // Register a token that expired 1 second ago
        let now = now_epoch();
        let entry = TokenEntry {
            role: Role::Admin,
            description: "expired".to_string(),
            created_at: now.saturating_sub(100),
            expires_at: Some(now.saturating_sub(1)),
        };
        store
            .tokens
            .write()
            .await
            .insert("expired-tok".to_string(), entry);

        assert!(store.authenticate("expired-tok").await.is_none());
    }

    #[tokio::test]
    async fn non_expired_token_works() {
        let store = TokenStore::new();
        store
            .register_with_ttl("ttl-tok", Role::Operator, "short-lived", Some(3600))
            .await;

        assert_eq!(
            store.authenticate("ttl-tok").await,
            Some(Role::Operator)
        );
    }

    #[tokio::test]
    async fn persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::with_persistence(dir.path());
        store
            .register("persist-tok", Role::Admin, "persisted token")
            .await;

        // Create a new store pointing to the same directory and load
        let store2 = TokenStore::with_persistence(dir.path());
        store2.load().await.unwrap();
        assert_eq!(
            store2.authenticate("persist-tok").await,
            Some(Role::Admin)
        );
    }

    #[test]
    fn extract_bearer() {
        assert_eq!(extract_bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(extract_bearer_token(Some("abc123")), None);
        assert_eq!(extract_bearer_token(None), None);
    }
}
