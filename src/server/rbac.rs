use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Role-based access control for the fleet API.
/// Each token maps to a role that grants specific permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Token store that maps bearer tokens to roles.
#[derive(Clone)]
pub struct TokenStore {
    tokens: Arc<RwLock<HashMap<String, Role>>>,
    descriptions: Arc<RwLock<HashMap<String, String>>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            descriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a token with a role. The initial admin token is registered at startup.
    pub async fn register(&self, token: &str, role: Role, description: &str) {
        self.tokens.write().await.insert(token.to_string(), role);
        self.descriptions
            .write()
            .await
            .insert(token.to_string(), description.to_string());
        tracing::info!(role = ?role, description = %description, "Token registered");
    }

    /// Get a reference to the inner token map for synchronous access (e.g., interceptors).
    pub fn inner_ref(&self) -> &Arc<RwLock<HashMap<String, Role>>> {
        &self.tokens
    }

    /// Look up the role for a bearer token.
    pub async fn authenticate(&self, token: &str) -> Option<Role> {
        let store = self.tokens.read().await;
        store.get(token).copied()
    }

    /// Revoke a token.
    pub async fn revoke(&self, token: &str) -> bool {
        self.descriptions.write().await.remove(token);
        self.tokens.write().await.remove(token).is_some()
    }

    /// List all tokens (returns description and role, not the token value itself).
    pub async fn list(&self) -> Vec<(String, Role)> {
        let tokens = self.tokens.read().await;
        let descriptions = self.descriptions.read().await;
        tokens
            .iter()
            .map(|(k, r)| {
                let desc = descriptions
                    .get(k)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                (desc, *r)
            })
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

    #[test]
    fn extract_bearer() {
        assert_eq!(extract_bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(extract_bearer_token(Some("abc123")), None);
        assert_eq!(extract_bearer_token(None), None);
    }
}
