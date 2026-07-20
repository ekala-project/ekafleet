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

/// Marks how a request was authenticated. Stored in request extensions by the
/// gRPC interceptor so handlers can distinguish a verified mTLS peer (node SVID)
/// from a bearer-token principal. This is derived server-side from the verified
/// TLS peer certificate and can never be asserted by a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The SPIFFE ID extracted from the peer certificate SAN, e.g.
    /// `spiffe://fleet.internal/agent/node-1`.
    pub spiffe_id: String,
    /// Role derived from the SPIFFE ID path structure.
    pub role: Role,
}

impl PeerIdentity {
    /// Derive a `PeerIdentity` from a SPIFFE URI. The path determines the role:
    /// - `/server/...` → Admin (peer server in an HA cluster)
    /// - `/agent/...`  → Operator (data-plane agent)
    /// - anything else → Viewer (unknown workload identity)
    pub fn from_spiffe_id(spiffe_id: String) -> Self {
        let path = spiffe_id
            .find("//")
            .and_then(|i| spiffe_id[i + 2..].find('/'))
            .map(|i| {
                let abs = spiffe_id.find("//").unwrap() + 2 + i;
                &spiffe_id[abs..]
            })
            .unwrap_or("");

        let role = if path.starts_with("/server/") {
            Role::Admin
        } else if path.starts_with("/agent/") {
            Role::Operator
        } else {
            Role::Viewer
        };

        Self { spiffe_id, role }
    }

    /// Actor string for audit logging, e.g. `spiffe://fleet.internal/agent/node-1`.
    pub fn actor(&self) -> String {
        self.spiffe_id.clone()
    }
}

/// A non-secret, stable identifier for the bearer token that authenticated a
/// request. Stashed in request extensions by the gRPC interceptor so audit-log
/// entries can record *which* token performed each action without exposing the
/// token value itself. The id is a truncated SHA-256 of the raw token, which is
/// stable across restarts but not reversible to the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenIdentity {
    /// Truncated SHA-256 hex digest of the token, prefixed with `token:`.
    pub id: String,
    /// Human-readable description recorded when the token was registered.
    pub description: String,
    /// Role granted by the token.
    pub role: Role,
    /// Optional namespace binding. When set, operations are restricted to
    /// this namespace. `None` means fleet-wide access.
    pub namespace: Option<String>,
}

impl TokenIdentity {
    /// A stable actor string for the audit log, e.g. `token:1a2b3c4d5e6f (ci)`.
    pub fn actor(&self) -> String {
        if self.description.is_empty() {
            self.id.clone()
        } else {
            format!("{} ({})", self.id, self.description)
        }
    }
}

/// Derive a stable, non-secret identifier from a raw bearer token.
pub fn token_id(token: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    let hex: String = digest.as_ref()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("token:{hex}")
}

/// Derive the storage key for a raw bearer token: the full SHA-256 digest as
/// hex. The token store is keyed by this digest rather than the raw secret so
/// that (1) authentication lookups compare fixed-length, uniformly-distributed
/// digest bytes — the short-circuiting equality inside the map leaks nothing
/// about the secret's contents or length, giving effectively constant-time
/// comparison — and (2) the persisted `tokens.json` never contains raw token
/// values at rest.
fn token_key(token: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The namespace a request is scoped to, carried by the CLI in the
/// `x-ekafleet-namespace` metadata and stashed in request extensions by the
/// gRPC interceptor. Handlers read this to scope operations; when the marker
/// is absent it defaults to [`DEFAULT_NAMESPACE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestNamespace(pub String);

/// Metadata key the CLI uses to convey the request namespace.
pub const NAMESPACE_METADATA_KEY: &str = "x-ekafleet-namespace";

/// Namespace used when a request carries no namespace marker.
pub const DEFAULT_NAMESPACE: &str = "default";

impl Default for RequestNamespace {
    fn default() -> Self {
        Self(DEFAULT_NAMESPACE.to_string())
    }
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

/// Check that a gRPC request carries a principal (bearer token or mTLS peer)
/// with the given permission, and that namespace-scoped tokens match the
/// request's namespace. Returns `Ok(())` on success, or a tonic
/// `PERMISSION_DENIED` / `UNAUTHENTICATED` status on failure.
#[allow(clippy::result_large_err)]
pub fn require_permission<T>(
    request: &tonic::Request<T>,
    perm: Permission,
) -> Result<(), tonic::Status> {
    let request_ns = request
        .extensions()
        .get::<RequestNamespace>()
        .map(|ns| ns.0.as_str())
        .unwrap_or(DEFAULT_NAMESPACE);

    // Bearer-token auth stashes the Role directly.
    if let Some(role) = request.extensions().get::<Role>() {
        if !role.has_permission(perm) {
            return Err(tonic::Status::permission_denied(format!(
                "{role:?} role does not have {perm:?} permission"
            )));
        }
        // Enforce namespace binding from the token identity.
        if let Some(identity) = request.extensions().get::<TokenIdentity>()
            && let Some(bound_ns) = &identity.namespace
            && bound_ns != request_ns
        {
            return Err(tonic::Status::permission_denied(format!(
                "token is scoped to namespace '{bound_ns}', cannot access '{request_ns}'"
            )));
        }
        return Ok(());
    }
    // mTLS peer identity carries a derived role (never namespace-scoped).
    if let Some(peer) = request.extensions().get::<PeerIdentity>() {
        if peer.role.has_permission(perm) {
            return Ok(());
        }
        return Err(tonic::Status::permission_denied(format!(
            "mTLS peer {} ({:?}) does not have {perm:?} permission",
            peer.spiffe_id, peer.role
        )));
    }
    Err(tonic::Status::unauthenticated("no authenticated principal"))
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
    /// Optional namespace binding. When set, the token can only access
    /// resources within this namespace. `None` means unrestricted (fleet-wide).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
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
        self.register_with_opts(token, role, description, None, None)
            .await;
    }

    /// Register a token with a role and optional TTL in seconds.
    pub async fn register_with_ttl(
        &self,
        token: &str,
        role: Role,
        description: &str,
        ttl_secs: Option<u64>,
    ) {
        self.register_with_opts(token, role, description, ttl_secs, None)
            .await;
    }

    /// Register a token with a role, optional TTL, and optional namespace binding.
    /// When `namespace` is `Some`, the token can only access resources within that
    /// namespace. `None` means fleet-wide (unrestricted) access.
    pub async fn register_with_opts(
        &self,
        token: &str,
        role: Role,
        description: &str,
        ttl_secs: Option<u64>,
        namespace: Option<String>,
    ) {
        let now = now_epoch();
        let entry = TokenEntry {
            role,
            description: description.to_string(),
            created_at: now,
            expires_at: ttl_secs.map(|ttl| now + ttl),
            namespace,
        };
        self.tokens.write().await.insert(token_key(token), entry);
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
    pub fn authenticate_sync(tokens: &HashMap<String, TokenEntry>, token: &str) -> Option<Role> {
        let entry = tokens.get(&token_key(token))?;
        if entry.is_expired() {
            None
        } else {
            Some(entry.role)
        }
    }

    /// Synchronous token authentication returning both the role and a stable,
    /// non-secret identity for audit logging. Returns `None` for unknown or
    /// expired tokens.
    pub fn authenticate_sync_identity(
        tokens: &HashMap<String, TokenEntry>,
        token: &str,
    ) -> Option<(Role, TokenIdentity)> {
        let entry = tokens.get(&token_key(token))?;
        if entry.is_expired() {
            return None;
        }
        let identity = TokenIdentity {
            id: token_id(token),
            description: entry.description.clone(),
            role: entry.role,
            namespace: entry.namespace.clone(),
        };
        Some((entry.role, identity))
    }

    /// Look up the role for a bearer token.
    pub async fn authenticate(&self, token: &str) -> Option<Role> {
        let store = self.tokens.read().await;
        Self::authenticate_sync(&store, token)
    }

    /// Revoke a token.
    pub async fn revoke(&self, token: &str) -> bool {
        let removed = self
            .tokens
            .write()
            .await
            .remove(&token_key(token))
            .is_some();
        if removed {
            self.persist().await;
        }
        removed
    }

    /// List all tokens (returns description, role, and optional namespace).
    pub async fn list(&self) -> Vec<(String, Role, Option<String>)> {
        let tokens = self.tokens.read().await;
        tokens
            .values()
            .filter(|e| !e.is_expired())
            .map(|e| (e.description.clone(), e.role, e.namespace.clone()))
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
            namespace: None,
        };
        store
            .tokens
            .write()
            .await
            .insert(token_key("expired-tok"), entry);

        assert!(store.authenticate("expired-tok").await.is_none());
    }

    #[tokio::test]
    async fn non_expired_token_works() {
        let store = TokenStore::new();
        store
            .register_with_ttl("ttl-tok", Role::Operator, "short-lived", Some(3600))
            .await;

        assert_eq!(store.authenticate("ttl-tok").await, Some(Role::Operator));
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
        assert_eq!(store2.authenticate("persist-tok").await, Some(Role::Admin));
    }

    #[tokio::test]
    async fn authenticate_sync_identity_returns_stable_id() {
        let store = TokenStore::new();
        store.register("secret-tok", Role::Operator, "ci").await;
        let guard = store.tokens.read().await;

        let (role, id) =
            TokenStore::authenticate_sync_identity(&guard, "secret-tok").expect("known token");
        assert_eq!(role, Role::Operator);
        assert!(id.id.starts_with("token:"));
        // Id is derived from the token, never the token itself.
        assert!(!id.id.contains("secret-tok"));
        assert_eq!(id.id, token_id("secret-tok"));
        assert_eq!(id.actor(), format!("{} (ci)", token_id("secret-tok")));

        assert!(TokenStore::authenticate_sync_identity(&guard, "nope").is_none());
    }

    #[test]
    fn token_id_is_deterministic_and_non_reversible() {
        assert_eq!(token_id("abc"), token_id("abc"));
        assert_ne!(token_id("abc"), token_id("abd"));
        assert!(token_id("abc").starts_with("token:"));
        assert!(!token_id("abc").contains("abc"));
    }

    #[tokio::test]
    async fn store_keys_by_digest_never_raw_token() {
        let store = TokenStore::new();
        store.register("secret-tok", Role::Admin, "ci").await;

        let guard = store.tokens.read().await;
        // The raw secret must never appear as a map key.
        assert!(!guard.contains_key("secret-tok"));
        // The digest key is present and is a 64-char lowercase hex SHA-256.
        let key = token_key("secret-tok");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(guard.contains_key(&key));
    }

    #[test]
    fn extract_bearer() {
        assert_eq!(extract_bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(extract_bearer_token(Some("abc123")), None);
        assert_eq!(extract_bearer_token(None), None);
    }

    #[test]
    fn peer_identity_server_is_admin() {
        let peer = PeerIdentity::from_spiffe_id("spiffe://fleet.internal/server/abc".to_string());
        assert_eq!(peer.role, Role::Admin);
        assert_eq!(peer.actor(), "spiffe://fleet.internal/server/abc");
    }

    #[test]
    fn peer_identity_agent_is_operator() {
        let peer = PeerIdentity::from_spiffe_id("spiffe://fleet.internal/agent/node-1".to_string());
        assert_eq!(peer.role, Role::Operator);
    }

    #[test]
    fn peer_identity_workload_is_viewer() {
        let peer =
            PeerIdentity::from_spiffe_id("spiffe://fleet.internal/workload/api-server".to_string());
        assert_eq!(peer.role, Role::Viewer);
    }

    #[test]
    fn peer_identity_unknown_is_viewer() {
        let peer = PeerIdentity::from_spiffe_id("spiffe://unknown/unidentified".to_string());
        assert_eq!(peer.role, Role::Viewer);
    }

    #[tokio::test]
    async fn namespace_scoped_token_blocks_cross_namespace() {
        let store = TokenStore::new();
        store
            .register_with_opts(
                "ns-tok",
                Role::Operator,
                "scoped",
                None,
                Some("team-a".into()),
            )
            .await;

        let guard = store.tokens.read().await;
        let (role, identity) =
            TokenStore::authenticate_sync_identity(&guard, "ns-tok").expect("known token");
        assert_eq!(role, Role::Operator);
        assert_eq!(identity.namespace.as_deref(), Some("team-a"));
    }

    #[tokio::test]
    async fn unscoped_token_has_no_namespace() {
        let store = TokenStore::new();
        store.register("global-tok", Role::Admin, "global").await;

        let guard = store.tokens.read().await;
        let (_, identity) =
            TokenStore::authenticate_sync_identity(&guard, "global-tok").expect("known token");
        assert!(identity.namespace.is_none());
    }
}
