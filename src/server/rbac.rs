use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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
    /// A fleet node's agent (mTLS node SVID). May only open its own control
    /// stream; it cannot read fleet state or perform operator actions, so a
    /// compromised node cannot act on the rest of the fleet.
    Agent,
    /// A service workload (mTLS service SVID). May only use the transit
    /// keys its service lists in `transitKeys`.
    Workload,
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
    /// Derive a `PeerIdentity` from a verified peer certificate's SPIFFE URI.
    /// Only identities in the server's own trust domain are accepted, and the
    /// path determines the role:
    /// - `/server/<id>` → Admin (peer server in an HA cluster)
    /// - `/agent/<name>` → Agent (data-plane node; control stream only)
    /// - `/service/<name>` → Workload (transit keys of its service only)
    ///
    /// Any other identity (foreign trust domains, malformed IDs) returns
    /// `None` and must be refused.
    pub fn from_spiffe_id(domain: &str, spiffe_id: String) -> Option<Self> {
        let path = spiffe_id
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.strip_prefix(domain))
            .filter(|path| path.starts_with('/'))?;
        let role = if crate::ca::agent_name_from_spiffe_id(domain, &spiffe_id).is_some() {
            Role::Agent
        } else if crate::ca::service_name_from_spiffe_id(domain, &spiffe_id).is_some() {
            Role::Workload
        } else if path
            .strip_prefix("/server/")
            .is_some_and(|id| crate::ca::validate_identity_name(id).is_ok())
        {
            Role::Admin
        } else {
            return None;
        };
        Some(Self { spiffe_id, role })
    }

    /// The node name when this peer is an agent of `domain`.
    pub fn agent_name(&self, domain: &str) -> Option<&str> {
        match self.role {
            Role::Agent => crate::ca::agent_name_from_spiffe_id(domain, &self.spiffe_id),
            _ => None,
        }
    }

    /// The service name when this peer is a workload of `domain`.
    pub fn service_name(&self, domain: &str) -> Option<&str> {
        match self.role {
            Role::Workload => crate::ca::service_name_from_spiffe_id(domain, &self.spiffe_id),
            _ => None,
        }
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
    /// Set and delete static secret values (listing names needs only Read)
    ManageSecrets,
    /// Stream control (agent connections)
    AgentConnect,
    /// Read the audit log (Admin only)
    ReadAudit,
    /// Encrypt and decrypt with transit keys
    Transit,
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
                    | Permission::ManageSecrets
                    | Permission::AgentConnect
                    | Permission::Transit
            ),
            Role::Viewer => matches!(permission, Permission::Read),
            Role::Agent => matches!(permission, Permission::AgentConnect),
            Role::Workload => matches!(permission, Permission::Transit),
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

/// The namespace a namespace-scoped bearer token is bound to; `None` for
/// fleet-wide principals (unscoped tokens and mTLS peers).
pub fn namespace_scope<T>(request: &tonic::Request<T>) -> Option<&str> {
    request
        .extensions()
        .get::<TokenIdentity>()
        .and_then(|identity| identity.namespace.as_deref())
}

/// Like [`require_permission`], for operations on the fleet as a whole
/// (nodes, the fleet configuration, tokens, Raft state, agent streams):
/// namespace-scoped tokens are refused whatever their role.
#[allow(clippy::result_large_err)]
pub fn require_fleet_permission<T>(
    request: &tonic::Request<T>,
    perm: Permission,
) -> Result<(), tonic::Status> {
    require_permission(request, perm)?;
    if let Some(ns) = namespace_scope(request) {
        return Err(tonic::Status::permission_denied(format!(
            "token is scoped to namespace '{ns}' and cannot perform fleet-wide operations"
        )));
    }
    Ok(())
}

/// The namespace a service belongs to: empty means [`DEFAULT_NAMESPACE`].
pub fn effective_namespace(namespace: &str) -> &str {
    if namespace.is_empty() {
        DEFAULT_NAMESPACE
    } else {
        namespace
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
    // A std lock: the gRPC interceptor authenticates synchronously, and no
    // guard is ever held across an await.
    tokens: Arc<RwLock<HashMap<String, TokenEntry>>>,
    persist_path: Option<PathBuf>,
    // Serializes snapshot+write so the last write on disk is the newest state.
    persist_lock: Arc<tokio::sync::Mutex<()>>,
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
            persist_lock: Arc::default(),
        }
    }

    /// Create a token store that persists tokens to the given directory.
    pub fn with_persistence(data_dir: &Path) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            persist_path: Some(data_dir.join("tokens.json")),
            persist_lock: Arc::default(),
        }
    }

    fn read_tokens(&self) -> RwLockReadGuard<'_, HashMap<String, TokenEntry>> {
        self.tokens.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_tokens(&self) -> RwLockWriteGuard<'_, HashMap<String, TokenEntry>> {
        self.tokens.write().unwrap_or_else(|e| e.into_inner())
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

        let mut tokens = self.write_tokens();
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
        let _persisting = self.persist_lock.lock().await;
        let serialized = serde_json::to_string_pretty(&*self.read_tokens());
        match serialized {
            Ok(data) => {
                if let Err(e) = crate::fsutil::write_atomic(path, data.as_bytes(), 0o600).await {
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
        self.write_tokens().insert(token_key(token), entry);
        tracing::info!(role = ?role, description = %description, "Token registered");
        self.persist().await;
    }

    /// Authenticate a bearer token, returning its role and a stable,
    /// non-secret identity for audit logging. `None` for unknown or expired
    /// tokens. Synchronous so the gRPC interceptor can call it.
    pub fn authenticate_identity(&self, token: &str) -> Option<(Role, TokenIdentity)> {
        let tokens = self.read_tokens();
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
    pub fn authenticate(&self, token: &str) -> Option<Role> {
        self.authenticate_identity(token).map(|(role, _)| role)
    }

    /// Revoke a token.
    pub async fn revoke(&self, token: &str) -> bool {
        let removed = self.write_tokens().remove(&token_key(token)).is_some();
        if removed {
            self.persist().await;
        }
        removed
    }

    /// List all tokens (returns description, role, and optional namespace).
    pub async fn list(&self) -> Vec<(String, Role, Option<String>)> {
        self.read_tokens()
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
        assert!(!Role::Viewer.has_permission(Permission::ManageSecrets));
        assert!(!Role::Agent.has_permission(Permission::ManageSecrets));
        assert!(Role::Operator.has_permission(Permission::ManageSecrets));
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

        assert_eq!(store.authenticate("admin-tok"), Some(Role::Admin));
        assert_eq!(store.authenticate("viewer-tok"), Some(Role::Viewer));
        assert!(store.authenticate("unknown").is_none());
    }

    #[tokio::test]
    async fn token_store_revoke() {
        let store = TokenStore::new();
        store.register("tok", Role::Operator, "ci pipeline").await;
        assert!(store.revoke("tok").await);
        assert!(store.authenticate("tok").is_none());
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
        store.write_tokens().insert(token_key("expired-tok"), entry);

        assert!(store.authenticate("expired-tok").is_none());
    }

    #[tokio::test]
    async fn non_expired_token_works() {
        let store = TokenStore::new();
        store
            .register_with_ttl("ttl-tok", Role::Operator, "short-lived", Some(3600))
            .await;

        assert_eq!(store.authenticate("ttl-tok"), Some(Role::Operator));
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
        assert_eq!(store2.authenticate("persist-tok"), Some(Role::Admin));
    }

    #[tokio::test]
    async fn authenticate_identity_returns_stable_id() {
        let store = TokenStore::new();
        store.register("secret-tok", Role::Operator, "ci").await;
        let (role, id) = store
            .authenticate_identity("secret-tok")
            .expect("known token");
        assert_eq!(role, Role::Operator);
        assert!(id.id.starts_with("token:"));
        // Id is derived from the token, never the token itself.
        assert!(!id.id.contains("secret-tok"));
        assert_eq!(id.id, token_id("secret-tok"));
        assert_eq!(id.actor(), format!("{} (ci)", token_id("secret-tok")));

        assert!(store.authenticate_identity("nope").is_none());
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

        let guard = store.read_tokens();
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
        let peer = PeerIdentity::from_spiffe_id(
            "fleet.internal",
            "spiffe://fleet.internal/server/abc".into(),
        )
        .unwrap();
        assert_eq!(peer.role, Role::Admin);
        assert_eq!(peer.actor(), "spiffe://fleet.internal/server/abc");
        assert_eq!(peer.agent_name("fleet.internal"), None);
    }

    #[test]
    fn peer_identity_agent_is_agent_role() {
        let peer = PeerIdentity::from_spiffe_id(
            "fleet.internal",
            "spiffe://fleet.internal/agent/node-1".into(),
        )
        .unwrap();
        assert_eq!(peer.role, Role::Agent);
        assert_eq!(peer.agent_name("fleet.internal"), Some("node-1"));
    }

    #[test]
    fn agent_role_can_only_connect() {
        assert!(Role::Agent.has_permission(Permission::AgentConnect));
        for perm in [
            Permission::Read,
            Permission::Deploy,
            Permission::Scale,
            Permission::Drain,
            Permission::ManageTokens,
        ] {
            assert!(!Role::Agent.has_permission(perm), "{perm:?}");
        }
    }

    #[test]
    fn workload_svids_may_only_use_transit() {
        let peer = PeerIdentity::from_spiffe_id(
            "fleet.internal",
            "spiffe://fleet.internal/service/api-server".into(),
        )
        .unwrap();
        assert_eq!(peer.role, Role::Workload);
        assert_eq!(peer.service_name("fleet.internal"), Some("api-server"));
        assert_eq!(peer.agent_name("fleet.internal"), None);
        assert!(Role::Workload.has_permission(Permission::Transit));
        for perm in [
            Permission::Read,
            Permission::Deploy,
            Permission::Scale,
            Permission::Drain,
            Permission::ManageTokens,
            Permission::ManageSecrets,
            Permission::AgentConnect,
            Permission::ReadAudit,
        ] {
            assert!(!Role::Workload.has_permission(perm), "{perm:?}");
        }
        assert!(!Role::Viewer.has_permission(Permission::Transit));
        assert!(!Role::Agent.has_permission(Permission::Transit));
    }

    #[test]
    fn peer_identity_rejects_other_identities() {
        for id in [
            "spiffe://fleet.internal/service/",
            "spiffe://fleet.internal/service/a/b",
            "spiffe://other.domain/service/api-server",
            "spiffe://fleet.internal/workload/api-server",
            "spiffe://unknown/unidentified",
            "spiffe://other.domain/server/abc",
            "spiffe://other.domain/agent/node-1",
            "spiffe://fleet.internalx/server/abc",
            "spiffe://fleet.internal/agent/a/b",
            "spiffe://fleet.internal/server/",
            "spiffe://fleet.internal/agent/",
            "https://fleet.internal/server/abc",
        ] {
            assert_eq!(
                PeerIdentity::from_spiffe_id("fleet.internal", id.into()),
                None,
                "{id} must not map to a role"
            );
        }
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

        let (role, identity) = store.authenticate_identity("ns-tok").expect("known token");
        assert_eq!(role, Role::Operator);
        assert_eq!(identity.namespace.as_deref(), Some("team-a"));
    }

    #[tokio::test]
    async fn unscoped_token_has_no_namespace() {
        let store = TokenStore::new();
        store.register("global-tok", Role::Admin, "global").await;

        let (_, identity) = store
            .authenticate_identity("global-tok")
            .expect("known token");
        assert!(identity.namespace.is_none());
    }

    #[test]
    fn namespace_tokens_are_refused_fleet_wide_operations() {
        let request = |namespace: Option<&str>, request_ns: &str| {
            let mut req = tonic::Request::new(());
            req.extensions_mut().insert(Role::Admin);
            req.extensions_mut().insert(TokenIdentity {
                id: "token:t".into(),
                description: "d".into(),
                role: Role::Admin,
                namespace: namespace.map(Into::into),
            });
            req.extensions_mut()
                .insert(RequestNamespace(request_ns.into()));
            req
        };

        let scoped = request(Some("team-a"), "team-a");
        assert_eq!(namespace_scope(&scoped), Some("team-a"));
        assert!(require_permission(&scoped, Permission::Deploy).is_ok());
        let err = require_fleet_permission(&scoped, Permission::Read).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        // ...and every request made outside its namespace.
        let elsewhere = request(Some("team-a"), "team-b");
        assert!(require_permission(&elsewhere, Permission::Read).is_err());

        let global = request(None, "team-b");
        assert_eq!(namespace_scope(&global), None);
        assert!(require_fleet_permission(&global, Permission::ManageTokens).is_ok());

        assert_eq!(effective_namespace(""), DEFAULT_NAMESPACE);
        assert_eq!(effective_namespace("team-a"), "team-a");
    }
}
