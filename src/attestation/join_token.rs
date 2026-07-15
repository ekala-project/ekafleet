use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::{AttestationError, AttestationResult};

/// Max failed consume attempts allowed within `RATE_LIMIT_WINDOW_SECS` before
/// further attempts are rejected outright. Protects against brute-forcing the
/// token namespace.
const RATE_LIMIT_MAX_FAILURES: u32 = 20;
/// Sliding window (seconds) over which failed attempts are counted.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Server-side store for one-time join tokens.
///
/// Tokens are registered via `ekafleet token create --type agent` and consumed
/// exactly once during node attestation. After successful attestation, the
/// token is deleted and an audit record of the consumption is retained so the
/// event survives a restart and cannot be silently replayed against a fresh
/// (empty) in-memory store.
///
/// A token may optionally be *bound* to a specific node ID at registration
/// time. A bound token will only attest for that exact node; a mismatching
/// node_id is rejected even if the token string is correct. This ties a token
/// to an out-of-band identity (e.g. a cloud instance ID) so a leaked token is
/// useless outside its intended host.
#[derive(Clone)]
pub struct JoinTokenStore {
    inner: Arc<RwLock<State>>,
    persist_path: Option<PathBuf>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Live, unconsumed tokens keyed by token string.
    tokens: HashMap<String, TokenEntry>,
    /// Audit trail of consumed tokens keyed by token string. Retained so a
    /// consumed token cannot be replayed after a restart.
    consumed: HashMap<String, ConsumedRecord>,
    /// Recent failed-attempt timestamps (epoch secs) for rate limiting. Not
    /// persisted — reset on restart is acceptable and desirable.
    #[serde(skip)]
    failures: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
struct TokenEntry {
    /// Optional node ID this token is bound to. If `Some`, attestation must
    /// present a matching node_id.
    bound_node_id: Option<String>,
    /// When this token was registered (epoch seconds).
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
struct ConsumedRecord {
    /// Node ID that consumed the token.
    node_id: String,
    /// When the token was consumed (epoch seconds).
    consumed_at: u64,
}

impl Default for JoinTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl JoinTokenStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(State::default())),
            persist_path: None,
        }
    }

    /// Create a token store that persists live tokens and the consumed-token
    /// audit trail to `join_tokens.json` under the given data directory.
    pub fn with_persistence(data_dir: &std::path::Path) -> Self {
        Self {
            inner: Arc::new(RwLock::new(State::default())),
            persist_path: Some(data_dir.join("join_tokens.json")),
        }
    }

    /// Load persisted tokens and audit trail from disk, if configured.
    pub async fn load(&self) -> anyhow::Result<()> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        if !path.exists() {
            return Ok(());
        }
        let data = tokio::fs::read_to_string(path).await?;
        let loaded: State = serde_json::from_str(&data)?;
        let mut state = self.inner.write().await;
        let live = loaded.tokens.len();
        let consumed = loaded.consumed.len();
        state.tokens = loaded.tokens;
        state.consumed = loaded.consumed;
        tracing::info!(live, consumed, "Loaded persisted join tokens");
        Ok(())
    }

    /// Persist current state to disk. Caller must hold the write lock's data;
    /// this takes a read snapshot internally.
    async fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let state = self.inner.read().await;
        match serde_json::to_string_pretty(&*state) {
            Ok(data) => {
                if let Err(e) = tokio::fs::write(path, data).await {
                    tracing::warn!(error = %e, "Failed to persist join tokens");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize join tokens");
            }
        }
    }

    /// Register a new unbound join token.
    pub async fn register(&self, token: &str) {
        self.register_bound(token, None).await;
    }

    /// Register a join token bound to a specific node ID. Attestation with any
    /// other node_id will be rejected.
    pub async fn register_bound(&self, token: &str, bound_node_id: Option<String>) {
        {
            let mut state = self.inner.write().await;
            state.tokens.insert(
                token.to_string(),
                TokenEntry {
                    bound_node_id,
                    created_at: now_epoch(),
                },
            );
        }
        tracing::info!("Join token registered");
        self.persist().await;
    }

    /// Remove tokens older than `max_age_secs`. Returns the number removed.
    pub async fn expire_old(&self, max_age_secs: u64) -> usize {
        let cutoff = now_epoch().saturating_sub(max_age_secs);
        let removed = {
            let mut state = self.inner.write().await;
            let before = state.tokens.len();
            state.tokens.retain(|_, entry| entry.created_at >= cutoff);
            before - state.tokens.len()
        };
        if removed > 0 {
            tracing::info!(removed, "Expired stale join tokens");
            self.persist().await;
        }
        removed
    }

    /// Attempt to consume a join token for `node_id`. Returns Ok if valid, Err
    /// if unknown, already used, bound to a different node, or rate limited.
    async fn consume(&self, token: &str, node_id: &str) -> Result<(), AttestationError> {
        let now = now_epoch();
        let mut state = self.inner.write().await;

        // Rate limit: prune the failure window, then reject if over threshold.
        let window_start = now.saturating_sub(RATE_LIMIT_WINDOW_SECS);
        state.failures.retain(|&t| t >= window_start);
        if state.failures.len() as u32 >= RATE_LIMIT_MAX_FAILURES {
            tracing::warn!(
                failures = state.failures.len(),
                "Join token attestation rate limit exceeded"
            );
            return Err(AttestationError::Failed(
                "too many failed attestation attempts; try again later".into(),
            ));
        }

        // Detect replay of an already-consumed token via the audit trail.
        if state.consumed.contains_key(token) {
            state.failures.push(now);
            drop(state);
            self.persist().await;
            return Err(AttestationError::Failed(
                "join token already consumed".into(),
            ));
        }

        let Some(entry) = state.tokens.get(token) else {
            state.failures.push(now);
            drop(state);
            self.persist().await;
            return Err(AttestationError::Failed(
                "unknown or already-used join token".into(),
            ));
        };

        // Enforce node binding if present.
        if let Some(bound) = &entry.bound_node_id
            && bound != node_id
        {
            tracing::warn!(
                expected = %bound,
                actual = %node_id,
                "Join token presented with mismatched bound node_id"
            );
            state.failures.push(now);
            drop(state);
            self.persist().await;
            return Err(AttestationError::Failed(
                "join token is bound to a different node".into(),
            ));
        }

        state.tokens.remove(token);
        state.consumed.insert(
            token.to_string(),
            ConsumedRecord {
                node_id: node_id.to_string(),
                consumed_at: now,
            },
        );
        drop(state);
        tracing::info!("Join token consumed (one-time use)");
        self.persist().await;
        Ok(())
    }

    /// Check how many live tokens are registered (for diagnostics).
    pub async fn count(&self) -> usize {
        self.inner.read().await.tokens.len()
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Validate a join token attestation request.
///
/// The `attestation_data` is the raw token bytes. On success, returns an
/// `AttestationResult` with the node_id and selectors describing how the node
/// was attested (attestation type, token binding, consumption time).
pub async fn attest(
    store: &JoinTokenStore,
    attestation_data: &[u8],
    node_id: &str,
) -> Result<AttestationResult, AttestationError> {
    let token = String::from_utf8(attestation_data.to_vec())
        .map_err(|_| AttestationError::InvalidData("token must be valid UTF-8".into()))?;

    if token.is_empty() {
        return Err(AttestationError::InvalidData("empty token".into()));
    }

    // Capture whether the token is bound before consuming (consume removes it).
    let was_bound = {
        let state = store.inner.read().await;
        state
            .tokens
            .get(&token)
            .map(|e| e.bound_node_id.is_some())
            .unwrap_or(false)
    };

    store.consume(&token, node_id).await?;

    let mut selectors = vec![
        ("attestation_type".to_string(), "join_token".to_string()),
        ("join_token:bound".to_string(), was_bound.to_string()),
    ];
    selectors.push(("node_id".to_string(), node_id.to_string()));

    Ok(AttestationResult {
        node_id: node_id.to_string(),
        selectors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn valid_token_consumed_once() {
        let store = JoinTokenStore::new();
        store.register("abc123").await;

        assert_eq!(store.count().await, 1);

        let result = attest(&store, b"abc123", "node-1").await;
        assert!(result.is_ok());

        // Token should be consumed
        assert_eq!(store.count().await, 0);

        // Replay should fail
        let replay = attest(&store, b"abc123", "node-1").await;
        assert!(matches!(replay, Err(AttestationError::Failed(_))));
    }

    #[tokio::test]
    async fn unknown_token_rejected() {
        let store = JoinTokenStore::new();

        let result = attest(&store, b"nonexistent", "node-1").await;
        assert!(matches!(result, Err(AttestationError::Failed(_))));
    }

    #[tokio::test]
    async fn empty_token_rejected() {
        let store = JoinTokenStore::new();

        let result = attest(&store, b"", "node-1").await;
        assert!(matches!(result, Err(AttestationError::InvalidData(_))));
    }

    #[tokio::test]
    async fn multiple_tokens_independent() {
        let store = JoinTokenStore::new();
        store.register("token-a").await;
        store.register("token-b").await;

        assert_eq!(store.count().await, 2);

        // Consume token-a
        attest(&store, b"token-a", "node-a").await.unwrap();
        assert_eq!(store.count().await, 1);

        // token-b should still work
        attest(&store, b"token-b", "node-b").await.unwrap();
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn attestation_result_has_correct_node_id_and_selectors() {
        let store = JoinTokenStore::new();
        store.register("test-token").await;

        let result = attest(&store, b"test-token", "my-node-uuid").await.unwrap();
        assert_eq!(result.node_id, "my-node-uuid");
        assert!(
            result
                .selectors
                .contains(&("attestation_type".to_string(), "join_token".to_string()))
        );
        assert!(
            result
                .selectors
                .contains(&("join_token:bound".to_string(), "false".to_string()))
        );
        assert!(
            result
                .selectors
                .contains(&("node_id".to_string(), "my-node-uuid".to_string()))
        );
    }

    #[tokio::test]
    async fn bound_token_rejects_mismatched_node() {
        let store = JoinTokenStore::new();
        store
            .register_bound("bound-tok", Some("node-expected".to_string()))
            .await;

        // Wrong node_id is rejected and the token is NOT consumed.
        let wrong = attest(&store, b"bound-tok", "node-attacker").await;
        assert!(matches!(wrong, Err(AttestationError::Failed(_))));
        assert_eq!(store.count().await, 1);

        // Correct node_id succeeds and marks the binding in selectors.
        let ok = attest(&store, b"bound-tok", "node-expected").await.unwrap();
        assert!(
            ok.selectors
                .contains(&("join_token:bound".to_string(), "true".to_string()))
        );
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn consumed_token_replay_rejected_via_audit() {
        let store = JoinTokenStore::new();
        store.register("once").await;
        attest(&store, b"once", "node-1").await.unwrap();

        // The audit trail must reject a replay even though the live token map
        // no longer contains it.
        let replay = attest(&store, b"once", "node-1").await;
        assert!(matches!(replay, Err(AttestationError::Failed(_))));
    }

    #[tokio::test]
    async fn rate_limit_blocks_after_too_many_failures() {
        let store = JoinTokenStore::new();

        // Exhaust the failure budget with unknown tokens.
        for _ in 0..RATE_LIMIT_MAX_FAILURES {
            let _ = attest(&store, b"nope", "node-1").await;
        }

        // A valid token now also gets rejected due to rate limiting.
        store.register("valid").await;
        let blocked = attest(&store, b"valid", "node-1").await;
        assert!(matches!(blocked, Err(AttestationError::Failed(_))));
        // Token was not consumed because the request was rate limited.
        assert_eq!(store.count().await, 1);
    }

    #[tokio::test]
    async fn expire_old_removes_stale_tokens() {
        let store = JoinTokenStore::new();
        store.register("fresh-token").await;

        // With a large max_age, nothing should expire
        let removed = store.expire_old(3600).await;
        assert_eq!(removed, 0);
        assert_eq!(store.count().await, 1);

        // Manually insert a token with an old created_at to simulate aging
        {
            let mut state = store.inner.write().await;
            state.tokens.insert(
                "old-token".to_string(),
                TokenEntry {
                    bound_node_id: None,
                    created_at: 1000, // epoch second 1000 — very old
                },
            );
        }
        assert_eq!(store.count().await, 2);

        // Expire tokens older than 1 hour — only old-token should be removed
        let removed = store.expire_old(3600).await;
        assert_eq!(removed, 1);
        assert_eq!(store.count().await, 1);

        // The fresh token should still be consumable
        attest(&store, b"fresh-token", "node-1").await.unwrap();
    }

    #[tokio::test]
    async fn expire_old_preserves_fresh_tokens() {
        let store = JoinTokenStore::new();
        store.register("token-a").await;
        store.register("token-b").await;

        // Both tokens just created — nothing should expire with 1h TTL
        let removed = store.expire_old(3600).await;
        assert_eq!(removed, 0);
        assert_eq!(store.count().await, 2);
    }

    #[tokio::test]
    async fn persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = JoinTokenStore::with_persistence(dir.path());
        store.register("live-tok").await;
        store
            .register_bound("bound-tok", Some("node-x".to_string()))
            .await;
        attest(&store, b"live-tok", "node-1").await.unwrap();

        // Reload from disk: bound-tok should still be live, live-tok in audit.
        let store2 = JoinTokenStore::with_persistence(dir.path());
        store2.load().await.unwrap();
        assert_eq!(store2.count().await, 1);

        // Replaying the consumed token must fail via the loaded audit trail.
        let replay = attest(&store2, b"live-tok", "node-1").await;
        assert!(matches!(replay, Err(AttestationError::Failed(_))));

        // The surviving bound token still enforces its binding.
        let wrong = attest(&store2, b"bound-tok", "node-y").await;
        assert!(matches!(wrong, Err(AttestationError::Failed(_))));
        attest(&store2, b"bound-tok", "node-x").await.unwrap();
    }
}
