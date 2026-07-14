use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::{AttestationError, AttestationResult};

/// Server-side store for one-time join tokens.
///
/// Tokens are registered via `ekafleet token create --type agent` and consumed
/// exactly once during node attestation. After successful attestation, the
/// token is deleted and cannot be replayed.
#[derive(Clone)]
pub struct JoinTokenStore {
    inner: Arc<RwLock<HashMap<String, TokenEntry>>>,
}

struct TokenEntry {
    /// Optional node ID to bind the token to a specific node.
    /// If None, the attestor will use the node_id from the CSR CN.
    _bound_node_id: Option<String>,
    /// When this token was registered (epoch seconds).
    created_at: u64,
}

impl Default for JoinTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl JoinTokenStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new join token. Returns the token string.
    pub async fn register(&self, token: &str) {
        let mut tokens = self.inner.write().await;
        tokens.insert(
            token.to_string(),
            TokenEntry {
                _bound_node_id: None,
                created_at: now_epoch(),
            },
        );
        tracing::info!("Join token registered");
    }

    /// Remove tokens older than `max_age_secs`. Returns the number removed.
    pub async fn expire_old(&self, max_age_secs: u64) -> usize {
        let cutoff = now_epoch().saturating_sub(max_age_secs);
        let mut tokens = self.inner.write().await;
        let before = tokens.len();
        tokens.retain(|_, entry| entry.created_at >= cutoff);
        let removed = before - tokens.len();
        if removed > 0 {
            tracing::info!(removed, "Expired stale join tokens");
        }
        removed
    }

    /// Attempt to consume a join token. Returns Ok if valid, Err if unknown or already used.
    pub async fn consume(&self, token: &str) -> Result<(), AttestationError> {
        let mut tokens = self.inner.write().await;
        if tokens.remove(token).is_some() {
            tracing::info!("Join token consumed (one-time use)");
            Ok(())
        } else {
            Err(AttestationError::Failed(
                "unknown or already-used join token".into(),
            ))
        }
    }

    /// Check how many tokens are registered (for diagnostics).
    pub async fn count(&self) -> usize {
        self.inner.read().await.len()
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
/// The `attestation_data` is the raw token bytes. On success, returns
/// an `AttestationResult` with the node_id derived from the CSR.
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

    store.consume(&token).await?;

    Ok(AttestationResult {
        node_id: node_id.to_string(),
        selectors: vec![("attestation_type".to_string(), "join_token".to_string())],
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
    async fn attestation_result_has_correct_node_id() {
        let store = JoinTokenStore::new();
        store.register("test-token").await;

        let result = attest(&store, b"test-token", "my-node-uuid").await.unwrap();
        assert_eq!(result.node_id, "my-node-uuid");
        assert!(
            result
                .selectors
                .contains(&("attestation_type".to_string(), "join_token".to_string()))
        );
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
            let mut tokens = store.inner.write().await;
            tokens.insert(
                "old-token".to_string(),
                TokenEntry {
                    _bound_node_id: None,
                    created_at: 1000, // epoch second 1000 — very old
                },
            );
        }
        assert_eq!(store.count().await, 2);

        // Expire tokens older than 1 hour — only old-token should be removed
        let removed = store.expire_old(3600).await;
        assert_eq!(removed, 1);
        assert_eq!(store.count().await, 1);

        // The fresh token should still be there
        store.consume("fresh-token").await.unwrap();
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
}
