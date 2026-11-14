//! One-time join tokens for node attestation.
//!
//! An operator (or the cloud actuator) creates a token for a specific node
//! name with `ekafleet token create --type agent --node <name>`. The new
//! node presents it once, together with a CSR, to `FleetBootstrap.Attest`
//! and receives the node SVID `spiffe://<domain>/agent/<name>`. The token
//! is the only credential on that call, so it is:
//!
//! - 256 bits from the system RNG, and stored only as its SHA-256 hash
//!   (a leaked `join_tokens.json` reveals no usable token);
//! - bound to one node name: presenting it for any other name fails and
//!   leaves it unconsumed;
//! - short-lived (default [`DEFAULT_TTL`], at most [`MAX_TTL`]);
//! - consumed on first use, with a consumption record kept until the token
//!   would have expired anyway, so replays are reported as such;
//! - guarded by a per-source failure rate limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use super::{AttestationError, AttestationResult};

/// Lifetime of a join token when none is requested.
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);
/// Longest lifetime a join token may be given.
pub const MAX_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Failed attempts allowed per source address within `RATE_LIMIT_WINDOW_SECS`.
const RATE_LIMIT_MAX_FAILURES: usize = 20;
/// Sliding window (seconds) over which failed attempts are counted.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Bound on the number of source addresses tracked for rate limiting.
const RATE_LIMIT_MAX_SOURCES: usize = 4096;

#[derive(Clone)]
pub struct JoinTokenStore {
    inner: Arc<RwLock<State>>,
    persist_path: Option<PathBuf>,
    /// Serializes writes of the persisted file.
    persist_lock: Arc<Mutex<()>>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Live tokens keyed by the hex SHA-256 of the token.
    tokens: HashMap<String, TokenEntry>,
    /// Consumed tokens (by hash), kept until they would have expired.
    consumed: HashMap<String, ConsumedRecord>,
    /// Recent failure timestamps per source address. Not persisted.
    #[serde(skip)]
    failures: HashMap<Option<IpAddr>, Vec<u64>>,
}

#[derive(Serialize, Deserialize)]
struct TokenEntry {
    /// The only node name this token can attest.
    node_name: String,
    created_at: u64,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct ConsumedRecord {
    node_name: String,
    consumed_at: u64,
    expires_at: u64,
}

impl Default for JoinTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a 256-bit random token as 64 hex characters.
pub fn generate_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .expect("system RNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn token_hash(token: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl JoinTokenStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(State::default())),
            persist_path: None,
            persist_lock: Arc::new(Mutex::new(())),
        }
    }

    /// A store persisted to `join_tokens.json` under `data_dir`.
    pub fn with_persistence(data_dir: &std::path::Path) -> Self {
        Self {
            persist_path: Some(data_dir.join("join_tokens.json")),
            ..Self::new()
        }
    }

    /// Load persisted tokens, if configured and present.
    pub async fn load(&self) -> anyhow::Result<()> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        let data = match tokio::fs::read_to_string(path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let loaded: State = serde_json::from_str(&data)?;
        let mut state = self.inner.write().await;
        state.tokens = loaded.tokens;
        state.consumed = loaded.consumed;
        tracing::info!(
            live = state.tokens.len(),
            consumed = state.consumed.len(),
            "Loaded persisted join tokens"
        );
        Ok(())
    }

    async fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let _guard = self.persist_lock.lock().await;
        let data = {
            let state = self.inner.read().await;
            serde_json::to_vec_pretty(&*state)
        };
        match data {
            Ok(data) => {
                if let Err(e) = crate::fsutil::write_atomic(path, &data, 0o600).await {
                    tracing::warn!(error = %e, "Failed to persist join tokens");
                }
            }
            Err(e) => tracing::warn!(error = %e, "Failed to serialize join tokens"),
        }
    }

    /// Create a token that can attest exactly `node_name` within `ttl`
    /// (default [`DEFAULT_TTL`]). Returns the token and its expiry.
    pub async fn create(
        &self,
        node_name: &str,
        ttl: Option<Duration>,
    ) -> Result<(String, u64), AttestationError> {
        crate::ca::validate_identity_name(node_name)
            .map_err(|e| AttestationError::InvalidData(format!("invalid node name: {e}")))?;
        let ttl = ttl.unwrap_or(DEFAULT_TTL);
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(AttestationError::InvalidData(format!(
                "join token TTL must be between 1s and {}s",
                MAX_TTL.as_secs()
            )));
        }
        let token = generate_token();
        let now = now_epoch();
        let expires_at = now + ttl.as_secs();
        self.inner.write().await.tokens.insert(
            token_hash(&token),
            TokenEntry {
                node_name: node_name.to_string(),
                created_at: now,
                expires_at,
            },
        );
        tracing::info!(node = %node_name, expires_at, "Join token created");
        self.persist().await;
        Ok((token, expires_at))
    }

    /// Drop expired tokens and consumption records. Returns how many live
    /// tokens expired.
    pub async fn expire(&self) -> usize {
        let now = now_epoch();
        let (removed, changed) = {
            let mut state = self.inner.write().await;
            let tokens = state.tokens.len();
            let consumed = state.consumed.len();
            state.tokens.retain(|_, e| e.expires_at > now);
            state.consumed.retain(|_, c| c.expires_at > now);
            let removed = tokens - state.tokens.len();
            (removed, removed > 0 || consumed != state.consumed.len())
        };
        if removed > 0 {
            tracing::info!(removed, "Expired unused join tokens");
        }
        if changed {
            self.persist().await;
        }
        removed
    }

    /// Consume `token` for `node_name`. `source` is the caller's address,
    /// used to rate-limit failures.
    async fn consume(
        &self,
        token: &str,
        node_name: &str,
        source: Option<IpAddr>,
    ) -> Result<(), AttestationError> {
        let now = now_epoch();
        let hash = token_hash(token);
        let mut state = self.inner.write().await;

        let window_start = now.saturating_sub(RATE_LIMIT_WINDOW_SECS);
        if let Some(recent) = state.failures.get_mut(&source) {
            recent.retain(|&t| t >= window_start);
            if recent.len() >= RATE_LIMIT_MAX_FAILURES {
                tracing::warn!(source = ?source, "Join token attestation rate limit exceeded");
                return Err(AttestationError::Failed(
                    "too many failed attestation attempts; try again later".into(),
                ));
            }
        }

        let failure = match state.tokens.get(&hash) {
            _ if state.consumed.contains_key(&hash) => "join token already used",
            None => "unknown join token",
            Some(entry) if entry.expires_at <= now => "join token expired",
            Some(entry) if entry.node_name != node_name => {
                tracing::warn!(
                    bound = %entry.node_name,
                    presented = %node_name,
                    "Join token presented for a different node name"
                );
                "join token is bound to a different node name"
            }
            Some(_) => "",
        };
        if !failure.is_empty() {
            if state.failures.len() >= RATE_LIMIT_MAX_SOURCES {
                state
                    .failures
                    .retain(|_, recent| recent.iter().any(|&t| t >= window_start));
                if state.failures.len() >= RATE_LIMIT_MAX_SOURCES {
                    state.failures.clear();
                }
            }
            state.failures.entry(source).or_default().push(now);
            return Err(AttestationError::Failed(failure.into()));
        }

        let entry = state.tokens.remove(&hash).expect("checked above");
        state.consumed.insert(
            hash,
            ConsumedRecord {
                node_name: node_name.to_string(),
                consumed_at: now,
                expires_at: entry.expires_at,
            },
        );
        drop(state);
        tracing::info!(node = %node_name, "Join token consumed");
        self.persist().await;
        Ok(())
    }

    /// Undo a successful [`attest`] whose SVID could not be issued (e.g. the
    /// CA signer was unreachable), so the node can retry with the same
    /// token. Only a consumed, unexpired token is restored.
    pub async fn release(&self, token: &str) {
        let hash = token_hash(token.trim());
        let restored = {
            let mut state = self.inner.write().await;
            match state.consumed.remove(&hash) {
                Some(record) if record.expires_at > now_epoch() => {
                    state.tokens.insert(
                        hash,
                        TokenEntry {
                            node_name: record.node_name,
                            created_at: record.consumed_at,
                            expires_at: record.expires_at,
                        },
                    );
                    true
                }
                _ => false,
            }
        };
        if restored {
            self.persist().await;
        }
    }

    /// Number of live (unconsumed) tokens.
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

/// Attest `node_name` with the join token in `attestation_data`.
pub async fn attest(
    store: &JoinTokenStore,
    attestation_data: &[u8],
    node_name: &str,
    source: Option<IpAddr>,
) -> Result<AttestationResult, AttestationError> {
    crate::ca::validate_identity_name(node_name)
        .map_err(|e| AttestationError::InvalidData(format!("invalid node name: {e}")))?;
    let token = std::str::from_utf8(attestation_data)
        .map_err(|_| AttestationError::InvalidData("token must be valid UTF-8".into()))?
        .trim();
    if token.is_empty() {
        return Err(AttestationError::InvalidData("empty token".into()));
    }

    store.consume(token, node_name, source).await?;

    Ok(AttestationResult {
        node_id: node_name.to_string(),
        selectors: vec![
            ("attestation_type".to_string(), "join_token".to_string()),
            ("node_name".to_string(), node_name.to_string()),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));

    #[tokio::test]
    async fn token_attests_its_node_once() {
        let store = JoinTokenStore::new();
        let (token, expires_at) = store.create("web-1", None).await.unwrap();
        assert_eq!(token.len(), 64);
        assert!(expires_at > now_epoch());
        assert_eq!(store.count().await, 1);

        let result = attest(&store, token.as_bytes(), "web-1", SRC)
            .await
            .unwrap();
        assert_eq!(result.node_id, "web-1");
        assert_eq!(store.count().await, 0);

        let replay = attest(&store, token.as_bytes(), "web-1", SRC).await;
        assert!(matches!(replay, Err(AttestationError::Failed(e)) if e.contains("already used")));
    }

    #[tokio::test]
    async fn token_is_bound_to_its_node_name() {
        let store = JoinTokenStore::new();
        let (token, _) = store.create("web-1", None).await.unwrap();
        let wrong = attest(&store, token.as_bytes(), "web-2", SRC).await;
        assert!(matches!(wrong, Err(AttestationError::Failed(e)) if e.contains("different node")));
        // A mismatch does not burn the token for its rightful node.
        attest(&store, token.as_bytes(), "web-1", SRC)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invalid_input_is_rejected() {
        let store = JoinTokenStore::new();
        assert!(matches!(
            attest(&store, b"", "web-1", SRC).await,
            Err(AttestationError::InvalidData(_))
        ));
        assert!(matches!(
            attest(&store, b"nope", "web-1", SRC).await,
            Err(AttestationError::Failed(_))
        ));
        for bad in ["", "../server/x", "a/b"] {
            assert!(store.create(bad, None).await.is_err(), "{bad:?}");
            assert!(matches!(
                attest(&store, b"tok", bad, SRC).await,
                Err(AttestationError::InvalidData(_))
            ));
        }
        assert!(store.create("web-1", Some(Duration::ZERO)).await.is_err());
        assert!(
            store
                .create("web-1", Some(MAX_TTL + Duration::from_secs(1)))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn expired_tokens_are_refused_and_dropped() {
        let store = JoinTokenStore::new();
        let (token, _) = store.create("web-1", None).await.unwrap();
        let (fresh, _) = store.create("web-2", None).await.unwrap();
        store
            .inner
            .write()
            .await
            .tokens
            .get_mut(&token_hash(&token))
            .unwrap()
            .expires_at = now_epoch() - 1;

        let expired = attest(&store, token.as_bytes(), "web-1", SRC).await;
        assert!(matches!(expired, Err(AttestationError::Failed(e)) if e.contains("expired")));
        assert_eq!(store.expire().await, 1);
        assert_eq!(store.count().await, 1);
        attest(&store, fresh.as_bytes(), "web-2", SRC)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failures_are_rate_limited_per_source() {
        let store = JoinTokenStore::new();
        let other = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)));
        for _ in 0..RATE_LIMIT_MAX_FAILURES {
            let _ = attest(&store, b"nope", "web-1", SRC).await;
        }
        let (token, _) = store.create("web-1", None).await.unwrap();
        let blocked = attest(&store, token.as_bytes(), "web-1", SRC).await;
        assert!(matches!(blocked, Err(AttestationError::Failed(e)) if e.contains("too many")));
        assert_eq!(store.count().await, 1);
        // Another source is unaffected.
        attest(&store, token.as_bytes(), "web-1", other)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn released_token_can_be_retried() {
        let store = JoinTokenStore::new();
        let (token, _) = store.create("web-1", None).await.unwrap();
        attest(&store, token.as_bytes(), "web-1", SRC)
            .await
            .unwrap();
        store.release(&token).await;
        assert_eq!(store.count().await, 1);
        attest(&store, token.as_bytes(), "web-1", SRC)
            .await
            .unwrap();
        // Releasing an unknown token is a no-op.
        store.release("unknown").await;
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn persisted_file_holds_hashes_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = JoinTokenStore::with_persistence(dir.path());
        let (used, _) = store.create("web-1", None).await.unwrap();
        let (live, _) = store.create("web-2", None).await.unwrap();
        attest(&store, used.as_bytes(), "web-1", SRC).await.unwrap();

        let path = dir.path().join("join_tokens.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(&used) && !raw.contains(&live));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let reloaded = JoinTokenStore::with_persistence(dir.path());
        reloaded.load().await.unwrap();
        assert_eq!(reloaded.count().await, 1);
        let replay = attest(&reloaded, used.as_bytes(), "web-1", SRC).await;
        assert!(matches!(replay, Err(AttestationError::Failed(e)) if e.contains("already used")));
        attest(&reloaded, live.as_bytes(), "web-2", SRC)
            .await
            .unwrap();
    }
}
