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
//!
//! On a server the tokens are kept in the replicated fleet state
//! ([`JoinTokenStore::with_replication`]), so a token created on one server
//! is accepted, and consumed once, cluster-wide. Failure counts stay local.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use super::{AttestationError, AttestationResult};
use crate::raft::state::{Command, FleetStateMachine};

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
    /// Where the tokens live when replicated (then `inner` keeps only the
    /// failure counts).
    replicated: Option<FleetStateMachine>,
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
            replicated: None,
        }
    }

    /// Keep the tokens in `state`, replicated to every server.
    pub fn with_replication(mut self, state: FleetStateMachine) -> Self {
        self.replicated = Some(state);
        self
    }

    /// Move the tokens loaded from a pre-replication `join_tokens.json` into
    /// the replicated state and remove the file. Call on the leader.
    pub async fn migrate_to_replicated(&self) -> Result<usize, crate::raft::RaftError> {
        let (Some(state), Some(path)) = (&self.replicated, &self.persist_path) else {
            return Ok(0);
        };
        let (tokens, consumed) = {
            let mut local = self.inner.write().await;
            (
                std::mem::take(&mut local.tokens),
                std::mem::take(&mut local.consumed),
            )
        };
        let count = tokens.len() + consumed.len();
        for (hash, entry) in tokens {
            state
                .apply_next(Command::JoinTokenPut {
                    hash,
                    node_name: entry.node_name,
                    expires_at: entry.expires_at,
                })
                .await?;
        }
        for (hash, record) in consumed {
            state
                .apply_next(Command::JoinTokenPut {
                    hash: hash.clone(),
                    node_name: record.node_name,
                    expires_at: record.expires_at,
                })
                .await?;
            state.apply_next(Command::JoinTokenConsume { hash }).await?;
        }
        match tokio::fs::remove_file(path).await {
            Ok(()) => tracing::info!(count, "Moved join tokens from join_tokens.json into Raft"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, "Could not remove the migrated join_tokens.json"),
        }
        Ok(count)
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
        if self.replicated.is_some() {
            return;
        }
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
        if let Some(state) = &self.replicated {
            state
                .apply_next(Command::JoinTokenPut {
                    hash: token_hash(&token),
                    node_name: node_name.to_string(),
                    expires_at,
                })
                .await
                .map_err(|e| {
                    AttestationError::Failed(format!("could not record the join token: {e}"))
                })?;
            tracing::info!(node = %node_name, expires_at, "Join token created");
            return Ok((token, expires_at));
        }
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
        if let Some(state) = &self.replicated {
            let tokens = state.join_tokens().await;
            let removed = tokens
                .values()
                .filter(|t| t.expires_at <= now && t.consumed_at.is_none())
                .count();
            let stale = tokens.values().any(|t| t.expires_at <= now)
                || state.acl_tokens().values().any(|t| t.expired_at(now));
            if !stale {
                return 0;
            }
            return match state.apply_next(Command::ExpireTokens).await {
                Ok(_) => {
                    if removed > 0 {
                        tracing::info!(removed, "Expired unused join tokens");
                    }
                    removed
                }
                // The leader expires them.
                Err(crate::raft::RaftError::NotLeader { .. }) => 0,
                Err(e) => {
                    tracing::warn!(error = %e, "Could not expire tokens");
                    0
                }
            };
        }
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

        let verdict = match &self.replicated {
            Some(replicated) => {
                // Not held across the commit: only failure counts live here.
                drop(state);
                let verdict = replicated
                    .consume_join_token(&hash, |record| {
                        check(
                            record.map(|r| (r.consumed_at.is_some(), &*r.node_name, r.expires_at)),
                            node_name,
                            now,
                        )
                    })
                    .await
                    .map_err(|e| {
                        AttestationError::Failed(format!("could not record the join token: {e}"))
                    })?;
                state = self.inner.write().await;
                if verdict.is_ok() {
                    drop(state);
                    tracing::info!(node = %node_name, "Join token consumed");
                    return Ok(());
                }
                verdict
            }
            None => check(
                state
                    .tokens
                    .get(&hash)
                    .map(|e| (false, &*e.node_name, e.expires_at))
                    .or_else(|| {
                        state
                            .consumed
                            .get(&hash)
                            .map(|c| (true, &*c.node_name, c.expires_at))
                    }),
                node_name,
                now,
            ),
        };
        if let Err(failure) = verdict {
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
        if let Some(state) = &self.replicated {
            let usable = state
                .join_token(&hash)
                .await
                .is_some_and(|t| t.consumed_at.is_some() && t.expires_at > now_epoch());
            if usable && let Err(e) = state.apply_next(Command::JoinTokenRelease { hash }).await {
                tracing::warn!(error = %e, "Could not release the join token");
            }
            return;
        }
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
        match &self.replicated {
            Some(state) => state
                .join_tokens()
                .await
                .values()
                .filter(|t| t.consumed_at.is_none())
                .count(),
            None => self.inner.read().await.tokens.len(),
        }
    }
}

/// Whether a token found as `(consumed, bound node name, expiry)` attests
/// `node_name` at `now`, or why not.
fn check(token: Option<(bool, &str, u64)>, node_name: &str, now: u64) -> Result<(), &'static str> {
    match token {
        Some((true, ..)) => Err("join token already used"),
        None => Err("unknown join token"),
        Some((_, _, expires_at)) if expires_at <= now => Err("join token expired"),
        Some((_, bound, _)) if bound != node_name => {
            tracing::warn!(
                bound = %bound,
                presented = %node_name,
                "Join token presented for a different node name"
            );
            Err("join token is bound to a different node name")
        }
        Some(_) => Ok(()),
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
    async fn replicated_tokens_are_consumed_once_cluster_wide() {
        use crate::raft::consensus::testing::{Router, node};
        use openraft::BasicNode;
        use std::collections::BTreeMap;

        let dir = tempfile::tempdir().unwrap();
        let router = Router::default();
        let mut nodes = Vec::new();
        for id in 1..=2u64 {
            let (raft, state) = node(&router, id, dir.path().join(id.to_string()).as_path()).await;
            state.attach(raft.clone());
            nodes.push((raft, state));
        }
        nodes[0]
            .0
            .initialize(BTreeMap::from([
                (1, BasicNode::new("s1:7400")),
                (2, BasicNode::new("s2:7400")),
            ]))
            .await
            .unwrap();
        nodes[0]
            .0
            .wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader == Some(1), "leader")
            .await
            .unwrap();

        // Tokens from a join_tokens.json written before replication move in.
        let legacy = JoinTokenStore::with_persistence(dir.path());
        let (old_used, _) = legacy.create("old-1", None).await.unwrap();
        let (old_live, _) = legacy.create("old-2", None).await.unwrap();
        attest(&legacy, old_used.as_bytes(), "old-1", SRC)
            .await
            .unwrap();
        let leader =
            JoinTokenStore::with_persistence(dir.path()).with_replication(nodes[0].1.clone());
        leader.load().await.unwrap();
        assert_eq!(leader.migrate_to_replicated().await.unwrap(), 2);
        assert!(!dir.path().join("join_tokens.json").exists());

        let (token, _) = leader.create("web-1", None).await.unwrap();
        assert_eq!(leader.count().await, 2);
        // Consumed through the leader once; then refused everywhere.
        attest(&leader, token.as_bytes(), "web-1", SRC)
            .await
            .unwrap();
        let follower = JoinTokenStore::new().with_replication(nodes[1].1.clone());
        let mut replay = Ok(());
        for _ in 0..100 {
            replay = follower
                .replicated
                .as_ref()
                .unwrap()
                .join_token(&token_hash(&token))
                .await
                .and_then(|t| t.consumed_at)
                .map_or(Ok(()), |_| Err(()));
            if replay.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(replay.is_err(), "consumption replicated");
        let again = attest(&leader, token.as_bytes(), "web-1", SRC).await;
        assert!(matches!(again, Err(AttestationError::Failed(e)) if e.contains("already used")));
        let replayed = attest(&leader, old_used.as_bytes(), "old-1", SRC).await;
        assert!(matches!(replayed, Err(AttestationError::Failed(e)) if e.contains("already used")));
        let wrong = attest(&leader, old_live.as_bytes(), "web-9", SRC).await;
        assert!(matches!(wrong, Err(AttestationError::Failed(e)) if e.contains("different node")));

        // Released after a failed issuance: usable again.
        leader.release(&token).await;
        attest(&leader, token.as_bytes(), "web-1", SRC)
            .await
            .unwrap();
        // A follower cannot consume: it would race the leader.
        let refused = attest(&follower, old_live.as_bytes(), "old-2", SRC).await;
        assert!(matches!(refused, Err(AttestationError::Failed(e)) if e.contains("leader")));
        assert_eq!(follower.expire().await, 0);
        for (raft, _) in nodes {
            raft.shutdown().await.unwrap();
        }
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
