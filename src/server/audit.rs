//! The control-plane audit log.
//!
//! Every audited action, and every refused request (failed authentication
//! or a permission/namespace denial), is appended as one JSON line to
//! `<data dir>/audit/audit.log` (0600, rotated by size) and kept in a
//! bounded in-memory ring for queries; the ring is reloaded from the files
//! at boot. Identical denials from one actor are coalesced: the first in a
//! minute is written at once, the rest are written as one entry carrying
//! their count, so a client hammering a refused RPC cannot flush history
//! out of the ring.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

const MAX_AUDIT_ENTRIES: usize = 50_000;
/// Rotate the log once it reaches this size.
const MAX_FILE_BYTES: u64 = 16 << 20;
/// Rotated files kept (`audit.log.1` is the newest).
const ROTATED_FILES: usize = 5;
/// Identical denials within this many seconds are coalesced.
const DENIAL_WINDOW_SECS: u64 = 60;
/// Most distinct denials tracked for coalescing at once.
const MAX_DENIAL_WINDOWS: usize = 10_000;

/// Structured audit log entry recording a control-plane action.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub actor: String,
    pub action: AuditAction,
    pub resource: String,
    pub detail: String,
    pub outcome: AuditOutcome,
    /// How many identical occurrences this entry stands for.
    #[serde(default = "one")]
    pub count: u64,
}

fn one() -> u64 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Apply,
    Plan,
    Drain,
    Scale,
    Rebalance,
    Rollback,
    TokenCreate,
    TokenRevoke,
    SecretWrite,
    SecretRead,
    VolumeSnapshot,
    VolumeRestore,
    NodeAttest,
    NodeJoin,
    NodeLeave,
    ConfigValidate,
    /// A request whose credentials were missing, invalid or not accepted.
    Authenticate,
    /// An authenticated request refused by RBAC or namespace scope.
    Access,
}

impl std::str::FromStr for AuditAction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .map_err(|_| format!("unknown audit action '{s}'"))
    }
}

impl AuditAction {
    pub fn as_str(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Denied,
    Failed,
}

impl std::str::FromStr for AuditOutcome {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "denied" => Ok(Self::Denied),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("unknown audit outcome '{s}'")),
        }
    }
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// Filters for [`AuditLog::query`].
#[derive(Debug, Default, Clone)]
pub struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<AuditAction>,
    pub outcome: Option<AuditOutcome>,
    pub limit: usize,
}

type DenialKey = (String, AuditAction, String, String);

struct DenialWindow {
    start: u64,
    /// Occurrences after the first, not yet written.
    suppressed: u64,
}

struct FileSink {
    dir: PathBuf,
    file: std::fs::File,
    size: u64,
}

impl FileSink {
    fn path(dir: &Path, index: usize) -> PathBuf {
        if index == 0 {
            dir.join("audit.log")
        } else {
            dir.join(format!("audit.log.{index}"))
        }
    }

    fn open(dir: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        let path = Self::path(dir, 0);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let size = file.metadata()?.len();
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
            size,
        })
    }

    fn append(&mut self, entry: &AuditEntry) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
        line.push(b'\n');
        if self.size > 0 && self.size + line.len() as u64 > MAX_FILE_BYTES {
            self.rotate()?;
        }
        self.file.write_all(&line)?;
        self.size += line.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        for index in (1..ROTATED_FILES).rev() {
            let from = Self::path(&self.dir, index);
            if from.exists() {
                std::fs::rename(&from, Self::path(&self.dir, index + 1))?;
            }
        }
        std::fs::rename(Self::path(&self.dir, 0), Self::path(&self.dir, 1))?;
        *self = Self::open(&self.dir)?;
        Ok(())
    }

    /// Entries of the newest files, oldest first, at most `max`.
    fn load(dir: &Path, max: usize) -> VecDeque<AuditEntry> {
        let mut entries = VecDeque::new();
        for index in [1, 0] {
            let Ok(text) = std::fs::read_to_string(Self::path(dir, index)) else {
                continue;
            };
            for line in text.lines() {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                    if entries.len() == max {
                        entries.pop_front();
                    }
                    entries.push_back(entry);
                }
            }
        }
        entries
    }
}

struct Inner {
    entries: VecDeque<AuditEntry>,
    sink: Option<FileSink>,
    denials: HashMap<DenialKey, DenialWindow>,
}

impl Inner {
    fn push(&mut self, entry: AuditEntry) {
        let level_denied = entry.outcome != AuditOutcome::Success;
        if level_denied {
            tracing::warn!(
                actor = %entry.actor,
                action = ?entry.action,
                resource = %entry.resource,
                outcome = ?entry.outcome,
                count = entry.count,
                "AUDIT: {}",
                entry.detail
            );
        } else {
            tracing::info!(
                actor = %entry.actor,
                action = ?entry.action,
                resource = %entry.resource,
                outcome = ?entry.outcome,
                "AUDIT: {}",
                entry.detail
            );
        }
        if let Some(sink) = &mut self.sink
            && let Err(e) = sink.append(&entry)
        {
            tracing::error!(error = %e, dir = %sink.dir.display(), "Cannot write the audit log");
        }
        if self.entries.len() >= MAX_AUDIT_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Write the counts of denial windows that ended before `now` (all of
    /// them with `all`).
    fn flush_denials(&mut self, now: u64, all: bool) {
        let ended: Vec<DenialKey> = self
            .denials
            .iter()
            .filter(|(_, w)| all || now >= w.start + DENIAL_WINDOW_SECS)
            .map(|(k, _)| k.clone())
            .collect();
        for key in ended {
            if let Some(window) = self.denials.remove(&key)
                && window.suppressed > 0
            {
                self.push(summary(key, window.suppressed, now));
            }
        }
    }
}

fn summary(key: DenialKey, count: u64, now: u64) -> AuditEntry {
    let (actor, action, resource, detail) = key;
    AuditEntry {
        timestamp: now,
        actor,
        action,
        resource,
        detail: format!("{detail} (repeated)"),
        outcome: AuditOutcome::Denied,
        count,
    }
}

/// Append-only audit log for compliance and incident investigation.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<RwLock<Inner>>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    /// An in-memory audit log (tests and `ekafleet dev`).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                entries: VecDeque::new(),
                sink: None,
                denials: HashMap::new(),
            })),
        }
    }

    /// The audit log persisted under `<data_dir>/audit`, loading the
    /// entries written before.
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        let dir = data_dir.join("audit");
        let sink = FileSink::open(&dir)?;
        let entries = FileSink::load(&dir, MAX_AUDIT_ENTRIES);
        tracing::info!(entries = entries.len(), dir = %dir.display(), "Audit log opened");
        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                entries,
                sink: Some(sink),
                denials: HashMap::new(),
            })),
        })
    }

    /// Record an audit event.
    pub async fn record(
        &self,
        actor: &str,
        action: AuditAction,
        resource: &str,
        detail: &str,
        outcome: AuditOutcome,
    ) {
        self.record_at(actor, action, resource, detail, outcome, now_epoch())
            .await;
    }

    async fn record_at(
        &self,
        actor: &str,
        action: AuditAction,
        resource: &str,
        detail: &str,
        outcome: AuditOutcome,
        now: u64,
    ) {
        let mut inner = self.inner.write().await;
        if outcome == AuditOutcome::Denied {
            let key: DenialKey = (
                actor.to_string(),
                action,
                resource.to_string(),
                detail.to_string(),
            );
            if let Some(window) = inner.denials.get_mut(&key) {
                if now < window.start + DENIAL_WINDOW_SECS {
                    window.suppressed += 1;
                    return;
                }
                let suppressed = window.suppressed;
                window.start = now;
                window.suppressed = 0;
                if suppressed > 0 {
                    inner.push(summary(key, suppressed, now));
                }
            } else {
                if inner.denials.len() >= MAX_DENIAL_WINDOWS {
                    inner.flush_denials(now, false);
                    if inner.denials.len() >= MAX_DENIAL_WINDOWS {
                        inner.flush_denials(now, true);
                    }
                }
                inner.denials.insert(
                    key,
                    DenialWindow {
                        start: now,
                        suppressed: 0,
                    },
                );
            }
        }
        inner.push(AuditEntry {
            timestamp: now,
            actor: actor.to_string(),
            action,
            resource: resource.to_string(),
            detail: detail.to_string(),
            outcome,
            count: 1,
        });
    }

    /// Write the counts of coalesced denials whose window ended.
    pub async fn flush(&self) {
        self.inner.write().await.flush_denials(now_epoch(), false);
    }

    /// Entries matching `query`, newest first.
    pub async fn query(&self, query: &AuditQuery) -> Vec<AuditEntry> {
        let inner = self.inner.read().await;
        let limit = if query.limit == 0 { 100 } else { query.limit };
        inner
            .entries
            .iter()
            .rev()
            .filter(|e| query.actor.as_ref().is_none_or(|a| &e.actor == a))
            .filter(|e| query.action.is_none_or(|a| e.action == a))
            .filter(|e| query.outcome.is_none_or(|o| e.outcome == o))
            .take(limit)
            .cloned()
            .collect()
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(action: Option<AuditAction>, outcome: Option<AuditOutcome>) -> AuditQuery {
        AuditQuery {
            action,
            outcome,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn record_and_query() {
        let log = AuditLog::new();
        log.record(
            "admin",
            AuditAction::Apply,
            "api-server",
            "deployed v2",
            AuditOutcome::Success,
        )
        .await;
        log.record(
            "ci-bot",
            AuditAction::Plan,
            "web",
            "dry-run",
            AuditOutcome::Success,
        )
        .await;
        log.record(
            "viewer",
            AuditAction::Scale,
            "api-server",
            "scale to 5",
            AuditOutcome::Denied,
        )
        .await;

        let all = log.query(&AuditQuery::default()).await;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].actor, "viewer"); // newest first

        let applies = log.query(&query(Some(AuditAction::Apply), None)).await;
        assert_eq!(applies.len(), 1);

        let admin = log
            .query(&AuditQuery {
                actor: Some("admin".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(admin.len(), 1);
        let denied = log.query(&query(None, Some(AuditOutcome::Denied))).await;
        assert_eq!(denied.len(), 1);
        assert_eq!("access".parse::<AuditAction>(), Ok(AuditAction::Access));
        assert_eq!(AuditAction::TokenCreate.as_str(), "token_create");
    }

    #[tokio::test]
    async fn repeated_denials_are_coalesced_per_window() {
        let log = AuditLog::new();
        let deny = |at: u64| {
            log.record_at(
                "token:abc",
                AuditAction::Access,
                "/fleet.FleetControl/Apply",
                "Viewer role does not have Deploy permission",
                AuditOutcome::Denied,
                at,
            )
        };
        for at in [100, 101, 102, 150] {
            deny(at).await;
        }
        // Only the first is written inside the window.
        assert_eq!(log.query(&AuditQuery::default()).await.len(), 1);
        // The next one after the window writes the count, then itself.
        deny(170).await;
        let entries = log.query(&AuditQuery::default()).await;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].count, 3);
        assert!(entries[1].detail.ends_with("(repeated)"));
        assert_eq!(entries[0].count, 1);

        // Flushing writes counts of windows that ended.
        deny(171).await;
        log.inner.write().await.flush_denials(229, false);
        assert_eq!(log.query(&AuditQuery::default()).await.len(), 3);
        log.inner.write().await.flush_denials(230, false);
        let entries = log.query(&AuditQuery::default()).await;
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].count, 1);
    }

    #[tokio::test]
    async fn entries_persist_across_restarts_and_rotate() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.record(
            "admin",
            AuditAction::Apply,
            "fleet",
            "revision 1",
            AuditOutcome::Success,
        )
        .await;
        log.record(
            "anonymous",
            AuditAction::Authenticate,
            "/fleet.FleetControl/Status",
            "missing token",
            AuditOutcome::Denied,
        )
        .await;
        drop(log);

        let path = dir.path().join("audit/audit.log");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let reopened = AuditLog::open(dir.path()).unwrap();
        let entries = reopened.query(&AuditQuery::default()).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, AuditAction::Authenticate);

        // Rotation keeps the newest files.
        {
            let mut inner = reopened.inner.write().await;
            let sink = inner.sink.as_mut().unwrap();
            for _ in 0..ROTATED_FILES + 2 {
                sink.rotate().unwrap();
            }
        }
        assert!(dir.path().join("audit/audit.log.1").exists());
        assert!(
            dir.path()
                .join(format!("audit/audit.log.{ROTATED_FILES}"))
                .exists()
        );
        assert!(
            !dir.path()
                .join(format!("audit/audit.log.{}", ROTATED_FILES + 1))
                .exists()
        );
    }
}
