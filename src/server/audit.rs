#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

const MAX_AUDIT_ENTRIES: usize = 50_000;

/// Structured audit log entry recording a control-plane action.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub actor: String,
    pub action: AuditAction,
    pub resource: String,
    pub detail: String,
    pub outcome: AuditOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Apply,
    Plan,
    Drain,
    Scale,
    Rollback,
    TokenCreate,
    TokenRevoke,
    SecretWrite,
    SecretRead,
    NodeAttest,
    NodeJoin,
    NodeLeave,
    ConfigValidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Denied,
    Failed,
}

/// Append-only audit log for compliance and incident investigation.
#[derive(Clone)]
pub struct AuditLog {
    entries: Arc<RwLock<VecDeque<AuditEntry>>>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_AUDIT_ENTRIES))),
        }
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
        let entry = AuditEntry {
            timestamp: now_epoch(),
            actor: actor.to_string(),
            action,
            resource: resource.to_string(),
            detail: detail.to_string(),
            outcome,
        };

        tracing::info!(
            actor = %entry.actor,
            action = ?entry.action,
            resource = %entry.resource,
            outcome = ?entry.outcome,
            "AUDIT: {}",
            entry.detail
        );

        let mut entries = self.entries.write().await;
        if entries.len() >= MAX_AUDIT_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Query audit entries with optional filters. Returns newest first.
    pub async fn query(
        &self,
        actor: Option<&str>,
        action: Option<AuditAction>,
        limit: usize,
    ) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .rev()
            .filter(|e| actor.is_none_or(|a| e.actor == a))
            .filter(|e| action.is_none_or(|a| e.action == a))
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

        let all = log.query(None, None, 100).await;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].actor, "viewer"); // newest first

        let applies = log.query(None, Some(AuditAction::Apply), 100).await;
        assert_eq!(applies.len(), 1);

        let admin = log.query(Some("admin"), None, 100).await;
        assert_eq!(admin.len(), 1);
    }
}
