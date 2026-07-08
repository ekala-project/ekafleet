#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

/// Maximum number of events retained in memory.
const MAX_EVENTS: usize = 10_000;

/// Maximum number of deployment history entries per service.
const MAX_DEPLOY_HISTORY: usize = 100;

/// Severity level for fleet events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EventLevel {
    Info,
    Warning,
    Error,
}

/// A fleet event recording a significant cluster action.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FleetEvent {
    pub timestamp: u64,
    pub level: EventLevel,
    pub category: EventCategory,
    pub service: Option<String>,
    pub node: Option<String>,
    pub message: String,
}

/// Category of fleet event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Deployment,
    Scheduling,
    Health,
    Scaling,
    NodeJoin,
    NodeLeave,
    Drain,
    SecretRotation,
    Attestation,
}

/// A deployment history entry for a service.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeployRecord {
    pub deployment_id: String,
    pub service_name: String,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub status: DeployOutcome,
    pub strategy: String,
    pub instance_count: u32,
    pub store_path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeployOutcome {
    InProgress,
    Succeeded,
    Failed,
    RolledBack,
}

/// In-memory event store and deployment history tracker.
#[derive(Clone)]
pub struct EventStore {
    events: Arc<RwLock<VecDeque<FleetEvent>>>,
    deploy_history: Arc<RwLock<VecDeque<DeployRecord>>>,
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_EVENTS))),
            deploy_history: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_DEPLOY_HISTORY))),
        }
    }

    /// Record a fleet event.
    pub async fn emit(&self, level: EventLevel, category: EventCategory, message: &str) {
        self.emit_detail(level, category, None, None, message).await;
    }

    /// Record a fleet event with optional service and node context.
    pub async fn emit_detail(
        &self,
        level: EventLevel,
        category: EventCategory,
        service: Option<&str>,
        node: Option<&str>,
        message: &str,
    ) {
        let event = FleetEvent {
            timestamp: now_epoch(),
            level,
            category,
            service: service.map(String::from),
            node: node.map(String::from),
            message: message.to_string(),
        };

        tracing::debug!(
            category = ?event.category,
            service = ?event.service,
            "Event: {}",
            event.message
        );

        let mut events = self.events.write().await;
        if events.len() >= MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Query events, optionally filtered by category and/or service.
    /// Returns events in reverse chronological order (newest first).
    pub async fn query(
        &self,
        category: Option<EventCategory>,
        service: Option<&str>,
        limit: usize,
    ) -> Vec<FleetEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .rev()
            .filter(|e| {
                category.as_ref().is_none_or(|c| e.category == *c)
                    && service.is_none_or(|s| e.service.as_deref() == Some(s))
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Record the start of a deployment.
    pub async fn record_deploy_start(
        &self,
        deployment_id: &str,
        service_name: &str,
        strategy: &str,
        instance_count: u32,
        store_path: &str,
    ) {
        let record = DeployRecord {
            deployment_id: deployment_id.to_string(),
            service_name: service_name.to_string(),
            started_at: now_epoch(),
            completed_at: None,
            status: DeployOutcome::InProgress,
            strategy: strategy.to_string(),
            instance_count,
            store_path: store_path.to_string(),
            message: "deployment started".to_string(),
        };

        self.emit_detail(
            EventLevel::Info,
            EventCategory::Deployment,
            Some(service_name),
            None,
            &format!(
                "Deployment {} started ({} strategy, {} instances)",
                deployment_id, strategy, instance_count
            ),
        )
        .await;

        let mut history = self.deploy_history.write().await;
        if history.len() >= MAX_DEPLOY_HISTORY {
            history.pop_front();
        }
        history.push_back(record);
    }

    /// Record the completion of a deployment.
    pub async fn record_deploy_complete(
        &self,
        deployment_id: &str,
        outcome: DeployOutcome,
        message: &str,
    ) {
        let mut history = self.deploy_history.write().await;
        if let Some(record) = history
            .iter_mut()
            .rev()
            .find(|r| r.deployment_id == deployment_id)
        {
            record.completed_at = Some(now_epoch());
            record.status = outcome;
            record.message = message.to_string();
        }

        let level = match outcome {
            DeployOutcome::Succeeded => EventLevel::Info,
            DeployOutcome::Failed | DeployOutcome::RolledBack => EventLevel::Error,
            DeployOutcome::InProgress => EventLevel::Info,
        };

        // Find the service name for the event
        let service_name = history
            .iter()
            .rev()
            .find(|r| r.deployment_id == deployment_id)
            .map(|r| r.service_name.clone());

        drop(history);

        self.emit_detail(
            level,
            EventCategory::Deployment,
            service_name.as_deref(),
            None,
            &format!("Deployment {deployment_id} {outcome:?}: {message}"),
        )
        .await;
    }

    /// Get deployment history for a specific service (newest first).
    pub async fn deploy_history(&self, service_name: &str, limit: usize) -> Vec<DeployRecord> {
        let history = self.deploy_history.read().await;
        history
            .iter()
            .rev()
            .filter(|r| r.service_name == service_name)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get all deployment history (newest first).
    pub async fn all_deploy_history(&self, limit: usize) -> Vec<DeployRecord> {
        let history = self.deploy_history.read().await;
        history.iter().rev().take(limit).cloned().collect()
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
    async fn emit_and_query() {
        let store = EventStore::new();
        store
            .emit_detail(
                EventLevel::Info,
                EventCategory::NodeJoin,
                None,
                Some("node-1"),
                "node joined",
            )
            .await;
        store
            .emit_detail(
                EventLevel::Warning,
                EventCategory::Health,
                Some("web"),
                Some("node-1"),
                "web unhealthy",
            )
            .await;

        let all = store.query(None, None, 100).await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].message, "web unhealthy"); // newest first

        let health = store.query(Some(EventCategory::Health), None, 100).await;
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].message, "web unhealthy");

        let web = store.query(None, Some("web"), 100).await;
        assert_eq!(web.len(), 1);
    }

    #[tokio::test]
    async fn deploy_lifecycle() {
        let store = EventStore::new();
        store
            .record_deploy_start("d1", "api", "rolling", 3, "/nix/store/xxx")
            .await;
        store
            .record_deploy_complete("d1", DeployOutcome::Succeeded, "all healthy")
            .await;

        let history = store.deploy_history("api", 10).await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, DeployOutcome::Succeeded);
        assert!(history[0].completed_at.is_some());
    }

    #[tokio::test]
    async fn event_limit() {
        let store = EventStore::new();
        for i in 0..5 {
            store
                .emit(
                    EventLevel::Info,
                    EventCategory::Scheduling,
                    &format!("event {i}"),
                )
                .await;
        }

        let limited = store.query(None, None, 2).await;
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].message, "event 4"); // newest
    }
}
