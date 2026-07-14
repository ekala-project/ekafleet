#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::raft::state::{Command, FleetStateMachine, TrackedCloudInstance};

/// Tracks cloud-provisioned machine instances and their association with
/// fleet agent node IDs. Backed by Raft state for persistence.
#[derive(Clone)]
pub struct InstanceTracker {
    raft: FleetStateMachine,
    /// Monotonically increasing index for Raft commands.
    next_index: Arc<RwLock<u64>>,
}

impl InstanceTracker {
    pub fn new(raft: FleetStateMachine) -> Self {
        Self {
            raft,
            next_index: Arc::new(RwLock::new(1_000_000)), // Start high to avoid collisions
        }
    }

    async fn next_index(&self) -> u64 {
        let mut idx = self.next_index.write().await;
        *idx += 1;
        *idx
    }

    /// Record a newly created cloud instance.
    pub async fn track(
        &self,
        instance_id: &str,
        provider: &str,
        pool: &str,
        private_ip: Option<&str>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let index = self.next_index().await;
        self.raft
            .apply(
                index,
                Command::TrackCloudInstance {
                    instance_id: instance_id.to_string(),
                    provider: provider.to_string(),
                    pool: pool.to_string(),
                    private_ip: private_ip.map(|s| s.to_string()),
                    created_at: now,
                },
            )
            .await;

        tracing::info!(instance_id, provider, pool, "Tracking cloud instance");
    }

    /// Associate a cloud instance with a fleet node ID (when the agent joins).
    pub async fn associate_node(&self, instance_id: &str, fleet_node_id: &str) {
        let index = self.next_index().await;
        self.raft
            .apply(
                index,
                Command::UpdateCloudInstance {
                    instance_id: instance_id.to_string(),
                    fleet_node_id: fleet_node_id.to_string(),
                },
            )
            .await;

        tracing::info!(
            instance_id,
            fleet_node_id,
            "Associated cloud instance with fleet node"
        );
    }

    /// Stop tracking a cloud instance (after termination).
    pub async fn untrack(&self, instance_id: &str) {
        let index = self.next_index().await;
        self.raft
            .apply(
                index,
                Command::UntrackCloudInstance {
                    instance_id: instance_id.to_string(),
                },
            )
            .await;

        tracing::info!(instance_id, "Untracked cloud instance");
    }

    /// Get all tracked instances.
    pub async fn all(&self) -> HashMap<String, TrackedCloudInstance> {
        self.raft.cloud_instances().await
    }

    /// Get tracked instances for a specific pool.
    pub async fn for_pool(&self, pool: &str) -> Vec<TrackedCloudInstance> {
        self.raft.cloud_instances_for_pool(pool).await
    }

    /// Find a tracked instance by its private IP address.
    /// Used to correlate an agent's source address with a cloud instance.
    pub async fn find_by_ip(&self, ip: &str) -> Option<TrackedCloudInstance> {
        self.raft.cloud_instance_by_ip(ip).await
    }

    /// Count of cloud-provisioned machines currently tracked for a pool,
    /// excluding terminated ones.
    pub async fn active_count_for_pool(&self, pool: &str) -> u32 {
        self.for_pool(pool).await.len() as u32
    }

    /// Get the fleet node IDs of all cloud-provisioned machines in a pool.
    /// Only includes instances that have joined the fleet.
    pub async fn joined_node_ids_for_pool(&self, pool: &str) -> Vec<String> {
        self.for_pool(pool)
            .await
            .into_iter()
            .filter_map(|i| i.fleet_node_id)
            .collect()
    }

    /// Select the best candidate for scale-down in a pool.
    /// Priority:
    /// 1. Un-joined instances (they're not serving anything)
    /// 2. Among joined instances, prefer those with fewest running services
    /// 3. Among equal service counts, prefer newest (most recently created)
    pub async fn select_scaledown_candidate(
        &self,
        pool: &str,
        fleet_state: &crate::server::state::FleetState,
    ) -> Option<TrackedCloudInstance> {
        let instances = self.for_pool(pool).await;
        if instances.is_empty() {
            return None;
        }

        // Prefer un-joined instances (they're not serving anything)
        let unjoined: Vec<_> = instances
            .iter()
            .filter(|i| i.fleet_node_id.is_none())
            .collect();
        if let Some(inst) = unjoined.first() {
            return Some((*inst).clone());
        }

        // Score joined instances: (service_count, -created_at) — prefer
        // fewest services, then newest among ties
        let mut scored: Vec<(TrackedCloudInstance, usize)> = Vec::new();
        for inst in &instances {
            let count = if let Some(node_id) = &inst.fleet_node_id {
                fleet_state.service_count_for_node(node_id).await
            } else {
                0
            };
            scored.push((inst.clone(), count));
        }

        // Sort: fewest services first, then newest first (highest created_at)
        scored.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.0.created_at.cmp(&a.0.created_at))
        });

        scored.into_iter().next().map(|(inst, _)| inst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> InstanceTracker {
        let raft = FleetStateMachine::new();
        InstanceTracker::new(raft)
    }

    #[tokio::test]
    async fn track_and_retrieve() {
        let tracker = make_tracker();
        tracker
            .track("i-abc", "aws", "workers", Some("10.0.1.5"))
            .await;

        let all = tracker.all().await;
        assert_eq!(all.len(), 1);
        let inst = &all["i-abc"];
        assert_eq!(inst.provider, "aws");
        assert_eq!(inst.pool, "workers");
        assert_eq!(inst.private_ip.as_deref(), Some("10.0.1.5"));
        assert!(inst.fleet_node_id.is_none());
    }

    #[tokio::test]
    async fn associate_node_sets_fleet_id() {
        let tracker = make_tracker();
        tracker
            .track("i-abc", "aws", "workers", Some("10.0.1.5"))
            .await;
        tracker.associate_node("i-abc", "node-uuid-1").await;

        let inst = tracker.all().await;
        assert_eq!(inst["i-abc"].fleet_node_id.as_deref(), Some("node-uuid-1"));
        assert!(inst["i-abc"].joined_at.is_some());
    }

    #[tokio::test]
    async fn find_by_ip() {
        let tracker = make_tracker();
        tracker
            .track("i-abc", "aws", "workers", Some("10.0.1.5"))
            .await;
        tracker
            .track("i-def", "aws", "workers", Some("10.0.1.6"))
            .await;

        let found = tracker.find_by_ip("10.0.1.5").await;
        assert_eq!(found.unwrap().cloud_instance_id, "i-abc");

        let missing = tracker.find_by_ip("10.0.1.99").await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn untrack_removes_instance() {
        let tracker = make_tracker();
        tracker.track("i-abc", "aws", "workers", None).await;
        assert_eq!(tracker.active_count_for_pool("workers").await, 1);

        tracker.untrack("i-abc").await;
        assert_eq!(tracker.active_count_for_pool("workers").await, 0);
    }

    #[tokio::test]
    async fn for_pool_filters_correctly() {
        let tracker = make_tracker();
        tracker.track("i-1", "aws", "workers", None).await;
        tracker.track("i-2", "aws", "compute", None).await;
        tracker.track("i-3", "gcp", "workers", None).await;

        assert_eq!(tracker.active_count_for_pool("workers").await, 2);
        assert_eq!(tracker.active_count_for_pool("compute").await, 1);
        assert_eq!(tracker.active_count_for_pool("missing").await, 0);
    }

    #[tokio::test]
    async fn joined_node_ids_only_returns_associated() {
        let tracker = make_tracker();
        tracker.track("i-1", "aws", "workers", None).await;
        tracker.track("i-2", "aws", "workers", None).await;
        tracker.associate_node("i-1", "node-A").await;

        let joined = tracker.joined_node_ids_for_pool("workers").await;
        assert_eq!(joined, vec!["node-A"]);
    }

    #[tokio::test]
    async fn scaledown_prefers_unjoined() {
        let tracker = make_tracker();
        let fleet_state = crate::server::state::FleetState::new();
        tracker.track("i-joined", "aws", "workers", None).await;
        tracker.associate_node("i-joined", "node-A").await;
        tracker.track("i-unjoined", "aws", "workers", None).await;

        let candidate = tracker
            .select_scaledown_candidate("workers", &fleet_state)
            .await
            .unwrap();
        assert_eq!(candidate.cloud_instance_id, "i-unjoined");
    }

    #[tokio::test]
    async fn scaledown_empty_pool_returns_none() {
        let tracker = make_tracker();
        let fleet_state = crate::server::state::FleetState::new();
        assert!(
            tracker
                .select_scaledown_candidate("workers", &fleet_state)
                .await
                .is_none()
        );
    }
}
