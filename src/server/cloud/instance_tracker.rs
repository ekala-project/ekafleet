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

        tracing::info!(
            instance_id,
            provider,
            pool,
            "Tracking cloud instance"
        );
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
    /// Prefers instances without a fleet node ID (never joined), then
    /// the most recently created (newest first) to preserve older, more
    /// established nodes.
    pub async fn select_scaledown_candidate(&self, pool: &str) -> Option<TrackedCloudInstance> {
        let mut instances = self.for_pool(pool).await;
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

        // Otherwise pick the newest (most recently created)
        instances.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        instances.into_iter().next()
    }
}
