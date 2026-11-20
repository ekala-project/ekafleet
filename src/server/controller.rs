//! Server-owned reconciliation.
//!
//! `Apply` and `Rollback` only record a configuration revision in Raft. One
//! controller loop per server reconciles the fleet toward the current
//! revision, on a timer and whenever a fleet event (node join/leave,
//! eviction, service crash) or a new revision triggers it. Because the
//! desired configuration lives in Raft, the loop resumes where it left off
//! after a restart, with no client attached.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::broadcast;

use super::cloud::actuator::ScalingActuator;
use super::cloud::instance_tracker::InstanceTracker;
use super::events::{EventCategory, EventLevel, EventStore};
use super::state::{FleetState, ReconcileTrigger};
use crate::attestation::join_token::JoinTokenStore;
use crate::config::FleetConfig;
use crate::proto::ApplyStatus;
use crate::raft::state::{ConfigRevision, FleetStateMachine};

/// How often the controller reconciles without a trigger.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// The outcome of one reconcile cycle.
#[derive(Debug, Clone)]
pub struct ReconcileUpdate {
    /// Configuration revision that was reconciled.
    pub revision: u64,
    pub status: ApplyStatus,
    /// Whether the cycle changed anything (or failed).
    pub changed: bool,
    pub message: String,
}

#[derive(Clone)]
pub struct Controller {
    state: FleetState,
    raft: FleetStateMachine,
    tracker: InstanceTracker,
    join_tokens: JoinTokenStore,
    events: EventStore,
    grpc_addr: String,
    trigger: ReconcileTrigger,
    updates: broadcast::Sender<ReconcileUpdate>,
    /// Departed nodes are removed from the mesh after each cycle.
    mesh: Option<super::mesh::MeshRegistry>,
}

impl Controller {
    pub fn new(
        state: FleetState,
        raft: FleetStateMachine,
        tracker: InstanceTracker,
        join_tokens: JoinTokenStore,
        events: EventStore,
        grpc_addr: &str,
    ) -> Self {
        let trigger = state.reconcile_trigger();
        Self {
            state,
            raft,
            tracker,
            join_tokens,
            events,
            grpc_addr: grpc_addr.to_string(),
            trigger,
            updates: broadcast::channel(64).0,
            mesh: None,
        }
    }

    /// Remove departed nodes from `mesh` after each cycle.
    pub fn with_mesh(mut self, mesh: super::mesh::MeshRegistry) -> Self {
        self.mesh = Some(mesh);
        self
    }

    /// Forget the mesh peers of nodes neither `config` nor the cloud
    /// tracker knows and that are not connected, and route replicas'
    /// namespace addresses to their nodes.
    async fn prune_mesh(&self, config: &FleetConfig) {
        let Some(mesh) = &self.mesh else {
            return;
        };
        let cloud: std::collections::HashSet<String> = self
            .tracker
            .all()
            .await
            .into_values()
            .filter_map(|i| i.fleet_node_id)
            .collect();
        mesh.prune(&self.state, |node| {
            config.machines.contains_key(node) || cloud.contains(node)
        })
        .await;
        mesh.sync_routes(&self.state).await;
    }

    /// Receive the outcome of every later reconcile cycle.
    pub fn subscribe(&self) -> broadcast::Receiver<ReconcileUpdate> {
        self.updates.subscribe()
    }

    /// Ask the loop to reconcile as soon as possible.
    pub fn trigger(&self) {
        self.trigger.trigger();
    }

    /// Wait on `updates` for the first cycle that reconciled `revision` or a
    /// later one. `None` if the controller stopped.
    pub async fn wait_for(
        updates: &mut broadcast::Receiver<ReconcileUpdate>,
        revision: u64,
    ) -> Option<ReconcileUpdate> {
        loop {
            match updates.recv().await {
                Ok(update) if update.revision >= revision => return Some(update),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Run the loop until `shutdown`. `ca_cert_pem` is handed to cloud VMs
    /// the scaling actuator provisions.
    pub fn spawn(
        self,
        ca_cert_pem: String,
        interval: Duration,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run(ca_cert_pem, interval, shutdown).await })
    }

    async fn run(
        self,
        ca_cert_pem: String,
        interval: Duration,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        let mut tick = tokio::time::interval(interval);
        let mut actuator: Option<(u64, ScalingActuator)> = None;
        // The last revision announced as an event; one recorded before a
        // restart was announced then.
        let mut announced = None;
        let mut drained = std::collections::HashSet::new();
        if let Some(current) = self.raft.current_config().await {
            announced = Some(current.revision);
            tracing::info!(
                revision = current.revision,
                flake_ref = %current.flake_ref,
                "Resuming reconciliation of the recorded configuration"
            );
        }
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tick.tick() => {}
                _ = self.trigger.notified() => {
                    tracing::debug!("Reconcile triggered");
                }
            }
            let Some(revision) = self.raft.current_config().await else {
                continue;
            };
            let update = self.cycle(&revision, &mut actuator, &ca_cert_pem).await;
            if update.status == ApplyStatus::ApplyFailed {
                tracing::error!(revision = update.revision, message = %update.message, "Reconcile failed");
            }
            if announced != Some(revision.revision) {
                announced = Some(revision.revision);
                self.announce(&revision, &update).await;
            }
            self.announce_drained(&mut drained).await;
            let _ = self.updates.send(update);
        }
    }

    /// Emit the event for the first reconcile of a new revision.
    async fn announce(&self, revision: &ConfigRevision, update: &ReconcileUpdate) {
        let (kind, level) = match (update.status, revision.rollback_of) {
            (ApplyStatus::ApplyFailed, _) => ("config.failed", EventLevel::Error),
            (_, Some(_)) => ("config.rolled_back", EventLevel::Warning),
            _ => ("config.applied", EventLevel::Info),
        };
        let message = match revision.rollback_of {
            Some(of) => format!(
                "{} (rollback to revision {of} by {})",
                update.message, revision.applied_by
            ),
            None => format!(
                "{} (applied by {} from {})",
                update.message, revision.applied_by, revision.flake_ref
            ),
        };
        self.events
            .emit_kind(
                kind,
                level,
                EventCategory::Configuration,
                None,
                None,
                &message,
            )
            .await;
    }

    /// Emit `drain.completed` once for each draining node that no longer
    /// runs any instance. `drained` remembers the nodes announced.
    async fn announce_drained(&self, drained: &mut std::collections::HashSet<String>) {
        let draining = self.state.draining_nodes().await;
        drained.retain(|node| draining.contains(node));
        let pending: Vec<_> = draining.iter().filter(|n| !drained.contains(*n)).collect();
        if pending.is_empty() {
            return;
        }
        let (_, services, _) = self.state.fleet_status().await;
        for node in pending {
            let busy = services
                .iter()
                .any(|s| s.instances.iter().any(|i| &i.node_id == node));
            if !busy {
                drained.insert(node.clone());
                self.events
                    .emit_kind(
                        "drain.completed",
                        EventLevel::Info,
                        EventCategory::Drain,
                        None,
                        Some(node),
                        &format!("Node {node} is drained"),
                    )
                    .await;
            }
        }
    }

    async fn cycle(
        &self,
        revision: &ConfigRevision,
        actuator: &mut Option<(u64, ScalingActuator)>,
        ca_cert_pem: &str,
    ) -> ReconcileUpdate {
        let failed = |message: String| ReconcileUpdate {
            revision: revision.revision,
            status: ApplyStatus::ApplyFailed,
            changed: true,
            message,
        };
        let config = match revision.config() {
            Ok(config) => config,
            Err(e) => {
                return failed(format!(
                    "recorded configuration revision {} cannot be read: {e}",
                    revision.revision
                ));
            }
        };

        if actuator.as_ref().map(|(r, _)| *r) != Some(revision.revision) {
            let built = self.build_actuator(config.clone(), ca_cert_pem).await;
            *actuator = Some((revision.revision, built));
        }
        if let Some((_, actuator)) = actuator {
            actuator.run_cycle().await;
        }

        match super::reconciler::reconcile(
            &config,
            &self.state,
            Some(&self.tracker),
            &self.raft,
            Some(&self.events),
        )
        .await
        {
            Ok(plan) => {
                self.prune_mesh(&config).await;
                for block in &plan.policy_blocked {
                    self.events
                        .emit_detail(
                            EventLevel::Error,
                            EventCategory::Scheduling,
                            Some(&block.service_name),
                            None,
                            &format!(
                                "Deployment blocked by policy '{}': {}",
                                block.rule_name, block.message
                            ),
                        )
                        .await;
                }
                let message = if plan.has_changes {
                    format!(
                        "Revision {}: {} creates, {} updates, {} destroys, {} reschedules",
                        revision.revision,
                        plan.creates.len(),
                        plan.updates.len(),
                        plan.destroys.len(),
                        plan.reschedules.len(),
                    )
                } else {
                    format!("Revision {}: no changes", revision.revision)
                };
                ReconcileUpdate {
                    revision: revision.revision,
                    status: ApplyStatus::ApplySucceeded,
                    changed: plan.has_changes || !plan.policy_blocked.is_empty(),
                    message,
                }
            }
            Err(e) => failed(format!(
                "Revision {}: reconciliation failed: {e}",
                revision.revision
            )),
        }
    }

    /// Resolve managed cloud images for `config` and build the scaling
    /// actuator for its node pools. Runs once per configuration revision.
    async fn build_actuator(&self, mut config: FleetConfig, ca_cert_pem: &str) -> ScalingActuator {
        use super::cloud::image;

        let image_tracker = super::cloud::image_tracker::ImageTracker::new(self.raft.clone());
        let mut image_managers: HashMap<String, Box<dyn image::CloudImageManagerDyn>> =
            HashMap::new();
        let mut active_hashes: HashMap<String, String> = HashMap::new();

        for (pool_name, pool_config) in &mut config.node_pools {
            let Some(cloud) = &mut pool_config.cloud else {
                continue;
            };
            let Some(image_config) = &cloud.image else {
                continue;
            };
            let manager = image::build_image_manager(cloud, image_config);
            let manager_key = match cloud.provider {
                crate::config::CloudProviderType::Aws => "aws",
                crate::config::CloudProviderType::Azure => "azure",
                crate::config::CloudProviderType::Gcp => "gcp",
            };
            match image::ensure_image(
                pool_name,
                cloud,
                image_config,
                &config.name,
                &image_tracker,
                manager.as_ref(),
            )
            .await
            {
                Ok(resolved_id) => {
                    if let Ok(toplevel) = super::nix::build(&format!(
                        "{}.config.system.build.toplevel",
                        image_config.nixos_config
                    ))
                    .await
                        && let Some(hash) = image::extract_store_path_hash(&toplevel)
                    {
                        active_hashes.insert(pool_name.clone(), hash.to_string());
                    }
                    cloud.image_id = Some(resolved_id);
                    image_managers
                        .entry(manager_key.to_string())
                        .or_insert(manager);
                }
                Err(e) => {
                    tracing::error!(
                        pool = %pool_name,
                        error = %e,
                        "Failed to resolve managed cloud image"
                    );
                }
            }
        }

        image::cleanup_expired_images(&config, &image_tracker, &image_managers, &active_hashes)
            .await;

        let providers = super::cloud::CloudProviderRegistry::from_pool_configs(&config.node_pools);
        let mut pool_engine = super::scaling::PoolScalingEngine::new(self.state.clone());
        for (pool_name, pool_config) in &config.node_pools {
            if let Some(scaling) = &pool_config.scaling {
                pool_engine.register_policy(pool_name, scaling.clone());
            }
        }
        ScalingActuator::new(
            pool_engine,
            providers,
            self.tracker.clone(),
            self.join_tokens.clone(),
            self.state.clone(),
            config,
            self.grpc_addr.clone(),
            ca_cert_pem.to_string(),
        )
    }
}
