#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use super::cloud::instance_tracker::InstanceTracker;
use super::deployer::{self, DeploymentPlan};
use super::nix;
use super::scheduler::{self, CurrentPlacements, Placement};
use super::state::FleetState;
use crate::config::{self, CapacityConfig, FleetConfig, MachineConfig};
use crate::raft::state::FleetStateMachine;

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("nix eval failed: {0}")]
    NixEval(#[from] nix::NixError),
    #[error("deployment failed: {0}")]
    Deploy(#[from] deployer::DeployError),
    #[error("validation failed: {0}")]
    Validation(String),
}

/// Result of comparing desired state with current state.
#[derive(Debug)]
pub struct ReconcilePlan {
    pub creates: Vec<ServiceOp>,
    pub updates: Vec<ServiceOp>,
    pub destroys: Vec<ServiceOp>,
    pub reschedules: Vec<ServiceOp>,
    pub has_changes: bool,
}

#[derive(Debug)]
pub struct ServiceOp {
    pub service_name: String,
    pub placements: Vec<Placement>,
    pub description: String,
    pub migrations: Vec<MigrationOp>,
}

/// Describes a volume data migration needed when a stateful service
/// instance moves to a different node.
#[derive(Debug)]
pub struct MigrationOp {
    pub instance_id: String,
    pub source_machine: String,
    pub dest_machine: String,
}

/// Run a single reconciliation cycle: eval → refresh → plan → apply.
pub async fn reconcile_once(
    config_path: &Path,
    state: &FleetState,
    auto_approve: bool,
    instance_tracker: Option<&InstanceTracker>,
    raft_state: &FleetStateMachine,
) -> Result<ReconcilePlan, ReconcileError> {
    // 1. Evaluate: get desired state from Nix
    tracing::info!(config = %config_path.display(), "Evaluating fleet configuration");
    let desired = nix::eval_fleet(config_path).await?;

    // 1b. Validate configuration consistency
    if let Err(errors) = config::validate(&desired) {
        return Err(ReconcileError::Validation(errors.join("; ")));
    }

    // 2. Refresh: query current state from agents
    let current_nodes = state.connected_nodes().await;
    tracing::info!(nodes = current_nodes.len(), "Current fleet state refreshed");

    // 3. Plan: diff desired vs actual
    let plan = compute_plan(
        &desired,
        &current_nodes,
        state,
        instance_tracker,
        raft_state,
    )
    .await;

    if !plan.has_changes {
        tracing::info!("No changes detected");
        return Ok(plan);
    }

    tracing::info!(
        creates = plan.creates.len(),
        updates = plan.updates.len(),
        destroys = plan.destroys.len(),
        reschedules = plan.reschedules.len(),
        "Reconciliation plan computed"
    );

    if !auto_approve {
        // In non-auto mode, just return the plan for review
        return Ok(plan);
    }

    // 4. Apply: execute deployment operations
    apply_plan(&desired, &plan, state).await?;

    Ok(plan)
}

/// Continuous reconciliation loop.
pub async fn reconcile_loop(
    config_path: &Path,
    state: &FleetState,
    interval: Duration,
    instance_tracker: Option<&InstanceTracker>,
    raft_state: &FleetStateMachine,
) -> Result<(), ReconcileError> {
    tracing::info!(
        interval = ?interval,
        "Starting continuous reconciliation"
    );

    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        match reconcile_once(config_path, state, true, instance_tracker, raft_state).await {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "Reconciliation cycle failed");
            }
        }
    }
}

/// Compare desired state with actual state to produce operations.
pub async fn compute_plan(
    desired: &FleetConfig,
    _current_nodes: &[String],
    state: &FleetState,
    instance_tracker: Option<&InstanceTracker>,
    raft_state: &FleetStateMachine,
) -> ReconcilePlan {
    // Merge static machines with cloud-provisioned dynamic machines
    let machines = merge_dynamic_machines(desired, instance_tracker).await;

    // Build current placements from Raft state for data-locality scoring
    let mut current_placements: CurrentPlacements = HashMap::new();
    for (_, deployment) in raft_state.all_deployments().await {
        for record in &deployment.placements {
            current_placements.insert(
                (deployment.service_name.clone(), record.instance_id.clone()),
                record.machine_name.clone(),
            );
        }
    }

    // Schedule services across all machines (static + cloud)
    let placement_plan = scheduler::schedule(
        &desired.services,
        &machines,
        &desired.node_pools,
        &current_placements,
    );

    // Log blocked placements
    for b in &placement_plan.blocked {
        tracing::warn!(
            service = %b.service_name,
            instance = %b.instance_id,
            reason = %b.reason,
            "Placement blocked"
        );
    }

    // Group placements by service
    let mut placements_by_service: HashMap<String, Vec<Placement>> = HashMap::new();
    for p in placement_plan.placements {
        placements_by_service
            .entry(p.service_name.clone())
            .or_default()
            .push(p);
    }

    let mut creates = Vec::new();
    let mut updates = Vec::new();
    let mut destroys = Vec::new();
    let mut reschedules = Vec::new();

    let (_, current_services, _) = state.fleet_status().await;
    let current_service_names: Vec<&str> =
        current_services.iter().map(|s| s.name.as_str()).collect();

    for (service_name, placements) in &placements_by_service {
        if current_service_names.contains(&service_name.as_str()) {
            updates.push(ServiceOp {
                service_name: service_name.clone(),
                placements: placements.clone(),
                description: format!("Update {service_name} ({} instances)", placements.len()),
                migrations: vec![],
            });
        } else {
            creates.push(ServiceOp {
                service_name: service_name.clone(),
                placements: placements.clone(),
                description: format!("Create {service_name} ({} instances)", placements.len()),
                migrations: vec![],
            });
        }
    }

    // Detect services that should be destroyed (in current but not desired)
    for svc in &current_services {
        if !placements_by_service.contains_key(&svc.name) {
            destroys.push(ServiceOp {
                service_name: svc.name.clone(),
                placements: vec![],
                description: format!("Destroy {} (no longer in desired state)", svc.name),
                migrations: vec![],
            });
        }
    }

    // Detect reschedules (same service, different placement)
    for (service_name, desired_placements) in &placements_by_service {
        if let Some(current_svc) = current_services.iter().find(|s| &s.name == service_name) {
            let current_nodes: Vec<&str> = current_svc
                .instances
                .iter()
                .map(|i| i.node_id.as_str())
                .collect();
            let desired_nodes: Vec<&str> = desired_placements
                .iter()
                .map(|p| p.machine_name.as_str())
                .collect();

            // If the set of nodes differs, it's a reschedule
            let mut current_sorted = current_nodes.clone();
            current_sorted.sort();
            let mut desired_sorted = desired_nodes.clone();
            desired_sorted.sort();

            if current_sorted != desired_sorted && !current_nodes.is_empty() {
                // For stateful services with local volumes and migrate_on_reschedule
                // enabled, detect per-instance node changes that require data migration.
                let mut migrations = Vec::new();
                if let Some(svc_cfg) = desired.services.get(service_name) {
                    let is_stateful = svc_cfg.scheduling.job_type == config::JobType::Stateful;
                    let has_local_volumes = svc_cfg.volumes.iter().any(|v| {
                        v.storage_class == "local"
                            && v.access_mode == config::VolumeAccessMode::ReadWriteOnce
                    });
                    let migrate_enabled = svc_cfg.scheduling.migrate.migrate_on_reschedule;

                    if is_stateful && has_local_volumes && migrate_enabled {
                        // Compare per-instance placements to find moves
                        for dp in desired_placements {
                            if let Some(old_machine) = current_placements
                                .get(&(service_name.clone(), dp.instance_id.clone()))
                            {
                                if old_machine != &dp.machine_name {
                                    migrations.push(MigrationOp {
                                        instance_id: dp.instance_id.clone(),
                                        source_machine: old_machine.clone(),
                                        dest_machine: dp.machine_name.clone(),
                                    });
                                }
                            }
                        }
                    }
                }

                if !migrations.is_empty() {
                    tracing::info!(
                        service = %service_name,
                        count = migrations.len(),
                        "Volume migrations required for reschedule"
                    );
                }

                reschedules.push(ServiceOp {
                    service_name: service_name.clone(),
                    placements: desired_placements.clone(),
                    description: format!(
                        "Reschedule {service_name} ({} → {} instances)",
                        current_nodes.len(),
                        desired_nodes.len()
                    ),
                    migrations,
                });
            }
        }
    }

    // Evaluate organizational policies against service configurations.
    if !desired.policies.is_empty() {
        let engine = super::policy::PolicyEngine::new();
        engine.set_rules(desired.policies.clone()).await;

        // Check each service for policy violations; remove creates/updates
        // that violate enforcing policies.
        let mut blocked_services = Vec::new();
        for (service_name, service_config) in &desired.services {
            match engine.check(service_name, service_config).await {
                Err(violations) => {
                    for v in &violations {
                        tracing::error!(
                            rule = %v.rule_name,
                            service = %v.service_name,
                            "Policy violation: {}",
                            v.message
                        );
                    }
                    blocked_services.push(service_name.clone());
                }
                Ok(warnings) => {
                    for w in &warnings {
                        tracing::warn!(
                            rule = %w.rule_name,
                            service = %w.service_name,
                            "Policy warning: {}",
                            w.message
                        );
                    }
                }
            }
        }

        creates.retain(|op| !blocked_services.contains(&op.service_name));
        updates.retain(|op| !blocked_services.contains(&op.service_name));
    }

    let has_changes = !creates.is_empty()
        || !updates.is_empty()
        || !destroys.is_empty()
        || !reschedules.is_empty();

    ReconcilePlan {
        creates,
        updates,
        destroys,
        reschedules,
        has_changes,
    }
}

/// Execute a reconciliation plan.
async fn apply_plan(
    desired: &FleetConfig,
    plan: &ReconcilePlan,
    state: &FleetState,
) -> Result<(), deployer::DeployError> {
    // Execute volume migrations for reschedules before deploying.
    // Migrations run first so data is available on the destination node
    // before the service starts there.
    for op in &plan.reschedules {
        if op.migrations.is_empty() {
            continue;
        }

        let service_cfg = match desired.services.get(&op.service_name) {
            Some(cfg) => cfg,
            None => continue,
        };
        let max_parallel = service_cfg.scheduling.migrate.max_parallel as usize;

        for chunk in op.migrations.chunks(max_parallel) {
            let mut handles = Vec::new();
            for migration in chunk {
                let source_host = desired
                    .machines
                    .get(&migration.source_machine)
                    .map(|m| m.target_host.clone())
                    .unwrap_or_default();
                let dest_machine = migration.dest_machine.clone();
                let service_name = op.service_name.clone();
                let s = state.clone();

                // Build volume paths for all local volumes in this service
                let volume_names: Vec<String> = service_cfg
                    .volumes
                    .iter()
                    .filter(|v| {
                        v.storage_class == "local"
                            && v.access_mode == config::VolumeAccessMode::ReadWriteOnce
                    })
                    .map(|v| v.name.clone())
                    .collect();

                handles.push(tokio::spawn(async move {
                    for vol_name in &volume_names {
                        let vol_path = format!(
                            "/var/lib/ekafleet/data/volumes/{}/{}",
                            service_name, vol_name
                        );
                        let correlation_id = uuid::Uuid::new_v4().to_string();
                        let cmd = crate::proto::MigrateVolumeCommand {
                            correlation_id: correlation_id.clone(),
                            service_name: service_name.clone(),
                            source_host: source_host.clone(),
                            source_path: vol_path.clone(),
                            dest_path: vol_path,
                        };
                        let msg = crate::proto::ServerMessage {
                            payload: Some(
                                crate::proto::server_message::Payload::MigrateVolumeCommand(cmd),
                            ),
                        };
                        let timeout = Duration::from_secs(600);
                        match s
                            .send_command(&dest_machine, msg, correlation_id, timeout)
                            .await
                        {
                            Ok(resp) if resp.success => {
                                tracing::info!(
                                    service = %service_name,
                                    volume = %vol_name,
                                    dest = %dest_machine,
                                    "Volume migration completed"
                                );
                            }
                            Ok(resp) => {
                                tracing::error!(
                                    service = %service_name,
                                    volume = %vol_name,
                                    dest = %dest_machine,
                                    error = %resp.error_message,
                                    "Volume migration failed"
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    service = %service_name,
                                    volume = %vol_name,
                                    dest = %dest_machine,
                                    error = %e,
                                    "Volume migration command failed"
                                );
                            }
                        }
                    }
                }));
            }
            for handle in handles {
                let _ = handle.await;
            }
        }
    }

    // Compute deployment order
    let tiers = deployer::compute_deploy_order(&desired.services);

    for tier in &tiers {
        for service_name in tier {
            // Find ops for this service (creates, updates, and reschedules)
            let ops: Vec<&ServiceOp> = plan
                .creates
                .iter()
                .chain(plan.updates.iter())
                .chain(plan.reschedules.iter())
                .filter(|op| &op.service_name == service_name)
                .collect();

            for op in ops {
                let service_cfg = match desired.services.get(service_name) {
                    Some(cfg) => cfg,
                    None => continue,
                };

                let deploy_plan = DeploymentPlan {
                    service_name: service_name.clone(),
                    strategy: service_cfg.scheduling.update.strategy.clone(),
                    max_parallel: service_cfg.scheduling.update.max_parallel,
                    placements: op.placements.clone(),
                    store_path: service_cfg.command.clone().unwrap_or_default(),
                    auto_revert: service_cfg.scheduling.update.auto_revert,
                    auto_promote: service_cfg.scheduling.update.auto_promote,
                    min_healthy_time: Duration::from_secs(
                        service_cfg.scheduling.update.min_healthy_time_secs,
                    ),
                    healthy_deadline: Duration::from_secs(
                        service_cfg.scheduling.update.healthy_deadline_secs,
                    ),
                    progress_deadline: service_cfg
                        .scheduling
                        .update
                        .progress_deadline_secs
                        .map(Duration::from_secs),
                    disruption_budget: service_cfg.scheduling.disruption_budget.clone(),
                    total_replicas: service_cfg.scheduling.replicas,
                };

                deployer::execute(state, deploy_plan).await?;
            }
        }
    }

    Ok(())
}

/// Merge statically declared machines with cloud-provisioned dynamic machines.
///
/// Cloud machines that have joined the fleet (have a `fleet_node_id`) are
/// converted to [`MachineConfig`] using the pool's `machineCapacity`.
pub(crate) async fn merge_dynamic_machines(
    config: &FleetConfig,
    instance_tracker: Option<&InstanceTracker>,
) -> HashMap<String, MachineConfig> {
    let mut machines = config.machines.clone();

    let Some(tracker) = instance_tracker else {
        return machines;
    };

    let tracked = tracker.all().await;

    for (instance_id, instance) in &tracked {
        // Only include instances that have joined the fleet
        let Some(node_id) = &instance.fleet_node_id else {
            continue;
        };

        // Skip if already represented in static config
        if machines.contains_key(node_id) {
            continue;
        }

        // Look up the pool's expected machine capacity
        let capacity = config
            .node_pools
            .get(&instance.pool)
            .and_then(|p| p.cloud.as_ref())
            .map(|c| c.machine_capacity.clone())
            .unwrap_or_default();

        let target_host = instance
            .private_ip
            .clone()
            .unwrap_or_else(|| node_id.clone());

        machines.insert(
            node_id.clone(),
            MachineConfig {
                target_host,
                labels: HashMap::new(),
                capacity,
                pool: instance.pool.clone(),
                reserved: CapacityConfig::default(),
                taints: vec![],
                extended_resources: HashMap::new(),
            },
        );

        tracing::debug!(
            node_id = %node_id,
            cloud_instance = %instance_id,
            pool = %instance.pool,
            "Merged cloud-provisioned machine into scheduler"
        );
    }

    machines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CapacityConfig, CloudProviderConfig, CloudProviderType, NodePoolConfig, SchedulingConfig,
        ServiceConfig,
    };
    use crate::raft::state::FleetStateMachine;

    fn empty_fleet_config() -> FleetConfig {
        FleetConfig {
            name: "test".into(),
            domain: "fleet.internal".into(),
            services: HashMap::new(),
            machines: HashMap::new(),
            node_pools: HashMap::new(),
            hooks: Default::default(),
            admission_webhooks: vec![],
            policies: vec![],
        }
    }

    #[tokio::test]
    async fn merge_without_tracker_returns_static_only() {
        let mut config = empty_fleet_config();
        config.machines.insert(
            "static-1".into(),
            MachineConfig {
                target_host: "10.0.0.1".into(),
                labels: HashMap::new(),
                capacity: CapacityConfig::default(),
                pool: "default".into(),
                reserved: CapacityConfig::default(),
                taints: vec![],
                extended_resources: HashMap::new(),
            },
        );

        let result = merge_dynamic_machines(&config, None).await;
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("static-1"));
    }

    #[tokio::test]
    async fn merge_adds_joined_cloud_machines() {
        let mut config = empty_fleet_config();
        config.node_pools.insert(
            "workers".into(),
            NodePoolConfig {
                labels: HashMap::new(),
                scaling: None,
                scheduler_algorithm: None,
                memory_oversubscription: false,
                cloud: Some(CloudProviderConfig {
                    provider: CloudProviderType::Aws,
                    region: "us-east-1".into(),
                    instance_type: "t3.large".into(),
                    image_id: Some("ami-123".into()),
                    image: None,
                    subnet_id: None,
                    security_group_ids: vec![],
                    ssh_key_name: None,
                    zone: None,
                    disk_size_gb: None,
                    resource_group: None,
                    project: None,
                    machine_capacity: CapacityConfig {
                        cpu: 2000,
                        memory: 4096,
                        disk: 50000,
                    },
                    iam_instance_profile: None,
                    spot: None,
                    launch_timeout_seconds: 300,
                    join_timeout_seconds: 600,
                    drain_wait_seconds: 30,
                }),
            },
        );

        let raft = FleetStateMachine::new();
        let tracker = InstanceTracker::new(raft);
        tracker
            .track("i-abc", "aws", "workers", Some("10.0.1.5"))
            .await;
        tracker.associate_node("i-abc", "node-cloud-1").await;

        let result = merge_dynamic_machines(&config, Some(&tracker)).await;
        assert_eq!(result.len(), 1);

        let machine = &result["node-cloud-1"];
        assert_eq!(machine.target_host, "10.0.1.5");
        assert_eq!(machine.pool, "workers");
        assert_eq!(machine.capacity.cpu, 2000);
        assert_eq!(machine.capacity.memory, 4096);
    }

    #[tokio::test]
    async fn merge_skips_unjoined_cloud_machines() {
        let config = empty_fleet_config();

        let raft = FleetStateMachine::new();
        let tracker = InstanceTracker::new(raft);
        // Tracked but not joined — no fleet_node_id
        tracker
            .track("i-pending", "aws", "workers", Some("10.0.1.5"))
            .await;

        let result = merge_dynamic_machines(&config, Some(&tracker)).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn merge_does_not_overwrite_static_machines() {
        let mut config = empty_fleet_config();
        config.machines.insert(
            "node-1".into(),
            MachineConfig {
                target_host: "10.0.0.1".into(),
                labels: HashMap::new(),
                capacity: CapacityConfig {
                    cpu: 8000,
                    memory: 16384,
                    disk: 100000,
                },
                pool: "default".into(),
                reserved: CapacityConfig::default(),
                taints: vec![],
                extended_resources: HashMap::new(),
            },
        );

        let raft = FleetStateMachine::new();
        let tracker = InstanceTracker::new(raft);
        // Cloud instance joined with same node_id as a static machine
        tracker
            .track("i-dup", "aws", "default", Some("10.0.0.99"))
            .await;
        tracker.associate_node("i-dup", "node-1").await;

        let result = merge_dynamic_machines(&config, Some(&tracker)).await;
        assert_eq!(result.len(), 1);
        // Should keep the static machine's config, not overwrite
        assert_eq!(result["node-1"].target_host, "10.0.0.1");
        assert_eq!(result["node-1"].capacity.cpu, 8000);
    }

    #[tokio::test]
    async fn policy_violations_block_service_creation() {
        use crate::server::policy::{PolicyEnforcement, PolicyRule};

        let state = FleetState::new();
        // Register a node so scheduling has somewhere to place services.
        let _rx = state
            .register_agent("node-1", "127.0.0.1:5000".into(), "default".into())
            .await;
        // Report resources so the scheduler sees capacity.
        state
            .update_heartbeat(
                "node-1",
                Some(crate::proto::NodeResources {
                    cpu_millicores: 4000,
                    memory_mb: 8192,
                    disk_mb: 100_000,
                }),
            )
            .await;

        let mut config = empty_fleet_config();
        config.machines.insert(
            "node-1".into(),
            MachineConfig {
                target_host: "127.0.0.1".into(),
                labels: HashMap::new(),
                capacity: CapacityConfig {
                    cpu: 4000,
                    memory: 8192,
                    disk: 100_000,
                },
                pool: "default".into(),
                reserved: CapacityConfig::default(),
                taints: vec![],
                extended_resources: HashMap::new(),
            },
        );
        config.services.insert(
            "blocked-svc".into(),
            ServiceConfig {
                command: Some("/bin/svc".into()),
                container: None,
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: Default::default(),
                scheduling: SchedulingConfig {
                    replicas: 1,
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
                volumes: vec![],
                sidecars: vec![],
            },
        );
        // Policy: requires at least 2 replicas.
        config.policies.push(PolicyRule {
            name: "min-replicas".into(),
            expression: "service.replicas >= 2".into(),
            message: "Must have at least 2 replicas".into(),
            enforcement: PolicyEnforcement::Enforce,
        });

        let raft = FleetStateMachine::new();
        let plan = compute_plan(&config, &["node-1".to_string()], &state, None, &raft).await;
        // The service should be blocked by the policy.
        assert!(plan.creates.is_empty(), "blocked-svc should not be created");
    }
}
