#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use super::cloud::instance_tracker::InstanceTracker;
use super::deployer::{self, DeploymentPlan};
use super::nix;
use super::scheduler::{self, CurrentPlacements, Placement};
use super::state::FleetState;
use crate::config::{self, CapacityConfig, FleetConfig, MachineConfig};
use crate::raft::state::{Command, FleetStateMachine, PlacementRecord, namespace_ip_holder};

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
    /// Services blocked from deployment due to policy violations.
    pub policy_blocked: Vec<PolicyBlock>,
}

/// A service that was blocked from deployment by a policy rule.
#[derive(Debug)]
pub struct PolicyBlock {
    pub service_name: String,
    pub rule_name: String,
    pub message: String,
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

/// Outcome of migrating a single instance's volumes to its destination node.
#[derive(Debug, Clone)]
struct MigrationResult {
    instance_id: String,
    dest_machine: String,
    /// `None` on success; failure reason otherwise.
    error: Option<String>,
}

/// Summary of a partially- or fully-failed set of migrations for one service.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationFailureSummary {
    /// Instance IDs whose migration failed.
    failed_instances: Vec<String>,
    /// Destination machines that *did* receive data before the service was
    /// abandoned — these hold orphaned partial copies from the failed attempt.
    orphaned_destinations: Vec<String>,
}

/// Pair each node a service leaves with a node it moves to (both sorted);
/// nodes left over on either side are a scale-down or a fresh replica.
pub(super) fn node_moves<'a>(current: &[&'a str], desired: &[&'a str]) -> Vec<(&'a str, &'a str)> {
    let mut leaving: Vec<&str> = current
        .iter()
        .filter(|n| !desired.contains(n))
        .copied()
        .collect();
    let mut joining: Vec<&str> = desired
        .iter()
        .filter(|n| !current.contains(n))
        .copied()
        .collect();
    leaving.dedup();
    joining.dedup();
    leaving.into_iter().zip(joining).collect()
}

/// Classify a set of per-instance migration results. Returns `None` if every
/// migration succeeded (the reschedule may proceed), or a summary of the
/// failure otherwise (the reschedule must be skipped). This is the pure
/// decision core of the reschedule partial-failure handling, factored out so it
/// can be tested without a live fleet.
fn summarize_migration_failure(results: &[MigrationResult]) -> Option<MigrationFailureSummary> {
    let any_failed = results.iter().any(|r| r.error.is_some());
    if !any_failed {
        return None;
    }

    let failed_instances = results
        .iter()
        .filter(|r| r.error.is_some())
        .map(|r| r.instance_id.clone())
        .collect();

    // Destinations that succeeded now hold orphaned copies, since the service
    // as a whole will not cut over to them.
    let mut orphaned_destinations: Vec<String> = results
        .iter()
        .filter(|r| r.error.is_none() && !r.dest_machine.is_empty())
        .map(|r| r.dest_machine.clone())
        .collect();
    orphaned_destinations.sort();
    orphaned_destinations.dedup();

    Some(MigrationFailureSummary {
        failed_instances,
        orphaned_destinations,
    })
}

/// Run one reconciliation cycle toward `desired`: validate → plan → apply.
pub async fn reconcile(
    desired: &FleetConfig,
    state: &FleetState,
    instance_tracker: Option<&InstanceTracker>,
    raft_state: &FleetStateMachine,
    events: Option<&super::events::EventStore>,
) -> Result<ReconcilePlan, ReconcileError> {
    if let Err(errors) = config::validate(desired) {
        return Err(ReconcileError::Validation(errors.join("; ")));
    }
    let current_nodes = state.connected_nodes().await;
    let plan = compute_plan(desired, &current_nodes, state, instance_tracker, raft_state).await;

    if !plan.has_changes {
        tracing::debug!("No changes detected");
        super::rebalance::settle(desired, &plan, &[], raft_state, events).await;
        return Ok(plan);
    }
    tracing::info!(
        creates = plan.creates.len(),
        updates = plan.updates.len(),
        destroys = plan.destroys.len(),
        reschedules = plan.reschedules.len(),
        "Reconciliation plan computed"
    );
    apply_plan(desired, &plan, state, raft_state, events).await?;
    Ok(plan)
}

/// What the scheduler places from: the desired services with runtime
/// replica overrides, the schedulable machines (static and cloud, minus
/// draining nodes), and where each instance runs now.
pub struct SchedulingInputs {
    pub services: HashMap<String, config::ServiceConfig>,
    pub machines: HashMap<String, MachineConfig>,
    pub current_placements: CurrentPlacements,
}

pub async fn scheduling_inputs(
    desired: &FleetConfig,
    state: &FleetState,
    instance_tracker: Option<&InstanceTracker>,
    raft_state: &FleetStateMachine,
) -> SchedulingInputs {
    // Merge static machines with cloud-provisioned dynamic machines, minus
    // nodes being drained: their services move elsewhere, taking
    // their volumes along.
    let mut machines = merge_dynamic_machines(desired, instance_tracker).await;
    for node in state.draining_nodes().await {
        machines.remove(&node);
    }

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

    // Apply runtime replica overrides from Scale RPC before scheduling.
    let mut services = desired.services.clone();
    for (name, cfg) in services.iter_mut() {
        if let Some(count) = raft_state.get_replica_override(name).await {
            tracing::debug!(
                service = %name,
                config_replicas = cfg.scheduling.replicas,
                override_replicas = count,
                "Applying runtime replica override"
            );
            cfg.scheduling.replicas = count;
        }
    }

    SchedulingInputs {
        services,
        machines,
        current_placements,
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
    let SchedulingInputs {
        services,
        machines,
        mut current_placements,
    } = scheduling_inputs(desired, state, instance_tracker, raft_state).await;
    // Instances `ekafleet rebalance` asked to move prefer their destination.
    for ((service, instance), node) in raft_state.placement_moves().await {
        current_placements.insert((service, instance), node);
    }

    // Publish per-service resource requests so read paths (e.g. the `top` RPC)
    // can report requested CPU/memory. CPU is in millicores, memory in MB.
    let service_requests = services
        .iter()
        .map(|(name, cfg)| {
            let cpu = cfg.resources.cpu.as_ref().map(|c| c.request).unwrap_or(0);
            let mem = cfg
                .resources
                .memory
                .as_ref()
                .map(|m| m.request)
                .unwrap_or(0);
            (name.clone(), (cpu, mem))
        })
        .collect();
    state.set_service_requests(service_requests).await;

    // Schedule services across all machines (static + cloud)
    let placement_plan = scheduler::schedule(
        &services,
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

    // Where each service runs now: where agents report it, and where its
    // last completed rollout placed it. Agents report on their heartbeat, so
    // a service deployed moments ago may not be reported yet; its recorded
    // placement still says where its volumes are, so a move migrates them.
    let (_, current_services, _) = state.fleet_status().await;
    let mut current_by_service: HashMap<String, BTreeSet<String>> = HashMap::new();
    for svc in &current_services {
        current_by_service
            .entry(svc.name.clone())
            .or_default()
            .extend(svc.instances.iter().map(|i| i.node_id.clone()));
    }
    for (_, deployment) in raft_state.all_deployments().await {
        current_by_service
            .entry(deployment.service_name.clone())
            .or_default()
            .extend(deployment.placements.iter().map(|p| p.machine_name.clone()));
    }

    for (service_name, placements) in &placements_by_service {
        if current_by_service.contains_key(service_name) {
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
        if let Some(current) = current_by_service.get(service_name) {
            let current_nodes: Vec<&str> = current.iter().map(String::as_str).collect();
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
                // Stateful services with ReadWriteOnce volumes and
                // migrate_on_reschedule take their data along. Volumes belong
                // to (service, node), so each node the service leaves hands
                // its copy to one node it moves to.
                let mut migrations = Vec::new();
                if let Some(svc_cfg) = desired.services.get(service_name) {
                    let is_stateful = svc_cfg.scheduling.job_type == config::JobType::Stateful;
                    let migrate_enabled = svc_cfg.scheduling.migrate.migrate_on_reschedule;
                    if is_stateful
                        && migrate_enabled
                        && super::scheduler::one_replica_per_node(svc_cfg)
                    {
                        migrations = node_moves(&current_sorted, &desired_sorted)
                            .into_iter()
                            .map(|(source, dest)| MigrationOp {
                                instance_id: format!("{service_name}@{source}"),
                                source_machine: source.to_string(),
                                dest_machine: dest.to_string(),
                            })
                            .collect();
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
    let mut policy_blocked = Vec::new();
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
                        policy_blocked.push(PolicyBlock {
                            service_name: v.service_name.clone(),
                            rule_name: v.rule_name.clone(),
                            message: v.message.clone(),
                        });
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
        policy_blocked,
    }
}

/// The port whose health checks a service's probes come from: the first,
/// by name, that declares any.
fn probe_port(cfg: &config::ServiceConfig) -> Option<&config::PortConfig> {
    let mut ports: Vec<_> = cfg.ports.iter().collect();
    ports.sort_by_key(|(name, _)| name.as_str());
    ports.into_iter().map(|(_, port)| port).find(|p| {
        p.health_check.is_some()
            || p.liveness.is_some()
            || p.readiness.is_some()
            || p.startup.is_some()
    })
}

/// Convert a fleet `ServiceConfig` to a proto `ServiceSpec` for sending to agents.
fn service_config_to_spec(name: &str, cfg: &config::ServiceConfig) -> crate::proto::ServiceSpec {
    let health_check_to_proto = |hc: &config::HealthCheckConfig| -> crate::proto::HealthCheckSpec {
        crate::proto::HealthCheckSpec {
            probe: hc.path.as_ref().map(|path| {
                crate::proto::health_check_spec::Probe::Http(crate::proto::HttpProbe {
                    path: path.clone(),
                    port: 0,
                })
            }),
            interval_seconds: hc.interval,
            timeout_seconds: hc.timeout,
            healthy_threshold: hc.healthy_threshold,
            unhealthy_threshold: hc.unhealthy_threshold,
        }
    };

    let first_port = probe_port(cfg);

    let health_check = first_port
        .and_then(|p| p.health_check.as_ref())
        .map(&health_check_to_proto);
    let liveness_probe = first_port
        .and_then(|p| p.liveness.as_ref())
        .map(&health_check_to_proto);
    let readiness_probe = first_port
        .and_then(|p| p.readiness.as_ref())
        .map(&health_check_to_proto);
    let startup_probe = first_port
        .and_then(|p| p.startup.as_ref())
        .map(&health_check_to_proto);

    let ports = cfg
        .ports
        .iter()
        .map(|(pname, pcfg)| crate::proto::PortSpec {
            name: pname.clone(),
            port: pcfg.port as u32,
            protocol: pcfg.protocol.clone().unwrap_or_default(),
            hostname: pcfg.hostname.clone().unwrap_or_default(),
        })
        .collect();

    let resources = Some(crate::proto::ResourceRequirements {
        cpu_request: cfg.resources.cpu.as_ref().map(|c| c.request).unwrap_or(0),
        memory_request: cfg
            .resources
            .memory
            .as_ref()
            .map(|m| m.request)
            .unwrap_or(0),
        cpu_limit: cfg
            .resources
            .cpu
            .as_ref()
            .and_then(|c| c.limit)
            .unwrap_or(0),
        memory_limit: cfg
            .resources
            .memory
            .as_ref()
            .and_then(|m| m.limit)
            .unwrap_or(0),
    });

    let lifecycle = Some(crate::proto::LifecycleHooks {
        pre_stop: cfg.lifecycle.pre_stop.clone().unwrap_or_default(),
        post_start: cfg.lifecycle.post_start.clone().unwrap_or_default(),
        stop_signal: cfg.lifecycle.stop_signal.clone(),
        termination_grace_period_seconds: cfg.lifecycle.termination_grace_period_seconds as u32,
    });

    let volumes = cfg
        .volumes
        .iter()
        .map(|v| crate::proto::VolumeMount {
            name: v.name.clone(),
            mount_path: v.mount_path.clone(),
            size_mb: v.size_mb,
            storage_class: v.storage_class.clone(),
            access_mode: format!("{:?}", v.access_mode),
            reclaim_retain: v.reclaim_retain,
        })
        .collect();

    let cgroup_controls = cfg.resources.to_cgroup_controls();

    let container_image = cfg
        .container
        .as_ref()
        .map(|c| c.image.clone())
        .unwrap_or_default();
    let container = cfg.container.as_ref().map(|c| {
        let list = |items: &Option<Vec<String>>| {
            items.as_ref().map(|items| crate::proto::StringList {
                items: items.clone(),
            })
        };
        crate::proto::ContainerOptions {
            entrypoint: list(&c.entrypoint),
            args: list(&c.args),
            working_dir: c.working_dir.clone().unwrap_or_default(),
            // Validated at apply.
            bind_mounts: c
                .parsed_bind_mounts()
                .unwrap_or_default()
                .into_iter()
                .map(|m| crate::proto::ContainerBindMount {
                    host_path: m.host_path,
                    container_path: m.container_path,
                    read_only: m.read_only,
                })
                .collect(),
            registry_auth_secret: c.registry_auth_secret.clone().unwrap_or_default(),
        }
    });

    crate::proto::ServiceSpec {
        name: name.to_string(),
        store_path: String::new(), // populated by deployer
        command: cfg.command.clone().unwrap_or_default(),
        environment: cfg.environment.clone(),
        resources,
        health_check,
        ports,
        liveness_probe,
        readiness_probe,
        startup_probe,
        lifecycle,
        volumes,
        cgroup_controls,
        container_image,
        namespace: cfg.namespace.clone(),
        namespace_ip: String::new(), // populated below from Raft IP allocations
        store_paths: cfg.store_paths.clone(),
        metrics: cfg.metrics.as_ref().map(|m| crate::proto::MetricsEndpoint {
            port: u32::from(m.port),
            path: m.path.clone(),
        }),
        templates: {
            let mut templates: Vec<_> = cfg
                .templates
                .values()
                .map(|t| crate::proto::TemplateSpec {
                    dest_path: t.dest_path.clone(),
                    source: t.source.clone(),
                    mode: config::template_mode(&t.perms).unwrap_or(0o644),
                    change_signal: t.change_signal.clone().unwrap_or_default(),
                })
                .collect();
            templates.sort_by(|a, b| a.dest_path.cmp(&b.dest_path));
            templates
        },
        secrets: config::declared_secrets(cfg),
        container,
    }
}

/// Push every node its complete `DesiredState` — every service placed on
/// it — before the deployer sends `DeployCommand` triggers.
///
/// Agents treat each `DesiredState` as authoritative and stop anything not
/// listed, so every known node (connected, previously assigned, or newly
/// placed) receives one, possibly empty. Services in `keep_previous` (blocked
/// by policy or whose volume migration failed) are not re-placed: each node
/// keeps whatever spec it was last assigned for them. Store paths carry over
/// from the node's previous assignment; new placements get theirs from the
/// deployer.
async fn send_desired_state(
    desired: &FleetConfig,
    plan: &ReconcilePlan,
    state: &FleetState,
    raft_state: &FleetStateMachine,
    keep_previous: &std::collections::HashSet<String>,
) -> Result<(), crate::raft::RaftError> {
    let mut nodes: std::collections::BTreeSet<String> =
        state.connected_nodes().await.into_iter().collect();
    nodes.extend(state.assigned_nodes().await);

    // Node → (service name → spec). Keyed by name so a service that appears
    // in several ops (e.g. update + reschedule) is listed once per node.
    let mut per_node: HashMap<
        String,
        std::collections::BTreeMap<String, crate::proto::ServiceSpec>,
    > = HashMap::new();

    let all_ops = plan
        .creates
        .iter()
        .chain(plan.updates.iter())
        .chain(plan.reschedules.iter())
        .filter(|op| !keep_previous.contains(&op.service_name));

    for op in all_ops {
        let Some(cfg) = desired.services.get(&op.service_name) else {
            continue;
        };
        let spec = service_config_to_spec(&op.service_name, cfg);
        let isolated = !crate::agent::netns::is_default_namespace(&cfg.namespace);

        for placement in &op.placements {
            let node = &placement.machine_name;
            nodes.insert(node.clone());
            let mut node_spec = spec.clone();
            node_spec.store_path = state
                .assigned_store_path(node, &op.service_name)
                .await
                .unwrap_or_default();
            // Each replica gets its own address in the namespace network.
            if isolated {
                let holder = namespace_ip_holder(&op.service_name, node);
                match raft_state
                    .ensure_namespace_ip(&cfg.namespace, &holder)
                    .await?
                {
                    Some(ip) => node_spec.namespace_ip = ip.to_string(),
                    None => tracing::error!(
                        service = %op.service_name,
                        namespace = %cfg.namespace,
                        node = %node,
                        "Namespace address space exhausted; replica gets no namespace IP"
                    ),
                }
            }
            per_node
                .entry(node.clone())
                .or_default()
                .insert(op.service_name.clone(), node_spec);
        }
    }

    // Held-back services stay exactly as previously assigned.
    let mut previous_system_paths: HashMap<String, String> = HashMap::new();
    for node in &nodes {
        let Some(previous) = state.assigned_desired_state(node).await else {
            continue;
        };
        previous_system_paths.insert(node.clone(), previous.system_path.clone());
        for spec in previous.services {
            if keep_previous.contains(&spec.name) {
                per_node
                    .entry(node.clone())
                    .or_default()
                    .insert(spec.name.clone(), spec);
            }
        }
    }

    let per_node: HashMap<String, Vec<crate::proto::ServiceSpec>> = per_node
        .into_iter()
        .map(|(node, specs)| (node, specs.into_values().collect()))
        .collect();

    // Free addresses of replicas no node runs any more (held-back specs
    // keep theirs); namespaces left empty lose their subnet.
    let live: std::collections::HashSet<(String, String)> = per_node
        .iter()
        .flat_map(|(node, specs)| {
            specs
                .iter()
                .filter(|spec| !spec.namespace_ip.is_empty())
                .map(move |spec| {
                    (
                        spec.namespace.clone(),
                        namespace_ip_holder(&spec.name, node),
                    )
                })
        })
        .collect();
    let released = raft_state.release_namespace_ips_except(&live).await?;
    if released > 0 {
        tracing::info!(released, "Released namespace IPs of removed replicas");
    }
    let mut subnets: HashMap<String, u8> = HashMap::new();
    for (ns, _) in &live {
        if !subnets.contains_key(ns)
            && let Some(octet) = raft_state.namespace_subnet(ns).await
        {
            subnets.insert(ns.clone(), octet);
        }
    }

    // Track which namespaces each node participates in.
    let mut per_node_namespaces: HashMap<String, std::collections::HashSet<String>> =
        HashMap::new();
    for (node, specs) in &per_node {
        for spec in specs {
            if !spec.namespace.is_empty() && spec.namespace != "default" {
                per_node_namespaces
                    .entry(node.clone())
                    .or_default()
                    .insert(spec.namespace.clone());
            }
        }
    }

    // Build cross-reference: namespace → [(node_id, [(service_name, ip, ports)])]
    // Used to populate remote_peers so each node knows about other nodes in
    // the same namespace for VXLAN tunnel setup.
    let mut ns_to_nodes: HashMap<String, Vec<(String, Vec<crate::proto::RemoteServiceEndpoint>)>> =
        HashMap::new();
    for (node_id, services) in &per_node {
        for svc in services {
            if !svc.namespace.is_empty()
                && svc.namespace != "default"
                && !svc.namespace_ip.is_empty()
            {
                let ports: Vec<u32> = svc.ports.iter().map(|p| p.port).collect();
                let entry = ns_to_nodes.entry(svc.namespace.clone()).or_default();
                if let Some((_, svc_list)) = entry.iter_mut().find(|(n, _)| n == node_id) {
                    svc_list.push(crate::proto::RemoteServiceEndpoint {
                        service_name: svc.name.clone(),
                        ip: svc.namespace_ip.clone(),
                        ports,
                    });
                } else {
                    entry.push((
                        node_id.clone(),
                        vec![crate::proto::RemoteServiceEndpoint {
                            service_name: svc.name.clone(),
                            ip: svc.namespace_ip.clone(),
                            ports,
                        }],
                    ));
                }
            }
        }
    }

    // Pre-fetch mesh IPs for all participating nodes to avoid repeated async lookups
    let mut mesh_ips: HashMap<String, std::net::Ipv4Addr> = HashMap::new();
    for node_id in per_node.keys() {
        if let Some(ip) = state.mesh_ip_for_node(node_id).await {
            mesh_ips.insert(node_id.clone(), ip);
        }
    }

    for node in &nodes {
        let services = per_node.get(node).cloned().unwrap_or_default();
        // Build NamespaceNetworkConfig for namespaces this node participates in
        let namespace_networks = per_node_namespaces
            .get(node)
            .map(|namespaces| {
                namespaces
                    .iter()
                    .filter_map(|ns| {
                        let third_octet = *subnets.get(ns)?;

                        // Populate remote_peers: other nodes in the same namespace
                        let remote_peers = ns_to_nodes
                            .get(ns)
                            .map(|nodes| {
                                nodes
                                    .iter()
                                    .filter(|(other, _)| other != node)
                                    .filter_map(|(other, svcs)| {
                                        let endpoint = mesh_ips.get(other)?;
                                        Some(crate::proto::NamespaceRemotePeer {
                                            node_id: other.clone(),
                                            tunnel_endpoint: endpoint.to_string(),
                                            services: svcs.clone(),
                                        })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        Some(crate::proto::NamespaceNetworkConfig {
                            namespace: ns.clone(),
                            subnet: format!("10.200.{third_octet}.0/24"),
                            gateway: format!("10.200.{third_octet}.1"),
                            vni: third_octet as u32,
                            remote_peers,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let desired_state = crate::proto::DesiredState {
            correlation_id: String::new(),
            services,
            system_path: previous_system_paths.remove(node).unwrap_or_default(),
            namespace_networks,
            cache_public_key: String::new(), // stamped by assign_desired_state
            signature_policy_json: desired
                .signature_policy
                .as_ref()
                .and_then(|p| serde_json::to_string(p).ok())
                .unwrap_or_default(),
        };
        if !state.assign_desired_state(node, desired_state).await {
            tracing::warn!(
                node = %node,
                "Node not connected; DesiredState will be sent when it reconnects"
            );
        }
    }

    // DNS records follow from these assignments; see `super::dns`.
    Ok(())
}

/// How long the source keeps a service stopped and its export open.
const MIGRATION_EXPORT_TTL_SECS: u32 = 900;

/// Move `service`'s volumes from `source` to `dest`: the source stops the
/// service and grants the destination one pull, then the destination pulls
/// over the mesh. If the pull never happens the source starts the service
/// again once the grant expires.
async fn migrate_volumes(
    state: &FleetState,
    service: &str,
    source: &str,
    dest: &str,
) -> Result<(), String> {
    use crate::proto::server_message::Payload;
    let source_ip = state
        .mesh_ip_for_node(source)
        .await
        .ok_or_else(|| format!("{source} has no mesh address"))?;
    let (Some(source_id), Some(dest_id)) =
        (state.agent_spiffe_id(source), state.agent_spiffe_id(dest))
    else {
        return Err("the server's trust domain is not known".into());
    };
    let command = |payload| crate::proto::ServerMessage {
        payload: Some(payload),
    };
    let run = |node: &str, payload, correlation_id: String, timeout| {
        let node = node.to_string();
        async move {
            match state
                .send_command(&node, command(payload), correlation_id, timeout)
                .await
            {
                Ok(resp) if resp.success => Ok(()),
                Ok(resp) => Err(format!("{node}: {}", resp.error_message)),
                Err(e) => Err(format!("{node}: {e}")),
            }
        }
    };

    let correlation_id = uuid::Uuid::new_v4().to_string();
    run(
        source,
        Payload::ExportVolumesCommand(crate::proto::ExportVolumesCommand {
            correlation_id: correlation_id.clone(),
            service_name: service.to_string(),
            dest_spiffe_id: dest_id,
            ttl_seconds: MIGRATION_EXPORT_TTL_SECS,
        }),
        correlation_id,
        Duration::from_secs(120),
    )
    .await
    .map_err(|e| format!("export from {e}"))?;

    let correlation_id = uuid::Uuid::new_v4().to_string();
    run(
        dest,
        Payload::MigrateVolumeCommand(crate::proto::MigrateVolumeCommand {
            correlation_id: correlation_id.clone(),
            service_name: service.to_string(),
            source_addr: format!(
                "{source_ip}:{}",
                crate::agent::migrate::VOLUME_TRANSFER_PORT
            ),
            source_spiffe_id: source_id,
        }),
        correlation_id,
        Duration::from_secs(u64::from(MIGRATION_EXPORT_TTL_SECS)),
    )
    .await
    .map_err(|e| format!("pull to {e}"))
}

/// Execute a reconciliation plan.
async fn apply_plan(
    desired: &FleetConfig,
    plan: &ReconcilePlan,
    state: &FleetState,
    raft_state: &FleetStateMachine,
    events: Option<&super::events::EventStore>,
) -> Result<(), deployer::DeployError> {
    // Execute volume migrations for reschedules before deploying.
    // Migrations run first so data is available on the destination node
    // before the service starts there. Services whose migrations fail are
    // skipped to prevent data loss.
    let mut migration_failed_services: Vec<String> = Vec::new();

    for op in &plan.reschedules {
        if op.migrations.is_empty() {
            continue;
        }

        let service_cfg = match desired.services.get(&op.service_name) {
            Some(cfg) => cfg,
            None => continue,
        };
        let max_parallel = service_cfg.scheduling.migrate.max_parallel as usize;

        let mut results: Vec<MigrationResult> = Vec::new();
        for chunk in op.migrations.chunks(max_parallel.max(1)) {
            let mut handles = Vec::new();
            for migration in chunk {
                let service_name = op.service_name.clone();
                let source = migration.source_machine.clone();
                let dest_machine = migration.dest_machine.clone();
                let instance_id = migration.instance_id.clone();
                let s = state.clone();

                // Each migration task returns a per-instance MigrationResult so
                // the caller can reason about partial failures: which instances
                // reached the destination and which did not.
                handles.push(tokio::spawn(async move {
                    let error = migrate_volumes(&s, &service_name, &source, &dest_machine)
                        .await
                        .err();
                    match &error {
                        Some(e) => tracing::error!(
                            service = %service_name,
                            source = %source,
                            dest = %dest_machine,
                            error = %e,
                            "Volume migration failed"
                        ),
                        None => tracing::info!(
                            service = %service_name,
                            source = %source,
                            dest = %dest_machine,
                            "Volume migration completed"
                        ),
                    }
                    MigrationResult {
                        instance_id,
                        dest_machine,
                        error,
                    }
                }));
            }
            for handle in handles {
                match handle.await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        // A panicked task means we cannot account for that
                        // instance's data at all; treat it as a failure with an
                        // unknown destination so the service is skipped.
                        tracing::error!(
                            service = %op.service_name,
                            error = %e,
                            "Volume migration task panicked"
                        );
                        results.push(MigrationResult {
                            instance_id: String::new(),
                            dest_machine: String::new(),
                            error: Some(format!("migration task panicked: {e}")),
                        });
                    }
                }
            }
        }

        // Partial-failure semantics: a reschedule is all-or-nothing. If any
        // instance failed to migrate, skip the whole service's cutover so the
        // service stays on its source nodes (source data is untouched — the
        // pull copies, it does not move — and the source restarts the service
        // when its export grant expires). Surface the destinations that *did*
        // receive data as orphaned partial copies; a retry replaces them.
        if let Some(summary) = summarize_migration_failure(&results) {
            tracing::error!(
                service = %op.service_name,
                failed = ?summary.failed_instances,
                partial_dests = ?summary.orphaned_destinations,
                "Volume migration partially failed — skipping reschedule to prevent data loss; \
                 destinations listed hold orphaned partial copies from this attempt"
            );
            migration_failed_services.push(op.service_name.clone());
        }
    }

    // Services that must not move this cycle: blocked by policy, or whose
    // volume migration failed (they stay on their source nodes).
    let keep_previous: std::collections::HashSet<String> = plan
        .policy_blocked
        .iter()
        .map(|b| b.service_name.clone())
        .chain(migration_failed_services.iter().cloned())
        .collect();

    // Send full ServiceSpec (with cgroup controls, health checks, lifecycle
    // hooks, etc.) to every agent before the deployer sends lightweight
    // DeployCommand triggers. This ensures agents have the complete service
    // definition — including resource limits — before starting workloads,
    // and stop services no longer assigned to them.
    send_desired_state(desired, plan, state, raft_state, &keep_previous).await?;
    record_undeploys(desired, raft_state).await?;

    // Compute deployment order
    let tiers = deployer::compute_deploy_order(&desired.services);

    for tier in &tiers {
        for service_name in tier {
            // Find ops for this service (creates, updates, and reschedules).
            // Held-back services (policy-blocked, failed migrations) are not
            // deployed to their new placements at all.
            if keep_previous.contains(service_name) {
                continue;
            }
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

                // Look up previous store_path from Raft state for auto-revert
                let previous_store_path = raft_state
                    .get_deployment(service_name)
                    .await
                    .map(|d| d.store_path);

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
                    previous_store_path,
                    // The agent probes the unified health check only.
                    health_checked: probe_port(service_cfg)
                        .is_some_and(|p| p.health_check.is_some()),
                };
                let store_path = deploy_plan.store_path.clone();

                match deployer::execute(state, deploy_plan, events).await {
                    Ok(()) => {
                        record_deployment(raft_state, service_name, &store_path, &op.placements)
                            .await?;
                    }
                    Err(deployer::DeployError::AwaitingPromotion(id)) => {
                        tracing::info!(
                            service = %service_name,
                            deployment_id = %id,
                            "Canary awaiting promotion — skipping remaining services in this tier"
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    super::rebalance::settle(
        desired,
        plan,
        &migration_failed_services,
        raft_state,
        events,
    )
    .await;
    Ok(())
}

/// Record a completed rollout in Raft, unless it changes nothing (the
/// reconciler re-converges unchanged services every cycle).
async fn record_deployment(
    raft_state: &FleetStateMachine,
    service_name: &str,
    store_path: &str,
    placements: &[Placement],
) -> Result<(), crate::raft::RaftError> {
    let placements: Vec<PlacementRecord> = placements
        .iter()
        .map(|p| PlacementRecord {
            instance_id: p.instance_id.clone(),
            machine_name: p.machine_name.clone(),
        })
        .collect();
    if let Some(current) = raft_state.get_deployment(service_name).await
        && !current.differs_from(store_path, &placements)
    {
        return Ok(());
    }
    raft_state
        .apply_next(Command::Deploy {
            service_name: service_name.to_string(),
            store_path: store_path.to_string(),
            placements,
        })
        .await?;
    Ok(())
}

/// Forget deployments of services that left the desired state. Agents have
/// already been sent desired state without them.
async fn record_undeploys(
    desired: &FleetConfig,
    raft_state: &FleetStateMachine,
) -> Result<(), crate::raft::RaftError> {
    for service_name in raft_state.all_deployments().await.into_keys() {
        if !desired.services.contains_key(&service_name) {
            raft_state
                .apply_next(Command::Undeploy {
                    service_name: service_name.clone(),
                })
                .await?;
            tracing::info!(service = %service_name, "Deployment removed from fleet state");
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

    fn mig_result(instance: &str, dest: &str, err: Option<&str>) -> MigrationResult {
        MigrationResult {
            instance_id: instance.to_string(),
            dest_machine: dest.to_string(),
            error: err.map(|e| e.to_string()),
        }
    }

    #[test]
    fn all_migrations_succeed_allows_reschedule() {
        // No failures — the reschedule may proceed, so no summary is produced.
        let results = vec![
            mig_result("i0", "node-b", None),
            mig_result("i1", "node-c", None),
        ];
        assert!(summarize_migration_failure(&results).is_none());
    }

    #[test]
    fn empty_results_allows_reschedule() {
        assert!(summarize_migration_failure(&[]).is_none());
    }

    #[test]
    fn total_failure_reports_no_orphans() {
        // Every migration failed, so nothing reached a destination — there are
        // no orphaned partial copies to clean up, only failed instances.
        let results = vec![
            mig_result("i0", "node-b", Some("timeout")),
            mig_result("i1", "node-c", Some("rsync failed")),
        ];
        let summary = summarize_migration_failure(&results).expect("failure expected");
        assert_eq!(summary.failed_instances, vec!["i0", "i1"]);
        assert!(summary.orphaned_destinations.is_empty());
    }

    #[test]
    fn partial_failure_reports_orphaned_destinations() {
        // i0 reached node-b, i1 failed. The whole reschedule is abandoned, so
        // node-b now holds an orphaned partial copy that must be surfaced.
        let results = vec![
            mig_result("i0", "node-b", None),
            mig_result("i1", "node-c", Some("dest unreachable")),
        ];
        let summary = summarize_migration_failure(&results).expect("failure expected");
        assert_eq!(summary.failed_instances, vec!["i1"]);
        assert_eq!(summary.orphaned_destinations, vec!["node-b"]);
    }

    #[test]
    fn orphaned_destinations_are_deduped_and_sorted() {
        // Two instances succeeded onto the same destination; it should appear
        // once. Ordering is deterministic for stable logging/testing.
        let results = vec![
            mig_result("i0", "node-z", None),
            mig_result("i1", "node-a", None),
            mig_result("i2", "node-z", None),
            mig_result("i3", "node-b", Some("boom")),
        ];
        let summary = summarize_migration_failure(&results).expect("failure expected");
        assert_eq!(summary.orphaned_destinations, vec!["node-a", "node-z"]);
    }

    #[test]
    fn panicked_task_with_empty_dest_is_not_an_orphan() {
        // A panicked task is recorded with an empty destination; it counts as a
        // failure but must not be reported as an orphaned destination.
        let results = vec![
            mig_result("i0", "node-b", None),
            mig_result("", "", Some("migration task panicked")),
        ];
        let summary = summarize_migration_failure(&results).expect("failure expected");
        assert_eq!(summary.orphaned_destinations, vec!["node-b"]);
        assert!(summary.failed_instances.contains(&String::new()));
    }

    fn empty_fleet_config() -> FleetConfig {
        FleetConfig {
            name: "test".into(),
            domain: "fleet.internal".into(),
            services: HashMap::new(),
            machines: HashMap::new(),
            node_pools: HashMap::new(),
            webhooks: vec![],
            admission_webhooks: vec![],
            namespaces: Default::default(),
            policies: vec![],
            signature_policy: None,
            alerts: vec![],
            secret_engines: HashMap::new(),
            external_services: HashMap::new(),
            federation: Default::default(),
            ingress: HashMap::new(),
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
            .await
            .unwrap();
        tracker
            .associate_node("i-abc", "node-cloud-1")
            .await
            .unwrap();

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
            .await
            .unwrap();

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
            .await
            .unwrap();
        tracker.associate_node("i-dup", "node-1").await.unwrap();

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
                namespace: String::new(),
                metrics: None,
                store_paths: vec![],
                transit_keys: vec![],
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

    #[tokio::test]
    async fn draining_moves_stateful_services_with_their_volumes() {
        let state = FleetState::new();
        let mut config = empty_fleet_config();
        let mut receivers = Vec::new();
        for node in ["alpha", "beta"] {
            receivers.push(
                state
                    .register_agent(node, "127.0.0.1:5000".into(), "default".into())
                    .await,
            );
            config.machines.insert(
                node.into(),
                MachineConfig {
                    target_host: node.into(),
                    labels: HashMap::new(),
                    capacity: CapacityConfig {
                        cpu: 4000,
                        memory: 8192,
                        disk: 0,
                    },
                    pool: "default".into(),
                    reserved: CapacityConfig::default(),
                    taints: vec![],
                    extended_resources: HashMap::new(),
                },
            );
        }
        let mut db = simple_service();
        db.scheduling.job_type = config::JobType::Stateful;
        db.volumes = vec![
            serde_json::from_value(serde_json::json!({
                "name": "data",
                "mountPath": "/var/lib/db",
            }))
            .unwrap(),
        ];
        config.services.insert("db".into(), db);
        state
            .update_status(
                "alpha",
                vec![crate::proto::ServiceInstance {
                    service_name: "db".into(),
                    instance_id: "db-0".into(),
                    store_path: String::new(),
                    state: crate::proto::ServiceState::ServiceRunning as i32,
                }],
            )
            .await;
        let raft = FleetStateMachine::new();
        // The service was placed on alpha.
        raft.apply_next(crate::raft::state::Command::Deploy {
            service_name: "db".into(),
            store_path: String::new(),
            placements: vec![crate::raft::state::PlacementRecord {
                instance_id: "db-0".into(),
                machine_name: "alpha".into(),
            }],
        })
        .await
        .unwrap();

        // Cordoning keeps the service where it is.
        state.set_schedulable("alpha", false).await;
        let plan = compute_plan(&config, &[], &state, None, &raft).await;
        assert!(plan.reschedules.is_empty());

        state.set_draining("alpha").await;
        let plan = compute_plan(&config, &[], &state, None, &raft).await;
        let [op] = plan.reschedules.as_slice() else {
            panic!("expected one reschedule, got {:?}", plan.reschedules);
        };
        assert_eq!(op.placements[0].machine_name, "beta");
        let [migration] = op.migrations.as_slice() else {
            panic!("expected one migration, got {:?}", op.migrations);
        };
        assert_eq!(
            (
                migration.source_machine.as_str(),
                migration.dest_machine.as_str()
            ),
            ("alpha", "beta")
        );

        // Making the node schedulable again ends the drain.
        state.set_schedulable("alpha", true).await;
        assert!(state.draining_nodes().await.is_empty());
    }

    #[tokio::test]
    async fn requested_moves_reschedule_and_settle() {
        let state = FleetState::new();
        let mut config = empty_fleet_config();
        let mut receivers = Vec::new();
        for node in ["alpha", "beta"] {
            receivers.push(
                state
                    .register_agent(node, "127.0.0.1:5000".into(), "default".into())
                    .await,
            );
            config.machines.insert(
                node.into(),
                MachineConfig {
                    target_host: node.into(),
                    labels: HashMap::new(),
                    capacity: CapacityConfig {
                        cpu: 4000,
                        memory: 8192,
                        disk: 0,
                    },
                    pool: "default".into(),
                    reserved: CapacityConfig::default(),
                    taints: vec![],
                    extended_resources: HashMap::new(),
                },
            );
        }
        let mut db = simple_service();
        db.scheduling.job_type = config::JobType::Stateful;
        db.volumes = vec![
            serde_json::from_value(serde_json::json!({
                "name": "data",
                "mountPath": "/var/lib/db",
            }))
            .unwrap(),
        ];
        config.services.insert("db".into(), db);
        state
            .update_status(
                "alpha",
                vec![crate::proto::ServiceInstance {
                    service_name: "db".into(),
                    instance_id: "db-0".into(),
                    store_path: String::new(),
                    state: crate::proto::ServiceState::ServiceRunning as i32,
                }],
            )
            .await;
        let raft = FleetStateMachine::new();
        let record = |node: &str| crate::raft::state::Command::Deploy {
            service_name: "db".into(),
            store_path: String::new(),
            placements: vec![crate::raft::state::PlacementRecord {
                instance_id: "db-0".into(),
                machine_name: node.into(),
            }],
        };
        raft.apply_next(record("alpha")).await.unwrap();
        let plan = compute_plan(&config, &[], &state, None, &raft).await;
        assert!(plan.reschedules.is_empty(), "the instance sticks to alpha");

        raft.set_placement_move("db", "db-0", "beta").await.unwrap();
        let plan = compute_plan(&config, &[], &state, None, &raft).await;
        let [op] = plan.reschedules.as_slice() else {
            panic!("expected one reschedule, got {:?}", plan.reschedules);
        };
        assert_eq!(op.placements[0].machine_name, "beta");
        assert_eq!(op.migrations.len(), 1);

        // Still on its way: the move stays.
        let events = super::super::events::EventStore::new();
        super::super::rebalance::settle(&config, &plan, &[], &raft, Some(&events)).await;
        assert_eq!(raft.placement_moves().await.len(), 1);

        // Recorded on beta: the move is done.
        raft.apply_next(record("beta")).await.unwrap();
        super::super::rebalance::settle(&config, &plan, &[], &raft, Some(&events)).await;
        assert!(raft.placement_moves().await.is_empty());
        assert!(
            events
                .query(None, None, 100)
                .await
                .iter()
                .any(|e| e.kind == "rebalance.completed")
        );

        // A failed migration abandons the move.
        raft.set_placement_move("db", "db-0", "alpha")
            .await
            .unwrap();
        super::super::rebalance::settle(&config, &plan, &["db".into()], &raft, Some(&events)).await;
        assert!(raft.placement_moves().await.is_empty());
    }

    /// Agents report what they run on their heartbeat. A stateful service
    /// moved before its node reported it still takes its data along: its
    /// recorded placement says where the volume is.
    #[tokio::test]
    async fn moves_before_the_first_report_migrate_from_the_recorded_node() {
        let state = FleetState::new();
        let mut config = empty_fleet_config();
        let mut receivers = Vec::new();
        for node in ["alpha", "beta"] {
            receivers.push(
                state
                    .register_agent(node, "127.0.0.1:5000".into(), "default".into())
                    .await,
            );
            config.machines.insert(
                node.into(),
                MachineConfig {
                    target_host: node.into(),
                    labels: HashMap::new(),
                    capacity: CapacityConfig {
                        cpu: 4000,
                        memory: 8192,
                        disk: 0,
                    },
                    pool: "default".into(),
                    reserved: CapacityConfig::default(),
                    taints: vec![],
                    extended_resources: HashMap::new(),
                },
            );
        }
        let mut db = simple_service();
        db.scheduling.job_type = config::JobType::Stateful;
        db.volumes = vec![
            serde_json::from_value(serde_json::json!({
                "name": "data",
                "mountPath": "/var/lib/db",
            }))
            .unwrap(),
        ];
        config.services.insert("db".into(), db);
        // Placed on alpha, which has not reported it yet.
        let raft = FleetStateMachine::new();
        raft.apply_next(crate::raft::state::Command::Deploy {
            service_name: "db".into(),
            store_path: String::new(),
            placements: vec![crate::raft::state::PlacementRecord {
                instance_id: "db-0".into(),
                machine_name: "alpha".into(),
            }],
        })
        .await
        .unwrap();
        let plan = compute_plan(&config, &[], &state, None, &raft).await;
        assert!(plan.creates.is_empty(), "{:?}", plan.creates);
        assert!(plan.reschedules.is_empty());

        raft.set_placement_move("db", "db-0", "beta").await.unwrap();
        let plan = compute_plan(&config, &[], &state, None, &raft).await;
        let [op] = plan.reschedules.as_slice() else {
            panic!("expected one reschedule, got {:?}", plan.reschedules);
        };
        let [migration] = op.migrations.as_slice() else {
            panic!("expected one migration, got {:?}", op.migrations);
        };
        assert_eq!(
            (
                migration.source_machine.as_str(),
                migration.dest_machine.as_str()
            ),
            ("alpha", "beta")
        );
    }

    fn simple_service() -> ServiceConfig {
        ServiceConfig {
            command: Some("/bin/svc".into()),
            container: None,
            ports: HashMap::new(),
            secrets: HashMap::new(),
            identity: Default::default(),
            resources: Default::default(),
            scheduling: SchedulingConfig::default(),
            environment: HashMap::new(),
            templates: HashMap::new(),
            lifecycle: Default::default(),
            volumes: vec![],
            sidecars: vec![],
            namespace: String::new(),
            metrics: None,
            store_paths: vec![],
            transit_keys: vec![],
        }
    }

    fn op(service: &str, machine: &str) -> ServiceOp {
        ServiceOp {
            service_name: service.into(),
            placements: vec![Placement {
                service_name: service.into(),
                instance_id: format!("{service}-0"),
                machine_name: machine.into(),
            }],
            description: String::new(),
            migrations: vec![],
        }
    }

    fn empty_plan() -> ReconcilePlan {
        ReconcilePlan {
            creates: vec![],
            updates: vec![],
            destroys: vec![],
            reschedules: vec![],
            has_changes: true,
            policy_blocked: vec![],
        }
    }

    fn desired_services(
        rx: &mut tokio::sync::mpsc::Receiver<crate::proto::ServerMessage>,
    ) -> Vec<String> {
        let msg = rx.try_recv().expect("node should receive a DesiredState");
        match msg.payload {
            Some(crate::proto::server_message::Payload::DesiredState(ds)) => {
                let mut names: Vec<String> = ds.services.into_iter().map(|s| s.name).collect();
                names.sort();
                names
            }
            other => panic!("expected DesiredState, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn desired_state_is_full_per_node_set() {
        let state = FleetState::new();
        let assignments = state.service_assignments();
        let mut rx1 = state
            .register_agent("node-1", "127.0.0.1:1".into(), "default".into())
            .await;
        let mut rx2 = state
            .register_agent("node-2", "127.0.0.1:2".into(), "default".into())
            .await;

        let mut config = empty_fleet_config();
        config.services.insert("web".into(), simple_service());
        config.services.insert("api".into(), simple_service());
        let raft = FleetStateMachine::new();

        // First pass: web on node-1 (created), api on node-2 (created).
        let mut plan = empty_plan();
        plan.creates = vec![op("web", "node-1"), op("api", "node-2")];
        send_desired_state(
            &config,
            &plan,
            &state,
            &raft,
            &std::collections::HashSet::new(),
        )
        .await
        .unwrap();
        assert_eq!(desired_services(&mut rx1), vec!["web"]);
        assert_eq!(desired_services(&mut rx2), vec!["api"]);
        assert!(assignments.is_assigned("node-1", "web").await);
        assert!(!assignments.is_assigned("node-1", "api").await);
        assert!(assignments.is_assigned("node-2", "api").await);

        // Second pass: api destroyed, web unchanged. node-2 must receive an
        // empty (authoritative) set so the agent stops api, and its SVID
        // authorization must be revoked.
        let mut plan = empty_plan();
        plan.updates = vec![op("web", "node-1")];
        plan.destroys = vec![op("api", "node-2")];
        send_desired_state(
            &config,
            &plan,
            &state,
            &raft,
            &std::collections::HashSet::new(),
        )
        .await
        .unwrap();
        assert_eq!(desired_services(&mut rx1), vec!["web"]);
        assert!(desired_services(&mut rx2).is_empty());
        assert!(!assignments.is_assigned("node-2", "api").await);
        assert!(assignments.is_assigned("node-1", "web").await);
    }

    /// The last DesiredState queued for a node.
    fn drain(
        rx: &mut tokio::sync::mpsc::Receiver<crate::proto::ServerMessage>,
    ) -> crate::proto::DesiredState {
        let mut desired = None;
        while let Ok(msg) = rx.try_recv() {
            if let Some(crate::proto::server_message::Payload::DesiredState(ds)) = msg.payload {
                desired = Some(ds);
            }
        }
        desired.expect("a DesiredState")
    }

    #[tokio::test]
    async fn namespace_replicas_get_unique_ips_and_tenants_unique_subnets() {
        let state = FleetState::new();
        let mut rx1 = state
            .register_agent("node-1", "127.0.0.1:1".into(), "default".into())
            .await;
        let mut rx2 = state
            .register_agent("node-2", "127.0.0.1:2".into(), "default".into())
            .await;
        let mut config = empty_fleet_config();
        let mut web = simple_service();
        web.namespace = "acme".into();
        let mut db = simple_service();
        db.namespace = "globex".into();
        config.services.insert("web".into(), web);
        config.services.insert("db".into(), db);
        let raft = FleetStateMachine::new();

        let web_op = || {
            let mut web = op("web", "node-1");
            web.placements.push(Placement {
                service_name: "web".into(),
                instance_id: "web-1".into(),
                machine_name: "node-2".into(),
            });
            web
        };
        let mut plan = empty_plan();
        plan.creates = vec![web_op(), op("db", "node-1")];
        let none = std::collections::HashSet::new();
        send_desired_state(&config, &plan, &state, &raft, &none)
            .await
            .unwrap();

        let ds1 = drain(&mut rx1);
        let ds2 = drain(&mut rx2);
        let ip = |ds: &crate::proto::DesiredState, name: &str| {
            let spec = ds.services.iter().find(|s| s.name == name).unwrap();
            spec.namespace_ip.parse::<std::net::Ipv4Addr>().unwrap()
        };
        let (web1, web2, db1) = (ip(&ds1, "web"), ip(&ds2, "web"), ip(&ds1, "db"));
        assert_ne!(web1, web2, "replicas share one overlay segment");
        assert_eq!(web1.octets()[2], web2.octets()[2]);
        assert_ne!(web1.octets()[2], db1.octets()[2], "tenants share a subnet");

        // Each node's network config uses the allocated subnet as VNI.
        let acme = raft.namespace_subnet("acme").await.unwrap();
        let net = ds2
            .namespace_networks
            .iter()
            .find(|n| n.namespace == "acme")
            .unwrap();
        assert_eq!(net.subnet, format!("10.200.{acme}.0/24"));
        assert_eq!(net.vni, acme as u32);
        assert!(
            !ds2.namespace_networks
                .iter()
                .any(|n| n.namespace == "globex")
        );

        // Same placement again keeps the same addresses.
        send_desired_state(&config, &plan, &state, &raft, &none)
            .await
            .unwrap();
        assert_eq!(ip(&drain(&mut rx2), "web"), web2);

        // db leaves: its address and the globex subnet are released.
        config.services.remove("db");
        let mut plan = empty_plan();
        plan.updates = vec![web_op()];
        plan.destroys = vec![op("db", "node-1")];
        send_desired_state(&config, &plan, &state, &raft, &none)
            .await
            .unwrap();
        assert!(raft.namespace_ips("globex").await.is_empty());
        assert_eq!(raft.namespace_subnet("globex").await, None);
        assert_eq!(raft.namespace_ips("acme").await.len(), 2);
    }

    #[tokio::test]
    async fn held_back_services_keep_previous_placement() {
        let state = FleetState::new();
        let assignments = state.service_assignments();
        let mut rx1 = state
            .register_agent("node-1", "127.0.0.1:1".into(), "default".into())
            .await;
        let mut rx2 = state
            .register_agent("node-2", "127.0.0.1:2".into(), "default".into())
            .await;

        let mut config = empty_fleet_config();
        config.services.insert("db".into(), simple_service());
        let raft = FleetStateMachine::new();

        let mut plan = empty_plan();
        plan.creates = vec![op("db", "node-1")];
        send_desired_state(
            &config,
            &plan,
            &state,
            &raft,
            &std::collections::HashSet::new(),
        )
        .await
        .unwrap();
        assert_eq!(desired_services(&mut rx1), vec!["db"]);
        assert!(desired_services(&mut rx2).is_empty());

        // A reschedule to node-2 whose volume migration failed: db must stay
        // on node-1 and must not be started on node-2.
        let mut plan = empty_plan();
        plan.reschedules = vec![op("db", "node-2")];
        let keep: std::collections::HashSet<String> = ["db".to_string()].into();
        send_desired_state(&config, &plan, &state, &raft, &keep)
            .await
            .unwrap();
        assert_eq!(desired_services(&mut rx1), vec!["db"]);
        assert!(desired_services(&mut rx2).is_empty());
        assert!(assignments.is_assigned("node-1", "db").await);
        assert!(!assignments.is_assigned("node-2", "db").await);
    }

    fn placed(instance: &str, machine: &str) -> Placement {
        Placement {
            service_name: "web".into(),
            instance_id: instance.into(),
            machine_name: machine.into(),
        }
    }

    #[tokio::test]
    async fn rollouts_are_recorded_once_and_removed_services_undeployed() {
        let raft = FleetStateMachine::new();
        let placements = [placed("web-0", "node-1")];
        record_deployment(&raft, "web", "/nix/store/a", &placements)
            .await
            .unwrap();
        // Re-converging an unchanged service writes nothing.
        record_deployment(&raft, "web", "/nix/store/a", &placements)
            .await
            .unwrap();
        assert_eq!(raft.last_applied().await, 1);

        record_deployment(&raft, "web", "/nix/store/b", &placements)
            .await
            .unwrap();
        let web = raft.get_deployment("web").await.unwrap();
        assert_eq!(
            (web.generation, web.store_path.as_str()),
            (2, "/nix/store/b")
        );
        assert_eq!(web.revision(1).unwrap().store_path, "/nix/store/a");

        let mut desired = empty_fleet_config();
        desired.services.insert("web".into(), simple_service());
        record_undeploys(&desired, &raft).await.unwrap();
        assert!(raft.get_deployment("web").await.is_some());

        record_undeploys(&empty_fleet_config(), &raft)
            .await
            .unwrap();
        assert!(raft.get_deployment("web").await.is_none());
    }
}
