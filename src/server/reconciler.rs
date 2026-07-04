#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use super::deployer::{self, DeploymentPlan};
use super::nix;
use super::scheduler::{self, Placement};
use super::state::FleetState;
use crate::config::FleetConfig;

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("nix eval failed: {0}")]
    NixEval(#[from] nix::NixError),
    #[error("deployment failed: {0}")]
    Deploy(#[from] deployer::DeployError),
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
}

/// Run a single reconciliation cycle: eval → refresh → plan → apply.
pub async fn reconcile_once(
    config_path: &Path,
    state: &FleetState,
    auto_approve: bool,
) -> Result<ReconcilePlan, ReconcileError> {
    // 1. Evaluate: get desired state from Nix
    tracing::info!(config = %config_path.display(), "Evaluating fleet configuration");
    let desired = nix::eval_fleet(config_path).await?;

    // 2. Refresh: query current state from agents
    let current_nodes = state.connected_nodes().await;
    tracing::info!(nodes = current_nodes.len(), "Current fleet state refreshed");

    // 3. Plan: diff desired vs actual
    let plan = compute_plan(&desired, &current_nodes, state).await;

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
) -> Result<(), ReconcileError> {
    tracing::info!(
        interval = ?interval,
        "Starting continuous reconciliation"
    );

    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        match reconcile_once(config_path, state, true).await {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "Reconciliation cycle failed");
            }
        }
    }
}

/// Compare desired state with actual state to produce operations.
async fn compute_plan(
    desired: &FleetConfig,
    _current_nodes: &[String],
    state: &FleetState,
) -> ReconcilePlan {
    // Schedule services across machines
    let placement_plan = scheduler::schedule(&desired.services, &desired.machines);

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
    let destroys = Vec::new();
    let reschedules = Vec::new();

    let (_, current_services) = state.fleet_status().await;
    let current_service_names: Vec<&str> =
        current_services.iter().map(|s| s.name.as_str()).collect();

    for (service_name, placements) in &placements_by_service {
        if current_service_names.contains(&service_name.as_str()) {
            updates.push(ServiceOp {
                service_name: service_name.clone(),
                placements: placements.clone(),
                description: format!("Update {service_name} ({} instances)", placements.len()),
            });
        } else {
            creates.push(ServiceOp {
                service_name: service_name.clone(),
                placements: placements.clone(),
                description: format!("Create {service_name} ({} instances)", placements.len()),
            });
        }
    }

    // TODO: detect services that should be destroyed (in current but not desired)
    // TODO: detect reschedules (same service, different placement)

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
    // Compute deployment order
    let tiers = deployer::compute_deploy_order(&desired.services);

    for tier in &tiers {
        for service_name in tier {
            // Find ops for this service
            let ops: Vec<&ServiceOp> = plan
                .creates
                .iter()
                .chain(plan.updates.iter())
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
                    store_path: String::new(), // TODO: resolve from nix build
                    auto_revert: service_cfg.scheduling.update.auto_revert,
                    min_healthy_time: Duration::from_secs(
                        service_cfg.scheduling.update.min_healthy_time_secs,
                    ),
                    healthy_deadline: Duration::from_secs(
                        service_cfg.scheduling.update.healthy_deadline_secs,
                    ),
                };

                deployer::execute(state, deploy_plan).await?;
            }
        }
    }

    Ok(())
}
