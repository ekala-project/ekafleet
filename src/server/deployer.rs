#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use super::events::{DeployOutcome, EventStore};
use super::scheduler::Placement;
use super::state::FleetState;
use crate::config::{DisruptionBudget, UpdateStrategy};
use crate::proto::server_message::Payload;
use crate::proto::{DeployCommand, DeployStrategy, ServerMessage};

/// A canary deployment that has been rolled out to its first instance, is
/// healthy, and is waiting for an operator to promote (roll out to the rest)
/// or fail it (roll the canary back). Holds everything needed to complete or
/// unwind the deployment without re-running the scheduler.
#[derive(Debug, Clone)]
pub struct PendingCanary {
    pub deployment_id: String,
    pub service_name: String,
    pub store_path: String,
    /// The canary instance already deployed (placements[0]).
    pub canary: Vec<Placement>,
    /// Instances not yet deployed; rolled out on promote.
    pub remaining: Vec<Placement>,
    pub max_parallel: u32,
    pub auto_revert: bool,
    pub min_healthy_time: Duration,
    pub healthy_deadline: Duration,
    pub progress_deadline: Option<Duration>,
    pub disruption_budget: Option<DisruptionBudget>,
    pub total_replicas: u32,
    /// Previous version for rollback on fail.
    pub previous_store_path: Option<String>,
}

/// Registry of canary deployments awaiting manual promotion, keyed by service
/// name (one active canary per service at a time). Shared between the reconcile
/// loop that creates them and the Promote/Fail RPC handlers that resolve them.
#[derive(Clone, Default)]
pub struct PendingCanaryStore {
    inner: Arc<RwLock<HashMap<String, PendingCanary>>>,
}

impl PendingCanaryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(&self, pending: PendingCanary) {
        self.inner
            .write()
            .await
            .insert(pending.service_name.clone(), pending);
    }

    /// Remove and return the pending canary for a service, if any.
    pub async fn take(&self, service_name: &str) -> Option<PendingCanary> {
        self.inner.write().await.remove(service_name)
    }

    pub async fn contains(&self, service_name: &str) -> bool {
        self.inner.read().await.contains_key(service_name)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    #[error("deployment timed out waiting for healthy status")]
    HealthTimeout,
    #[error("deployment failed on node {node}: {reason}")]
    NodeFailed { node: String, reason: String },
    #[error("auto-reverted: {0}")]
    Reverted(String),
    #[error("disruption budget violated: {0}")]
    DisruptionBudgetViolation(String),
    #[error("canary healthy — awaiting manual promotion (deployment_id: {0})")]
    AwaitingPromotion(String),
}

/// A deployment operation for a single service.
#[derive(Debug)]
pub struct DeploymentPlan {
    pub service_name: String,
    pub strategy: UpdateStrategy,
    pub max_parallel: u32,
    pub placements: Vec<Placement>,
    pub store_path: String,
    pub auto_revert: bool,
    pub auto_promote: bool,
    pub min_healthy_time: Duration,
    pub healthy_deadline: Duration,
    pub progress_deadline: Option<Duration>,
    /// Disruption budget limiting how many instances can be down simultaneously.
    pub disruption_budget: Option<DisruptionBudget>,
    /// Total desired replica count (used with disruption budget).
    pub total_replicas: u32,
    /// Previous store path for auto-revert. When set and auto_revert is true,
    /// nodes that received the new version will be rolled back to this path
    /// on deployment failure.
    pub previous_store_path: Option<String>,
}

/// Execute a deployment plan against the fleet.
pub async fn execute(
    state: &FleetState,
    plan: DeploymentPlan,
    events: Option<&EventStore>,
) -> Result<(), DeployError> {
    let deployment_id = uuid::Uuid::new_v4().to_string();

    tracing::info!(
        deployment_id = %deployment_id,
        service = %plan.service_name,
        strategy = ?plan.strategy,
        instances = plan.placements.len(),
        "Starting deployment"
    );

    if let Some(es) = events {
        es.record_deploy_start(
            &deployment_id,
            &plan.service_name,
            &format!("{:?}", plan.strategy),
            plan.placements.len() as u32,
            &plan.store_path,
        )
        .await;
    }

    // If a progress deadline is set, wrap the deployment in a timeout
    let result = if let Some(progress_deadline) = plan.progress_deadline {
        match tokio::time::timeout(progress_deadline, async {
            match plan.strategy {
                UpdateStrategy::Rolling => execute_rolling(state, &deployment_id, &plan).await,
                UpdateStrategy::Canary => execute_canary(state, &deployment_id, &plan).await,
                UpdateStrategy::BlueGreen => execute_blue_green(state, &deployment_id, &plan).await,
            }
        })
        .await
        {
            Ok(inner) => inner,
            Err(_) => {
                tracing::error!(
                    deployment_id = %deployment_id,
                    service = %plan.service_name,
                    "Deployment exceeded progress deadline"
                );
                if plan.auto_revert {
                    Err(DeployError::Reverted(
                        "progress deadline exceeded".to_string(),
                    ))
                } else {
                    Err(DeployError::HealthTimeout)
                }
            }
        }
    } else {
        match plan.strategy {
            UpdateStrategy::Rolling => execute_rolling(state, &deployment_id, &plan).await,
            UpdateStrategy::Canary => execute_canary(state, &deployment_id, &plan).await,
            UpdateStrategy::BlueGreen => execute_blue_green(state, &deployment_id, &plan).await,
        }
    };

    match &result {
        Ok(()) => {
            tracing::info!(
                deployment_id = %deployment_id,
                service = %plan.service_name,
                "Deployment completed successfully"
            );
            if let Some(es) = events {
                es.record_deploy_complete(
                    &deployment_id,
                    DeployOutcome::Succeeded,
                    "all instances healthy",
                )
                .await;
            }
        }
        Err(DeployError::AwaitingPromotion(_)) => {
            // Canary is healthy but waiting for manual promotion — not a failure.
            tracing::info!(
                deployment_id = %deployment_id,
                service = %plan.service_name,
                "Canary deployed and healthy — awaiting manual promotion"
            );
            // Don't record as completed; it stays InProgress until promoted.
        }
        Err(e) => {
            tracing::error!(
                deployment_id = %deployment_id,
                service = %plan.service_name,
                error = %e,
                "Deployment failed"
            );

            // On failure with auto_revert, roll back nodes that already
            // received the new version to the previous store path.
            let reverted = if plan.auto_revert {
                if let Some(ref prev_path) = plan.previous_store_path {
                    revert_deployed_nodes(
                        state,
                        &deployment_id,
                        &plan.service_name,
                        prev_path,
                        &plan.placements,
                    )
                    .await;
                    true
                } else {
                    tracing::warn!(
                        deployment_id = %deployment_id,
                        service = %plan.service_name,
                        "auto_revert requested but no previous store path available — \
                         cannot roll back (first deployment?)"
                    );
                    false
                }
            } else {
                false
            };

            if let Some(es) = events {
                let outcome = if reverted {
                    DeployOutcome::RolledBack
                } else {
                    DeployOutcome::Failed
                };
                es.record_deploy_complete(&deployment_id, outcome, &e.to_string())
                    .await;
            }
        }
    }

    result
}

/// Send the previous store path to all nodes that may have received the
/// new deployment, reverting them to the last known-good version.
async fn revert_deployed_nodes(
    state: &FleetState,
    deployment_id: &str,
    service_name: &str,
    previous_store_path: &str,
    placements: &[Placement],
) {
    tracing::info!(
        deployment_id = %deployment_id,
        service = %service_name,
        nodes = placements.len(),
        previous_store_path = %previous_store_path,
        "Reverting nodes to previous version"
    );

    for placement in placements {
        let msg = ServerMessage {
            payload: Some(Payload::Deploy(DeployCommand {
                deployment_id: deployment_id.to_string(),
                service_name: service_name.to_string(),
                store_path: previous_store_path.to_string(),
                strategy: DeployStrategy::Rolling as i32,
                container_image: String::new(),
            })),
        };

        if !state.send_to_agent(&placement.machine_name, msg).await {
            tracing::error!(
                deployment_id = %deployment_id,
                node = %placement.machine_name,
                "Failed to send revert command to node"
            );
        }
    }

    tracing::info!(
        deployment_id = %deployment_id,
        service = %service_name,
        "Revert commands sent to all placement nodes"
    );
}

/// Rolling deployment: update instances in batches of max_parallel.
/// Respects disruption budgets by limiting batch sizes.
async fn execute_rolling(
    state: &FleetState,
    deployment_id: &str,
    plan: &DeploymentPlan,
) -> Result<(), DeployError> {
    // Compute effective max_parallel respecting disruption budget.
    let effective_parallel = if let Some(ref budget) = plan.disruption_budget {
        let allowed = budget.allowed_disruptions(plan.total_replicas);
        if allowed == 0 {
            return Err(DeployError::DisruptionBudgetViolation(
                "disruption budget allows 0 simultaneous disruptions".to_string(),
            ));
        }
        plan.max_parallel.min(allowed)
    } else {
        plan.max_parallel
    };

    let batches = plan
        .placements
        .chunks(effective_parallel as usize)
        .collect::<Vec<_>>();

    for (batch_idx, batch) in batches.iter().enumerate() {
        tracing::info!(
            deployment_id,
            batch = batch_idx + 1,
            total_batches = batches.len(),
            size = batch.len(),
            "Deploying batch"
        );

        // Send deploy command to each node in the batch
        for placement in *batch {
            let msg = ServerMessage {
                payload: Some(Payload::Deploy(DeployCommand {
                    deployment_id: deployment_id.to_string(),
                    service_name: plan.service_name.clone(),
                    store_path: plan.store_path.clone(),
                    strategy: DeployStrategy::Rolling as i32,
                    container_image: String::new(),
                })),
            };

            if !state.send_to_agent(&placement.machine_name, msg).await {
                if plan.auto_revert {
                    return Err(DeployError::Reverted(format!(
                        "failed to reach node {}",
                        placement.machine_name
                    )));
                }
                return Err(DeployError::NodeFailed {
                    node: placement.machine_name.clone(),
                    reason: "unreachable".into(),
                });
            }
        }

        // Wait for health gate before proceeding to next batch
        if batch_idx < batches.len() - 1 {
            wait_healthy(
                state,
                &plan.service_name,
                batch,
                plan.min_healthy_time,
                plan.healthy_deadline,
            )
            .await?;
        }
    }

    Ok(())
}

/// Canary deployment: deploy to a subset first, then promote.
async fn execute_canary(
    state: &FleetState,
    deployment_id: &str,
    plan: &DeploymentPlan,
) -> Result<(), DeployError> {
    if plan.placements.is_empty() {
        return Ok(());
    }

    // Deploy canary (first instance)
    let canary = &plan.placements[0..1];
    tracing::info!(
        deployment_id,
        node = %canary[0].machine_name,
        "Deploying canary"
    );

    let msg = ServerMessage {
        payload: Some(Payload::Deploy(DeployCommand {
            deployment_id: deployment_id.to_string(),
            service_name: plan.service_name.clone(),
            store_path: plan.store_path.clone(),
            strategy: DeployStrategy::Canary as i32,
            container_image: String::new(),
        })),
    };

    if !state.send_to_agent(&canary[0].machine_name, msg).await {
        return Err(DeployError::NodeFailed {
            node: canary[0].machine_name.clone(),
            reason: "unreachable".into(),
        });
    }

    // Wait for canary to be healthy
    wait_healthy(
        state,
        &plan.service_name,
        canary,
        plan.min_healthy_time,
        plan.healthy_deadline,
    )
    .await?;

    if plan.auto_promote {
        tracing::info!(
            deployment_id,
            "Canary healthy, auto-promoting to remaining instances"
        );
    } else {
        tracing::info!(
            deployment_id,
            "Canary healthy — awaiting manual promotion via Promote RPC"
        );
        // Persist everything needed to complete or unwind this canary so the
        // Promote/Fail RPCs can act on it later.
        let remaining = if plan.placements.len() > 1 {
            plan.placements[1..].to_vec()
        } else {
            Vec::new()
        };
        state
            .pending_canaries()
            .insert(PendingCanary {
                deployment_id: deployment_id.to_string(),
                service_name: plan.service_name.clone(),
                store_path: plan.store_path.clone(),
                canary: canary.to_vec(),
                remaining,
                max_parallel: plan.max_parallel,
                auto_revert: plan.auto_revert,
                min_healthy_time: plan.min_healthy_time,
                healthy_deadline: plan.healthy_deadline,
                progress_deadline: plan.progress_deadline,
                disruption_budget: plan.disruption_budget.clone(),
                total_replicas: plan.total_replicas,
                previous_store_path: plan.previous_store_path.clone(),
            })
            .await;
        return Err(DeployError::AwaitingPromotion(deployment_id.to_string()));
    }

    // Deploy remaining instances via rolling strategy
    if plan.placements.len() > 1 {
        let remaining = &plan.placements[1..];
        let remaining_plan = DeploymentPlan {
            service_name: plan.service_name.clone(),
            strategy: UpdateStrategy::Rolling,
            max_parallel: plan.max_parallel,
            placements: remaining.to_vec(),
            store_path: plan.store_path.clone(),
            auto_revert: plan.auto_revert,
            auto_promote: plan.auto_promote,
            min_healthy_time: plan.min_healthy_time,
            healthy_deadline: plan.healthy_deadline,
            progress_deadline: plan.progress_deadline,
            disruption_budget: plan.disruption_budget.clone(),
            total_replicas: plan.total_replicas,
            previous_store_path: plan.previous_store_path.clone(),
        };
        execute_rolling(state, deployment_id, &remaining_plan).await?;
    }

    Ok(())
}

/// Promote a healthy canary: roll the new version out to the remaining
/// instances. Returns Ok once all remaining instances are deployed and healthy.
pub async fn promote_canary(
    state: &FleetState,
    pending: &PendingCanary,
    events: Option<&EventStore>,
) -> Result<(), DeployError> {
    tracing::info!(
        deployment_id = %pending.deployment_id,
        service = %pending.service_name,
        remaining = pending.remaining.len(),
        "Promoting canary to remaining instances"
    );

    if pending.remaining.is_empty() {
        if let Some(es) = events {
            es.record_deploy_complete(
                &pending.deployment_id,
                DeployOutcome::Succeeded,
                "canary promoted (no remaining instances)",
            )
            .await;
        }
        return Ok(());
    }

    let remaining_plan = DeploymentPlan {
        service_name: pending.service_name.clone(),
        strategy: UpdateStrategy::Rolling,
        max_parallel: pending.max_parallel,
        placements: pending.remaining.clone(),
        store_path: pending.store_path.clone(),
        auto_revert: pending.auto_revert,
        auto_promote: true,
        min_healthy_time: pending.min_healthy_time,
        healthy_deadline: pending.healthy_deadline,
        progress_deadline: pending.progress_deadline,
        disruption_budget: pending.disruption_budget.clone(),
        total_replicas: pending.total_replicas,
        previous_store_path: pending.previous_store_path.clone(),
    };

    let result = execute_rolling(state, &pending.deployment_id, &remaining_plan).await;

    if let Some(es) = events {
        match &result {
            Ok(()) => {
                es.record_deploy_complete(
                    &pending.deployment_id,
                    DeployOutcome::Succeeded,
                    "canary promoted to full rollout",
                )
                .await;
            }
            Err(e) => {
                es.record_deploy_complete(
                    &pending.deployment_id,
                    DeployOutcome::Failed,
                    &format!("promotion failed: {e}"),
                )
                .await;
            }
        }
    }

    result
}

/// Fail a canary: roll the canary instance back to the previous version (if
/// known) and record the deployment as rolled back / failed.
pub async fn fail_canary(state: &FleetState, pending: &PendingCanary, events: Option<&EventStore>) {
    tracing::info!(
        deployment_id = %pending.deployment_id,
        service = %pending.service_name,
        "Failing canary — rolling back canary instance"
    );

    let rolled_back = if let Some(prev) = &pending.previous_store_path {
        revert_deployed_nodes(
            state,
            &pending.deployment_id,
            &pending.service_name,
            prev,
            &pending.canary,
        )
        .await;
        true
    } else {
        tracing::warn!(
            deployment_id = %pending.deployment_id,
            service = %pending.service_name,
            "No previous store path — canary instance left in place (first deployment?)"
        );
        false
    };

    if let Some(es) = events {
        let outcome = if rolled_back {
            DeployOutcome::RolledBack
        } else {
            DeployOutcome::Failed
        };
        es.record_deploy_complete(&pending.deployment_id, outcome, "canary manually failed")
            .await;
    }
}

/// Blue-green deployment: deploy all new instances, then switch.
async fn execute_blue_green(
    state: &FleetState,
    deployment_id: &str,
    plan: &DeploymentPlan,
) -> Result<(), DeployError> {
    tracing::info!(
        deployment_id,
        instances = plan.placements.len(),
        "Deploying green instances"
    );

    // Deploy all at once
    for placement in &plan.placements {
        let msg = ServerMessage {
            payload: Some(Payload::Deploy(DeployCommand {
                deployment_id: deployment_id.to_string(),
                service_name: plan.service_name.clone(),
                store_path: plan.store_path.clone(),
                strategy: DeployStrategy::BlueGreen as i32,
                container_image: String::new(),
            })),
        };

        if !state.send_to_agent(&placement.machine_name, msg).await {
            return Err(DeployError::NodeFailed {
                node: placement.machine_name.clone(),
                reason: "unreachable".into(),
            });
        }
    }

    // Wait for all to be healthy before switching traffic
    wait_healthy(
        state,
        &plan.service_name,
        &plan.placements,
        plan.min_healthy_time,
        plan.healthy_deadline,
    )
    .await?;

    tracing::info!(deployment_id, "Green instances healthy, switching traffic");
    Ok(())
}

/// Wait for instances to report healthy status.
async fn wait_healthy(
    state: &FleetState,
    service_name: &str,
    placements: &[Placement],
    min_healthy_time: Duration,
    deadline: Duration,
) -> Result<(), DeployError> {
    let nodes: Vec<&str> = placements.iter().map(|p| p.machine_name.as_str()).collect();

    tracing::debug!(
        service = %service_name,
        nodes = ?nodes,
        min_healthy = ?min_healthy_time,
        deadline = ?deadline,
        "Waiting for health gate"
    );

    let started = tokio::time::Instant::now();
    let mut healthy_since: Option<tokio::time::Instant> = None;

    loop {
        if started.elapsed() > deadline {
            return Err(DeployError::HealthTimeout);
        }

        // Check if all nodes report the service as healthy
        let (_, services, _) = state.fleet_status().await;
        let svc_status = services.iter().find(|s| s.name == service_name);

        let all_healthy = if let Some(svc) = svc_status {
            nodes.iter().all(|node| {
                svc.instances.iter().any(|i| {
                    i.node_id == *node && i.health == crate::proto::HealthStatus::Healthy as i32
                })
            })
        } else {
            false
        };

        if all_healthy {
            match healthy_since {
                Some(since) if since.elapsed() >= min_healthy_time => {
                    tracing::info!(
                        service = %service_name,
                        "Health gate passed"
                    );
                    return Ok(());
                }
                None => {
                    healthy_since = Some(tokio::time::Instant::now());
                }
                _ => {}
            }
        } else {
            healthy_since = None;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Execute a deployment lifecycle hook script.
///
/// The hook command is executed with the following environment variables:
/// - `EKAFLEET_SERVICE`: the name of the service being deployed
/// - `EKAFLEET_ACTION`: the lifecycle action (e.g., "pre-deploy", "post-deploy")
pub async fn run_hook(
    hook: &[String],
    service_name: &str,
    action: &str,
) -> Result<(), DeployError> {
    if hook.is_empty() {
        return Ok(());
    }

    let program = &hook[0];
    let args = &hook[1..];

    tracing::info!(
        service = %service_name,
        action = %action,
        command = %program,
        "Executing deployment hook"
    );

    let output = tokio::process::Command::new(program)
        .args(args)
        .env("EKAFLEET_SERVICE", service_name)
        .env("EKAFLEET_ACTION", action)
        .output()
        .await
        .map_err(|e| DeployError::NodeFailed {
            node: "hook".to_string(),
            reason: format!("failed to execute hook: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(
            service = %service_name,
            action = %action,
            stderr = %stderr,
            "Hook failed"
        );
        return Err(DeployError::NodeFailed {
            node: "hook".to_string(),
            reason: format!("hook '{action}' failed: {stderr}"),
        });
    }

    tracing::info!(
        service = %service_name,
        action = %action,
        "Hook completed successfully"
    );

    Ok(())
}

/// Compute a dependency-ordered deployment sequence.
/// Services with dependencies are deployed after their dependencies.
pub fn compute_deploy_order(
    services: &HashMap<String, crate::config::ServiceConfig>,
) -> Vec<Vec<String>> {
    // Build dependency graph from identity.allowedCallers
    // A service that is in allowedCallers of another is a dependency
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for (name, cfg) in services {
        for caller in &cfg.identity.allowed_callers {
            dependents
                .entry(caller.as_str())
                .or_default()
                .push(name.as_str());
        }
    }

    // Simple topological sort into tiers
    let mut remaining: Vec<&str> = services.keys().map(|s| s.as_str()).collect();
    let mut tiers = Vec::new();
    let mut deployed: Vec<&str> = Vec::new();

    while !remaining.is_empty() {
        // Find services whose dependencies are all deployed.
        // A service's deps are the things it calls (allowed_targets).
        let tier: Vec<&str> = remaining
            .iter()
            .filter(|&&svc| {
                services[svc].identity.allowed_targets.iter().all(|target| {
                    deployed.contains(&target.as_str()) || !services.contains_key(target.as_str())
                })
            })
            .copied()
            .collect();

        if tier.is_empty() {
            // Circular dependency or no progress — deploy remaining
            tiers.push(remaining.iter().map(|s| s.to_string()).collect());
            break;
        }

        deployed.extend(&tier);
        remaining.retain(|s| !tier.contains(s));
        tiers.push(tier.iter().map(|s| s.to_string()).collect());
    }

    tiers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placement(service: &str, instance: &str, machine: &str) -> Placement {
        Placement {
            service_name: service.to_string(),
            instance_id: instance.to_string(),
            machine_name: machine.to_string(),
        }
    }

    fn sample_pending(service: &str, remaining: Vec<Placement>) -> PendingCanary {
        PendingCanary {
            deployment_id: "dep-1".to_string(),
            service_name: service.to_string(),
            store_path: "/nix/store/new".to_string(),
            canary: vec![placement(service, "i0", "node-0")],
            remaining,
            max_parallel: 1,
            auto_revert: true,
            min_healthy_time: Duration::from_secs(0),
            healthy_deadline: Duration::from_secs(1),
            progress_deadline: None,
            disruption_budget: None,
            total_replicas: 3,
            previous_store_path: Some("/nix/store/old".to_string()),
        }
    }

    #[tokio::test]
    async fn pending_store_insert_take_is_one_shot() {
        let store = PendingCanaryStore::new();
        assert!(!store.contains("web").await);

        store.insert(sample_pending("web", vec![])).await;
        assert!(store.contains("web").await);

        let taken = store.take("web").await;
        assert!(taken.is_some());
        // A second take returns None — the pending canary is consumed.
        assert!(store.take("web").await.is_none());
        assert!(!store.contains("web").await);
    }

    #[tokio::test]
    async fn promote_with_no_remaining_succeeds() {
        // A canary that is the only replica has nothing left to roll out;
        // promotion must succeed without contacting any agent.
        let state = FleetState::new();
        let pending = sample_pending("web", vec![]);
        let result = promote_canary(&state, &pending, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn promote_with_unreachable_remaining_fails() {
        // Remaining instances target a node that is not connected, so the
        // rollout must surface a NodeFailed error rather than reporting success.
        let state = FleetState::new();
        let pending = sample_pending("web", vec![placement("web", "i1", "missing-node")]);
        let result = promote_canary(&state, &pending, None).await;
        // auto_revert is true, so an unreachable node surfaces as Reverted;
        // either way the promotion must not report success.
        assert!(matches!(
            result,
            Err(DeployError::Reverted(_)) | Err(DeployError::NodeFailed { .. })
        ));
    }

    #[tokio::test]
    async fn fail_canary_does_not_panic_without_previous_path() {
        // Failing a first-ever canary (no previous version) must be a no-op
        // rollback, not a panic.
        let state = FleetState::new();
        let mut pending = sample_pending("web", vec![]);
        pending.previous_store_path = None;
        fail_canary(&state, &pending, None).await;
    }
}
