//! Moving stateful instances back to their best placement.
//!
//! Stateless services are placed from scratch on every reconciliation, so
//! they always run where the scheduler wants them. Stateful instances stick
//! to the node holding their data, so after a node fails and returns, or
//! new nodes join, they can stay on worse nodes indefinitely.
//! `ekafleet rebalance` compares their placement with the one the scheduler
//! would choose from scratch and proposes moves; applied moves are recorded
//! in Raft and made by the reconciler, which migrates the volumes along.
//!
//! Only services that can take their data along (`migrate.migrateOnReschedule`
//! with ReadWriteOnce volumes) are moved, no more instances per service than
//! the disruption budget allows, and every move is checked against the
//! scheduler first: one that would push any other stateful instance off its
//! node is not proposed.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::events::{EventCategory, EventLevel, EventStore};
use super::reconciler::{ReconcilePlan, SchedulingInputs, node_moves};
use super::scheduler::{self, one_replica_per_node};
use crate::config::{FleetConfig, JobType};
use crate::raft::state::FleetStateMachine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    pub service: String,
    pub instance_id: String,
    pub from_node: String,
    pub to_node: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip {
    pub service: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Evaluation {
    /// Moves to make, at most `max_moves`.
    pub moves: Vec<Move>,
    pub skipped: Vec<Skip>,
    /// Moves requested earlier that the reconciler hasn't made yet.
    pub pending: Vec<Move>,
}

type Instances = BTreeMap<(String, String), String>;

/// Propose up to `max_moves` moves for the stateful services in `only` (all
/// when `None`). `pending` are moves already requested.
pub fn evaluate(
    config: &FleetConfig,
    inputs: &SchedulingInputs,
    pending: &BTreeMap<(String, String), String>,
    only: Option<&HashSet<String>>,
    max_moves: usize,
) -> Evaluation {
    let mut eval = Evaluation::default();
    let stateful: BTreeMap<&str, &crate::config::ServiceConfig> = inputs
        .services
        .iter()
        .filter(|(name, cfg)| {
            cfg.scheduling.job_type == JobType::Stateful
                && only.is_none_or(|only| only.contains(*name))
        })
        .map(|(name, cfg)| (name.as_str(), cfg))
        .collect();

    // Where instances are recorded, and where the reconciler will put them
    // (with the moves already requested).
    let recorded: Instances = inputs
        .current_placements
        .iter()
        .filter(|((service, _), _)| stateful.contains_key(service.as_str()))
        .map(|(key, node)| (key.clone(), node.clone()))
        .collect();
    let with_pending: Vec<Move> = pending
        .iter()
        .filter(|((service, _), _)| stateful.contains_key(service.as_str()))
        .map(|((service, instance_id), to_node)| Move {
            service: service.clone(),
            instance_id: instance_id.clone(),
            from_node: recorded
                .get(&(service.clone(), instance_id.clone()))
                .cloned()
                .unwrap_or_default(),
            to_node: to_node.clone(),
        })
        .collect();
    let baseline = simulate(config, inputs, &stateful, &with_pending);
    let ideal = scheduler::schedule(
        &inputs.services,
        &inputs.machines,
        &config.node_pools,
        &HashMap::new(),
    );

    let mut chosen: Vec<Move> = Vec::new();
    for (&service, cfg) in &stateful {
        let mut current: Vec<(&str, &str)> = recorded
            .iter()
            .filter(|((s, _), _)| s == service)
            .map(|((_, instance), node)| (instance.as_str(), node.as_str()))
            .collect();
        current.sort_by_key(|(_, node)| *node);
        let mut current_nodes: Vec<&str> = current.iter().map(|(_, node)| *node).collect();
        current_nodes.dedup();
        let mut ideal_nodes: Vec<&str> = ideal
            .placements
            .iter()
            .filter(|p| p.service_name == service)
            .map(|p| p.machine_name.as_str())
            .collect();
        ideal_nodes.sort();
        ideal_nodes.dedup();
        let wanted = node_moves(&current_nodes, &ideal_nodes);
        if wanted.is_empty() {
            continue;
        }
        let skip = |reason: &str| Skip {
            service: service.to_string(),
            reason: reason.to_string(),
        };
        if with_pending.iter().any(|m| m.service == service) {
            eval.skipped
                .push(skip("an earlier move hasn't been made yet"));
            continue;
        }
        let settled = recorded
            .iter()
            .filter(|((s, _), _)| s == service)
            .all(|(key, node)| baseline.get(key) == Some(node))
            && baseline.keys().filter(|(s, _)| s == service).count() == current.len();
        if !settled {
            eval.skipped
                .push(skip("the reconciler is still placing its instances"));
            continue;
        }
        if !(cfg.scheduling.migrate.migrate_on_reschedule && one_replica_per_node(cfg)) {
            eval.skipped.push(skip(
                "its volumes can't follow it (needs migrate.migrateOnReschedule and \
                 ReadWriteOnce volumes)",
            ));
            continue;
        }
        let replicas = current.len() as u32;
        let budget = cfg
            .scheduling
            .disruption_budget
            .as_ref()
            .map_or(replicas, |b| b.allowed_disruptions(replicas)) as usize;
        if budget == 0 {
            eval.skipped
                .push(skip("its disruption budget allows no instance to stop"));
            continue;
        }

        let mut moved = 0;
        for (from, to) in wanted {
            if moved == budget {
                eval.skipped.push(skip(
                    "its disruption budget allows no more moves this round",
                ));
                break;
            }
            if chosen.len() == max_moves {
                eval.skipped.push(skip("limited by --max-moves"));
                break;
            }
            let Some((instance, _)) = current.iter().find(|(_, node)| *node == from) else {
                continue;
            };
            let candidate = Move {
                service: service.to_string(),
                instance_id: instance.to_string(),
                from_node: from.to_string(),
                to_node: to.to_string(),
            };
            chosen.push(candidate);
            let all: Vec<Move> = with_pending.iter().chain(&chosen).cloned().collect();
            if only_moves(
                &baseline,
                &simulate(config, inputs, &stateful, &all),
                &chosen,
            ) {
                moved += 1;
            } else {
                let rejected = chosen.pop().expect("just pushed");
                eval.skipped.push(skip(&format!(
                    "moving {} to {} would displace other instances",
                    rejected.instance_id, rejected.to_node
                )));
            }
        }
    }
    eval.moves = chosen;
    eval.pending = with_pending;
    eval
}

/// Where the scheduler puts the stateful instances when `moves` are
/// requested.
fn simulate(
    config: &FleetConfig,
    inputs: &SchedulingInputs,
    stateful: &BTreeMap<&str, &crate::config::ServiceConfig>,
    moves: &[Move],
) -> Instances {
    let mut current = inputs.current_placements.clone();
    for m in moves {
        current.insert(
            (m.service.clone(), m.instance_id.clone()),
            m.to_node.clone(),
        );
    }
    scheduler::schedule(
        &inputs.services,
        &inputs.machines,
        &config.node_pools,
        &current,
    )
    .placements
    .into_iter()
    .filter(|p| stateful.contains_key(p.service_name.as_str()))
    .map(|p| ((p.service_name, p.instance_id), p.machine_name))
    .collect()
}

/// Whether `after` differs from `before` exactly by `moves`.
fn only_moves(before: &Instances, after: &Instances, moves: &[Move]) -> bool {
    let mut expected = before.clone();
    for m in moves {
        expected.insert(
            (m.service.clone(), m.instance_id.clone()),
            m.to_node.clone(),
        );
    }
    &expected == after
}

/// After a reconciliation, forget the moves that were made or can't be:
/// made when the instance is recorded on its destination, abandoned when
/// the reconciler didn't reschedule the service (the destination no longer
/// fits) or its volume migration failed (`failed`).
pub async fn settle(
    desired: &FleetConfig,
    plan: &ReconcilePlan,
    failed: &[String],
    raft_state: &FleetStateMachine,
    events: Option<&EventStore>,
) {
    let moves = raft_state.placement_moves().await;
    if moves.is_empty() {
        return;
    }
    let deployments = raft_state.all_deployments().await;
    for ((service, instance), to_node) in moves {
        let recorded = deployments.get(&service).and_then(|d| {
            d.placements
                .iter()
                .find(|p| p.instance_id == instance)
                .map(|p| p.machine_name.clone())
        });
        let stateful = desired
            .services
            .get(&service)
            .is_some_and(|cfg| cfg.scheduling.job_type == JobType::Stateful);
        let rescheduled = plan.reschedules.iter().any(|op| op.service_name == service);
        let outcome = match recorded {
            Some(node) if node == to_node => Some((
                "rebalance.completed",
                EventLevel::Info,
                format!("moved {instance} to {to_node}"),
            )),
            Some(_) if stateful && failed.contains(&service) => Some((
                "rebalance.failed",
                EventLevel::Error,
                format!("moving {instance} to {to_node} failed: its volumes could not be migrated"),
            )),
            Some(node) if stateful && !rescheduled => Some((
                "rebalance.failed",
                EventLevel::Warning,
                format!("{instance} stays on {node}: {to_node} no longer fits it"),
            )),
            Some(_) if stateful => continue,
            // The service or instance is gone.
            _ => None,
        };
        if let Err(e) = raft_state.clear_placement_move(&service, &instance).await {
            tracing::warn!(service = %service, instance = %instance, error = %e,
                "Failed to clear placement move");
            continue;
        }
        if let (Some((kind, level, message)), Some(events)) = (outcome, events) {
            events
                .emit_kind(
                    kind,
                    level,
                    EventCategory::Scheduling,
                    Some(&service),
                    Some(&to_node),
                    &message,
                )
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CapacityConfig, DisruptionBudget, DisruptionValue, MachineConfig, ResourceConfig,
        ResourceValue, ServiceConfig,
    };

    fn machine(cpu: u64) -> MachineConfig {
        MachineConfig {
            target_host: "10.0.0.1".into(),
            labels: HashMap::new(),
            capacity: CapacityConfig {
                cpu,
                memory: 16384,
                disk: 0,
            },
            pool: "default".into(),
            reserved: CapacityConfig::default(),
            taints: vec![],
            extended_resources: HashMap::new(),
        }
    }

    fn stateful(replicas: u32, migrate: bool) -> ServiceConfig {
        let mut cfg: ServiceConfig = serde_json::from_value(serde_json::json!({
            "command": "/bin/db",
            "volumes": [{"name": "data", "mountPath": "/data"}],
        }))
        .unwrap();
        cfg.resources = ResourceConfig {
            cpu: Some(ResourceValue {
                request: 1000,
                limit: None,
            }),
            ..Default::default()
        };
        cfg.scheduling.job_type = JobType::Stateful;
        cfg.scheduling.replicas = replicas;
        cfg.scheduling.migrate.migrate_on_reschedule = migrate;
        cfg
    }

    /// A fleet whose `db` instances run on the small nodes `small-*` while
    /// the scheduler prefers the big ones.
    fn drifted(replicas: u32, migrate: bool) -> (FleetConfig, SchedulingInputs) {
        let mut config: FleetConfig =
            serde_json::from_value(serde_json::json!({"name": "test", "domain": "fleet.internal"}))
                .unwrap();
        config
            .services
            .insert("db".into(), stateful(replicas, migrate));
        let machines: HashMap<String, MachineConfig> = [
            ("big-a".to_string(), machine(16000)),
            ("big-b".to_string(), machine(16000)),
            ("small-a".to_string(), machine(2000)),
            ("small-b".to_string(), machine(2000)),
        ]
        .into();
        config.machines = machines.clone();
        let current_placements = (0..replicas)
            .map(|i| {
                let node = ["small-a", "small-b"][i as usize];
                (("db".to_string(), format!("db-{i}")), node.to_string())
            })
            .collect();
        let inputs = SchedulingInputs {
            services: config.services.clone(),
            machines,
            current_placements,
        };
        (config, inputs)
    }

    #[test]
    fn proposes_moves_to_the_preferred_nodes_up_to_the_limit() {
        let (config, inputs) = drifted(2, true);
        let eval = evaluate(&config, &inputs, &BTreeMap::new(), None, 1);
        assert_eq!(eval.moves.len(), 1, "{eval:?}");
        let m = &eval.moves[0];
        assert!(m.from_node.starts_with("small-") && m.to_node.starts_with("big-"));
        assert_eq!(eval.skipped[0].reason, "limited by --max-moves");

        let eval = evaluate(&config, &inputs, &BTreeMap::new(), None, 5);
        assert_eq!(eval.moves.len(), 2, "{eval:?}");
        assert!(eval.skipped.is_empty());
    }

    #[test]
    fn respects_the_disruption_budget() {
        let (mut config, mut inputs) = drifted(2, true);
        let budget = DisruptionBudget {
            min_available: Some(DisruptionValue::Count(1)),
            max_unavailable: None,
        };
        for services in [&mut config.services, &mut inputs.services] {
            services.get_mut("db").unwrap().scheduling.disruption_budget = Some(budget.clone());
        }
        let eval = evaluate(&config, &inputs, &BTreeMap::new(), None, 5);
        assert_eq!(eval.moves.len(), 1, "{eval:?}");
        assert!(eval.skipped[0].reason.contains("disruption budget"));
    }

    #[test]
    fn leaves_services_whose_data_cannot_follow() {
        let (config, inputs) = drifted(1, false);
        let eval = evaluate(&config, &inputs, &BTreeMap::new(), None, 5);
        assert!(eval.moves.is_empty());
        assert!(eval.skipped[0].reason.contains("migrateOnReschedule"));
    }

    #[test]
    fn waits_for_pending_moves_and_honours_the_service_filter() {
        let (config, inputs) = drifted(2, true);
        let pending = BTreeMap::from([(("db".into(), "db-0".into()), "big-a".to_string())]);
        let eval = evaluate(&config, &inputs, &pending, None, 5);
        assert!(eval.moves.is_empty());
        assert_eq!(eval.pending.len(), 1);
        assert_eq!(eval.pending[0].from_node, "small-a");

        let only = HashSet::from(["other".to_string()]);
        let eval = evaluate(&config, &inputs, &BTreeMap::new(), Some(&only), 5);
        assert!(eval.moves.is_empty() && eval.skipped.is_empty());
    }

    #[test]
    fn nothing_to_do_once_placement_matches() {
        let (config, mut inputs) = drifted(2, true);
        let eval = evaluate(&config, &inputs, &BTreeMap::new(), None, 5);
        for m in eval.moves {
            inputs
                .current_placements
                .insert((m.service, m.instance_id), m.to_node);
        }
        let eval = evaluate(&config, &inputs, &BTreeMap::new(), None, 5);
        assert!(eval.moves.is_empty() && eval.skipped.is_empty(), "{eval:?}");
    }
}
