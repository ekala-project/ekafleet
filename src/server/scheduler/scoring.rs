#![allow(dead_code)]

use std::collections::HashMap;

use crate::config::{
    AffinityConfig, Constraint, SchedulerAlgorithm, ServiceAffinityConfig, ServiceConfig,
    SpreadConfig, TaintEffect,
};

use super::constraints::{evaluate_operator, get_attribute, passes_constraints, passes_taints};
use super::{Candidate, Preemption, ResourceRequirements};

/// Compute a placement score for a candidate. Higher is better.
pub(super) fn compute_score(
    candidate: &Candidate,
    service_name: &str,
    all_candidates: &[Candidate],
    affinities: &[AffinityConfig],
    spreads: &[SpreadConfig],
    service_affinities: &[ServiceAffinityConfig],
    pool_algorithm: Option<&SchedulerAlgorithm>,
    current_machine: Option<&str>,
) -> f64 {
    let mut score = 0.0;

    // Bin-packing score: direction depends on pool algorithm
    let util = candidate.utilization();
    match pool_algorithm {
        Some(SchedulerAlgorithm::Spread) => {
            // Spread: prefer less utilized machines
            score += (1.0 - util) * 30.0;
        }
        _ => {
            // Binpack (default): prefer more utilized machines
            score += util * 30.0;
        }
    }

    // Spread scores: distribute instances across distinct attribute values
    for spread_cfg in spreads {
        let my_attr = get_attribute(candidate, &spread_cfg.attribute);
        if let Some(ref my_val) = my_attr {
            let same_count = all_candidates
                .iter()
                .filter(|c| {
                    c.assigned_services.contains(&service_name.to_string())
                        && get_attribute(c, &spread_cfg.attribute).as_deref() == Some(my_val)
                })
                .count();
            let spread_weight = spread_cfg.weight.unwrap_or(50) as f64;
            if spread_cfg.targets.is_empty() {
                // Even distribution (existing behavior)
                score += spread_weight / (same_count as f64 + 1.0);
            } else {
                // Target-based distribution
                let total_placed: usize = all_candidates
                    .iter()
                    .flat_map(|c| c.assigned_services.iter())
                    .filter(|s| s.as_str() == service_name)
                    .count();
                if let Some(target) = spread_cfg.targets.iter().find(|t| t.value == *my_val) {
                    let desired = target.percent as f64 / 100.0;
                    let actual_pct = if total_placed > 0 {
                        same_count as f64 / total_placed as f64
                    } else {
                        0.0
                    };
                    let deviation = (actual_pct - desired).abs();
                    score += spread_weight * (1.0 - deviation);
                }
            }
        }
    }

    // Affinity scores — delegate common ops to evaluate_operator
    for affinity in affinities {
        let actual = get_attribute(candidate, &affinity.attribute);
        let matches = evaluate_operator(actual.as_deref(), &affinity.op, &affinity.value);
        if matches {
            score += affinity.weight as f64;
        }
    }

    // Distinct hosts: penalize placing same service on same machine
    let same_service_count = candidate
        .assigned_services
        .iter()
        .filter(|s| s.as_str() == service_name)
        .count();
    if same_service_count > 0 {
        score -= 100.0 * same_service_count as f64;
    }

    // PreferNoSchedule taint penalty
    for taint in &candidate.config.taints {
        if taint.effect == TaintEffect::PreferNoSchedule {
            score -= 50.0;
        }
    }

    // Service affinity: co-locate or separate from other services
    for sa in service_affinities {
        let my_topo = get_attribute(candidate, &sa.topology_key);
        if let Some(ref my_val) = my_topo {
            let has_target = all_candidates.iter().any(|c| {
                c.assigned_services.contains(&sa.target_service)
                    && get_attribute(c, &sa.topology_key).as_deref() == Some(my_val)
            });
            if has_target {
                score += sa.weight as f64;
            }
        }
    }

    // Data locality: strongly prefer the node where this instance's data
    // already lives. Only applied for Stateful jobs via current_machine.
    if let Some(current) = current_machine {
        if candidate.name == current {
            score += 200.0;
        }
    }

    score
}

/// Find a machine where evicting lower-priority services would free enough
/// resources for the requesting service. Returns the candidate index and
/// the list of evictions required. Only services with priority delta >= 10
/// are eligible for preemption.
pub(super) fn find_preemption_candidate(
    candidates: &[Candidate],
    constraints: &[Constraint],
    tolerations: &[crate::config::Toleration],
    service_name: &str,
    service_priority: u32,
    reqs: &ResourceRequirements,
    all_services: &HashMap<String, ServiceConfig>,
) -> Option<(usize, Vec<Preemption>)> {
    let mut best: Option<(usize, Vec<Preemption>, u32)> = None;

    for (idx, candidate) in candidates.iter().enumerate() {
        // Machine must still pass constraints and taints
        if !passes_constraints(candidate, constraints, service_name) {
            continue;
        }
        if !passes_taints(candidate, tolerations) {
            continue;
        }

        // Find evictable services on this machine (priority delta >= 10)
        let mut evictable: Vec<(&str, u64, u64, u64, u32)> = Vec::new();
        for assigned in &candidate.assigned_services {
            if let Some(svc_cfg) = all_services.get(assigned) {
                let svc_priority = svc_cfg.scheduling.priority;
                if service_priority >= svc_priority + 10 {
                    let cpu = svc_cfg
                        .resources
                        .cpu
                        .as_ref()
                        .map(|r| r.request)
                        .unwrap_or(0);
                    let mem = svc_cfg
                        .resources
                        .memory
                        .as_ref()
                        .map(|r| r.request)
                        .unwrap_or(0);
                    let disk = svc_cfg
                        .resources
                        .disk
                        .as_ref()
                        .map(|r| r.request)
                        .unwrap_or(0);
                    evictable.push((assigned, cpu, mem, disk, svc_priority));
                }
            }
        }

        if evictable.is_empty() {
            continue;
        }

        // Sort by priority ascending (evict lowest priority first)
        evictable.sort_by_key(|e| e.4);

        // Greedily evict until we have enough resources
        let mut freed_cpu = candidate.available_cpu();
        let mut freed_mem = candidate.available_memory();
        let mut freed_disk = candidate.available_disk();
        let mut evictions = Vec::new();
        let mut total_evicted_priority = 0u32;

        for (svc_name, cpu, mem, disk, priority) in &evictable {
            if freed_cpu >= reqs.cpu && freed_mem >= reqs.memory && freed_disk >= reqs.disk {
                break;
            }
            freed_cpu += cpu;
            freed_mem += mem;
            freed_disk += disk;
            total_evicted_priority += priority;
            evictions.push(Preemption {
                evicted_service: svc_name.to_string(),
                evicted_instance_id: format!("{svc_name}-{}", candidate.name),
                machine_name: candidate.name.clone(),
                reason: format!(
                    "preempted by {service_name} (priority {service_priority} > {priority})"
                ),
            });
        }

        // Check if enough resources after evictions
        if freed_cpu >= reqs.cpu && freed_mem >= reqs.memory && freed_disk >= reqs.disk {
            // Prefer fewer evictions, then lower total evicted priority
            let is_better = match &best {
                None => true,
                Some((_, prev_evictions, prev_priority)) => {
                    evictions.len() < prev_evictions.len()
                        || (evictions.len() == prev_evictions.len()
                            && total_evicted_priority < *prev_priority)
                }
            };
            if is_better {
                best = Some((idx, evictions, total_evicted_priority));
            }
        }
    }

    best.map(|(idx, evictions, _)| (idx, evictions))
}
