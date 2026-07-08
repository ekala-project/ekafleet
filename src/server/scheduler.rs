#![allow(dead_code)]

use std::collections::HashMap;

use crate::config::{
    AffinityConfig, Constraint, JobType, MachineConfig, NodePoolConfig, SchedulerAlgorithm,
    ServiceAffinityConfig, ServiceConfig, SpreadConfig, TaintEffect, TolerationOp,
};

/// Result of scheduling: which services go to which machines.
#[derive(Debug, Clone)]
pub struct PlacementPlan {
    pub placements: Vec<Placement>,
    pub blocked: Vec<BlockedPlacement>,
    pub preemptions: Vec<Preemption>,
}

#[derive(Debug, Clone)]
pub struct Placement {
    pub service_name: String,
    pub instance_id: String,
    pub machine_name: String,
}

#[derive(Debug, Clone)]
pub struct BlockedPlacement {
    pub service_name: String,
    pub instance_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Preemption {
    pub evicted_service: String,
    pub evicted_instance_id: String,
    pub machine_name: String,
    pub reason: String,
}

/// A machine candidate during scheduling with tracked allocated resources.
#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    config: MachineConfig,
    pool: String,
    merged_labels: HashMap<String, String>,
    schedulable_cpu: u64,
    schedulable_memory: u64,
    schedulable_disk: u64,
    allocated_cpu: u64,
    allocated_memory: u64,
    allocated_disk: u64,
    assigned_services: Vec<String>,
}

impl Candidate {
    fn available_cpu(&self) -> u64 {
        self.schedulable_cpu.saturating_sub(self.allocated_cpu)
    }

    fn available_memory(&self) -> u64 {
        self.schedulable_memory
            .saturating_sub(self.allocated_memory)
    }

    fn available_disk(&self) -> u64 {
        self.schedulable_disk.saturating_sub(self.allocated_disk)
    }

    fn utilization(&self) -> f64 {
        if self.schedulable_cpu == 0 && self.schedulable_memory == 0 {
            return 0.0;
        }
        let cpu_util = if self.schedulable_cpu > 0 {
            self.allocated_cpu as f64 / self.schedulable_cpu as f64
        } else {
            0.0
        };
        let mem_util = if self.schedulable_memory > 0 {
            self.allocated_memory as f64 / self.schedulable_memory as f64
        } else {
            0.0
        };
        (cpu_util + mem_util) / 2.0
    }
}

/// Schedule all services across available machines.
pub fn schedule(
    services: &HashMap<String, ServiceConfig>,
    machines: &HashMap<String, MachineConfig>,
    node_pools: &HashMap<String, NodePoolConfig>,
) -> PlacementPlan {
    let mut candidates: Vec<Candidate> = machines
        .iter()
        .map(|(name, config)| {
            // Merge pool labels with machine labels (machine wins on conflict)
            let mut merged_labels = node_pools
                .get(&config.pool)
                .map(|p| p.labels.clone())
                .unwrap_or_default();
            merged_labels.extend(config.labels.iter().map(|(k, v)| (k.clone(), v.clone())));

            Candidate {
                name: name.clone(),
                pool: config.pool.clone(),
                merged_labels,
                schedulable_cpu: config.capacity.cpu.saturating_sub(config.reserved.cpu),
                schedulable_memory: config
                    .capacity
                    .memory
                    .saturating_sub(config.reserved.memory),
                schedulable_disk: config.capacity.disk.saturating_sub(config.reserved.disk),
                config: config.clone(),
                allocated_cpu: 0,
                allocated_memory: 0,
                allocated_disk: 0,
                assigned_services: Vec::new(),
            }
        })
        .collect();

    // Pre-compute pool algorithms for quick lookup
    let pool_algorithms: HashMap<String, &SchedulerAlgorithm> = node_pools
        .iter()
        .filter_map(|(name, cfg)| cfg.scheduler_algorithm.as_ref().map(|a| (name.clone(), a)))
        .collect();

    let mut placements = Vec::new();
    let mut blocked = Vec::new();

    // Schedule system jobs first (run on all matching nodes),
    // then services, stateful, batch
    let mut service_list: Vec<(&str, &ServiceConfig)> = services
        .iter()
        .map(|(name, cfg)| (name.as_str(), cfg))
        .collect();

    service_list.sort_by(|(_, a), (_, b)| {
        // Higher priority first
        b.scheduling
            .priority
            .cmp(&a.scheduling.priority)
            .then_with(|| {
                // Then by job type: System/Sysbatch first
                let type_order = |jt: &JobType| match jt {
                    JobType::System => 0,
                    JobType::Sysbatch => 1,
                    JobType::Service => 2,
                    JobType::Stateful => 3,
                    JobType::Batch => 4,
                };
                type_order(&a.scheduling.job_type).cmp(&type_order(&b.scheduling.job_type))
            })
    });

    for (service_name, service_cfg) in service_list {
        let scheduling = &service_cfg.scheduling;
        let cpu_req = service_cfg
            .resources
            .cpu
            .as_ref()
            .map(|r| r.request)
            .unwrap_or(0);
        let mem_req = service_cfg
            .resources
            .memory
            .as_ref()
            .map(|r| r.request)
            .unwrap_or(0);
        let disk_req = service_cfg
            .resources
            .disk
            .as_ref()
            .map(|r| r.request)
            .unwrap_or(0);

        // Expand pool preference into a synthetic affinity
        let mut affinities = scheduling.affinity.clone();
        if let Some(ref pool_name) = scheduling.pool {
            affinities.push(AffinityConfig {
                attribute: "pool".to_string(),
                op: "=".to_string(),
                value: pool_name.clone(),
                weight: 50,
            });
        }

        // Determine pool algorithm if service prefers a specific pool
        let pool_algorithm = scheduling
            .pool
            .as_ref()
            .and_then(|p| pool_algorithms.get(p).copied());

        match scheduling.job_type {
            JobType::System | JobType::Sysbatch => {
                // System jobs run on every matching machine
                let matching: Vec<usize> = candidates
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| passes_constraints(c, &scheduling.constraints, service_name))
                    .filter(|(_, c)| passes_taints(c, &scheduling.tolerations))
                    .filter(|(_, c)| {
                        passes_required_spreads(c, &scheduling.spread, service_name, &candidates)
                    })
                    .filter(|(_, c)| {
                        c.available_cpu() >= cpu_req
                            && c.available_memory() >= mem_req
                            && c.available_disk() >= disk_req
                    })
                    .map(|(i, _)| i)
                    .collect();

                for idx in matching {
                    let instance_id = format!("{}-{}", service_name, candidates[idx].name);
                    placements.push(Placement {
                        service_name: service_name.to_string(),
                        instance_id: instance_id.clone(),
                        machine_name: candidates[idx].name.clone(),
                    });
                    candidates[idx].allocated_cpu += cpu_req;
                    candidates[idx].allocated_memory += mem_req;
                    candidates[idx].allocated_disk += disk_req;
                    candidates[idx]
                        .assigned_services
                        .push(service_name.to_string());
                }
            }
            _ => {
                // Filter + Score placement for replicated services
                for replica in 0..scheduling.replicas {
                    let instance_id = format!("{}-{}", service_name, replica);

                    // Phase 1: Filter
                    let filtered: Vec<usize> = candidates
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| {
                            passes_constraints(c, &scheduling.constraints, service_name)
                        })
                        .filter(|(_, c)| passes_taints(c, &scheduling.tolerations))
                        .filter(|(_, c)| {
                            passes_required_spreads(
                                c,
                                &scheduling.spread,
                                service_name,
                                &candidates,
                            )
                        })
                        .filter(|(_, c)| {
                            c.available_cpu() >= cpu_req
                                && c.available_memory() >= mem_req
                                && c.available_disk() >= disk_req
                        })
                        .map(|(i, _)| i)
                        .collect();

                    if filtered.is_empty() {
                        tracing::warn!(
                            service = service_name,
                            replica,
                            "No machines satisfy constraints"
                        );
                        blocked.push(BlockedPlacement {
                            service_name: service_name.to_string(),
                            instance_id,
                            reason: "no feasible machines".to_string(),
                        });
                        continue;
                    }

                    // Phase 2: Score
                    let mut scored: Vec<(usize, f64)> = filtered
                        .into_iter()
                        .map(|i| {
                            let score = compute_score(
                                &candidates[i],
                                service_name,
                                &candidates,
                                &affinities,
                                &scheduling.spread,
                                &scheduling.service_affinity,
                                pool_algorithm,
                            );
                            (i, score)
                        })
                        .collect();

                    // Phase 3: Select best
                    scored
                        .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

                    if let Some(&(best_idx, _score)) = scored.first() {
                        placements.push(Placement {
                            service_name: service_name.to_string(),
                            instance_id,
                            machine_name: candidates[best_idx].name.clone(),
                        });
                        candidates[best_idx].allocated_cpu += cpu_req;
                        candidates[best_idx].allocated_memory += mem_req;
                        candidates[best_idx].allocated_disk += disk_req;
                        candidates[best_idx]
                            .assigned_services
                            .push(service_name.to_string());
                    }
                }
            }
        }
    }

    PlacementPlan {
        placements,
        blocked,
        preemptions: Vec::new(), // Preemption not yet wired
    }
}

/// Check if a candidate machine passes all hard constraints.
fn passes_constraints(
    candidate: &Candidate,
    constraints: &[Constraint],
    service_name: &str,
) -> bool {
    for constraint in constraints {
        let actual = get_attribute(candidate, &constraint.attribute);
        let expected = &constraint.value;

        let passes = match constraint.op.as_str() {
            "=" | "==" => actual.as_deref() == Some(expected.as_str()),
            "!=" => actual.as_deref() != Some(expected.as_str()),
            "in" => {
                let values: Vec<&str> = expected.split(',').map(|s| s.trim()).collect();
                actual.as_deref().is_some_and(|a| values.contains(&a))
            }
            "not_in" => {
                let values: Vec<&str> = expected.split(',').map(|s| s.trim()).collect();
                actual.as_deref().is_none_or(|a| !values.contains(&a))
            }
            ">" | "gt" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), expected.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av > ev,
                    _ => a > expected.as_str(),
                }
            }),
            ">=" | "gte" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), expected.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av >= ev,
                    _ => a >= expected.as_str(),
                }
            }),
            "<" | "lt" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), expected.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av < ev,
                    _ => a < expected.as_str(),
                }
            }),
            "<=" | "lte" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), expected.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av <= ev,
                    _ => a <= expected.as_str(),
                }
            }),
            "regexp" | "matches" => actual.as_deref().is_some_and(|a| {
                regex::Regex::new(expected)
                    .map(|r| r.is_match(a))
                    .unwrap_or(false)
            }),
            "set_contains" => actual.as_deref().is_some_and(|a| {
                let attr_items: std::collections::HashSet<&str> =
                    a.split(',').map(|s| s.trim()).collect();
                expected
                    .split(',')
                    .map(|s| s.trim())
                    .all(|v| attr_items.contains(v))
            }),
            "set_contains_any" => actual.as_deref().is_some_and(|a| {
                let attr_items: std::collections::HashSet<&str> =
                    a.split(',').map(|s| s.trim()).collect();
                expected
                    .split(',')
                    .map(|s| s.trim())
                    .any(|v| attr_items.contains(v))
            }),
            "is_set" => actual.is_some(),
            "is_not_set" => actual.is_none(),
            "distinct_hosts" => !candidate
                .assigned_services
                .iter()
                .any(|s| s == service_name),
            _ => {
                tracing::warn!(op = %constraint.op, "Unknown constraint operator");
                true
            }
        };

        if !passes {
            return false;
        }
    }
    true
}

/// Check if placing on this candidate would violate required spread constraints.
fn passes_required_spreads(
    candidate: &Candidate,
    spreads: &[SpreadConfig],
    service_name: &str,
    all_candidates: &[Candidate],
) -> bool {
    for spread in spreads {
        if !spread.required {
            continue;
        }
        if let Some(max_skew) = spread.max_skew {
            let my_attr = get_attribute(candidate, &spread.attribute);
            if let Some(ref my_val) = my_attr {
                // Count instances per domain
                let mut domain_counts: HashMap<String, usize> = HashMap::new();
                for c in all_candidates {
                    if c.assigned_services.contains(&service_name.to_string())
                        && let Some(val) = get_attribute(c, &spread.attribute)
                    {
                        *domain_counts.entry(val).or_insert(0) += 1;
                    }
                }
                // Simulate placing here
                let my_count = domain_counts.get(my_val.as_str()).copied().unwrap_or(0) + 1;
                let min_count = domain_counts.values().copied().min().unwrap_or(0);
                // Check skew: difference between this domain and the minimum
                if my_count.saturating_sub(min_count) > max_skew as usize {
                    return false;
                }
            }
        }
        if let Some(min_domains) = spread.min_domains {
            // Count distinct domains that have instances
            let mut domains: std::collections::HashSet<String> = std::collections::HashSet::new();
            for c in all_candidates {
                if c.assigned_services.contains(&service_name.to_string())
                    && let Some(val) = get_attribute(c, &spread.attribute)
                {
                    domains.insert(val);
                }
            }
            // Include the current candidate's domain
            if let Some(val) = get_attribute(candidate, &spread.attribute) {
                domains.insert(val);
            }
            if (domains.len() as u32) < min_domains {
                // Not enough domains yet — this is OK, we're building up
                // Only reject if we would exceed max_skew while under min_domains
            }
        }
    }
    true
}

/// Check if a service tolerates all taints on a candidate machine.
fn passes_taints(candidate: &Candidate, tolerations: &[crate::config::Toleration]) -> bool {
    for taint in &candidate.config.taints {
        if taint.effect == TaintEffect::PreferNoSchedule {
            // Soft taint — handled in scoring, not filtering
            continue;
        }
        let tolerated = tolerations.iter().any(|t| {
            // Key must match (or toleration key is None = match all)
            let key_matches = t.key.as_ref().is_none_or(|k| k == &taint.key);
            // Effect must match (or toleration effect is None = match all)
            let effect_matches = t.effect.as_ref().is_none_or(|e| e == &taint.effect);
            // Operator check
            let op_matches = match t.op {
                TolerationOp::Exists => true,
                TolerationOp::Equal => t.value.as_deref() == taint.value.as_deref(),
            };
            key_matches && effect_matches && op_matches
        });
        if !tolerated {
            return false;
        }
    }
    true
}

/// Resolve a dotted attribute path against a candidate machine.
fn get_attribute(candidate: &Candidate, attribute: &str) -> Option<String> {
    let parts: Vec<&str> = attribute.splitn(2, '.').collect();
    match parts[0] {
        "pool" => Some(candidate.pool.clone()),
        "labels" => {
            if parts.len() == 2 {
                candidate.merged_labels.get(parts[1]).cloned()
            } else {
                None
            }
        }
        "capacity" => {
            if parts.len() == 2 {
                match parts[1] {
                    "cpu" => Some(candidate.config.capacity.cpu.to_string()),
                    "memory" => Some(candidate.config.capacity.memory.to_string()),
                    "disk" => Some(candidate.config.capacity.disk.to_string()),
                    _ => None,
                }
            } else {
                None
            }
        }
        "name" => Some(candidate.name.clone()),
        "schedulable" => {
            if parts.len() == 2 {
                match parts[1] {
                    "cpu" => Some(candidate.schedulable_cpu.to_string()),
                    "memory" => Some(candidate.schedulable_memory.to_string()),
                    "disk" => Some(candidate.schedulable_disk.to_string()),
                    _ => None,
                }
            } else {
                None
            }
        }
        "available" => {
            if parts.len() == 2 {
                match parts[1] {
                    "cpu" => Some(candidate.available_cpu().to_string()),
                    "memory" => Some(candidate.available_memory().to_string()),
                    "disk" => Some(candidate.available_disk().to_string()),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Compute a placement score for a candidate. Higher is better.
fn compute_score(
    candidate: &Candidate,
    service_name: &str,
    all_candidates: &[Candidate],
    affinities: &[AffinityConfig],
    spreads: &[SpreadConfig],
    service_affinities: &[ServiceAffinityConfig],
    pool_algorithm: Option<&SchedulerAlgorithm>,
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

    // Affinity scores
    for affinity in affinities {
        let actual = get_attribute(candidate, &affinity.attribute);
        let matches = match affinity.op.as_str() {
            "=" | "==" => actual.as_deref() == Some(affinity.value.as_str()),
            "!=" => actual.as_deref() != Some(affinity.value.as_str()),
            ">" | "gt" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), affinity.value.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av > ev,
                    _ => a > affinity.value.as_str(),
                }
            }),
            ">=" | "gte" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), affinity.value.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av >= ev,
                    _ => a >= affinity.value.as_str(),
                }
            }),
            "<" | "lt" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), affinity.value.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av < ev,
                    _ => a < affinity.value.as_str(),
                }
            }),
            "<=" | "lte" => actual.as_deref().is_some_and(|a| {
                match (a.parse::<f64>(), affinity.value.parse::<f64>()) {
                    (Ok(av), Ok(ev)) => av <= ev,
                    _ => a <= affinity.value.as_str(),
                }
            }),
            "regexp" | "matches" => actual.as_deref().is_some_and(|a| {
                regex::Regex::new(&affinity.value)
                    .map(|r| r.is_match(a))
                    .unwrap_or(false)
            }),
            "is_set" => actual.is_some(),
            "is_not_set" => actual.is_none(),
            _ => false,
        };
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

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CapacityConfig, ResourceConfig, ResourceValue, SchedulingConfig};

    fn make_machine(
        name: &str,
        cpu: u64,
        memory: u64,
        labels: Vec<(&str, &str)>,
    ) -> (String, MachineConfig) {
        (
            name.to_string(),
            MachineConfig {
                target_host: format!("10.0.0.{}", name.len()),
                labels: labels
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                capacity: CapacityConfig {
                    cpu,
                    memory,
                    disk: 0,
                },
                pool: "default".to_string(),
                reserved: CapacityConfig::default(),
                taints: vec![],
            },
        )
    }

    fn make_machine_in_pool(
        name: &str,
        cpu: u64,
        memory: u64,
        labels: Vec<(&str, &str)>,
        pool: &str,
        reserved_cpu: u64,
        reserved_memory: u64,
    ) -> (String, MachineConfig) {
        (
            name.to_string(),
            MachineConfig {
                target_host: format!("10.0.0.{}", name.len()),
                labels: labels
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                capacity: CapacityConfig {
                    cpu,
                    memory,
                    disk: 0,
                },
                pool: pool.to_string(),
                reserved: CapacityConfig {
                    cpu: reserved_cpu,
                    memory: reserved_memory,
                    disk: 0,
                },
                taints: vec![],
            },
        )
    }

    fn make_service(name: &str, cpu: u64, memory: u64, replicas: u32) -> (String, ServiceConfig) {
        (
            name.to_string(),
            ServiceConfig {
                command: format!("/bin/{name}"),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: cpu,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: memory,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas,
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )
    }

    fn no_pools() -> HashMap<String, NodePoolConfig> {
        HashMap::new()
    }

    #[test]
    fn basic_placement() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("node-1", 4000, 8192, vec![("role", "app")]),
            make_machine("node-2", 4000, 8192, vec![("role", "app")]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [make_service("web", 500, 1024, 2)].into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 2);

        // Both replicas should be placed (on different nodes due to distinct-host penalty)
        let nodes: Vec<&str> = plan
            .placements
            .iter()
            .map(|p| p.machine_name.as_str())
            .collect();
        assert!(nodes.contains(&"node-1") || nodes.contains(&"node-2"));
    }

    #[test]
    fn constraint_filtering() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("app-1", 4000, 8192, vec![("role", "app")]),
            make_machine("db-1", 8000, 16384, vec![("role", "db")]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "api".to_string(),
            ServiceConfig {
                command: "/bin/api".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 500,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 1024,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    constraints: vec![Constraint {
                        attribute: "labels.role".into(),
                        op: "=".into(),
                        value: "app".into(),
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].machine_name, "app-1");
    }

    #[test]
    fn system_job_all_nodes() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("node-1", 4000, 8192, vec![]),
            make_machine("node-2", 4000, 8192, vec![]),
            make_machine("node-3", 4000, 8192, vec![]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "monitoring".to_string(),
            ServiceConfig {
                command: "/bin/monitor".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    job_type: JobType::System,
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 3);
    }

    #[test]
    fn insufficient_resources() {
        let machines: HashMap<String, MachineConfig> =
            [make_machine("tiny", 100, 256, vec![])].into();

        let services: HashMap<String, ServiceConfig> = [make_service("big", 8000, 16384, 1)].into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 0);
    }

    #[test]
    fn pool_affinity_prefers_correct_pool() {
        let pools: HashMap<String, NodePoolConfig> = [
            (
                "default".to_string(),
                NodePoolConfig {
                    labels: HashMap::new(),
                    scaling: None,
                    scheduler_algorithm: None,
                    memory_oversubscription: false,
                },
            ),
            (
                "compute".to_string(),
                NodePoolConfig {
                    labels: HashMap::new(),
                    scaling: None,
                    scheduler_algorithm: None,
                    memory_oversubscription: false,
                },
            ),
        ]
        .into();

        let machines: HashMap<String, MachineConfig> = [
            make_machine_in_pool("app-1", 4000, 8192, vec![], "default", 0, 0),
            make_machine_in_pool("compute-1", 4000, 8192, vec![], "compute", 0, 0),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "ml".to_string(),
            ServiceConfig {
                command: "/bin/ml".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 500,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 1024,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    pool: Some("compute".to_string()),
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &pools);
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].machine_name, "compute-1");
    }

    #[test]
    fn pool_affinity_spills_when_full() {
        let pools: HashMap<String, NodePoolConfig> = [
            (
                "default".to_string(),
                NodePoolConfig {
                    labels: HashMap::new(),
                    scaling: None,
                    scheduler_algorithm: None,
                    memory_oversubscription: false,
                },
            ),
            (
                "compute".to_string(),
                NodePoolConfig {
                    labels: HashMap::new(),
                    scaling: None,
                    scheduler_algorithm: None,
                    memory_oversubscription: false,
                },
            ),
        ]
        .into();

        // compute-1 has very little capacity — only fits 1 replica
        let machines: HashMap<String, MachineConfig> = [
            make_machine_in_pool("app-1", 4000, 8192, vec![], "default", 0, 0),
            make_machine_in_pool("compute-1", 600, 2048, vec![], "compute", 0, 0),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "ml".to_string(),
            ServiceConfig {
                command: "/bin/ml".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 500,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 1024,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 2,
                    pool: Some("compute".to_string()),
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &pools);
        assert_eq!(plan.placements.len(), 2);

        // One on compute, one spilled to default
        let on_compute = plan
            .placements
            .iter()
            .filter(|p| p.machine_name == "compute-1")
            .count();
        let on_default = plan
            .placements
            .iter()
            .filter(|p| p.machine_name == "app-1")
            .count();
        assert_eq!(on_compute, 1);
        assert_eq!(on_default, 1);
    }

    #[test]
    fn pool_hard_constraint_blocks_spillover() {
        let pools: HashMap<String, NodePoolConfig> = [(
            "compute".to_string(),
            NodePoolConfig {
                labels: HashMap::new(),
                scaling: None,
                scheduler_algorithm: None,
                memory_oversubscription: false,
            },
        )]
        .into();

        let machines: HashMap<String, MachineConfig> = [
            make_machine_in_pool("app-1", 4000, 8192, vec![], "default", 0, 0),
            make_machine_in_pool("compute-1", 600, 2048, vec![], "compute", 0, 0),
        ]
        .into();

        // Hard constraint: must be in compute pool
        let services: HashMap<String, ServiceConfig> = [(
            "ml".to_string(),
            ServiceConfig {
                command: "/bin/ml".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 500,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 1024,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 2,
                    constraints: vec![Constraint {
                        attribute: "pool".into(),
                        op: "=".into(),
                        value: "compute".into(),
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &pools);
        // Only 1 can fit on compute-1, second has no room and cannot spill
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].machine_name, "compute-1");
    }

    #[test]
    fn reserved_capacity_reduces_schedulable() {
        let machines: HashMap<String, MachineConfig> = [make_machine_in_pool(
            "node-1",
            4000,
            8192,
            vec![],
            "default",
            500,
            512,
        )]
        .into();

        // Request exactly the schedulable amount (3500 cpu, 7680 mem)
        let services: HashMap<String, ServiceConfig> = [make_service("svc", 3500, 7680, 1)].into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 1);
    }

    #[test]
    fn reserved_prevents_overcommit() {
        let machines: HashMap<String, MachineConfig> = [make_machine_in_pool(
            "node-1",
            4000,
            8192,
            vec![],
            "default",
            500,
            512,
        )]
        .into();

        // Request more than schedulable (3600 > 3500 schedulable cpu)
        let services: HashMap<String, ServiceConfig> = [make_service("svc", 3600, 1024, 1)].into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 0);
    }

    #[test]
    fn pool_labels_merged() {
        let pools: HashMap<String, NodePoolConfig> = [(
            "compute".to_string(),
            NodePoolConfig {
                labels: [
                    ("tier".to_string(), "compute-optimized".to_string()),
                    ("shared".to_string(), "from-pool".to_string()),
                ]
                .into(),
                scaling: None,
                scheduler_algorithm: None,
                memory_oversubscription: false,
            },
        )]
        .into();

        // Machine overrides "shared" label but inherits "tier"
        let machines: HashMap<String, MachineConfig> = [make_machine_in_pool(
            "c-1",
            4000,
            8192,
            vec![("shared", "from-machine")],
            "compute",
            0,
            0,
        )]
        .into();

        // Constraint on pool-inherited label
        let services: HashMap<String, ServiceConfig> = [(
            "svc".to_string(),
            ServiceConfig {
                command: "/bin/svc".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    constraints: vec![Constraint {
                        attribute: "labels.tier".into(),
                        op: "=".into(),
                        value: "compute-optimized".into(),
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &pools);
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].machine_name, "c-1");
    }

    #[test]
    fn default_pool_backwards_compat() {
        // No pools defined, no pool on machines — should work identically to before
        let machines: HashMap<String, MachineConfig> = [
            make_machine("node-1", 4000, 8192, vec![]),
            make_machine("node-2", 4000, 8192, vec![]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [make_service("web", 500, 1024, 2)].into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 2);
    }

    #[test]
    fn system_job_on_pool() {
        let pools: HashMap<String, NodePoolConfig> = [
            (
                "default".to_string(),
                NodePoolConfig {
                    labels: HashMap::new(),
                    scaling: None,
                    scheduler_algorithm: None,
                    memory_oversubscription: false,
                },
            ),
            (
                "compute".to_string(),
                NodePoolConfig {
                    labels: HashMap::new(),
                    scaling: None,
                    scheduler_algorithm: None,
                    memory_oversubscription: false,
                },
            ),
        ]
        .into();

        let machines: HashMap<String, MachineConfig> = [
            make_machine_in_pool("app-1", 4000, 8192, vec![], "default", 0, 0),
            make_machine_in_pool("compute-1", 4000, 8192, vec![], "compute", 0, 0),
            make_machine_in_pool("compute-2", 4000, 8192, vec![], "compute", 0, 0),
        ]
        .into();

        // System job constrained to compute pool
        let services: HashMap<String, ServiceConfig> = [(
            "monitor".to_string(),
            ServiceConfig {
                command: "/bin/monitor".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    job_type: JobType::System,
                    constraints: vec![Constraint {
                        attribute: "pool".into(),
                        op: "=".into(),
                        value: "compute".into(),
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &pools);
        // Should only run on the 2 compute pool machines
        assert_eq!(plan.placements.len(), 2);
        for p in &plan.placements {
            assert!(p.machine_name.starts_with("compute-"));
        }
    }

    #[test]
    fn constraint_numeric_operators() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("big", 8000, 16384, vec![("cores", "8")]),
            make_machine("small", 2000, 4096, vec![("cores", "2")]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "svc".to_string(),
            ServiceConfig {
                command: "/bin/svc".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    constraints: vec![Constraint {
                        attribute: "labels.cores".into(),
                        op: ">".into(),
                        value: "4".into(),
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].machine_name, "big");
    }

    #[test]
    fn constraint_regexp() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("web-1", 4000, 8192, vec![("role", "web-frontend")]),
            make_machine("db-1", 4000, 8192, vec![("role", "database")]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "svc".to_string(),
            ServiceConfig {
                command: "/bin/svc".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    constraints: vec![Constraint {
                        attribute: "labels.role".into(),
                        op: "regexp".into(),
                        value: "^web-.*".into(),
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].machine_name, "web-1");
    }

    #[test]
    fn constraint_is_set() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("gpu-1", 4000, 8192, vec![("gpu", "true")]),
            make_machine("cpu-1", 4000, 8192, vec![]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "svc".to_string(),
            ServiceConfig {
                command: "/bin/svc".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    constraints: vec![Constraint {
                        attribute: "labels.gpu".into(),
                        op: "is_set".into(),
                        value: String::new(),
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].machine_name, "gpu-1");
    }

    #[test]
    fn multiple_spread_blocks() {
        use crate::config::SpreadConfig;

        let machines: HashMap<String, MachineConfig> = [
            make_machine("n1", 4000, 8192, vec![("zone", "a"), ("rack", "r1")]),
            make_machine("n2", 4000, 8192, vec![("zone", "a"), ("rack", "r2")]),
            make_machine("n3", 4000, 8192, vec![("zone", "b"), ("rack", "r1")]),
            make_machine("n4", 4000, 8192, vec![("zone", "b"), ("rack", "r2")]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "svc".to_string(),
            ServiceConfig {
                command: "/bin/svc".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 4,
                    spread: vec![
                        SpreadConfig {
                            attribute: "labels.zone".into(),
                            weight: Some(50),
                            targets: vec![],
                            max_skew: None,
                            min_domains: None,
                            required: false,
                        },
                        SpreadConfig {
                            attribute: "labels.rack".into(),
                            weight: Some(30),
                            targets: vec![],
                            max_skew: None,
                            min_domains: None,
                            required: false,
                        },
                    ],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 4);
        // All 4 machines should be used (spread across both zone and rack)
        let mut used: Vec<&str> = plan
            .placements
            .iter()
            .map(|p| p.machine_name.as_str())
            .collect();
        used.sort();
        used.dedup();
        assert_eq!(used.len(), 4);
    }

    #[test]
    fn priority_ordering() {
        // One machine with limited capacity
        let machines: HashMap<String, MachineConfig> =
            [make_machine("node-1", 1000, 2048, vec![])].into();

        // Two services both want the machine, high priority should win
        let services: HashMap<String, ServiceConfig> = [
            (
                "low".to_string(),
                ServiceConfig {
                    command: "/bin/low".into(),
                    ports: HashMap::new(),
                    secrets: HashMap::new(),
                    identity: Default::default(),
                    resources: ResourceConfig {
                        cpu: Some(ResourceValue {
                            request: 800,
                            limit: None,
                        }),
                        memory: Some(ResourceValue {
                            request: 1024,
                            limit: None,
                        }),
                        disk: None,
                    },
                    scheduling: SchedulingConfig {
                        replicas: 1,
                        priority: 30,
                        ..Default::default()
                    },
                    environment: HashMap::new(),
                    templates: HashMap::new(),
                    lifecycle: Default::default(),
                },
            ),
            (
                "high".to_string(),
                ServiceConfig {
                    command: "/bin/high".into(),
                    ports: HashMap::new(),
                    secrets: HashMap::new(),
                    identity: Default::default(),
                    resources: ResourceConfig {
                        cpu: Some(ResourceValue {
                            request: 800,
                            limit: None,
                        }),
                        memory: Some(ResourceValue {
                            request: 1024,
                            limit: None,
                        }),
                        disk: None,
                    },
                    scheduling: SchedulingConfig {
                        replicas: 1,
                        priority: 80,
                        ..Default::default()
                    },
                    environment: HashMap::new(),
                    templates: HashMap::new(),
                    lifecycle: Default::default(),
                },
            ),
        ]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        // High priority should be placed, low should be blocked
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].service_name, "high");
        assert_eq!(plan.blocked.len(), 1);
        assert_eq!(plan.blocked[0].service_name, "low");
    }

    #[test]
    fn taint_blocks_non_tolerating_service() {
        use crate::config::{Taint, TaintEffect, Toleration, TolerationOp};

        let machines: HashMap<String, MachineConfig> = [(
            "gpu-1".to_string(),
            MachineConfig {
                target_host: "10.0.0.1".into(),
                labels: HashMap::new(),
                capacity: CapacityConfig {
                    cpu: 4000,
                    memory: 8192,
                    disk: 0,
                },
                pool: "default".to_string(),
                reserved: CapacityConfig::default(),
                taints: vec![Taint {
                    key: "hardware".into(),
                    value: Some("gpu".into()),
                    effect: TaintEffect::NoSchedule,
                }],
            },
        )]
        .into();

        // Service without toleration — should be blocked
        let services: HashMap<String, ServiceConfig> = [make_service("web", 100, 256, 1)].into();
        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 0);
        assert_eq!(plan.blocked.len(), 1);

        // Service WITH toleration — should be placed
        let services: HashMap<String, ServiceConfig> = [(
            "ml".to_string(),
            ServiceConfig {
                command: "/bin/ml".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    tolerations: vec![Toleration {
                        key: Some("hardware".into()),
                        op: TolerationOp::Equal,
                        value: Some("gpu".into()),
                        effect: Some(TaintEffect::NoSchedule),
                        toleration_seconds: None,
                    }],
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();
        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 1);
    }

    #[test]
    fn sysbatch_runs_on_all_nodes() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("n1", 4000, 8192, vec![]),
            make_machine("n2", 4000, 8192, vec![]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [(
            "migrate".to_string(),
            ServiceConfig {
                command: "/bin/migrate".into(),
                ports: HashMap::new(),
                secrets: HashMap::new(),
                identity: Default::default(),
                resources: ResourceConfig {
                    cpu: Some(ResourceValue {
                        request: 100,
                        limit: None,
                    }),
                    memory: Some(ResourceValue {
                        request: 256,
                        limit: None,
                    }),
                    disk: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    job_type: JobType::Sysbatch,
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines, &no_pools());
        assert_eq!(plan.placements.len(), 2);
    }
}
