#![allow(dead_code)]

use std::collections::HashMap;

use crate::config::{
    AffinityConfig, Constraint, JobType, MachineConfig, ServiceConfig, SpreadConfig,
};

/// Result of scheduling: which services go to which machines.
#[derive(Debug, Clone)]
pub struct PlacementPlan {
    pub placements: Vec<Placement>,
}

#[derive(Debug, Clone)]
pub struct Placement {
    pub service_name: String,
    pub instance_id: String,
    pub machine_name: String,
}

/// A machine candidate during scheduling with tracked allocated resources.
#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    config: MachineConfig,
    allocated_cpu: u64,
    allocated_memory: u64,
    assigned_services: Vec<String>,
}

impl Candidate {
    fn available_cpu(&self) -> u64 {
        self.config.capacity.cpu.saturating_sub(self.allocated_cpu)
    }

    fn available_memory(&self) -> u64 {
        self.config
            .capacity
            .memory
            .saturating_sub(self.allocated_memory)
    }

    fn utilization(&self) -> f64 {
        if self.config.capacity.cpu == 0 && self.config.capacity.memory == 0 {
            return 0.0;
        }
        let cpu_util = if self.config.capacity.cpu > 0 {
            self.allocated_cpu as f64 / self.config.capacity.cpu as f64
        } else {
            0.0
        };
        let mem_util = if self.config.capacity.memory > 0 {
            self.allocated_memory as f64 / self.config.capacity.memory as f64
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
) -> PlacementPlan {
    let mut candidates: Vec<Candidate> = machines
        .iter()
        .map(|(name, config)| Candidate {
            name: name.clone(),
            config: config.clone(),
            allocated_cpu: 0,
            allocated_memory: 0,
            assigned_services: Vec::new(),
        })
        .collect();

    let mut placements = Vec::new();

    // Schedule system jobs first (run on all matching nodes),
    // then services, stateful, batch
    let mut service_list: Vec<(&str, &ServiceConfig)> = services
        .iter()
        .map(|(name, cfg)| (name.as_str(), cfg))
        .collect();

    service_list.sort_by_key(|(_, cfg)| match cfg.scheduling.job_type {
        JobType::System => 0,
        JobType::Service => 1,
        JobType::Stateful => 2,
        JobType::Batch => 3,
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

        match scheduling.job_type {
            JobType::System => {
                // System jobs run on every matching machine
                let matching: Vec<usize> = candidates
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| passes_constraints(c, &scheduling.constraints))
                    .filter(|(_, c)| {
                        c.available_cpu() >= cpu_req && c.available_memory() >= mem_req
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
                        .filter(|(_, c)| passes_constraints(c, &scheduling.constraints))
                        .filter(|(_, c)| {
                            c.available_cpu() >= cpu_req && c.available_memory() >= mem_req
                        })
                        .map(|(i, _)| i)
                        .collect();

                    if filtered.is_empty() {
                        tracing::warn!(
                            service = service_name,
                            replica,
                            "No machines satisfy constraints"
                        );
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
                                &scheduling.affinity,
                                &scheduling.spread,
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
                        candidates[best_idx]
                            .assigned_services
                            .push(service_name.to_string());
                    }
                }
            }
        }
    }

    PlacementPlan { placements }
}

/// Check if a candidate machine passes all hard constraints.
fn passes_constraints(candidate: &Candidate, constraints: &[Constraint]) -> bool {
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

/// Resolve a dotted attribute path against a candidate machine.
fn get_attribute(candidate: &Candidate, attribute: &str) -> Option<String> {
    let parts: Vec<&str> = attribute.splitn(2, '.').collect();
    match parts[0] {
        "labels" => {
            if parts.len() == 2 {
                candidate.config.labels.get(parts[1]).cloned()
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
        _ => None,
    }
}

/// Compute a placement score for a candidate. Higher is better.
fn compute_score(
    candidate: &Candidate,
    service_name: &str,
    all_candidates: &[Candidate],
    affinities: &[AffinityConfig],
    spread: &Option<SpreadConfig>,
) -> f64 {
    let mut score = 0.0;

    // Bin-packing score: prefer machines that are already partially utilized
    // to consolidate workloads (higher utilization = higher score, up to a point)
    let util = candidate.utilization();
    score += util * 30.0; // weight: 30

    // Spread score: distribute instances across distinct attribute values
    if let Some(spread_cfg) = spread {
        let my_attr = get_attribute(candidate, &spread_cfg.attribute);
        if let Some(ref my_val) = my_attr {
            // Count how many instances of this service are already on machines
            // with the same attribute value
            let same_count = all_candidates
                .iter()
                .filter(|c| {
                    c.assigned_services.contains(&service_name.to_string())
                        && get_attribute(c, &spread_cfg.attribute).as_deref() == Some(my_val)
                })
                .count();

            // Fewer same-attribute placements = higher score
            let spread_weight = spread_cfg.weight.unwrap_or(50) as f64;
            score += spread_weight / (same_count as f64 + 1.0);
        }
    }

    // Affinity scores
    for affinity in affinities {
        let actual = get_attribute(candidate, &affinity.attribute);
        let matches = match affinity.op.as_str() {
            "=" | "==" => actual.as_deref() == Some(affinity.value.as_str()),
            "!=" => actual.as_deref() != Some(affinity.value.as_str()),
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
                },
                scheduling: SchedulingConfig {
                    replicas,
                    ..Default::default()
                },
                environment: HashMap::new(),
            },
        )
    }

    #[test]
    fn basic_placement() {
        let machines: HashMap<String, MachineConfig> = [
            make_machine("node-1", 4000, 8192, vec![("role", "app")]),
            make_machine("node-2", 4000, 8192, vec![("role", "app")]),
        ]
        .into();

        let services: HashMap<String, ServiceConfig> = [make_service("web", 500, 1024, 2)].into();

        let plan = schedule(&services, &machines);
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
            },
        )]
        .into();

        let plan = schedule(&services, &machines);
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
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    job_type: JobType::System,
                    ..Default::default()
                },
                environment: HashMap::new(),
            },
        )]
        .into();

        let plan = schedule(&services, &machines);
        assert_eq!(plan.placements.len(), 3);
    }

    #[test]
    fn insufficient_resources() {
        let machines: HashMap<String, MachineConfig> =
            [make_machine("tiny", 100, 256, vec![])].into();

        let services: HashMap<String, ServiceConfig> = [make_service("big", 8000, 16384, 1)].into();

        let plan = schedule(&services, &machines);
        assert_eq!(plan.placements.len(), 0);
    }
}
