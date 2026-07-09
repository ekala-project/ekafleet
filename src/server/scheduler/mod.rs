#![allow(dead_code)]

mod constraints;
mod scoring;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use crate::config::{
    AffinityConfig, JobType, MachineConfig, NodePoolConfig, ResourceConfig, SchedulerAlgorithm,
    ServiceConfig,
};

use constraints::{passes_constraints, passes_required_spreads, passes_taints};
use scoring::{compute_score, find_preemption_candidate};

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

/// Flattened resource requirements extracted from a service's ResourceConfig.
#[derive(Debug, Clone)]
pub struct ResourceRequirements {
    pub cpu: u64,
    pub memory: u64,
    pub disk: u64,
    pub extended: HashMap<String, u64>,
}

impl ResourceRequirements {
    pub fn from_config(resources: &ResourceConfig) -> Self {
        Self {
            cpu: resources.cpu.as_ref().map(|r| r.request).unwrap_or(0),
            memory: resources.memory.as_ref().map(|r| r.request).unwrap_or(0),
            disk: resources.disk.as_ref().map(|r| r.request).unwrap_or(0),
            extended: resources.extended.clone(),
        }
    }
}

/// A machine candidate during scheduling with tracked allocated resources.
#[derive(Debug, Clone)]
struct Candidate {
    pub(crate) name: String,
    pub(crate) config: MachineConfig,
    pub(crate) pool: String,
    pub(crate) merged_labels: HashMap<String, String>,
    pub(crate) schedulable_cpu: u64,
    pub(crate) schedulable_memory: u64,
    pub(crate) schedulable_disk: u64,
    pub(crate) allocated_cpu: u64,
    pub(crate) allocated_memory: u64,
    pub(crate) allocated_disk: u64,
    pub(crate) assigned_services: Vec<String>,
    pub(crate) extended_resources: HashMap<String, u64>,
    pub(crate) allocated_extended: HashMap<String, u64>,
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

    /// Allocate resources for a service on this candidate.
    fn allocate(&mut self, reqs: &ResourceRequirements, service_name: &str) {
        self.allocated_cpu += reqs.cpu;
        self.allocated_memory += reqs.memory;
        self.allocated_disk += reqs.disk;
        for (key, val) in &reqs.extended {
            *self.allocated_extended.entry(key.clone()).or_insert(0) += val;
        }
        self.assigned_services.push(service_name.to_string());
    }

    /// Deallocate resources for a service from this candidate.
    fn deallocate(&mut self, reqs: &ResourceRequirements, service_name: &str) {
        self.allocated_cpu = self.allocated_cpu.saturating_sub(reqs.cpu);
        self.allocated_memory = self.allocated_memory.saturating_sub(reqs.memory);
        self.allocated_disk = self.allocated_disk.saturating_sub(reqs.disk);
        for (key, val) in &reqs.extended {
            if let Some(alloc) = self.allocated_extended.get_mut(key) {
                *alloc = alloc.saturating_sub(*val);
            }
        }
        self.assigned_services.retain(|s| s != service_name);
    }

    /// Check if this candidate has enough resources for the given requirements.
    fn has_resources_for(&self, reqs: &ResourceRequirements) -> bool {
        self.available_cpu() >= reqs.cpu
            && self.available_memory() >= reqs.memory
            && self.available_disk() >= reqs.disk
            && reqs.extended.iter().all(|(key, needed)| {
                let total = self.extended_resources.get(key).copied().unwrap_or(0);
                let used = self.allocated_extended.get(key).copied().unwrap_or(0);
                total.saturating_sub(used) >= *needed
            })
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
                extended_resources: config.extended_resources.clone(),
                config: config.clone(),
                allocated_cpu: 0,
                allocated_memory: 0,
                allocated_disk: 0,
                assigned_services: Vec::new(),
                allocated_extended: HashMap::new(),
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
    let mut preemptions = Vec::new();

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
        let reqs = ResourceRequirements::from_config(&service_cfg.resources);

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
                    .filter(|(_, c)| c.has_resources_for(&reqs))
                    .map(|(i, _)| i)
                    .collect();

                for idx in matching {
                    let instance_id = format!("{}-{}", service_name, candidates[idx].name);
                    placements.push(Placement {
                        service_name: service_name.to_string(),
                        instance_id: instance_id.clone(),
                        machine_name: candidates[idx].name.clone(),
                    });
                    candidates[idx].allocate(&reqs, service_name);
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
                        .filter(|(_, c)| c.has_resources_for(&reqs))
                        .map(|(i, _)| i)
                        .collect();

                    if filtered.is_empty() {
                        // Attempt preemption
                        if let Some((preempt_idx, evicted)) = find_preemption_candidate(
                            &candidates,
                            &scheduling.constraints,
                            &scheduling.tolerations,
                            service_name,
                            scheduling.priority,
                            &reqs,
                            services,
                        ) {
                            for ev in &evicted {
                                preemptions.push(ev.clone());
                                let ev_reqs = ResourceRequirements::from_config(
                                    &services[&ev.evicted_service].resources,
                                );
                                candidates[preempt_idx].deallocate(&ev_reqs, &ev.evicted_service);
                            }

                            placements.push(Placement {
                                service_name: service_name.to_string(),
                                instance_id,
                                machine_name: candidates[preempt_idx].name.clone(),
                            });
                            candidates[preempt_idx].allocate(&reqs, service_name);
                            continue;
                        }

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
                        candidates[best_idx].allocate(&reqs, service_name);
                    }
                }
            }
        }
    }

    PlacementPlan {
        placements,
        blocked,
        preemptions,
    }
}
