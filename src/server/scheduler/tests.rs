use super::*;
use crate::config::{CapacityConfig, Constraint, ResourceConfig, ResourceValue, SchedulingConfig};
use std::collections::HashMap;

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
            extended_resources: HashMap::new(),
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
            extended_resources: HashMap::new(),
        },
    )
}

fn make_service(name: &str, cpu: u64, memory: u64, replicas: u32) -> (String, ServiceConfig) {
    (
        name.to_string(),
        ServiceConfig {
            command: Some(format!("/bin/{name}")),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
            },
            scheduling: SchedulingConfig {
                replicas,
                ..Default::default()
            },
            environment: HashMap::new(),
            templates: HashMap::new(),
            lifecycle: Default::default(),
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            command: Some("/bin/api".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            command: Some("/bin/monitor".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
            },
            scheduling: SchedulingConfig {
                replicas: 1,
                job_type: JobType::System,
                ..Default::default()
            },
            environment: HashMap::new(),
            templates: HashMap::new(),
            lifecycle: Default::default(),
            volumes: Vec::new(),
            sidecars: Vec::new(),
        },
    )]
    .into();

    let plan = schedule(&services, &machines, &no_pools());
    assert_eq!(plan.placements.len(), 3);
}

#[test]
fn insufficient_resources() {
    let machines: HashMap<String, MachineConfig> = [make_machine("tiny", 100, 256, vec![])].into();

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
                cloud: None,
            },
        ),
        (
            "compute".to_string(),
            NodePoolConfig {
                labels: HashMap::new(),
                scaling: None,
                scheduler_algorithm: None,
                memory_oversubscription: false,
                cloud: None,
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
            command: Some("/bin/ml".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
            },
            scheduling: SchedulingConfig {
                replicas: 1,
                pool: Some("compute".to_string()),
                ..Default::default()
            },
            environment: HashMap::new(),
            templates: HashMap::new(),
            lifecycle: Default::default(),
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
                cloud: None,
            },
        ),
        (
            "compute".to_string(),
            NodePoolConfig {
                labels: HashMap::new(),
                scaling: None,
                scheduler_algorithm: None,
                memory_oversubscription: false,
                cloud: None,
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
            command: Some("/bin/ml".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
            },
            scheduling: SchedulingConfig {
                replicas: 2,
                pool: Some("compute".to_string()),
                ..Default::default()
            },
            environment: HashMap::new(),
            templates: HashMap::new(),
            lifecycle: Default::default(),
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            cloud: None,
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
            command: Some("/bin/ml".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            cloud: None,
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
            command: Some("/bin/svc".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
                cloud: None,
            },
        ),
        (
            "compute".to_string(),
            NodePoolConfig {
                labels: HashMap::new(),
                scaling: None,
                scheduler_algorithm: None,
                memory_oversubscription: false,
                cloud: None,
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
            command: Some("/bin/monitor".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            command: Some("/bin/svc".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            command: Some("/bin/svc".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            command: Some("/bin/svc".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            command: Some("/bin/svc".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
                command: Some("/bin/low".into()),
                container: None,
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
                    extended: HashMap::new(),
                    cgroup_controls: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    priority: 30,
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
                volumes: Vec::new(),
                sidecars: Vec::new(),
            },
        ),
        (
            "high".to_string(),
            ServiceConfig {
                command: Some("/bin/high".into()),
                container: None,
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
                    extended: HashMap::new(),
                    cgroup_controls: None,
                },
                scheduling: SchedulingConfig {
                    replicas: 1,
                    priority: 80,
                    ..Default::default()
                },
                environment: HashMap::new(),
                templates: HashMap::new(),
                lifecycle: Default::default(),
                volumes: Vec::new(),
                sidecars: Vec::new(),
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
            extended_resources: HashMap::new(),
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
            command: Some("/bin/ml".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
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
            volumes: Vec::new(),
            sidecars: Vec::new(),
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
            command: Some("/bin/migrate".into()),
            container: None,
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
                extended: HashMap::new(),
                cgroup_controls: None,
            },
            scheduling: SchedulingConfig {
                replicas: 1,
                job_type: JobType::Sysbatch,
                ..Default::default()
            },
            environment: HashMap::new(),
            templates: HashMap::new(),
            lifecycle: Default::default(),
            volumes: Vec::new(),
            sidecars: Vec::new(),
        },
    )]
    .into();

    let plan = schedule(&services, &machines, &no_pools());
    assert_eq!(plan.placements.len(), 2);
}
