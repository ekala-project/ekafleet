# Scheduling Reference

This document is a comprehensive specification for ekafleet's scheduling system. It covers the current implementation, documents the gaps relative to Nomad and Kubernetes, and specifies exactly what needs to be built. It is intended to serve as a complete reference for any agent implementing scheduling features.

---

## Table of Contents

1. [Current Implementation](#current-implementation)
2. [Scheduler Types](#scheduler-types)
3. [Priority and Preemption](#priority-and-preemption)
4. [Constraints](#constraints)
5. [Affinities](#affinities)
6. [Spread](#spread)
7. [Topology Spread Constraints](#topology-spread-constraints)
8. [Taints and Tolerations](#taints-and-tolerations)
9. [Resources](#resources)
10. [Node Pools](#node-pools)
11. [Restart Policy](#restart-policy)
12. [Reschedule Policy](#reschedule-policy)
13. [Update / Deployment Strategy](#update--deployment-strategy)
14. [Migration (Node Drain)](#migration-node-drain)
15. [Periodic / Cron Jobs](#periodic--cron-jobs)
16. [Scaling](#scaling)
17. [Scheduler Algorithm and Architecture](#scheduler-algorithm-and-architecture)
18. [Feature Matrix](#feature-matrix)

---

## Current Implementation

### Key Files

| File | Purpose |
|------|---------|
| `src/config.rs` | All scheduling-related types: `SchedulingConfig`, `Constraint`, `AffinityConfig`, `SpreadConfig`, `UpdateConfig`, `JobType`, `NodePoolConfig`, `PoolScalingConfig` |
| `src/server/scheduler.rs` | Two-phase placement engine: `schedule()`, `Candidate`, `passes_constraints()`, `compute_score()`, `get_attribute()` |
| `src/server/reconciler.rs` | Reconciliation loop: `reconcile_once()`, `compute_plan()`, `apply_plan()` |
| `src/server/deployer.rs` | Deployment orchestration: rolling, canary, blue-green strategies |
| `src/server/scaling.rs` | Service-level `ScalingEngine` and pool-level `PoolScalingEngine` |
| `src/server/state.rs` | Runtime fleet state: `FleetState`, `NodeInfo`, `AgentServiceInfo` |
| `proto/fleet.proto` | gRPC message types: `Heartbeat`, `NodeStatus`, `PoolStatus`, `ServiceStatus` |

### Current Algorithm

The scheduler (`src/server/scheduler.rs:schedule()`) runs a three-phase algorithm:

1. **Sort services by job type priority**: System (0) > Service (1) > Stateful (2) > Batch (3)
2. **For each service**, per-replica:
   - **Phase 1 — Filter**: Eliminate machines that fail hard constraints or lack resources
   - **Phase 2 — Score**: Rank remaining candidates by weighted scoring function
   - **Phase 3 — Select**: Pick highest-scoring candidate, allocate resources, continue to next replica
3. **System jobs** skip the per-replica loop and instead place on every matching machine

### Current Scoring Function (`compute_score()`)

| Factor | Weight | Description |
|--------|--------|-------------|
| Bin-packing | 30 | Prefer partially utilized machines (higher utilization = higher score) |
| Spread | Configurable (default 50) | Fewer same-attribute placements = higher score |
| Affinity | Per-affinity weight | Matching affinity adds weight to score |
| Distinct hosts | -100 penalty | Penalize placing same service on same machine |

### Current Candidate Model

```rust
struct Candidate {
    name: String,
    config: MachineConfig,
    pool: String,                           // from machine.pool
    merged_labels: HashMap<String, String>,  // pool labels + machine labels
    schedulable_cpu: u64,                   // capacity.cpu - reserved.cpu
    schedulable_memory: u64,                // capacity.memory - reserved.memory
    allocated_cpu: u64,
    allocated_memory: u64,
    assigned_services: Vec<String>,
}
```

### Current Attribute Resolution (`get_attribute()`)

| Attribute | Resolves to |
|-----------|-------------|
| `pool` | `candidate.pool` |
| `labels.<key>` | `candidate.merged_labels[key]` (pool labels + machine labels, machine wins) |
| `capacity.cpu` | Total CPU (not schedulable) |
| `capacity.memory` | Total memory |
| `capacity.disk` | Total disk |
| `name` | Machine name |

---

## Scheduler Types

### Current State

```rust
pub enum JobType {
    Service,    // Placed on best N machines (N = replicas)
    Stateful,   // Same as Service (sticky placement NOT implemented)
    System,     // Runs on every matching machine
    Batch,      // Same as Service
}
```

All non-system types currently use the identical filter-score-select algorithm. There is no behavioral difference between Service, Stateful, and Batch.

### What Nomad Does

| Type | Nomad Behavior |
|------|----------------|
| `service` | Long-running. Evaluates large portion of nodes for best placement. Unlimited reschedule with exponential backoff on failure. |
| `batch` | Run-to-completion. "Power of two choices" fast placement (evaluates fewer candidates). Limited reschedule (1 attempt/24h). Exits with code 0 = success. |
| `system` | Runs on ALL nodes matching constraints. Auto-evaluates when new nodes join. No rescheduling (restarts locally only). Can preempt lower-priority tasks. |
| `sysbatch` | System + batch hybrid. Runs once on all matching nodes then completes. Supports periodic/parameterized. |

### What Kubernetes Does

| Type | K8s Behavior |
|------|--------------|
| Deployment/ReplicaSet | Long-running replicated workloads. Rolling update support. |
| StatefulSet | Stable identity, ordered deployment, persistent storage per replica. |
| DaemonSet | Runs on every node (equivalent to Nomad `system`). Tolerates taints automatically. |
| Job | Run-to-completion. `completions`, `parallelism`, `backoffLimit`, `activeDeadlineSeconds`. |
| CronJob | Periodic Job with cron schedule. `concurrencyPolicy` (Allow/Forbid/Replace). |

### What to Build

**Service type**: Keep current behavior. Add:
- Configurable reschedule policy (see [Reschedule Policy](#reschedule-policy))
- Restart policy for local restarts before rescheduling (see [Restart Policy](#restart-policy))

**Batch type**: Differentiate from service:
- Exit code 0 = success (allocation complete, do not restart)
- Non-zero exit = failure, subject to restart/reschedule policy
- Default reschedule: 1 attempt per 24h (vs unlimited for service)
- Optional: fast placement path (evaluate fewer candidates for lower scheduling latency)

**Stateful type**: Implement sticky placement:
- On reschedule, prefer the machine a service instance was previously placed on
- Persist last-known placement in Raft state (`PlacementRecord` already has `machine_name`)
- Add affinity bonus for previous machine during scoring

**System type**: Add auto-evaluation:
- When a new agent registers (`register_agent`), trigger re-evaluation of all system jobs
- If the new machine matches system job constraints and has capacity, place the system job on it
- Currently, system jobs are only placed during `reconcile_once()` — this means new nodes don't get system jobs until the next reconciliation cycle

**Sysbatch type** (new): System + batch hybrid:
- Runs on every matching machine, but each instance exits on completion
- Once completed on a machine, do not restart
- Track per-machine completion state
- Useful for one-time fleet-wide operations (e.g., rotate credentials, run migration)

**Periodic type** (new): Cron-scheduled batch jobs:
- Add `PeriodicConfig` to `SchedulingConfig`:
  ```rust
  pub struct PeriodicConfig {
      pub cron: String,              // Cron expression (e.g., "0 3 * * *")
      pub time_zone: Option<String>, // IANA timezone (default: UTC)
      pub prohibit_overlap: bool,    // Don't start if previous run is still active
  }
  ```
- Only valid for `Batch` and `Sysbatch` job types
- The server spawns child job instances at each cron tick
- `prohibit_overlap`: if previous instance is still running, skip this tick
- Nomad supports `@daily`, `@hourly`, `@weekly` macros — support these too
- Kubernetes CronJob adds `concurrencyPolicy` with three modes:
  - `Allow` (default) — multiple concurrent runs allowed
  - `Forbid` — skip if previous still running (same as `prohibit_overlap = true`)
  - `Replace` — kill the running job and start a new one
- Implement all three as an enum:
  ```rust
  pub enum ConcurrencyPolicy {
      Allow,    // Multiple concurrent runs
      Forbid,   // Skip if previous running
      Replace,  // Kill previous, start new
  }
  ```

---

## Priority and Preemption

### Current State

No priority system exists. All services are treated equally during scheduling. Services are sorted by job type (System > Service > Stateful > Batch) but not by importance within a type.

### What Nomad Does

- **Priority**: Integer 1–100 (default 50). Higher = more important.
- **Scheduling order**: Higher priority jobs are evaluated first by the evaluation broker.
- **Preemption**: When a high-priority job can't be placed, the scheduler identifies lower-priority allocations that could be evicted. Only allocations with priority delta >= 10 are eligible. Preemption is enabled by default for system jobs and configurable for service/batch.
- **Tracking**: `PreemptedAllocs` and `PreemptedByAllocID` fields track who evicted whom.
- The `nomad plan` command shows potential preemptions as a dry-run.

### What Kubernetes Does

- **PriorityClass**: Named objects mapping to i32 priority values. `globalDefault` sets the default.
- **preemptionPolicy**: `PreemptLowerPriority` (default) or `Never` (non-preempting high priority — scheduled first but won't evict).
- **Preemption**: The `PostFilter` extension point runs when no feasible nodes exist. It finds the node where evicting the fewest lowest-priority pods makes room. Respects `PodDisruptionBudgets` and graceful termination periods.
- **Built-in classes**: `system-cluster-critical` and `system-node-critical` for critical infrastructure.

### What to Build

Add `priority` field to `SchedulingConfig`:
```rust
pub struct SchedulingConfig {
    // ... existing fields ...
    #[serde(default = "default_priority")]
    pub priority: u32,  // 1-100, default 50
}
```

**Scheduling order**: Sort services by priority (descending) before job type. Higher priority services get first pick of resources.

**Preemption** (can be implemented in a later phase):
- When a service cannot be placed (filtered list is empty), run a preemption check:
  1. For each machine, identify running services with priority < (this service's priority - 10)
  2. Calculate if evicting some/all of those services would free enough resources
  3. Score eviction candidates by: fewest evictions, lowest total priority evicted, best resource fit
  4. If a viable eviction plan exists, record it in the `PlacementPlan` as `preemptions: Vec<Preemption>`
  5. The deployer stops the preempted services before deploying the new one
- Add `Preemption` struct:
  ```rust
  pub struct Preemption {
      pub evicted_service: String,
      pub evicted_instance_id: String,
      pub machine_name: String,
      pub reason: String,  // "priority preemption: 80 > 50"
  }
  ```
- Make preemption configurable per-pool or globally (Nomad approach)
- Support non-preempting priority (K8s `preemptionPolicy: Never`): services that schedule ahead of lower-priority services in the queue but never evict running ones

---

## Constraints

### Current State

```rust
pub struct Constraint {
    pub attribute: String,  // "labels.role", "pool", "name", "capacity.cpu"
    pub op: String,         // "=", "==", "!=", "in", "not_in"
    pub value: String,
}
```

Constraints are hard filters — a machine must pass ALL constraints to be eligible.

### What Nomad Supports

| Operator | Description | ekafleet Status |
|----------|-------------|-----------------|
| `=` / `==` | Equality | Implemented |
| `!=` | Not equal | Implemented |
| `in` | Value in comma-separated list | Implemented |
| `not_in` | Value not in list | Implemented |
| `>`, `>=`, `<`, `<=` | Numeric/lexical ordering | **Missing** |
| `regexp` | RE2 regex match | **Missing** |
| `set_contains` | Attribute contains ALL listed elements | **Missing** |
| `set_contains_any` | Attribute contains ANY listed element | **Missing** (similar to `in` but reversed) |
| `version` | Semantic version comparison with pessimistic operator | **Missing** |
| `semver` | SemVer 2.0 compliant comparison | **Missing** |
| `is_set` | Attribute exists (value ignored) | **Missing** |
| `is_not_set` | Attribute does not exist | **Missing** |
| `distinct_hosts` | No two instances of same service on same machine | **Missing** as constraint (exists as scoring penalty) |
| `distinct_property` | Ensure N distinct values of attribute across instances | **Missing** |

### What Kubernetes Adds

| Operator | Description | ekafleet Status |
|----------|-------------|-----------------|
| `In` | Label value in list | Same as `in` |
| `NotIn` | Label value not in list | Same as `not_in` |
| `Exists` | Label key exists | Same as `is_set` |
| `DoesNotExist` | Label key doesn't exist | Same as `is_not_set` |
| `Gt` | Greater than (numeric) | Same as `>` |
| `Lt` | Less than (numeric) | Same as `<` |

K8s also has `requiredDuringSchedulingIgnoredDuringExecution` vs `preferredDuringScheduling` — the "IgnoredDuringExecution" means constraints are only checked at scheduling time, not enforced if labels change later. ekafleet's model is the same (constraints checked at schedule time, not continuously enforced).

### What to Build

Add the following operators to `passes_constraints()` in `src/server/scheduler.rs`:

```rust
// Numeric comparison (parse both sides as f64)
">" => parse_num(actual) > parse_num(expected),
">=" => parse_num(actual) >= parse_num(expected),
"<" => parse_num(actual) < parse_num(expected),
"<=" => parse_num(actual) <= parse_num(expected),

// Regex (use the `regex` crate, already a transitive dependency)
"regexp" | "matches" => Regex::new(expected).ok().map(|r| r.is_match(actual)).unwrap_or(false),

// Set operations
"set_contains" => {
    // attribute is comma-separated list, value is comma-separated required elements
    // ALL elements in value must be present in attribute
    let attr_set: HashSet<&str> = actual.split(',').map(|s| s.trim()).collect();
    expected.split(',').map(|s| s.trim()).all(|v| attr_set.contains(v))
}
"set_contains_any" => {
    let attr_set: HashSet<&str> = actual.split(',').map(|s| s.trim()).collect();
    expected.split(',').map(|s| s.trim()).any(|v| attr_set.contains(v))
}

// Existence checks (value field is ignored)
"is_set" => actual.is_some(),      // attribute exists
"is_not_set" => actual.is_none(),  // attribute does not exist

// Semantic version (use the `semver` crate)
"semver" | "version" => {
    semver::VersionReq::parse(expected).ok()
        .and_then(|req| semver::Version::parse(actual).ok().map(|v| req.matches(&v)))
        .unwrap_or(false)
}
```

Add `distinct_hosts` as a constraint (not just a scoring penalty):
```rust
"distinct_hosts" => {
    // No other instance of this service on this machine
    !candidate.assigned_services.contains(&service_name.to_string())
}
```

Add `distinct_property`:
```rust
// In SchedulingConfig or as a special constraint:
pub struct DistinctPropertyConfig {
    pub attribute: String,  // e.g., "labels.rack"
    pub count: u32,         // max instances per distinct value (default 1)
}
```
This requires counting how many instances of the current service are already placed on machines with the same attribute value, and rejecting placement if count >= limit. This is similar to spread but as a hard constraint rather than soft scoring.

### Attribute Resolution Expansion

Extend `get_attribute()` to support more attributes:

```rust
// Current
"pool" => candidate.pool
"labels.<key>" => candidate.merged_labels[key]
"capacity.cpu" / "capacity.memory" / "capacity.disk" => total capacity
"name" => machine name

// New (inspired by Nomad ${attr.*} and K8s node labels)
"schedulable.cpu" => schedulable_cpu (capacity - reserved)
"schedulable.memory" => schedulable_memory
"available.cpu" => available_cpu (schedulable - allocated)
"available.memory" => available_memory
```

---

## Affinities

### Current State

```rust
pub struct AffinityConfig {
    pub attribute: String,
    pub op: String,      // "=" or "!="
    pub value: String,
    pub weight: i32,     // default 50, can be negative for anti-affinity
}
```

Affinities are soft preferences that add to the candidate's score. Multiple affinities are additive. The pool preference (`scheduling.pool`) is expanded into a synthetic affinity with weight 50.

### What Nomad Supports

- Weight range: -100 to 100 (ekafleet uses i32, which is more flexible)
- Operators: `=`, `!=`, `>`, `>=`, `<`, `<=`, `regexp`, `set_contains_all`, `set_contains_any`, `version`
- Scoping: job/group/task levels (ekafleet has service-level only, which is appropriate)

### What Kubernetes Adds

**Inter-pod affinity/anti-affinity**: Schedule a service near/away from instances of *another* service, using a topology key.

Example: "Schedule service A on nodes that are in the same zone as service B"

```yaml
podAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
  - labelSelector:
      matchLabels:
        app: service-b
    topologyKey: topology.kubernetes.io/zone
```

This is a powerful concept not present in either Nomad or ekafleet. It enables:
- Co-locating related services (app + cache on same node/zone)
- Separating competing services (two CPU-heavy services on different nodes)

### What to Build

**Extended operators**: Add the same operators to affinity evaluation that are added to constraints (`>`, `>=`, `<`, `<=`, `regexp`, `set_contains`, `set_contains_any`, `version`). Since affinities use the same attribute resolution and operator matching, this can share the same operator evaluation function as constraints — the only difference is that constraint failure eliminates the candidate, while affinity failure just doesn't add the weight.

**Service affinity** (inter-service, inspired by K8s pod affinity):

```rust
pub struct ServiceAffinityConfig {
    pub target_service: String,      // "redis-cache"
    pub topology_key: String,        // "labels.zone", "name" (same node), "pool"
    pub weight: i32,                 // positive = co-locate, negative = separate
}
```

In `compute_score()`, for each service affinity rule:
1. Find all machines where `target_service` is already assigned
2. For each such machine, get the value of `topology_key`
3. If the current candidate has the same `topology_key` value, add `weight` to score

This is additive with existing scoring. Example Nix config:

```nix
services.web-api = {
  scheduling = {
    replicas = 3;
    serviceAffinity = [
      # Prefer nodes in the same zone as redis-cache
      { targetService = "redis-cache"; topologyKey = "labels.zone"; weight = 30; }
      # Avoid nodes where cpu-worker is running
      { targetService = "cpu-worker"; topologyKey = "name"; weight = -50; }
    ];
  };
};
```

---

## Spread

### Current State

```rust
pub struct SpreadConfig {
    pub attribute: String,   // e.g., "labels.zone"
    pub weight: Option<u32>, // default 50
}
```

A single spread block per service. The scoring formula is:
```
spread_score = weight / (same_count + 1.0)
```
Where `same_count` is the number of instances of this service already on machines with the same attribute value. This favors even distribution but doesn't support target percentages.

### What Nomad Adds

**Target percentages**: Specify desired distribution across attribute values:
```hcl
spread {
  attribute = "${node.datacenter}"
  target "us-east-1" { percent = 60 }
  target "us-west-2" { percent = 40 }
}
```

**Multiple spread blocks**: A single service can spread across multiple attributes simultaneously (e.g., spread across zones AND spread across racks).

### What to Build

**Multiple spread blocks**: Change `spread: Option<SpreadConfig>` to `spread: Vec<SpreadConfig>`:
```rust
#[serde(default)]
pub spread: Vec<SpreadConfig>,
```
In `compute_score()`, iterate over all spread configs and sum their contributions.

**Spread targets**: Add optional target percentages:
```rust
pub struct SpreadConfig {
    pub attribute: String,
    pub weight: Option<u32>,
    #[serde(default)]
    pub targets: Vec<SpreadTarget>,
}

pub struct SpreadTarget {
    pub value: String,   // e.g., "us-east-1a"
    pub percent: u32,    // desired percentage (0-100)
}
```

When targets are specified, the scoring formula changes:
```
// For each target, compute how close the current distribution is to desired
actual_percent = instances_with_this_value / total_placed_instances
desired_percent = target.percent / 100.0
deviation = |actual_percent - desired_percent|
// Lower deviation = higher score
target_score = weight * (1.0 - deviation)
```

When targets are NOT specified (current behavior), distribute evenly across all observed values (existing formula).

Example Nix config:
```nix
scheduling.spread = [
  {
    attribute = "labels.zone";
    weight = 50;
    targets = [
      { value = "us-east-1a"; percent = 50; }
      { value = "us-east-1b"; percent = 30; }
      { value = "us-east-1c"; percent = 20; }
    ];
  }
  { attribute = "labels.rack"; weight = 20; }  # even spread across racks
];
```

---

## Topology Spread Constraints

### Current State

Not implemented. Kubernetes has a dedicated `topologySpreadConstraints` mechanism that is more powerful than simple spread.

### What Kubernetes Does

```yaml
topologySpreadConstraints:
- maxSkew: 1
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: DoNotSchedule  # or ScheduleAnyway
  labelSelector:
    matchLabels:
      app: my-app
  minDomains: 3
```

- **maxSkew**: Maximum allowed difference in pod count between any two topology domains
- **topologyKey**: The node label that defines topology domains (zone, region, hostname)
- **whenUnsatisfiable**: Hard (`DoNotSchedule`) or soft (`ScheduleAnyway`) enforcement
- **minDomains**: Minimum number of domains required

This is strictly more powerful than Nomad's spread because it enforces a **maximum skew** rather than just preferring balance.

### What to Build

This can be implemented as an extension of the spread system rather than a separate mechanism. Add to `SpreadConfig`:

```rust
pub struct SpreadConfig {
    pub attribute: String,
    pub weight: Option<u32>,
    #[serde(default)]
    pub targets: Vec<SpreadTarget>,
    #[serde(default, rename = "maxSkew")]
    pub max_skew: Option<u32>,           // Max difference between domains
    #[serde(default, rename = "minDomains")]
    pub min_domains: Option<u32>,         // Minimum number of domains
    #[serde(default)]
    pub required: bool,                   // true = hard constraint, false = soft scoring (default)
}
```

When `max_skew` is set and `required = true`, the spread becomes a hard constraint (filter phase): reject placement on any machine where placing here would cause the skew to exceed `max_skew`.

When `max_skew` is set and `required = false` (default), it becomes a scoring penalty proportional to how much skew would increase.

When `min_domains` is set, placement is rejected (or penalized) if the number of distinct domain values with assigned instances is less than `min_domains`.

---

## Taints and Tolerations

### Current State

Not implemented.

### What Kubernetes Does

Taints are applied to nodes to repel services that don't explicitly tolerate them:

**Effects**:
- `NoSchedule`: Don't schedule non-tolerating pods (hard)
- `PreferNoSchedule`: Try to avoid non-tolerating pods (soft)
- `NoExecute`: Evict running non-tolerating pods (with optional grace period via `tolerationSeconds`)

**Built-in taints** automatically applied:
- `node.kubernetes.io/not-ready` — node health check failing
- `node.kubernetes.io/unreachable` — node not reachable
- `node.kubernetes.io/memory-pressure` — low memory
- `node.kubernetes.io/disk-pressure` — low disk
- `node.kubernetes.io/unschedulable` — node cordoned

**Common use cases**:
- Dedicated nodes (only certain services can run on GPU nodes)
- Maintenance mode (taint + NoExecute evicts everything)
- Gradual rollout (taint new nodes, add tolerations to services one at a time)

### What to Build

Taints are the inverse of constraints — instead of services filtering machines, machines filter services. This is valuable for ekafleet because:
- Machines can mark themselves as unavailable without changing service configs
- Node conditions (low disk, etc.) can automatically repel services
- Dedicated hardware can require explicit opt-in

**Machine taints** (in `MachineConfig`):
```rust
pub struct MachineConfig {
    // ... existing fields ...
    #[serde(default)]
    pub taints: Vec<Taint>,
}

pub struct Taint {
    pub key: String,
    pub value: Option<String>,
    pub effect: TaintEffect,
}

pub enum TaintEffect {
    NoSchedule,       // Hard: don't place non-tolerating services
    PreferNoSchedule, // Soft: avoid non-tolerating services (scoring penalty)
    NoExecute,        // Hard: evict running non-tolerating services
}
```

**Service tolerations** (in `SchedulingConfig`):
```rust
pub struct SchedulingConfig {
    // ... existing fields ...
    #[serde(default)]
    pub tolerations: Vec<Toleration>,
}

pub struct Toleration {
    pub key: Option<String>,        // None = match all keys
    pub op: TolerationOp,           // Equal (default) or Exists
    pub value: Option<String>,      // Ignored for Exists
    pub effect: Option<TaintEffect>, // None = match all effects
    #[serde(default, rename = "tolerationSeconds")]
    pub toleration_seconds: Option<u64>, // For NoExecute: grace period before eviction
}

pub enum TolerationOp {
    Equal,   // key and value must match
    Exists,  // only key must match (value ignored)
}
```

**Filter phase integration**: In `passes_constraints()` (or a new `passes_taints()` check):
1. For each taint on the machine, check if the service has a matching toleration
2. A toleration matches if: keys match, effects match (or toleration effect is None), and operator condition is met
3. If any `NoSchedule` taint is not tolerated, the machine is eliminated
4. If any `PreferNoSchedule` taint is not tolerated, apply a scoring penalty (e.g., -50)

**NoExecute handling**: When a `NoExecute` taint is added to a machine (e.g., during maintenance), the reconciler should:
1. Find all services running on that machine that don't tolerate the taint
2. If the service has a toleration with `tolerationSeconds`, schedule eviction after that delay
3. If no toleration, evict immediately (reschedule to another machine)

**Built-in taints** (applied automatically by agents):
- `ekafleet/not-ready` — agent hasn't sent heartbeat recently (NoExecute)
- `ekafleet/unschedulable` — machine is being drained (NoSchedule)
- `ekafleet/memory-pressure` — available memory below threshold (NoSchedule)
- `ekafleet/disk-pressure` — available disk below threshold (NoSchedule)

Example Nix config:
```nix
machines.gpu-1 = {
  targetHost = "10.0.3.1";
  capacity = { cpu = 8000; memory = 32768; };
  taints = [
    { key = "hardware"; value = "gpu"; effect = "noSchedule"; }
  ];
};

services.ml-training = {
  scheduling = {
    tolerations = [
      { key = "hardware"; op = "equal"; value = "gpu"; effect = "noSchedule"; }
    ];
  };
};
```

---

## Resources

### Current State

```rust
pub struct ResourceConfig {
    pub cpu: Option<ResourceValue>,     // millicores
    pub memory: Option<ResourceValue>,  // MB
}

pub struct ResourceValue {
    pub request: u64,
    pub limit: Option<u64>,
}
```

The scheduler uses `request` for placement decisions. `limit` is stored but not enforced by the scheduler (enforcement would be at the systemd/cgroup level on the agent).

### What Nomad Supports

- **CPU**: MHz (default 100) or `cores` (reserves physical cores exclusively)
- **Memory**: `memory` (soft/scheduling) + `memory_max` (hard limit). Memory oversubscription allows `memory_max > memory`.
- **Disk**: `ephemeral_disk` with `size`, `migrate` (move data during reschedule), `sticky` (prefer same node)
- **Network**: mbits reservation
- **Device**: GPU/FPGA scheduling via `device` blocks
- **NUMA**: Core pinning

### What Kubernetes Adds

- **Requests vs Limits**: Requests for scheduling, limits for runtime enforcement. Different combinations create QoS classes (Guaranteed, Burstable, BestEffort).
- **Extended resources**: `nvidia.com/gpu: 1` — opaque integer resources that can only be specified as limits
- **Pod overhead**: `RuntimeClass` specifies per-pod overhead added to container requests during scheduling
- **Ephemeral storage**: Request/limit on local disk usage
- **Hugepages**: `hugepages-2Mi: 100Mi`

### What to Build

**Disk scheduling** — Add disk to resource requests:
```rust
pub struct ResourceConfig {
    pub cpu: Option<ResourceValue>,
    pub memory: Option<ResourceValue>,
    pub disk: Option<ResourceValue>,    // NEW
}
```
The scheduler should check `available_disk >= disk_request` in the filter phase and track `allocated_disk` in `Candidate`.

**Memory oversubscription** — When `limit > request` for memory, the scheduler places based on `request` but the agent enforces `limit` via cgroups. This allows more services per machine at the cost of potential OOM kills under pressure. Make this opt-in per pool:
```rust
pub struct NodePoolConfig {
    // ... existing fields ...
    #[serde(default, rename = "memoryOversubscription")]
    pub memory_oversubscription: bool,
}
```

**Extended/custom resources** (future phase) — Allow machines to declare arbitrary countable resources and services to request them:
```rust
// In MachineConfig
pub extended_resources: HashMap<String, u64>,  // e.g., {"nvidia.com/gpu": 4}

// In ResourceConfig
pub extended: HashMap<String, u64>,  // e.g., {"nvidia.com/gpu": 1}
```
The scheduler tracks allocation of each extended resource per candidate and rejects placement when insufficient.

---

## Node Pools

### Current State

```rust
pub struct NodePoolConfig {
    pub labels: HashMap<String, String>,
    pub scaling: Option<PoolScalingConfig>,
}
```

- Machines declare `pool: String` (default `"default"`)
- Pool labels merge into machine labels (machine wins on conflict)
- Services can soft-prefer a pool (`scheduling.pool`) or hard-constrain (`constraint attribute="pool"`)
- Pool scaling is advisory only

### What Nomad Adds

- **Per-pool scheduler algorithm**: `binpack` or `spread` — controls whether the pool favors consolidation or distribution
- **Per-pool memory oversubscription**: Enable/disable independently per pool
- **Pool metadata**: `meta` block (equivalent to ekafleet's `labels`)
- **Built-in pools**: `all` (read-only superset), `default`

### What to Build

**Per-pool scheduler algorithm**:
```rust
pub struct NodePoolConfig {
    pub labels: HashMap<String, String>,
    pub scaling: Option<PoolScalingConfig>,
    #[serde(default, rename = "schedulerAlgorithm")]
    pub scheduler_algorithm: Option<SchedulerAlgorithm>,
    #[serde(default, rename = "memoryOversubscription")]
    pub memory_oversubscription: bool,
}

pub enum SchedulerAlgorithm {
    Binpack,  // Prefer consolidation (current default)
    Spread,   // Prefer distribution
}
```

When `scheduler_algorithm = Spread`, invert the bin-packing score: lower utilization = higher score (prefer empty machines). This only affects the bin-packing component of the total score.

**Pool metadata/description**:
```rust
pub struct NodePoolConfig {
    pub description: Option<String>,
    pub labels: HashMap<String, String>,
    // ...
}
```

---

## Restart Policy

### Current State

Not implemented. When a service fails, the reconciler detects it on the next cycle and redeploys.

### What Nomad Does

```hcl
restart {
  attempts = 2       # Max restarts within interval
  interval = "30m"   # Time window
  delay    = "15s"   # Wait before restart (+ 25% jitter)
  mode     = "fail"  # "fail" or "delay"
}
```

- Restarts happen **locally** on the same machine (agent-side)
- Only after restart attempts are exhausted does the service enter the reschedule path
- Default for service/system: 2 attempts in 30m
- Default for batch: 3 attempts in 24h
- `mode = "fail"`: mark allocation failed after exhausting attempts
- `mode = "delay"`: wait for next interval window, then retry

### What Kubernetes Does

- `restartPolicy`: `Always` (default for Deployments), `OnFailure` (for Jobs), `Never`
- kubelet restarts containers locally with exponential backoff (10s, 20s, 40s, ... up to 5 minutes)

### What to Build

Add `RestartConfig` to `SchedulingConfig`:
```rust
pub struct RestartConfig {
    #[serde(default = "default_restart_attempts")]
    pub attempts: u32,          // Max restarts in interval
    #[serde(default = "default_restart_interval")]
    pub interval_secs: u64,     // Time window (seconds)
    #[serde(default = "default_restart_delay")]
    pub delay_secs: u64,        // Wait before each restart
    #[serde(default)]
    pub mode: RestartMode,      // What happens after exhausting attempts
}

pub enum RestartMode {
    Fail,   // Mark failed, enter reschedule path (default)
    Delay,  // Wait for next interval, retry
}
```

Defaults by job type:
- Service/System: `{ attempts: 2, interval: 1800, delay: 15, mode: Fail }`
- Batch: `{ attempts: 3, interval: 86400, delay: 15, mode: Fail }`

This is implemented **agent-side**: the agent supervisor restarts the process locally before reporting failure to the server. Only after exhausting restart attempts does it report `ServiceState::Failed`, which triggers the server-side reschedule policy.

---

## Reschedule Policy

### Current State

Not implemented. When a service instance fails (after restart exhaustion), the reconciler places it on any available machine on the next cycle. There is no backoff, attempt limiting, or delay.

### What Nomad Does

```hcl
reschedule {
  delay          = "30s"
  delay_function = "exponential"  # constant | exponential | fibonacci
  max_delay      = "1h"
  unlimited      = true
}
```

- Rescheduling moves a failed allocation to a **different machine**
- Delay functions prevent thrashing:
  - `constant`: always wait `delay`
  - `exponential`: delay doubles each attempt (30s, 60s, 120s, ...)
  - `fibonacci`: delay follows fibonacci sequence (30s, 30s, 60s, 90s, 150s, ...)
- `max_delay` caps the growing delay
- `unlimited = true` means infinite attempts (default for service)
- Batch default: 1 attempt in 24h, constant delay

### What to Build

Add `RescheduleConfig` to `SchedulingConfig`:
```rust
pub struct RescheduleConfig {
    #[serde(default = "default_reschedule_delay")]
    pub delay_secs: u64,
    #[serde(default)]
    pub delay_function: DelayFunction,
    #[serde(default = "default_max_delay")]
    pub max_delay_secs: u64,
    pub attempts: Option<u32>,  // None = unlimited (for service), Some(N) for batch
    #[serde(default = "default_reschedule_interval")]
    pub interval_secs: u64,     // Window for counting attempts
}

pub enum DelayFunction {
    Constant,
    Exponential,
    Fibonacci,
}
```

Defaults by job type:
- Service: `{ delay: 30, function: Exponential, max_delay: 3600, attempts: None }` (unlimited)
- Batch: `{ delay: 5, function: Constant, max_delay: 5, attempts: Some(1), interval: 86400 }`
- System: No reschedule (restart only, system jobs run on specific machines)

**Implementation**: The server tracks reschedule state per service instance:
```rust
pub struct RescheduleState {
    pub attempt: u32,
    pub first_attempt_at: Instant,
    pub last_attempt_at: Instant,
    pub next_eligible_at: Instant,
}
```

When a service instance reports `Failed` (after local restarts exhausted):
1. Look up its `RescheduleState`
2. If within attempt limits and past delay: reschedule to a different machine (add anti-affinity for the failed machine)
3. If delay hasn't elapsed: skip until next reconciliation cycle
4. If attempts exhausted: mark the service instance as permanently failed, log warning

---

## Update / Deployment Strategy

### Current State

```rust
pub struct UpdateConfig {
    pub strategy: UpdateStrategy,        // Rolling | Canary | BlueGreen
    pub max_parallel: u32,               // Concurrent updates (default 1)
    pub canary: u32,                     // Canary count
    pub min_healthy_time_secs: u64,      // 10s default
    pub healthy_deadline_secs: u64,      // 300s default
    pub auto_revert: bool,               // Rollback on failure
}
```

### What Nomad Adds

- **`auto_promote`**: Automatically promote canaries when all are healthy (ekafleet requires manual promotion)
- **`progress_deadline`**: Overall deployment timeout (separate from per-instance `healthy_deadline`). If no allocation becomes healthy within this window, the entire deployment fails.
- **Health check modes**:
  - `checks`: All health checks pass (ekafleet default)
  - `task_states`: Only requires processes to be running
  - `manual`: Operator explicitly marks healthy via API
- **`stagger`**: Delay between update batches (deprecated in favor of `min_healthy_time`)

### What Kubernetes Adds

- **`maxUnavailable`**: Maximum number/percentage of pods that can be unavailable during update
- **`maxSurge`**: Maximum number/percentage of pods above desired count during update
- **Rollback**: `kubectl rollout undo` with revision history

### What to Build

```rust
pub struct UpdateConfig {
    pub strategy: UpdateStrategy,
    pub max_parallel: u32,
    pub canary: u32,
    pub min_healthy_time_secs: u64,
    pub healthy_deadline_secs: u64,
    pub auto_revert: bool,
    #[serde(default, rename = "autoPromote")]
    pub auto_promote: bool,                   // NEW: auto-promote canaries
    #[serde(default, rename = "progressDeadline")]
    pub progress_deadline_secs: Option<u64>,  // NEW: overall deployment timeout
    #[serde(default, rename = "healthCheck")]
    pub health_check: HealthCheckMode,        // NEW: how to assess health
    #[serde(default, rename = "maxUnavailable")]
    pub max_unavailable: Option<u32>,         // NEW: max instances down during update
}

pub enum HealthCheckMode {
    Checks,     // Health check endpoint must pass (default)
    TaskStates, // Process must be running
    Manual,     // Operator marks healthy via API
}
```

---

## Migration (Node Drain)

### Current State

`ekafleet drain <machine>` CLI command exists but the migration policy is not configurable. All services are rescheduled off the machine.

### What Nomad Does

```hcl
migrate {
  max_parallel     = 1       # Concurrent migrations
  health_check     = "checks" # or "task_states"
  min_healthy_time = "10s"
  healthy_deadline = "5m"
}
```

- Only applies to `service` jobs with count > 1
- Node drain has its own deadline that overrides `migrate` settings
- Drain can be graceful (wait for healthy migration) or forced (deadline)

### What to Build

Add `MigrateConfig` to `SchedulingConfig`:
```rust
pub struct MigrateConfig {
    #[serde(default = "default_migrate_parallel", rename = "maxParallel")]
    pub max_parallel: u32,           // default 1
    #[serde(default, rename = "healthCheck")]
    pub health_check: HealthCheckMode,
    #[serde(default = "default_min_healthy_time", rename = "minHealthyTime")]
    pub min_healthy_time_secs: u64,  // default 10s
    #[serde(default = "default_healthy_deadline", rename = "healthyDeadline")]
    pub healthy_deadline_secs: u64,  // default 300s
}
```

Update the `drain` CLI command:
- Accept `--deadline <duration>` flag for forced drain timeout
- Use the service's `migrate` config to control migration pacing
- Report progress as services are migrated

---

## Periodic / Cron Jobs

### Current State

Not implemented.

### What to Build

See [Scheduler Types](#scheduler-types) for `PeriodicConfig` and `ConcurrencyPolicy`.

Implementation requires:
1. A new server-side loop (similar to `reconcile_loop`) that evaluates periodic schedules
2. At each cron tick, create a "child" batch job instance with a unique name (e.g., `backup-20260707T030000`)
3. The child job goes through normal scheduling (filter-score-select)
4. Track child job history: `successfulJobsHistoryLimit` (default 3), `failedJobsHistoryLimit` (default 1) — borrowed from K8s CronJob
5. Enforce `concurrencyPolicy` before spawning

Add to config:
```rust
pub struct SchedulingConfig {
    // ... existing fields ...
    #[serde(default)]
    pub periodic: Option<PeriodicConfig>,
}

pub struct PeriodicConfig {
    pub cron: String,
    #[serde(default = "default_timezone", rename = "timeZone")]
    pub time_zone: String,
    #[serde(default, rename = "concurrencyPolicy")]
    pub concurrency_policy: ConcurrencyPolicy,
    #[serde(default = "default_successful_history", rename = "successfulJobsHistoryLimit")]
    pub successful_jobs_history_limit: u32,
    #[serde(default = "default_failed_history", rename = "failedJobsHistoryLimit")]
    pub failed_jobs_history_limit: u32,
}

pub enum ConcurrencyPolicy {
    Allow,
    Forbid,
    Replace,
}
```

Use the `cron` crate for parsing cron expressions. Support standard syntax plus `@daily`, `@hourly`, `@weekly`, `@monthly`, `@yearly` macros.

---

## Scaling

### Current State

- **Service-level**: `ScalingEngine` evaluates metric-based policies, adjusts replica counts
- **Pool-level**: `PoolScalingEngine` evaluates pool utilization, produces advisory decisions

### What Nomad Adds

- `scaling` block on task groups: `min`, `max`, `enabled`, opaque `policy` for external autoscaler
- Task-level scaling: `scaling "cpu"` and `scaling "mem"` for dynamic resource sizing

### What to Build

Add `ScalingConfig` to `SchedulingConfig` (replaces the separate `ScalingPolicy` registration):
```rust
pub struct ScalingConfig {
    pub min: u32,
    pub max: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<ScalingRule>,
}
```

This makes scaling policy part of the service definition (in fleet.nix) rather than requiring separate `register_policy` calls. The `ScalingEngine` reads policies from `FleetConfig` instead of maintaining its own registry.

---

## Scheduler Algorithm and Architecture

### Current Architecture

The scheduler is a pure function: `schedule(services, machines, node_pools) -> PlacementPlan`. It runs synchronously during reconciliation. There is no concurrency, no evaluation queue, no plan queue.

### What Nomad Does

- **Evaluation broker**: Priority-ordered queue on the leader. Evaluations created on state changes.
- **Scheduling workers**: One per CPU core. Pull evaluations from broker, run scheduler, produce plans.
- **Plan queue**: Workers submit plans to leader. Leader checks for conflicts (another plan already consumed the resources), accepts or rejects. On rejection, worker retries with updated state.
- **Optimistic concurrency**: Multiple schedulers run in parallel without locks. Conflicts are resolved by the leader.

### What Kubernetes Does

- **Scheduling framework**: Plugin-based with extension points (PreFilter, Filter, PostFilter, PreScore, Score, Reserve, Permit, PreBind, Bind, PostBind)
- **Scheduling profiles**: Multiple scheduler configurations can run in the same cluster
- **Performance tuning**: `percentageOfNodesToScore` limits how many nodes are evaluated (default scales with cluster size: 50% at 100 nodes, 10% at 5000 nodes)
- **Scheduling cycle vs binding cycle**: Scheduling is synchronous per-pod; binding is async

### What to Build (Future)

For ekafleet's scale (tens to low hundreds of machines), the current synchronous model is adequate. However, for future growth:

**Performance tuning**: Add a `percentageOfMachinesToScore` config option. When set, the scheduler stops scoring after evaluating this percentage of feasible machines. Default: 100% (evaluate all). For large fleets, reduce to 50% or lower.

**Scheduler algorithm toggle**: The existing `SchedulerAlgorithm` enum on `NodePoolConfig` (binpack vs spread) should affect the bin-packing score sign in `compute_score()`:
- `Binpack`: current behavior (higher utilization = higher score)
- `Spread`: invert (lower utilization = higher score)

**Blocked placements**: When a service can't be placed (no feasible machines), instead of silently warning, track it as a "blocked" placement:
```rust
pub struct PlacementPlan {
    pub placements: Vec<Placement>,
    pub blocked: Vec<BlockedPlacement>,    // NEW
    pub preemptions: Vec<Preemption>,      // NEW
}

pub struct BlockedPlacement {
    pub service_name: String,
    pub instance_id: String,
    pub reason: String,  // "no machines satisfy constraints" or "insufficient resources"
}
```
Blocked placements should be visible in `ekafleet plan` output and `ekafleet status`.

---

## Feature Matrix

Summary of all features with implementation status and priority.

### Legend
- **Implemented**: Working in current codebase
- **Build (High)**: Core scheduling feature, implement next
- **Build (Medium)**: Valuable operational feature
- **Build (Low)**: Specialized, implement when needed
- **Skip**: Not applicable to ekafleet's model

### Scheduler Types

| Feature | Nomad | K8s | Status | Priority |
|---------|-------|-----|--------|----------|
| Service (long-running) | `service` | Deployment | Implemented | — |
| Batch (run-to-completion) | `batch` | Job | Partial (no exit-code handling) | High |
| System (all nodes) | `system` | DaemonSet | Implemented (no auto-eval on join) | High |
| Stateful (sticky) | — | StatefulSet | Partial (no sticky placement) | Medium |
| Sysbatch (system+batch) | `sysbatch` | — | Missing | Medium |
| Periodic / Cron | `periodic` | CronJob | Missing | Medium |
| Parameterized / Dispatch | `parameterized` | — | Missing | Low |

### Constraints

| Feature | Status | Priority |
|---------|--------|----------|
| `=`, `!=` | Implemented | — |
| `in`, `not_in` | Implemented | — |
| `>`, `>=`, `<`, `<=` | Missing | High |
| `regexp` | Missing | High |
| `is_set`, `is_not_set` | Missing | High |
| `set_contains`, `set_contains_any` | Missing | Medium |
| `version` / `semver` | Missing | Low |
| `distinct_hosts` (hard constraint) | Missing (scoring penalty only) | Medium |
| `distinct_property` | Missing | Medium |

### Affinities

| Feature | Status | Priority |
|---------|--------|----------|
| Basic affinity (=, !=) | Implemented | — |
| Extended operators | Missing | Medium |
| Anti-affinity (negative weight) | Implemented | — |
| Service affinity (inter-service) | Missing | Medium |

### Spread

| Feature | Status | Priority |
|---------|--------|----------|
| Even distribution by attribute | Implemented | — |
| Multiple spread blocks | Missing | High |
| Target percentages | Missing | Medium |
| maxSkew (topology spread) | Missing | Medium |

### Priority and Preemption

| Feature | Status | Priority |
|---------|--------|----------|
| Service priority (1-100) | Missing | High |
| Priority-ordered scheduling | Missing | High |
| Preemption | Missing | Medium |
| Non-preempting priority | Missing | Low |

### Taints and Tolerations

| Feature | Status | Priority |
|---------|--------|----------|
| Machine taints (NoSchedule) | Missing | Medium |
| Machine taints (PreferNoSchedule) | Missing | Medium |
| Machine taints (NoExecute) | Missing | Medium |
| Service tolerations | Missing | Medium |
| Built-in taints (health-based) | Missing | Low |

### Resources

| Feature | Status | Priority |
|---------|--------|----------|
| CPU request/limit | Implemented | — |
| Memory request/limit | Implemented | — |
| Disk scheduling | Missing | Medium |
| Memory oversubscription | Missing | Low |
| Extended resources (GPU) | Missing | Low |

### Lifecycle

| Feature | Status | Priority |
|---------|--------|----------|
| Restart policy (local) | Missing | High |
| Reschedule policy (cross-node) | Missing | High |
| Delay functions (exp/fib) | Missing | High |

### Deployment

| Feature | Status | Priority |
|---------|--------|----------|
| Rolling update | Implemented | — |
| Canary | Implemented | — |
| Blue-green | Implemented | — |
| auto_promote | Missing | High |
| progress_deadline | Missing | High |
| Health check modes | Missing | Medium |
| Configurable migration | Missing | Medium |

### Node Pools

| Feature | Status | Priority |
|---------|--------|----------|
| Named pools with labels | Implemented | — |
| Pool affinity (soft) | Implemented | — |
| Pool constraint (hard) | Implemented | — |
| Pool scaling (advisory) | Implemented | — |
| Per-pool scheduler algorithm | Missing | Medium |

### Scheduling Architecture

| Feature | Status | Priority |
|---------|--------|----------|
| Filter-score-select | Implemented | — |
| Blocked placement tracking | Missing | High |
| Scheduler performance tuning | Missing | Low |
