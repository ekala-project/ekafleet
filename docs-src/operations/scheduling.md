# Scheduling

ekafleet uses a Nomad-inspired placement engine to decide which services run on which machines. Services are scheduled in priority order using a three-phase algorithm: filter, score, select.

## Priority

Services have a `priority` field (1–100, default 50). Higher priority services are scheduled first and get first pick of resources. When combined with preemption (future), higher priority services can evict lower priority ones (delta >= 10 required).

```nix
scheduling.priority = 80;  # high priority — scheduled before default (50)
```

## Phase 1: Filter

Machines that don't satisfy hard requirements are eliminated. A machine must:

- Match all constraint expressions
- Have sufficient available CPU, memory, and disk
- Not have any `NoSchedule` taints that the service doesn't tolerate

### Constraint Operators

```nix
constraints = [
  # Equality
  { attribute = "labels.role"; op = "="; value = "app"; }
  { attribute = "labels.env"; op = "!="; value = "staging"; }

  # Set membership
  { attribute = "labels.zone"; op = "in"; value = "us-east-1a, us-east-1b"; }

  # Numeric comparison
  { attribute = "capacity.cpu"; op = ">="; value = "4000"; }

  # Regular expression
  { attribute = "labels.hostname"; op = "regexp"; value = "^web-.*"; }

  # Existence checks
  { attribute = "labels.gpu"; op = "is_set"; value = ""; }
  { attribute = "labels.deprecated"; op = "is_not_set"; value = ""; }

  # Set contains (attribute is comma-separated list)
  { attribute = "labels.features"; op = "set_contains"; value = "avx2,sse4"; }
  { attribute = "labels.features"; op = "set_contains_any"; value = "gpu,tpu"; }

  # Semantic version
  { attribute = "labels.kernel"; op = "version"; value = ">= 5.15"; }
];
```

### Supported Attributes

| Attribute | Example |
|-----------|---------|
| `labels.<key>` | `labels.role`, `labels.zone` (includes pool-inherited labels) |
| `pool` | Node pool name |
| `capacity.cpu` | Total CPU millicores |
| `capacity.memory` | Total memory MB |
| `capacity.disk` | Total disk MB |
| `schedulable.cpu` | CPU after reserved subtracted |
| `schedulable.memory` | Memory after reserved subtracted |
| `available.cpu` | Currently unallocated CPU |
| `available.memory` | Currently unallocated memory |
| `name` | Machine name |

### Taints and Tolerations

Machines can have taints that repel services unless the service explicitly tolerates them:

```nix
# Machine with a taint
machines.gpu-1 = {
  targetHost = "10.0.3.1";
  capacity = { cpu = 8000; memory = 32768; };
  taints = [
    { key = "hardware"; value = "gpu"; effect = "noSchedule"; }
  ];
};

# Service that tolerates the taint
services.ml-training = {
  scheduling.tolerations = [
    { key = "hardware"; op = "equal"; value = "gpu"; effect = "noSchedule"; }
  ];
};
```

**Taint effects:**

| Effect | Behavior |
|--------|----------|
| `noSchedule` | Hard: don't place non-tolerating services |
| `preferNoSchedule` | Soft: scoring penalty (-50) for non-tolerating services |
| `noExecute` | Hard: evict running non-tolerating services |

## Phase 2: Score

Remaining candidates are ranked by a weighted scoring function:

### Bin-packing (weight: 30)

Prefer machines that are already partially utilized to consolidate workloads. The direction depends on the node pool's `schedulerAlgorithm`:

- `binpack` (default): higher utilization = higher score
- `spread`: lower utilization = higher score

### Spread (configurable weight, default: 50)

Distribute instances across distinct values of an attribute. Multiple spread blocks can be specified simultaneously:

```nix
scheduling.spread = [
  { attribute = "labels.zone"; weight = 50; }
  { attribute = "labels.rack"; weight = 30; }
];
```

Spread targets allow percentage-based distribution:

```nix
scheduling.spread = [{
  attribute = "labels.zone";
  weight = 50;
  targets = [
    { value = "us-east-1a"; percent = 50; }
    { value = "us-east-1b"; percent = 30; }
    { value = "us-east-1c"; percent = 20; }
  ];
}];
```

### Affinity (configurable weight)

Soft preference for machines matching an expression. Supports all constraint operators:

```nix
affinity = [
  { attribute = "labels.tier"; op = "="; value = "fast"; weight = 30; }
  { attribute = "labels.generation"; op = ">="; value = "3"; weight = 20; }
];
```

Negative weights create anti-affinities.

### Service Affinity

Co-locate or separate services based on topology:

```nix
scheduling.serviceAffinity = [
  # Prefer same zone as cache service
  { targetService = "redis"; topologyKey = "labels.zone"; weight = 30; }
  # Avoid same node as another CPU-heavy service
  { targetService = "encoder"; topologyKey = "name"; weight = -50; }
];
```

### Pool Preference

```nix
scheduling.pool = "compute";  # soft preference (weight 50 affinity)
```

### Distinct Hosts (penalty: -100)

Placing multiple replicas of the same service on the same machine is penalized heavily.

## Phase 3: Select

The highest-scoring candidate is selected. Resources are allocated, and the next replica is scheduled with updated availability.

## Job Types

| Type | Scheduling Behavior |
|------|-------------------|
| `service` | Placed on best N machines (N = `replicas`). Long-running. |
| `stateful` | Same as service but with sticky placement preference |
| `system` | Runs on **every** machine matching constraints (ignores `replicas`) |
| `batch` | Same as service but exits on completion |
| `sysbatch` | Runs once on every matching machine, then completes |

Services are scheduled in priority order (highest first), then by type: system, sysbatch, service, stateful, batch.

## Lifecycle Policies

### Restart (Local)

```nix
scheduling.restart = {
  attempts = 2;         # max restarts within interval
  intervalSecs = 1800;  # 30 minute window
  delaySecs = 15;       # wait before each restart
  mode = "fail";        # "fail" or "delay"
};
```

### Reschedule (Cross-Node)

```nix
scheduling.reschedule = {
  delaySecs = 30;
  delayFunction = "exponential";  # constant | exponential | fibonacci
  maxDelaySecs = 3600;
  attempts = null;                # null = unlimited
};
```

### Migration (Node Drain)

```nix
scheduling.migrate = {
  maxParallel = 1;
  minHealthyTime = 10;
  healthyDeadline = 300;
};
```

## Periodic Jobs

Batch and sysbatch jobs can run on a cron schedule:

```nix
services.backup = {
  command = "${pkgs.backup}/bin/run";
  scheduling = {
    type = "batch";
    periodic = {
      cron = "0 3 * * *";        # daily at 3 AM
      timeZone = "UTC";
      concurrencyPolicy = "forbid"; # allow | forbid | replace
    };
  };
};
```
