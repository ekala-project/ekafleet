# Scheduling

ekafleet uses a Nomad-inspired two-phase placement engine to decide which services run on which machines.

## Phase 1: Filter

Machines that don't satisfy hard constraints are eliminated. A machine must:

- Match all constraint expressions
- Have sufficient available CPU and memory

### Constraint Examples

```nix
constraints = [
  # Must be an app node
  { attribute = "labels.role"; op = "="; value = "app"; }

  # Must be in one of these zones
  { attribute = "labels.zone"; op = "in"; value = "us-east-1a, us-east-1b"; }

  # Must not be a GPU node
  { attribute = "labels.gpu"; op = "!="; value = "true"; }
];
```

### Supported Attributes

| Attribute | Example |
|-----------|---------|
| `labels.<key>` | `labels.role`, `labels.zone` |
| `capacity.cpu` | Total CPU millicores |
| `capacity.memory` | Total memory MB |
| `capacity.disk` | Total disk MB |
| `name` | Machine name |

## Phase 2: Score

Remaining candidates are ranked by a weighted scoring function:

### Bin-packing (weight: 30)

Prefer machines that are already partially utilized to consolidate workloads. Higher utilization scores higher, concentrating workloads onto fewer machines.

### Spread (configurable weight, default: 50)

Distribute instances across distinct values of an attribute. Fewer existing instances with the same attribute value scores higher.

```nix
spread = { attribute = "labels.zone"; weight = 50; };
```

### Affinity (configurable weight)

Soft preference for machines matching an expression:

```nix
affinity = [
  { attribute = "labels.tier"; op = "="; value = "fast"; weight = 30; }
];
```

### Distinct Hosts (penalty: -100)

Placing multiple replicas of the same service on the same machine is penalized heavily, distributing replicas across machines by default.

## Phase 3: Select

The highest-scoring candidate is selected. Resources are allocated, and the next replica is scheduled with updated availability.

## Job Types

| Type | Scheduling Behavior |
|------|-------------------|
| `system` | Runs on **every** machine matching constraints (ignores `replicas`) |
| `service` | Placed on best N machines (N = `replicas`) |
| `stateful` | Same as service but with sticky placement |
| `batch` | Same as service but exits when done |

System jobs are scheduled first, then services, stateful, and batch.
