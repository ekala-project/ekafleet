# Scaling

ekafleet supports manual scaling, metric-based autoscaling, and pool-level scaling.

## Manual Scaling

```bash
ekafleet scale api-server 5
```

This triggers re-evaluation and deployment of the delta.

## Service Autoscaling

The autoscaling engine evaluates policies against collected metrics and computes desired replica counts.

### Scaling Policies

Policies define min/max bounds and metric-based rules:

| Field | Description |
|-------|-------------|
| `min_replicas` | Floor for scale-down |
| `max_replicas` | Ceiling for scale-up |
| `rules` | List of metric-based scaling rules |

### Scaling Rules

Each rule defines a target metric value and thresholds:

| Field | Description |
|-------|-------------|
| `metric_name` | Prometheus metric to evaluate |
| `target_value` | Desired metric value |
| `scale_up_threshold` | Ratio above which to scale up |
| `scale_down_threshold` | Ratio below which to scale down |

### How It Works

1. Metrics are collected from agents every 15 seconds
2. The scaling engine evaluates policies periodically
3. For each service, it computes the average metric value across instances
4. If the ratio of current to target exceeds the scale-up threshold, it adds replicas
5. If below the scale-down threshold, it removes replicas
6. A cooldown period (default: 60 seconds) prevents thrashing

## Pool-Level Scaling

Node pools can define scaling policies that monitor aggregate pool utilization:

```nix
nodePools.compute = {
  scaling = {
    minCount = 2;
    maxCount = 10;
    rules = [{
      metricName = "pool_cpu_utilization";
      targetValue = 0.7;
      scaleUpThreshold = 1.3;
      scaleDownThreshold = 0.5;
    }];
  };
};
```

Pool scaling decisions are advisory — they produce events and log recommendations but do not automatically provision machines (since ekafleet manages NixOS machines provisioned by external IaC tools).

## Node Drain

To remove a machine from the fleet (e.g., for maintenance):

```bash
ekafleet drain app-1 --deadline 300
```

This marks the node as unschedulable and reschedules all services to other nodes. The optional `--deadline` flag (in seconds) sets a time limit for the drain operation. The migration policy on each service controls the pacing:

```nix
scheduling.migrate = {
  maxParallel = 1;       # Migrate one instance at a time
  minHealthyTime = 10;   # New instance must be healthy for 10s
  healthyDeadline = 300;  # 5 minute deadline for migration
};
```

## Node Maintenance Windows

To prevent new workloads from being placed on a node without draining existing services (e.g., scheduled maintenance in the future):

```bash
# Mark node as ineligible for scheduling
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://server:7402/v1/nodes/app-1/schedulable?enabled=false

# Re-enable scheduling
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://server:7402/v1/nodes/app-1/schedulable?enabled=true
```

An ineligible node continues running its existing services but does not receive new placements. This is less disruptive than a full drain — existing workloads are undisturbed until the maintenance window begins.

## Data Migration on Reschedule

When a stateful service is rescheduled to a different machine, its volume data can be migrated automatically using rsync over SSH:

1. The agent on the source machine snapshots the volume
2. The agent on the destination machine provisions the volume directory
3. Data is transferred via `rsync -avz --delete` from source to destination
4. The service is started on the destination machine after migration completes

Migration respects the service's `migrate` config for pacing and health gates.

## Rebalancing

After cluster drift (node failures, recoveries, scale-ups), workloads may concentrate on surviving nodes. The descheduler evaluates whether services would be better placed on different machines by comparing actual placement against ideal (freshly computed) placement:

```bash
# Check for rebalance opportunities
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/rebalance
```

Each suggestion includes the service name, current node, ideal node, and reason. Rebalancing is advisory — the operator reviews suggestions and triggers rescheduling manually.

## Capacity Planning

View resource utilization across the fleet:

```bash
ekafleet capacity
```

Output includes per-pool breakdown when node pools are configured.

View service placement:

```bash
ekafleet services
```
