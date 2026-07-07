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
ekafleet drain app-1
```

This reschedules all services off the machine. The migration policy on each service controls the pacing:

```nix
scheduling.migrate = {
  maxParallel = 1;       # Migrate one instance at a time
  minHealthyTime = 10;   # New instance must be healthy for 10s
  healthyDeadline = 300;  # 5 minute deadline for migration
};
```

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
