# Scaling

ekafleet supports both manual and automatic scaling.

## Manual Scaling

```bash
ekafleet scale api-server 5
```

This triggers re-evaluation and deployment of the delta.

## Autoscaling

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

### Draining

To remove a machine from the fleet (e.g., for maintenance):

```bash
ekafleet drain app-1
```

This reschedules all services off the machine before it's taken offline.

## Capacity Planning

View resource utilization across the fleet:

```bash
ekafleet capacity
```

View service placement:

```bash
ekafleet services
```
