# Observability

ekafleet provides built-in metrics collection and aggregation.

## Metrics Collection

### Service Metrics

The agent scrapes Prometheus-format metrics from local services every 15 seconds. Services expose metrics on the port declared in their configuration.

### Node Metrics

The agent collects system-level metrics from `/proc`:

| Metric | Description |
|--------|-------------|
| `node_cpu_usage_ratio` | CPU utilization (0-1) |
| `node_memory_total_bytes` | Total system memory |
| `node_memory_available_bytes` | Available memory |
| `node_memory_usage_ratio` | Memory utilization (0-1) |

### Fleet-Wide Aggregation

The server aggregates metrics from all agents and provides:

- Per-service averages and maximums across instances
- Per-node resource utilization
- Fleet-wide averages for capacity planning

## Prometheus Endpoint

The server exposes a Prometheus-compatible endpoint at:

```
http://<server>:7402/metrics
```

Point Grafana or other monitoring tools at this endpoint for fleet-wide dashboards.

## Logging

ekafleet uses structured logging via the `tracing` framework. Control log level with the `RUST_LOG` environment variable:

```bash
# Default: info
RUST_LOG=info ekafleet server

# Debug logging for specific subsystems
RUST_LOG=ekafleet::server::scheduler=debug ekafleet server

# Trace everything
RUST_LOG=trace ekafleet server
```

### Aggregated Logs

View logs from all replicas of a service:

```bash
ekafleet logs api-server
```

## Health Status

```bash
# Fleet overview
ekafleet status

# Check for state divergence
ekafleet drift
```
