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

## Event Timeline

ekafleet records significant fleet events in an in-memory timeline, queryable via the REST API:

```bash
# All recent events
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/events

# Filter by service
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/events?service=api-server&limit=20
```

Event categories: `deployment`, `scheduling`, `health`, `scaling`, `node_join`, `node_leave`, `drain`, `secret_rotation`, `attestation`.

Each event includes a timestamp, severity level (info/warning/error), optional service and node context, and a human-readable message.

## REST API

The server exposes JSON REST endpoints alongside the gRPC API:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (unauthenticated) |
| `GET /metrics` | Prometheus metrics |
| `GET /v1/status` | Fleet health overview (nodes, services, pools) |
| `GET /v1/services` | Service placement listing with instance details |
| `GET /v1/capacity` | Resource utilization with per-pool breakdown |
| `GET /v1/events` | Queryable event timeline (`?service=...&limit=...`) |
| `GET /v1/deployments` | All deployment history |
| `GET /v1/deployments/:service` | Per-service deployment history |

All `/v1/` endpoints require a bearer token with at least `viewer` role permissions.

## Health Status

```bash
# Fleet overview
ekafleet status

# Check for state divergence
ekafleet drift
```
