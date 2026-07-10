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
| `GET /v1/query` | Metric query (`?metric=...&service=...` or `?metric=...&node=...`) |
| `GET /v1/kv/:key` | Key-value store read |
| `PUT /v1/kv/:key` | Key-value store write |
| `DELETE /v1/kv/:key` | Key-value store delete |
| `GET /v1/kv?prefix=...` | Key-value store prefix listing |
| `GET /v1/metrics/services/:name` | Per-service metrics for HPA integration |
| `GET /v1/cloud/instances` | List tracked cloud-provisioned VM instances |
| `GET /v1/alerts/silences` | List active alert silences |
| `POST /v1/alerts/silences` | Create an alert silence |
| `DELETE /v1/alerts/silences/:id` | Remove an alert silence |
| `GET /ui/` | Embedded web dashboard |

All `/v1/` endpoints require a bearer token with at least `viewer` role permissions.

## Web Dashboard

ekafleet includes an embedded web dashboard accessible at:

```
http://<server>:7402/ui/
```

The dashboard provides a real-time view of the fleet with five pages:

- **Overview** — Node count, service count, health summary
- **Nodes** — Table of nodes with health status, pool, and resources
- **Services** — Table of services with instance details and health
- **Events** — Live event feed with historical event browsing
- **Deployments** — Deployment history timeline

The dashboard uses the same REST API endpoints as the CLI and requires authentication via bearer token.

## Key-Value Store

ekafleet provides a general-purpose key-value store (similar to Consul KV) for coordination primitives:

```bash
# Write a key
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -d 'my-value' http://server:7402/v1/kv/my-key

# Read a key
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/kv/my-key

# List keys by prefix
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/kv?prefix=config/

# Delete a key
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://server:7402/v1/kv/my-key
```

Use the KV store for leader election, distributed locks, feature flags, and configuration sharing.

## Metric Queries

Query current metric values for services and nodes:

```bash
# Service metric
curl -H "Authorization: Bearer $TOKEN" \
  "http://server:7402/v1/query?metric=cpu_usage&service=api-server"

# Node metric
curl -H "Authorization: Bearer $TOKEN" \
  "http://server:7402/v1/query?metric=node_cpu_usage_ratio&node=app-1"
```

### HPA Metrics API

External autoscaling tools can query per-service metrics:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://server:7402/v1/metrics/services/api-server
```

Returns all metrics for the service with per-node breakdowns in JSON format.

### Event Streaming (SSE)

For real-time event notifications without polling, use the Server-Sent Events endpoint:

```bash
curl -N -H "Authorization: Bearer $TOKEN" http://server:7402/v1/watch
```

The stream emits JSON events as they occur (deployments, health transitions, node joins/leaves, scaling actions). Each event is delivered as an SSE `data:` line. A keep-alive is sent every 15 seconds.

## Audit Logging

ekafleet records a structured audit trail of all control-plane actions for compliance (SOC2, HIPAA) and incident investigation.

Each audit entry contains:

| Field | Description |
|-------|-------------|
| `timestamp` | Unix epoch seconds |
| `actor` | Who performed the action (token identity) |
| `action` | What was done (`apply`, `plan`, `drain`, `scale`, `token_create`, `secret_write`, etc.) |
| `resource` | Target resource (service name, node ID, secret name) |
| `detail` | Human-readable description |
| `outcome` | `success`, `denied`, or `failed` |

Audit entries are retained in memory (up to 50,000 entries) and are also emitted via structured logging (`tracing`), so they can be forwarded to external log aggregation systems.

## Alerting Rules

ekafleet evaluates alerting rules against collected metrics and fires alerts when thresholds are breached:

```nix
alerting.rules = [
  {
    name = "high-cpu";
    metric = "node_cpu_usage_ratio";
    threshold = 0.9;
    op = "gt";                      # "gt", "lt", "gte", "lte", "eq"
    forSeconds = 300;               # condition must hold for 5 minutes
    severity = "critical";          # "warning" or "critical"
    webhook_url = "http://alertmanager:9093/api/v1/alerts";
  }
];
```

When an alert fires, ekafleet logs it at `WARN` level and optionally sends a webhook notification to the configured URL.

### Alert Deduplication

Alerts are deduplicated — only state transitions generate notifications:
- **ok → firing**: Alert notification sent
- **firing → ok**: Resolved notification sent (with `resolved: true`)
- **firing → firing**: No duplicate notification

### Alert Silencing

Silence alerts during planned maintenance via the REST API:

```bash
# Create a silence (matches alerts with label service=api-server)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"matchers":[["service","api-server"]],"starts_at":1720000000,"ends_at":1720003600,"comment":"maintenance window"}' \
  http://server:7402/v1/alerts/silences

# List active silences
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/alerts/silences

# Remove a silence
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://server:7402/v1/alerts/silences/0
```

Silenced alerts are suppressed during the specified time window. Silencing does not affect metric collection or threshold evaluation — only notification delivery.

## Webhook Notifications

Configure outbound webhooks to integrate with external systems (Slack, PagerDuty, custom dashboards):

```nix
webhooks = [
  {
    name = "slack-deploys";
    url = "http://slack-webhook-proxy:8080/deploy";
    events = [ "deployment" "rollback" ];
    timeout_seconds = 10;
  }
  {
    name = "pagerduty-health";
    url = "http://pd-proxy:8080/alert";
    events = [ "*" ];  # all events
  }
];
```

Webhook payloads are JSON with `event`, `data`, and `timestamp` fields. Delivery failures are logged but don't block the triggering operation.

## Distributed Tracing

The reverse proxy propagates W3C Trace Context headers (`traceparent` / `tracestate`) through the request chain. When an incoming request has a `traceparent` header, the proxy generates a child span ID while preserving the trace ID. When no trace context is present, the proxy generates a new one.

This enables integration with OpenTelemetry, Jaeger, and other distributed tracing systems for end-to-end request visibility across fleet services.

## Health Status

```bash
# Fleet overview
ekafleet status

# Check for state divergence
ekafleet drift
```
