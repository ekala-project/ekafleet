# Reverse Proxy & Ingress

ekafleet includes a built-in reverse proxy supporting both L7 (HTTP) and L4 (TCP) proxying for routing external traffic to services.

## How It Works

The L7 proxy listener binds on HTTP ports (default 80/443) and routes requests based on hostname and path prefix, derived from service port contracts. All HTTP methods, headers, and request bodies are forwarded to upstreams via a hyper-based HTTP client.

```text
Client → ekafleet proxy (80/443)
    ↓ (hostname + path matching)
Route resolved via ProxyRouter
    ↓ (circuit breaker check)
Circuit breaker allows request?
    ↓ (round-robin selection)
Upstream selected via UpstreamPool
    ↓ (forwarded with retries)
Backend service
```

For non-HTTP protocols (databases, gRPC, AMQP), the L4 TCP proxy performs bidirectional byte forwarding without protocol inspection.

## Port Contracts

Services declare their ingress requirements in the fleet configuration:

```nix
services.web-frontend = {
  ports.http = {
    port = 8080;
    hostname = "app.example.com";
    healthCheck.path = "/ready";
  };
};
```

The proxy automatically:
- Routes requests for `app.example.com` to port 8080
- Performs health checks on `/ready`
- Removes unhealthy backends from the pool
- Marks backends as unhealthy on connection failure

## Routing Rules

Routes are matched in order of specificity (longest path prefix wins):

| Priority | Rule |
|----------|------|
| 1 | Exact hostname + longest path prefix |
| 2 | Exact hostname + shorter path prefix |
| 3 | Wildcard hostname (`*`) + path prefix |

## Traffic Splitting (Canary)

For canary deployments, traffic can be split between stable and canary backends:

```nix
update = {
  strategy = "canary";
  canary = 1;
};
```

The `TrafficSplitter` uses weighted random selection:
- `weight = 90` → 90% of requests go to stable
- `weight = 10` → 10% go to canary

Weights are adjusted automatically during canary progression.

## L4 TCP Proxy

For non-HTTP services (databases, gRPC, message brokers), the L4 proxy binds a TCP listener and forwards raw bytes to an upstream selected from the same `UpstreamPool`:

```nix
services.postgres = {
  command = "${pkgs.postgresql}/bin/postgres";
  ports.tcp = {
    port = 5432;
    protocol = "tcp";
  };
};
```

The L4 proxy performs bidirectional `tokio::io::copy` between inbound and outbound connections, with no protocol awareness. Upstream selection uses the same round-robin health-aware pool as the L7 proxy.

## Circuit Breaking

The proxy includes a per-service circuit breaker that protects against cascading failures:

| State | Behavior |
|-------|----------|
| **Closed** | Requests flow normally. Failures are counted. |
| **Open** | All requests immediately return 503. Entered after `failure_threshold` consecutive failures. |
| **Half-Open** | One probe request is allowed through. If it succeeds, the circuit closes; if it fails, the circuit re-opens. |

Configuration defaults:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `failure_threshold` | 5 | Consecutive failures to open the circuit |
| `open_duration` | 30s | Time the circuit stays open before probing |
| `success_threshold` | 2 | Successes in half-open state to close the circuit |

## Retry Logic

Failed upstream requests are automatically retried with exponential backoff:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_retries` | 2 | Maximum retry attempts (0 = no retries) |
| `base_delay` | 100ms | Initial delay between retries |
| `max_delay` | 2s | Maximum delay (caps exponential growth) |

The retry delay for attempt N is `min(base_delay * 2^N, max_delay)`. After all attempts fail, the circuit breaker records the failure and the upstream is marked unhealthy.

Non-idempotent methods (`POST`, `PATCH`) are not retried after the first attempt to avoid duplicate side effects. Only idempotent methods (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`) are eligible for retry.

## Upstream Health

The `UpstreamPool` tracks backend health:

- **Round-robin** selection among healthy endpoints
- Backends marked unhealthy on connection failure (502)
- Backends recover when health checks pass again
- Circuit breaker records success/failure for threshold tracking

## Rate Limiting

The proxy includes per-service rate limiting using a token bucket algorithm. Configure limits to prevent individual callers from overwhelming a service:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `requests_per_second` | 100 | Sustained request rate |
| `burst` | 200 | Maximum burst capacity |

When the rate limit is exceeded, the proxy returns `429 Too Many Requests`. Each service has its own independent token bucket that refills at the configured rate.

## Session Affinity

For stateful applications that need sticky routing, the proxy supports client-IP-based session affinity:

- Requests from the same client IP are routed to the same backend
- Sessions expire after a configurable TTL (default 1 hour)
- When a sticky backend becomes unhealthy, the session is cleared and a new backend is selected

Session affinity works alongside round-robin — the first request from a client gets round-robin selection, and subsequent requests within the TTL go to the same backend.

## mTLS Enforcement

When the proxy receives a request from another fleet service (internal traffic), it can validate the caller's SPIFFE identity:

1. Extract peer certificate from the mTLS connection
2. Parse the SPIFFE ID from the certificate's SAN URI
3. Check against the target service's `allowedCallers`
4. Deny with 403 if unauthorized

This enforces identity-based access control at the application layer.

## Error Handling

| Scenario | Response |
|----------|----------|
| No matching route | 404 Not Found |
| Circuit breaker open | 503 Service Unavailable |
| All backends unhealthy | 503 Service Unavailable |
| All retry attempts failed | 502 Bad Gateway (backend marked unhealthy) |
| Rate limit exceeded | 429 Too Many Requests |
| Unauthorized caller (mTLS) | 403 Forbidden |
