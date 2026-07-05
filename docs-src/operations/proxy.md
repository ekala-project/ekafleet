# Reverse Proxy & Ingress

ekafleet includes a built-in L7 reverse proxy for routing external traffic to services.

## How It Works

The proxy listener binds on HTTP ports (default 80/443) and routes requests based on hostname and path prefix, derived from service port contracts.

```text
Client → ekafleet proxy (80/443)
    ↓ (hostname + path matching)
Route resolved via ProxyRouter
    ↓ (round-robin selection)
Upstream selected via UpstreamPool
    ↓ (forwarded)
Backend service
```

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

## Upstream Health

The `UpstreamPool` tracks backend health:

- **Round-robin** selection among healthy endpoints
- Backends marked unhealthy on connection failure (502)
- Backends recover when health checks pass again

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
| All backends unhealthy | 502 Bad Gateway |
| Backend connection timeout | 502 Bad Gateway (backend marked unhealthy) |
| Unauthorized caller (mTLS) | 403 Forbidden |
