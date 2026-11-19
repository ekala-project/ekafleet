# Ingress Proxy

Every agent node runs `ekafleet-proxy`, an unprivileged HTTP reverse proxy. It routes traffic from outside the fleet to fleet services, along the `ingress` routes of the fleet configuration.

## Routes

```nix
ingress = {
  site = {
    host = "www.example.com";   # Host header, without port; "*" matches any host
    service = "web";            # default-namespace service
    port = "http";              # name of one of the service's ports
    pools = [ "edge" ];         # serve on nodes of these pools ...
  };
  api = {
    host = "www.example.com";
    path = "/api";              # path prefix (default "/")
    service = "api";
    port = "http";
    nodes = [ "edge-1" ];       # ... and/or on these nodes
  };
};
```

**Where a route is served:**

- on nodes that match its `pools` or `nodes`;
- on every node if it lists neither.

**Matching:**

- A request matches a route when its `Host` header matches (case-insensitive, any port ignored) and its path starts with the route's `path`.
- The longest matching prefix wins.
- Routes for an exact host take precedence over `*` only when their prefix is at least as long.
- Two routes may not have the same host and path.

## How It Works

```text
fleet config `ingress`
    ↓ server, every 5 s: routes for each node + mesh addresses of serving replicas
IngressUpdate (agent stream)
    ↓ agent
/run/ekafleet/ingress-routes.json  (0644, rewritten only on change)
    ↓ proxy, polled every 2 s
routing table + one upstream pool per route
    ↓
backend replica (over the WireGuard mesh)
```

- **Backends:** a route's backends are the replicas serving its service, in the same sense as DNS (running and not unhealthy). They are addressed by their node's mesh address and the port's number. A replica that stops serving leaves the pool within seconds.
- **Network reachability:** the service has to listen on its node's mesh address (or `0.0.0.0`). The NixOS module trusts the `wg-fleet` interface by default (`services.ekafleet.agent.mesh.trustInterface`), so the proxy can reach it.
- **Opening the ingress port:** the proxy listens on `services.ekafleet.agent.proxyListen` (default `0.0.0.0:8080`). On ingress nodes, set `services.ekafleet.agent.proxyOpenFirewall = true`.
- **Missing or invalid file:** a missing routes file means no routes. An invalid one keeps the previous routes.

The proxy speaks plain HTTP. Terminate TLS in front of it, for example at a cloud load balancer.

## Requests

| Step | Behavior |
|------|----------|
| Forwarding | Method, headers (including the original `Host`), query and body (up to 10 MiB) are forwarded. |
| Selection | Round-robin over the route's backends. |
| Retries | Up to 2 retries with exponential backoff (100 ms doubling, capped at 2 s), for idempotent methods only (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`). |
| Ejection | A backend whose attempts all fail is skipped for 10 seconds. |
| Circuit breaking | Each route has a circuit breaker. After 5 consecutive failures it opens for 30 seconds and answers 503. Then it lets probes through, and 2 successes close it. |

| Scenario | Response |
|----------|----------|
| No matching route | 404 Not Found |
| Circuit breaker open | 503 Service Unavailable |
| No usable backend | 503 Service Unavailable |
| All attempts failed | 502 Bad Gateway |

## Not Yet Wired

The `proxy` module contains these components, but the ingress proxy does not use them yet:

- TLS termination;
- L4 (TCP) proxying;
- rate limiting;
- session affinity;
- weighted traffic splitting;
- SPIFFE caller authorization.
