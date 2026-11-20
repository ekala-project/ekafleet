# Ingress Proxy

Every agent node runs `ekafleet-proxy`, an unprivileged HTTP(S) and TCP reverse proxy. It routes traffic from outside the fleet to fleet services, along the `ingress` routes of the fleet configuration.

## Routes

```nix
ingress = {
  site = {
    host = "www.example.com";   # Host header, without port; "*" matches any host
    service = "web";            # any service, in any namespace
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

## Route Options

```nix
ingress = {
  shop = {
    host = "shop.example.com";
    service = "shop";
    port = "http";
    split = [ { service = "shop-v2"; weight = 10; } ];   # 10% to shop-v2, 90% to shop
    affinity = "clientIp";                               # a client keeps its replica
    rateLimit = { requestsPerSecond = 20; burst = 40; }; # per client IP
    tls = { certSecret = "shop-crt"; keySecret = "shop-key"; };
  };
  admin = {
    host = "shop.example.com";
    path = "/admin";
    service = "shop";
    port = "http";
    tls = { certSecret = "shop-crt"; keySecret = "shop-key"; };
    allowedCallers = [ "backoffice" ];                   # clients need this service's SVID
  };
  db = {
    service = "postgres";
    port = "pg";
    tcpPort = 5432;                                      # raw TCP on the proxy's port 5432
    pools = [ "edge" ];
  };
};
```

| Option | Behavior |
|--------|----------|
| `split` | Each entry takes `weight` percent of the traffic (1-100, at most 100 in total) to another service declaring the same port; `service` gets the rest. When a share has no usable backend, the others take its traffic. |
| `affinity = "clientIp"` | Requests (and TCP connections) from one client IP go to the same split share and the same replica while it serves (rendezvous hashing; nothing is stored). Without it, backends are picked round-robin. |
| `rateLimit` | A token bucket per client IP (IPv6: per /64): `burst` requests at once, refilled at `requestsPerSecond`. Over the limit the proxy answers 429. HTTP routes only. |
| `tcpPort` | Forward TCP connections on this port (on the address of `proxyListen`) to the route's backends; `host` and `path` must stay unset. A port that is busy is retried every 2 seconds. Open it in the firewall yourself. |
| `tls` | Serve the route on the proxy's HTTPS listener (`services.ekafleet.agent.proxyTlsListen`), with the certificate chain and key held in two `_fleet` secrets (PEM, leaf first). See below. |
| `allowedCallers` | Only clients presenting the X.509-SVID of one of these fleet services (over HTTPS, chaining to the fleet CA) reach the route; others get 403. Requires `tls`. |

### TLS

```sh
ekafleet secret set _fleet shop-crt --file fullchain.pem
ekafleet secret set _fleet shop-key --file privkey.pem
```

- The secrets reach only the nodes serving the route, re-encrypted for each node like any secret. The agent checks that the key matches the certificate, then writes both to `/run/ekafleet/ingress-tls/<route>.{crt,key}`. The key is readable by root and the proxy's group (`ekafleet-ingress-tls`) only.
- The proxy picks the certificate by SNI. A `*` route's certificate, or any one if there is none, answers clients that send no or an unknown name. Routes sharing a host must name the same secrets.
- Plain-HTTP requests for a TLS route are redirected (308) to HTTPS.
- Until both secrets have a value, the route is served over plain HTTP, and `ekafleet apply` warns about it. Rotating a certificate is setting the secrets again; the proxy picks the new one up within seconds.
- Without `proxyTlsListen`, TLS routes are served over plain HTTP only.

## How It Works

```text
fleet config `ingress`
    ↓ server, every 5 s: routes for each node + addresses of serving replicas
IngressUpdate (agent stream)
    ↓ agent
/run/ekafleet/ingress-routes.json  (0644, rewritten only on change)
    ↓ proxy, polled every 2 s
routing table + one upstream pool per route
    ↓
backend replica (over the WireGuard mesh)
```

- **Backends:** a route's backends are the replicas serving its service, in the same sense as DNS (running and not unhealthy). They are addressed by their node's mesh address and the port's number, or, for a service in a namespace other than `default`, by the replica's namespace address (routed to its node over the mesh, see [namespace networks](mesh.md#namespace-networks)). A replica that stops serving leaves the pool within seconds.
- **Network reachability:** the service has to listen on its node's mesh address, its namespace address, or `0.0.0.0`. The NixOS module trusts the `wg-fleet` interface by default (`services.ekafleet.agent.mesh.trustInterface`), so the proxy can reach it.
- **Opening the ingress ports:** the proxy listens on `services.ekafleet.agent.proxyListen` (default `0.0.0.0:8080`) and, when set, `proxyTlsListen` (e.g. `0.0.0.0:443`). On ingress nodes, set `services.ekafleet.agent.proxyOpenFirewall = true` to open both.
- **Network policy:** nodes serving a route count as callers of its services (split ones included) for [network policy](network-policy.md).
- **Missing or invalid file:** a missing routes file means no routes. An invalid one keeps the previous routes.

## Requests

| Step | Behavior |
|------|----------|
| Forwarding | Method, headers (including the original `Host`), query and body (up to 10 MiB) are forwarded, with `X-Forwarded-For` (the client's address appended) and `X-Forwarded-Proto`. |
| Selection | A split share by weight, then round-robin over its backends (or by client IP with `affinity`). |
| Retries | Up to 2 retries with exponential backoff (100 ms doubling, capped at 2 s), for idempotent methods only (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`). |
| Ejection | A backend whose attempts all fail is skipped for 10 seconds. |
| Circuit breaking | Each route has a circuit breaker. After 5 consecutive failures it opens for 30 seconds and answers 503. Then it lets probes through, and 2 successes close it. |

| Scenario | Response |
|----------|----------|
| No matching route | 404 Not Found |
| Plain HTTP for a TLS route | 308 Permanent Redirect to HTTPS |
| Caller not in `allowedCallers` | 403 Forbidden |
| Over the `rateLimit` | 429 Too Many Requests |
| Circuit breaker open | 503 Service Unavailable |
| No usable backend | 503 Service Unavailable |
| All attempts failed | 502 Bad Gateway |
