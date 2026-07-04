# DNS & Service Discovery

ekafleet provides built-in DNS for service discovery, replacing Consul DNS and external-dns.

## How It Works

### Server: DNS Authority

The server maintains authoritative DNS records for the fleet domain (e.g., `fleet.internal`):

- **A records**: `<service>.service.fleet.internal` → WireGuard IPs of hosting machines
- **SRV records**: `_<port>._tcp.<service>.service.fleet.internal` → port + host
- Records are **health-aware** — unhealthy instances are removed
- Updated **immediately** on deploy or reschedule

### Agent: DNS Resolver

Each agent runs a local caching resolver:

- Listens on `127.0.0.53:53`
- Fleet queries → answered from cache or forwarded to server
- External queries → forwarded to upstream DNS
- Cache TTL equals the health check interval
- Cache invalidated on health status changes

Services use this resolver via `/etc/resolv.conf`.

## Usage

Services discover each other using DNS names:

```bash
# A record: get IPs of the api-server service
dig api-server.service.fleet.internal

# SRV record: get port and host
dig _http._tcp.api-server.service.fleet.internal SRV
```

In application code, just use the hostname:

```python
# Python example
import requests
response = requests.get("http://api-server.service.fleet.internal:8080/data")
```

## Gossip-Based Discovery

The service catalog is also propagated between agents via gossip. This provides eventually-consistent service discovery that works even when the server is unreachable.
