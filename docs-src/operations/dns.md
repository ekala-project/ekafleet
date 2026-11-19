# DNS & Service Discovery

ekafleet has built-in DNS for service discovery, replacing Consul DNS.

## How It Works

### Server: record authority

The server is the authority for the fleet domain (e.g. `fleet.internal`). Every 5 seconds it builds each node's complete record set from:

- the desired state it assigned each node,
- the mesh addresses nodes advertised,
- replica health,
- the health of external services.

When a node's records change, the server pushes that node a `DnsUpdate` snapshot. Unchanged snapshots are re-sent every 30 seconds. Every answer has a TTL of 10 seconds.

A replica is served while its node reports it running and not unhealthy.

### Agent: local resolver

Each agent answers queries itself, from the last snapshot it received, so name resolution keeps working through a server outage:

- **Host:** listens on `127.0.0.1:53` (`--dns-listen`, or `--no-dns` to disable).
- **Namespace networks:** each namespace network gets a listener on its bridge gateway, and that namespace's services get a `resolv.conf` pointing at it.
- **Other names:** queries outside the fleet domain go to the upstream resolvers (`--dns-upstream`, default: the nameservers in `/etc/resolv.conf`).

## Names

All names are relative to the fleet domain.

| Name | Records | Visible to |
|------|---------|------------|
| `<node>.node` | A: the node's mesh address | everyone |
| `<svc>.service` | A: mesh addresses of nodes with a serving replica; SRV: `<port> <node>.node` per declared port | everyone (default-namespace services) |
| `<svc>.service` | A: overlay addresses of serving replicas; SRV: `<port> <svc>.service` | nodes running something in the service's namespace |
| `<name>.external` | A: healthy addresses of the external service; SRV: `<port> <name>.external` | everyone |
| `<svc>.<peer>.federation` | A: underlay addresses of the peer's nodes serving the exported service; SRV: `<port> <svc>.<peer>.federation` | everyone |

Namespace records take precedence over fleet-wide records with the same name, and are hidden outside their namespace.

```bash
dig api.service.fleet.internal          # A
dig api.service.fleet.internal SRV      # port + target
dig orders-db.external.fleet.internal   # external service
```

In application code, use the hostname:

```python
requests.get("http://api.service.fleet.internal:8080/data")
```

## External Services

Services outside the fleet, such as managed databases or SaaS endpoints, can be declared in the fleet configuration. Fleet services can then find them by name instead of hard-coding addresses:

```nix
externalServices.orders-db = {
  addresses = [ "10.0.0.50:5432" "10.0.0.51:5432" ];   # IPv4 ip:port
  healthCheck = {
    type = "tcp";        # or "http": GET `path`, passes on 2xx/3xx
    interval = 10;       # seconds (default 10)
    timeout = 2;         # seconds (default 2)
  };
};
```

How health checks work:

- **Where checks run:** on the server. The server therefore needs to reach the addresses.
- **Failing addresses:** an address that fails two checks in a row is left out of DNS until a check passes again.
- **When all addresses fail:** the name answers NXDOMAIN.
- **Without a `healthCheck`:** every address is always served.
- **Events:** health changes are recorded as `external.unhealthy` and `external.healthy` fleet events, which [event webhooks](../reference/fleet-config.md#eventwebhook) can subscribe to.

## Federated Services

Services that a [federation peer](spiffe.md#trust-domain-federation) exports resolve under the local name of that peer:

```bash
dig api.east.federation.fleet.internal       # A: east's nodes serving api
dig api.east.federation.fleet.internal SRV   # its declared ports
```

The addresses come from the peer's last federation document, which is fetched every 30 seconds. If the peer has not answered for 5 minutes, its names answer NXDOMAIN.
