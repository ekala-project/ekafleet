# Ports & Protocols

## ekafleet Ports

| Port | Protocol | Used By | Purpose |
|------|----------|---------|---------|
| 7400 | TCP (gRPC) | Server + Agent | Server API, agent ↔ server communication, node join (`FleetBootstrap`) |
| 7402 | TCP (HTTP) | Server | HTTP API (health, metrics) |
| 7404 | TCP (HTTPS, mutual TLS) | Server | Federation listener (`--federation-listen`, off by default) |
| 53 | UDP/TCP | Server + Agent | DNS (authority on server, resolver on agent) |
| 51820 | UDP | Server + Agent | WireGuard mesh |
| 8080 | TCP (HTTP) | Agent (ingress) | Ingress proxy (`proxyListen`; opened by `proxyOpenFirewall`) |
| — | TCP (HTTPS) | Agent (ingress) | Ingress proxy TLS listener (`proxyTlsListen`, unset by default; opened by `proxyOpenFirewall`) |
| `tcpPort` | TCP | Agent (ingress) | TCP ingress routes (not opened automatically) |

## Unix Sockets

| Path | Protocol | Used By | Purpose |
|------|----------|---------|---------|
| `/run/ekafleet-ca/ca.sock` | Length-prefixed JSON (UDS) | Server | CA signer ↔ control plane (SignCSR, TrustBundle, IssueServerSVID, SignJwtSvid, JwtBundle) |
| `/run/ekafleet/workload-api.sock` | gRPC (UDS) | Agent | SPIFFE Workload API (X.509 and JWT SVIDs and bundles) |

## Firewall Requirements

### Between Server and Agents

Agents must be able to reach the server on:
- TCP 7400 (gRPC)

Servers must be able to reach agents on:
- TCP 7400 (for gRPC callbacks, if applicable)

### Between All Fleet Nodes

All fleet nodes (servers and agents) need mutual connectivity on:
- UDP 51820 (WireGuard)

### Between Federated Clusters

Each server must reach every peer's federation listener (e.g. TCP 7404). Clients of exported services must reach the serving nodes' underlay addresses on the service ports.

### External Access (Ingress Nodes)

Nodes serving `ingress` routes need the ingress proxy's port open (TCP 8080 by default; `services.ekafleet.agent.proxyOpenFirewall`).

### Service Ports Over the Mesh

Fleet DNS addresses and ingress backends are mesh addresses, so nodes reach each other's service ports over `wg-fleet`. The NixOS module trusts that interface (`services.ekafleet.agent.mesh.trustInterface`, default on); with it off, open service ports with `networking.firewall.interfaces.wg-fleet.allowedTCPPorts`.

## Mesh Network

The WireGuard mesh uses the `10.100.0.0/16` subnet by default. All inter-service traffic flows over this encrypted mesh.
