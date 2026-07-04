# Communication

## Server ↔ Agent: gRPC (tonic)

The primary communication channel is a bidirectional gRPC stream over TCP port 7400.

### Agent → Server Messages

| Message | Purpose |
|---------|---------|
| `Heartbeat` | Periodic liveness signal with available resources |
| `HealthReport` | Health status of local services |
| `StatusReport` | Running services, store paths, states |
| `CertificateRequest` | Request a new certificate for a service |
| `MetricsSummary` | Aggregated metrics from local services |
| `Nack` | Reject an invalid server command |

### Server → Agent Messages

| Message | Purpose |
|---------|---------|
| `DesiredState` | Full desired state for this agent's services |
| `DeployCommand` | Deploy a specific service version |
| `SecretUpdate` | Push an encrypted secret for a service |
| `DnsUpdate` | DNS record updates for the local resolver cache |
| `CertificateResponse` | Signed certificate + chain |
| `PeerUpdate` | WireGuard peer list update |
| `PolicyUpdate` | Network policy rules to apply |

### RPC Methods

```protobuf
service FleetControl {
  rpc StreamControl(stream AgentMessage) returns (stream ServerMessage);
  rpc Plan(PlanRequest) returns (PlanResponse);
  rpc Apply(ApplyRequest) returns (stream ApplyEvent);
  rpc Status(StatusRequest) returns (FleetStatus);
}
```

## Gossip: UDP (SWIM)

Port 7401. Used for:

- **Membership** — Alive/suspect/dead detection (2-5 second failure detection)
- **Service catalog** — Eventually-consistent service discovery between agents
- **DNS cache hints** — Cache invalidation signals between agents

The gossip layer works independently of the server, providing continued service discovery even during server outages.

## HTTP API

Port 7402. Provides:

- `GET /health` — Server health check
- `GET /metrics` — Prometheus-compatible metrics endpoint
