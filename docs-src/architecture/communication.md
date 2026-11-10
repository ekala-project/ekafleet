# Communication

## Server ↔ Agent: gRPC (tonic)

The primary communication channel is a bidirectional gRPC stream over TCP port 7400.

### Agent → Server Messages

| Message | Purpose |
|---------|---------|
| `Heartbeat` | Periodic liveness signal with available resources |
| `HealthReport` | Health status of local services |
| `StatusReport` | Running services, store paths, states |
| `CertificateRequest` | PKCS#10 CSR for a service or node SVID |
| `MetricsSummary` | Aggregated metrics from local services |
| `Nack` | Reject an invalid server command |
| `NodeAttestationResponse` | Response to attestation challenge (TPM, future) |
| `PeerAdvert` | This node's WireGuard key, endpoint and mesh address, signed with its node SVID (mTLS streams only) |

### Agent → Server Messages (continued)

| Message | Purpose |
|---------|---------|
| `AgentCommandResponse` | Response to any server-initiated command (exec, logs, inspect, etc.) with correlation ID |

### Server → Agent Messages

| Message | Purpose |
|---------|---------|
| `DesiredState` | Full desired state for this agent's services |
| `DeployCommand` | Deploy a specific service version |
| `SecretUpdate` | Push an encrypted secret for a service |
| `DnsUpdate` | DNS record updates for the local resolver cache |
| `CertificateResponse` | Signed certificate + chain + service name |
| `PeerUpdate` | The full set of verified, SVID-signed WireGuard adverts (sent on connect and whenever it changes) |
| `PolicyUpdate` | Network policy rules to apply |
| `TrustBundleUpdate` | CA certificate + trust domain |
| `NodeAttestationChallenge` | Server challenge during attestation |
| `FleetKeyUpdate` | Per-agent derived encryption key + version for secret decryption |
| `ExecCommand` | Execute a command in a service's cgroup context |
| `LogsCommand` | Read or stream journal logs from a service |
| `ListGenerationsCommand` | List NixOS system generations |
| `SwitchGenerationCommand` | Switch/boot/test a NixOS generation |
| `DiffGenerationsCommand` | Diff two NixOS generations |
| `SystemGCCommand` | Run nix-collect-garbage |
| `SystemRebootCommand` | Initiate a system reboot |
| `SystemRebuildCommand` | Run nixos-rebuild switch |
| `InspectServiceCommand` | Query systemd unit properties and cgroup accounting |
| `MigrateVolumeCommand` | Move a persistent volume's data to another node |
| `GossipConfig` | Gossip key, the server's gossip port and current members (sent on connect and on fleet-key rotation) |

### Request-Response Correlation

Server-initiated commands use a `correlation_id` field to match responses. The server sends a command with a unique ID, registers a oneshot channel, and awaits the agent's `AgentCommandResponse` with the same ID. Timeouts are enforced per-command (default 30s, up to 600s for GC).

### RPC Methods

```protobuf
service FleetControl {
  // Bidirectional agent ↔ server stream
  rpc StreamControl(stream AgentMessage) returns (stream ServerMessage);

  // Deployment lifecycle
  rpc Plan(PlanRequest) returns (PlanResponse);
  rpc Apply(ApplyRequest) returns (stream ApplyEvent);
  rpc Status(StatusRequest) returns (FleetStatus);

  // Node attestation (requires Attest permission)
  rpc Attest(NodeAttestationRequest) returns (NodeAttestationResult);

  // Cluster operations
  rpc Rollback(RollbackRequest) returns (RollbackResponse);
  rpc Drain(DrainRequest) returns (DrainResponse);
  rpc Scale(ScaleRequest) returns (ScaleResponse);
  rpc Snapshot(SnapshotRequest) returns (SnapshotResponse);
  rpc Restore(RestoreRequest) returns (RestoreResponse);
  rpc Dispatch(DispatchRequest) returns (DispatchResponse);

  // Agent-relayed operations
  rpc Exec(ExecRequest) returns (ExecResponse);
  rpc Logs(LogsRequest) returns (stream LogsChunk);
  rpc InspectService(InspectServiceRequest) returns (InspectServiceResponse);

  // Fleet queries
  rpc Events(EventsRequest) returns (EventsResponse);
  rpc ListNodes(ListNodesRequest) returns (ListNodesResponse);
  rpc GetNode(GetNodeRequest) returns (NodeDetail);
  rpc UpdateNode(UpdateNodeRequest) returns (UpdateNodeResponse);
  rpc Top(TopRequest) returns (TopResponse);
  rpc ListDeployments(ListDeploymentsRequest) returns (ListDeploymentsResponse);
  rpc PromoteDeployment(PromoteRequest) returns (PromoteResponse);
  rpc FailDeployment(FailDeploymentRequest) returns (FailDeploymentResponse);

  // ACL token management
  rpc CreateACLToken(CreateACLTokenRequest) returns (CreateACLTokenResponse);
  rpc RevokeACLToken(RevokeACLTokenRequest) returns (RevokeACLTokenResponse);
  rpc ListACLTokens(ListACLTokensRequest) returns (ListACLTokensResponse);

  // NixOS generation management
  rpc ListGenerations(ListGenerationsRequest) returns (ListGenerationsResponse);
  rpc SwitchGeneration(SwitchGenerationRequest) returns (SwitchGenerationResponse);
  rpc DiffGenerations(DiffGenerationsRequest) returns (DiffGenerationsResponse);

  // System-wide operations
  rpc SystemGC(SystemGCRequest) returns (SystemGCResponse);
  rpc SystemReboot(SystemRebootRequest) returns (SystemRebootResponse);
  rpc SystemRebuild(SystemRebuildRequest) returns (SystemRebuildResponse);

  // Key management
  rpc RotateFleetKey(RotateFleetKeyRequest) returns (RotateFleetKeyResponse);
}
```

All RPCs enforce RBAC via `require_permission()`. The `Attest` RPC requires `Attest` permission (granted to Operator and Admin). Authentication is via bearer token or mTLS (the SPIFFE ID is extracted from the verified peer cert and mapped to a role).

### SPIFFE Workload API (Unix Socket)

Each agent also serves the standard SPIFFE Workload API v2 over a Unix domain socket at `/run/ekafleet/workload-api.sock`. This is a separate gRPC service that workloads connect to for fetching SVIDs and trust bundles.

```protobuf
service SpiffeWorkloadAPI {
  rpc FetchX509SVID(X509SVIDRequest) returns (stream X509SVIDResponse);
  rpc FetchX509Bundles(X509BundlesRequest) returns (stream X509BundlesResponse);
}
```

## Gossip: UDP (SWIM)

Port 7401 (`--gossip-listen`; `off` disables it). The server and every agent run SWIM membership: each member pings the others every second, marks a member *suspect* after 3 seconds without a reply and *dead* after 10, and marks it alive again when it answers.

**Bootstrap.** Agents do not have the gossip key until they connect. The server derives it from the fleet key (HKDF-SHA256, salt `ekafleet-gossip-hmac-v1`) and sends it in `GossipConfig` over the authenticated control stream, with its gossip port and the members it currently sees as alive. The agent starts SWIM on the first `GossipConfig`, seeded with the server and those members. Rotating the fleet key sends a new `GossipConfig`, and gossip switches to the new key.

**Message authentication.** Every message is `type || timestamp || node_id || HMAC-SHA256` over all the preceding fields. Messages with a bad tag, an invalid node ID, or a timestamp more than 30 seconds from the receiver's clock are dropped. There is no indirect probe (ping-req), so a packet cannot make a node send traffic to a third party.

**What gossip is not.** The key is shared by every connected agent, so any agent can claim any node ID in gossip. Gossip is not encrypted. Gossip membership is therefore advisory: identity comes from node SVIDs on the control stream, and WireGuard peer keys travel as SVID-signed adverts over that stream, never over gossip. Agents keep gossiping with each other while the server is down, but an agent that restarts cannot rejoin until the server is reachable.

> **Status:** the service catalog (`src/gossip/catalog.rs`) and DNS cache hints are not yet carried over gossip.

## HTTP API

Port 7402. Public endpoints:

- `GET /health` — Server health check (unauthenticated)

Authenticated endpoints (require `Authorization: Bearer <token>` header):

- `GET /metrics` — Prometheus-compatible metrics endpoint
- `GET /v1/status` — Fleet status (nodes, services, pools)
- `GET /v1/services` — Service listing
- `GET /v1/capacity` — Cluster capacity summary
- `GET /v1/events` — Event timeline with category/service/limit filters
- `GET /v1/deployments` — Deployment history
- `GET /v1/watch` — Server-Sent Events stream for real-time updates
- `GET /v1/query` — PromQL-style metrics query
- `GET/PUT/DELETE /v1/kv/{key}` — Key-value store CRUD
- `GET /v1/kv?prefix=` — KV prefix listing
- `GET/POST /v1/alerts/silences` — Alert silence management
- `DELETE /v1/alerts/silences/{id}` — Remove a silence
- `GET /v1/metrics/services/{name}` — Per-service metrics
- `GET /v1/cloud/instances` — Cloud instance tracking
- `GET /ui/` — Embedded web dashboard
