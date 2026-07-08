# Server Mode

Start with `ekafleet server`. The server runs the control plane and can optionally run workloads too.

## Responsibilities

- **Scheduling** — Priority-based placement with constraints, affinities, taints/tolerations, node pools, spread, and disruption budgets
- **Deployment orchestration** — Manages rollouts with health gates and disruption budget enforcement
- **RBAC** — Role-based access control with admin, operator, and viewer roles
- **Certificate Authority** — Issues SPIFFE X.509-SVIDs, signs CSRs (private keys stay with workloads)
- **Node attestation** — Validates join tokens, issues node SVIDs for mTLS bootstrap
- **Secret management** — Stores and distributes encrypted secrets; distributes fleet encryption key
- **DNS authority** — Authoritative DNS for the fleet domain
- **Metrics aggregation** — Collects fleet-wide metrics for scaling decisions
- **Event tracking** — Records deployment, scheduling, health, scaling, and node events
- **REST API** — JSON endpoints for status, services, capacity, events, and deployment history
- **Raft consensus** — Multi-server HA with consistent state replication

## High Availability

For production, run 3 server nodes in a Raft cluster:

```bash
# First server (bootstrap)
ekafleet server --data-dir /var/lib/ekafleet

# Additional servers
ekafleet server --data-dir /var/lib/ekafleet --peers node1:7400,node2:7400
```

The Raft state machine stores:
- Fleet state (what's deployed where)
- Encrypted secrets
- Scheduling plans
- DNS zone data

## State Persistence

Server state is stored in `--data-dir` (default: `/var/lib/ekafleet`):

```text
/var/lib/ekafleet/
├── server-id        # Persistent server identity (UUIDv4)
├── ca-key.pem       # Root CA private key (mode 0600)
├── ca-cert.pem      # Root CA certificate
├── fleet-key        # Fleet encryption key (mode 0600, hex-encoded)
└── raft/
    ├── log/         # Raft log entries (JSON files)
    └── snapshots/   # State machine snapshots
```

Log compaction happens automatically after snapshots to prevent unbounded growth.

## Built-in Certificate Authority

The server operates a root CA that:
- Generates a self-signed root key/cert on first start (or loads from disk)
- Issues short-lived leaf certificates (1 hour default TTL) by signing PKCS#10 CSRs
- Includes SPIFFE URIs: `spiffe://<domain>/service/<name>`, `spiffe://<domain>/agent/<node-id>`, `spiffe://<domain>/server/<server-id>`
- Signs CSRs without ever seeing the workload's private key
- Performs workload attestation by verifying node-to-service assignment
- Distributes trust bundles to all connected agents
- The server itself has a SPIFFE SVID: `spiffe://<domain>/server/<server-id>`

## Node Attestation

The server handles SPIFFE-style node attestation via the `Attest` RPC:
- **Join token**: One-time-use tokens registered via `ekafleet token create`; consumed on attestation and cannot be replayed
- After attestation, the server issues a node SVID and the agent connects via mTLS
- The `Attest` RPC bypasses bearer token authentication (the join token itself is the credential)

## Fleet Encryption Key

The server generates a 256-bit AES-256-GCM encryption key on first start (persisted at `<data-dir>/fleet-key`). This key is distributed to agents over the mTLS channel for secret decryption.
