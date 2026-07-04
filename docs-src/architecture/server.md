# Server Mode

Start with `ekafleet server`. The server runs the control plane and can optionally run workloads too.

## Responsibilities

- **Scheduling** — Decides which services run on which machines
- **Deployment orchestration** — Manages rollouts with health gates
- **Certificate Authority** — Issues SPIFFE-compatible X.509 certificates
- **Secret management** — Stores and distributes encrypted secrets
- **DNS authority** — Authoritative DNS for the fleet domain
- **Metrics aggregation** — Collects fleet-wide metrics for scaling decisions
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
├── node-id          # Unique server identity
└── raft/
    ├── log/         # Raft log entries (JSON files)
    └── snapshots/   # State machine snapshots
```

Log compaction happens automatically after snapshots to prevent unbounded growth.

## Built-in Certificate Authority

The server operates a root CA that:
- Generates a self-signed root key/cert on first start (or loads from Raft state)
- Issues short-lived leaf certificates (1 hour default TTL)
- Includes SPIFFE URIs: `spiffe://fleet.internal/service/<name>`
- Performs workload attestation by verifying Nix store paths
- Automatically renews certificates before expiry
