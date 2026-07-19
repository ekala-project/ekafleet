# Server Mode

Start with `ekafleet server`. The server runs the control plane and can optionally run workloads too. In production, the NixOS module deploys the server as two processes: `ekafleet-ca-signer` (holds the CA key in isolation) and `ekafleet-server --ca-socket` (the control plane connecting to the CA via Unix socket).

## Responsibilities

- **Scheduling** — Priority-based placement with constraints, affinities, taints/tolerations, node pools, spread, and disruption budgets
- **Deployment orchestration** — Manages rollouts with health gates and disruption budget enforcement
- **RBAC** — Role-based access control with admin, operator, and viewer roles
- **Certificate Authority** — Issues SPIFFE X.509-SVIDs, signs CSRs (private keys stay with workloads). In production, the CA key is held in a separate `ca-signer` process with `PrivateNetwork=true` and no capabilities
- **Node attestation** — Validates join tokens, issues node SVIDs for mTLS bootstrap
- **Secret management** — Stores and distributes encrypted secrets; distributes fleet encryption key
- **DNS authority** — Authoritative DNS for the fleet domain
- **Metrics aggregation** — Collects fleet-wide metrics for scaling decisions
- **Cloud provider management** — Provisions and destroys AWS, Azure, and GCP VMs for pool autoscaling; tracks cloud instances in Raft state; correlates agents with cloud VMs by IP
- **Event tracking** — Records deployment, scheduling, health, scaling, and node events
- **REST API** — JSON endpoints for status, services, capacity, events, deployment history, and cloud instances
- **Persistent state** — Encrypted Raft-style log and snapshots with automatic restore-on-boot

## State Machine

The server maintains a persistent state machine backed by encrypted log entries and snapshots (AES-256-GCM). On startup, `restore_raft_state` loads the latest snapshot and replays trailing log entries so fleet state survives restarts. Multi-node consensus (`--peers`) is parsed but not yet wired; today a single server is authoritative.

The state machine stores:
- Fleet state (what's deployed where)
- Encrypted secrets
- Scheduling plans
- DNS zone data
- Cloud instance tracking (cloud VM ID to fleet node ID mappings)

## State Persistence

Server state is stored in `--data-dir` (default: `/var/lib/ekafleet`):

```text
/var/lib/ekafleet/
├── server-id               # Persistent server identity (UUIDv4)
├── ca-key.pem              # Root CA private key (sealed¹, mode 0600)
├── ca-cert.pem             # Root CA certificate
├── ca-intermediate-key.pem # Short-lived intermediate CA key (sealed¹, mode 0600)
├── ca-intermediate-cert.pem# Intermediate CA certificate
├── fleet-key               # Fleet encryption key (sealed¹, mode 0600)
├── tokens.json             # Persisted ACL tokens (keyed by SHA-256 digest)
└── raft/
    ├── log/                # Encrypted log entries (AES-256-GCM)
    └── snapshots/          # Encrypted state machine snapshots
```

¹ When `EKAFLEET_SEAL_PASSPHRASE` is set, key files are encrypted at rest using PBKDF2-HMAC-SHA256 + AES-256-GCM envelope encryption. Without it, they are stored as plaintext with a warning. In-memory copies of all key material are wrapped in `Zeroizing<T>` so they are cleared on drop.

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

### CA Process Isolation

In production (via the NixOS module), the CA runs as a separate `ekafleet-ca-signer` process that communicates with the control plane via a Unix socket. The CA process is maximally hardened:

- `PrivateNetwork=true` — no network access at all
- `CapabilityBoundingSet=` — no Linux capabilities
- `MemoryDenyWriteExecute=true` — no JIT or writable+executable memory
- `IPAddressDeny=any` — belt-and-suspenders network denial

This ensures that a vulnerability in the REST API, webhook dispatcher, or any other control plane subsystem cannot access the CA private key — it lives in a different address space.

For development and quick bootstrapping, `ekafleet server` (without `--ca-socket`) embeds the CA in-process.

## Node Attestation

The server handles SPIFFE-style node attestation via the `Attest` RPC:
- **Join token**: One-time-use tokens registered via `ekafleet token create`; consumed on attestation and cannot be replayed
- After attestation, the server issues a node SVID and the agent connects via mTLS
- The `Attest` RPC requires `Attest` permission (granted to Operator and Admin roles)

## Fleet Encryption Key

The server generates a 256-bit AES-256-GCM master key on first start (persisted at `<data-dir>/fleet-key`). The master key never leaves the server. Instead, each agent receives a unique key derived via HKDF-SHA256 using its SPIFFE ID (`spiffe://<domain>/agent/<node-id>`) as context. This ensures that compromising one agent's key does not expose secrets encrypted for other agents. Secrets stored in the Raft state are encrypted with the master key and re-encrypted under the agent's derived key before distribution.

All ciphertext is bound to its context via AES-256-GCM additional authenticated data (AAD). For secrets, the AAD is `service_name\x00secret_name`, preventing encrypted values from being swapped between services. Raft log entries and snapshots use their own distinct AAD tags.

### Key Rotation

The fleet encryption key can be rotated at runtime via the `RotateFleetKey` gRPC RPC. Rotation is an atomic operation that:

1. Generates a new 256-bit master key
2. Re-encrypts every secret in the store under the new key
3. Persists the new key to `<data-dir>/fleet-key`
4. Pushes fresh HKDF-derived keys to all connected agents

The key carries a monotonic version number so agents can detect rotations. Agents that connect after a rotation receive the current key version automatically. Rotation does not require downtime — agents update their decryption key in-place and continue injecting secrets normally.

## Agent Command Relay

The server can relay operational commands to individual agents through the bidirectional gRPC stream and await correlated responses. This powers the `exec`, `logs`, `inspect`, `generation`, `system gc`, `system reboot`, and `system rebuild` commands. Each request carries a unique `correlation_id`; the server registers a oneshot channel and awaits the agent's response with a per-command timeout.

For fleet-wide operations like `system gc` and `system rebuild`, the server fans out commands to all connected nodes concurrently. For `system reboot`, the server orchestrates a rolling reboot in configurable batches, waiting for each batch of nodes to reconnect before proceeding to the next.

## Policy Enforcement

During `plan` and `apply`, the server evaluates organizational policy rules from the fleet configuration against each service. Policies use a simple expression language (e.g., `service.replicas >= 2`) with two enforcement levels:

- **enforce** — Violations block the service from being created or updated
- **warn** — Violations are logged but do not block deployment

## Authentication & RBAC

The gRPC API supports two authentication methods:

- **Bearer token**: Validated against the token store; the token's role is inserted into request extensions
- **mTLS (SPIFFE SVID)**: The SPIFFE ID is extracted from the verified peer certificate's SAN URI and mapped to a role based on the path: `/server/*` → Admin, `/agent/*` → Operator, others → Viewer

Every gRPC handler enforces RBAC via `require_permission()`:

| Permission | Roles | RPCs |
|---|---|---|
| Read | Admin, Operator, Viewer | status, plan, logs, events, list_*, top, snapshot, inspect, diff |
| Deploy | Admin, Operator | apply, rollback, restore, dispatch, exec, switch_generation, system_* |
| Scale | Admin, Operator | scale |
| Drain | Admin, Operator | drain |
| AgentConnect | Admin, Operator | stream_control |
| Attest | Admin, Operator | attest |
| ManageTokens | Admin only | create/revoke/list_acl_tokens, rotate_fleet_key |

Client-supplied `x-ekafleet-mtls` and `x-ekafleet-attest` metadata headers are stripped at the interceptor boundary to prevent spoofing.

## ACL Token Management

The server maintains an RBAC token store with three roles: **admin**, **operator**, and **viewer**. Tokens can be created, listed, and revoked via both the gRPC API and the `ekafleet acl token` CLI commands. Token management requires the **ManageTokens** permission (Admin only). The token store is shared between the gRPC and REST API layers. Tokens are persisted to `tokens.json` keyed by SHA-256 digest (the raw token value is never stored at rest).
