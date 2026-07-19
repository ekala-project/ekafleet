# Architecture Overview

ekafleet is a single binary with multiple subcommands. For development and quick bootstrapping, convenience modes (`server`, `agent`, `dev`) embed all subsystems in a single process. In production, the NixOS module deploys a **process-isolated topology** where security-sensitive components run as separate daemons.

## Runtime Topology

### Production (NixOS Module)

```text
SERVER NODE:
  ekafleet-ca-signer.service     <- PrivateNetwork, no caps, owns CA key
       | Unix socket (/run/ekafleet/ca.sock)
  ekafleet-server.service        <- Control plane (state machine, scheduler, API)

AGENT NODE:
  ekafleet-agent.service         <- Root, manages systemd/WG/nft/secrets
       | writes SVID files to disk
  ekafleet-workload-api.service  <- Unprivileged, serves SVIDs via Unix socket
  ekafleet-proxy.service         <- CAP_NET_BIND_SERVICE only, mesh traffic
```

### Development / Quick Bootstrap

```text
  ekafleet server                <- All server components in one process
  ekafleet agent                 <- All agent components in one process
  ekafleet dev                   <- Server + agent, no TLS, no WireGuard
```

## Process Isolation Rationale

Three subsystems are split into separate processes for security:

| Component | Why Isolated | Hardening |
|-----------|-------------|-----------|
| **CA Signer** | CA private key must not share address space with HTTP parsers, webhook handlers, cloud API clients | `PrivateNetwork`, no capabilities, `MemoryDenyWriteExecute` |
| **Workload API** | Workload private keys must not share address space with the remote exec handler or container supervisor | `PrivateNetwork`, `DynamicUser`, no capabilities |
| **Proxy** | Untrusted network traffic parsing must not have root access or fleet key access | `DynamicUser`, only `CAP_NET_BIND_SERVICE` |

Everything else stays in-process: the state machine, scheduler, and reconciler need tight coupling for consistency, the REST/gRPC APIs share state, and the heartbeat/health/renewal tasks are lightweight with no secrets.

## Subsystems

### Server-Side (Control Plane)

| Subsystem | Purpose |
|-----------|---------|
| **scheduler** | Priority-based placement with constraints, affinities, taints, spread, preemption |
| **nix_eval** | Evaluates fleet.nix via `nix eval` |
| **raft** | Persistent state machine with encrypted log and snapshots; restore-on-boot |
| **ca_root** | Root Certificate Authority, signs CSRs, issues SPIFFE SVIDs (isolated via `ca-signer` process) |
| **attestation** | Node attestation (join token, future: TPM, Nix store path) |
| **dns_authority** | Authoritative DNS for the fleet domain |
| **deployer** | Rolling/canary/blue-green deployment orchestration |
| **secrets_store** | Encrypted secret storage (Raft-backed) |
| **scaling** | Autoscaling engine based on metrics |
| **api** | gRPC + HTTP REST API + SSE event stream |
| **rbac** | Role-based access control (admin/operator/viewer) with per-handler permission enforcement |
| **audit** | Structured audit trail of control-plane actions |
| **events** | Fleet event timeline and deployment history |
| **policy** | Organizational policy engine for admission control |
| **federation** | Multi-region cluster federation and cross-cluster discovery |
| **webhooks** | Outbound webhook notifications on fleet events |
| **alerting** | Threshold-based metric alerting with webhook delivery |
| **rebalancer** | Descheduler for workload rebalancing after drift |
| **quotas** | Per-pool/namespace resource quota enforcement |

### Agent-Side (Data Plane)

| Subsystem | Purpose |
|-----------|---------|
| **supervisor** | Manages local services via systemd units (native processes and OCI containers via systemd-nspawn) |
| **health** | HTTP/TCP/exec health check probes |
| **dns_resolver** | Local caching DNS resolver for fleet queries |
| **wireguard** | Kernel WireGuard mesh interface management |
| **nftables** | Network policy enforcement |
| **secrets_inj** | Local secret file injection |
| **metrics** | Scrapes local service metrics, collects node metrics |
| **template** | Config file template rendering with fleet context |
| **storage** | Persistent volume provisioning, snapshots, migration |
| **gossip** | SWIM-based membership and service catalog propagation |
| **certs** | CSR generation, certificate request/renewal from built-in CA |
| **oci_images** | OCI registry client, content-addressable image store, layer unpacking, garbage collection |
| **workload_api** | SPIFFE Workload API over Unix domain socket (isolated via `workload-api` process) |
| **proxy_l7/l4** | HTTP reverse proxy with circuit breaking, retries, rate limiting + L4 TCP proxy (isolated via `proxy` process) |

## Reconciliation Model

ekafleet follows a Terraform-inspired reconciliation loop:

```text
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Evaluate   │────>│  Refresh │────>│   Plan   │────>│  Apply   │
│  (nix eval) │     │  (query) │     │  (diff)  │     │(converge)│
└─────────────┘     └──────────┘     └──────────┘     └──────────┘
```

1. **Evaluate** — `nix eval --json .#fleet` produces the desired state as JSON
2. **Refresh** — Query agents for current running services and health
3. **Plan** — Diff desired vs actual, compute placement and operations
4. **Apply** — Execute operations with health gates and rollback on failure

In continuous mode (`ekafleet apply --watch`), this loop runs every 30 seconds.
