# Architecture Overview

ekafleet is a single binary with two operational modes. Server mode includes all agent capabilities, allowing server nodes to also run workloads.

```text
┌─────────────────────────────────────────────────────────────────────┐
│                    ekafleet (single binary)                         │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    ALWAYS ACTIVE                               │  │
│  │                                                                │  │
│  │  supervisor   health     dns_resolver   wireguard   nftables   │  │
│  │  secrets_inj  metrics    proxy_l7/l4    gossip      certs      │  │
│  │  workload_api template   storage        oci_images             │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              SERVER MODE ONLY (ekafleet server)                │  │
│  │                                                                │  │
│  │  scheduler    nix_eval    raft      ca_root     dns_authority  │  │
│  │  deployer     secrets_store         scaling     api            │  │
│  │  attestation  rbac        audit     events      policy         │  │
│  │  federation   webhooks    alerting  rebalancer  quotas         │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Subsystems

### Always Active (Agent + Server)

| Subsystem | Purpose |
|-----------|---------|
| **supervisor** | Manages local services via systemd units (native processes and OCI containers via systemd-nspawn) |
| **health** | HTTP/TCP/exec health check probes |
| **dns_resolver** | Local caching DNS resolver for fleet queries |
| **wireguard** | Kernel WireGuard mesh interface management |
| **nftables** | Network policy enforcement |
| **secrets_inj** | Local secret file injection |
| **metrics** | Scrapes local service metrics, collects node metrics |
| **proxy_l7/l4** | HTTP reverse proxy with circuit breaking, retries, rate limiting, session affinity + L4 TCP proxy |
| **template** | Config file template rendering with fleet context |
| **storage** | Persistent volume provisioning, snapshots, migration |
| **gossip** | SWIM-based membership and service catalog propagation |
| **certs** | CSR generation, certificate request/renewal from built-in CA |
| **workload_api** | SPIFFE Workload API over Unix domain socket |
| **oci_images** | OCI registry client, content-addressable image store, layer unpacking, garbage collection |

### Server Mode Only

| Subsystem | Purpose |
|-----------|---------|
| **scheduler** | Priority-based placement with constraints, affinities, taints, spread, preemption |
| **nix_eval** | Evaluates fleet.nix via `nix eval` |
| **raft** | Consensus for server HA (3-node) |
| **ca_root** | Root Certificate Authority, signs CSRs, issues SPIFFE SVIDs |
| **attestation** | Node attestation (join token, future: TPM, Nix store path) |
| **dns_authority** | Authoritative DNS for the fleet domain |
| **deployer** | Rolling/canary/blue-green deployment orchestration |
| **secrets_store** | Encrypted secret storage (Raft-backed) |
| **scaling** | Autoscaling engine based on metrics |
| **api** | gRPC + HTTP REST API + SSE event stream |
| **rbac** | Role-based access control (admin/operator/viewer) |
| **audit** | Structured audit trail of control-plane actions |
| **events** | Fleet event timeline and deployment history |
| **policy** | Organizational policy engine for admission control |
| **federation** | Multi-region cluster federation and cross-cluster discovery |
| **webhooks** | Outbound webhook notifications on fleet events |
| **alerting** | Threshold-based metric alerting with webhook delivery |
| **rebalancer** | Descheduler for workload rebalancing after drift |
| **quotas** | Per-pool/namespace resource quota enforcement |

## Reconciliation Model

ekafleet follows a Terraform-inspired reconciliation loop:

```text
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Evaluate   │────▶│  Refresh │────▶│   Plan   │────▶│  Apply   │
│  (nix eval) │     │  (query) │     │  (diff)  │     │(converge)│
└─────────────┘     └──────────┘     └──────────┘     └──────────┘
```

1. **Evaluate** — `nix eval --json .#fleet` produces the desired state as JSON
2. **Refresh** — Query agents for current running services and health
3. **Plan** — Diff desired vs actual, compute placement and operations
4. **Apply** — Execute operations with health gates and rollback on failure

In continuous mode (`ekafleet apply --watch`), this loop runs every 30 seconds.
