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
│  │  secrets_inj  metrics    proxy_l7       gossip      certs      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              SERVER MODE ONLY (ekafleet server)                │  │
│  │                                                                │  │
│  │  scheduler    nix_eval    raft      ca_root     dns_authority  │  │
│  │  deployer     secrets_store         scaling     api            │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Subsystems

### Always Active (Agent + Server)

| Subsystem | Purpose |
|-----------|---------|
| **supervisor** | Manages local services via systemd units |
| **health** | HTTP/TCP/exec health check probes |
| **dns_resolver** | Local caching DNS resolver for fleet queries |
| **wireguard** | Kernel WireGuard mesh interface management |
| **nftables** | Network policy enforcement |
| **secrets_inj** | Local secret file injection |
| **metrics** | Scrapes local service metrics, collects node metrics |
| **proxy_l7** | HTTP reverse proxy with routing and TLS termination |
| **gossip** | SWIM-based membership and service catalog propagation |
| **certs** | Certificate request/renewal from built-in CA |

### Server Mode Only

| Subsystem | Purpose |
|-----------|---------|
| **scheduler** | Two-phase (filter + score) workload placement |
| **nix_eval** | Evaluates fleet.nix via `nix eval` |
| **raft** | Consensus for server HA (3-node) |
| **ca_root** | Root Certificate Authority, issues SPIFFE certs |
| **dns_authority** | Authoritative DNS for `fleet.internal` |
| **deployer** | Rolling/canary/blue-green deployment orchestration |
| **secrets_store** | Encrypted secret storage (Raft-backed) |
| **scaling** | Autoscaling engine based on metrics |
| **api** | gRPC + HTTP API endpoints |

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
