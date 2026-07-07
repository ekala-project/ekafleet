# ekafleet

ekafleet is a single Rust binary that replaces the entire HashiCorp stack (Nomad + Consul + Vault) and supporting infrastructure tools with one purpose-built application for managing [ekaos](https://github.com/ekala-project/ekapkgs-roadmap) fleets.

## One Binary, Two Modes

- **`ekafleet server`** — Control plane: scheduling, CA, secrets, DNS authority, deployment orchestration, Raft consensus, node attestation
- **`ekafleet agent`** — Data plane: system activation, service supervision, health checks, DNS resolver, secret injection, mesh networking, SPIFFE Workload API, L7 proxy

Server mode embeds all agent capabilities, meaning a server node can also run workloads. This follows the same pattern as k3s and Nomad.

## Why ekafleet?

Running a production fleet typically requires deploying and maintaining a dozen separate tools. ekafleet consolidates these into a single, statically-linked binary with no runtime dependencies:

- **Small footprint** — single ~5MB musl-static binary
- **No runtime dependencies** — no JVM, no interpreters, no container runtimes
- **Predictable latency** — Rust's zero-cost abstractions and no GC
- **Nix-native** — fleet configuration is pure Nix, consumed via `nix eval`
- **OS deployment** — activates full EkaOS/NixOS system closures, not just services
- **Secure by default** — mTLS everywhere, SPIFFE workload identity with standard Workload API, node attestation, encrypted secrets at rest, proper CSR flow (private keys never leave the workload)

## Design Principles

1. **Convention over configuration** — sensible defaults for everything, override when needed
2. **Reconciliation model** — desired state is declared in Nix, ekafleet continuously converges actual state to match
3. **Graceful degradation** — agents continue operating when the server is unreachable
4. **Defense in depth** — mTLS (SPIFFE SVIDs) for identity, nftables for network policy, WireGuard for transport encryption, AES-256-GCM for secrets at rest
5. **OS-level deployments** — manages full system closures, not just application containers

## Key Features

| Category | Capabilities |
|----------|-------------|
| Scheduling | Priority-based placement, constraints, affinities, spread, taints/tolerations, node pools |
| Deployment | Rolling, canary, blue-green; health-gated; auto-revert; auto-promote; OS activation |
| Identity | SPIFFE X.509-SVIDs, Workload API (UDS), node attestation, mTLS bootstrap, automatic renewal |
| Secrets | Static (encrypted), dynamic (PostgreSQL/MySQL credential rotation), transit encryption |
| Networking | WireGuard mesh, DNS authority + resolver, nftables policy |
| Proxy | L7 HTTP routing, traffic splitting, upstream health tracking |
| Observability | Prometheus scraping, node metrics, fleet-wide aggregation |
| Scaling | Metric-based autoscaling, manual scaling, pool-level scaling |
| HA | Raft consensus for server state, gossip for failure detection |
