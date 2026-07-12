# ekafleet

ekafleet is a single Rust binary that replaces the entire HashiCorp stack (Nomad + Consul + Vault) and supporting infrastructure tools with one purpose-built application for managing [ekaos](https://github.com/ekala-project/ekapkgs-roadmap) fleets.

## One Binary, Two Modes

- **`ekafleet server`** — Control plane: scheduling, RBAC, CA, secrets, DNS authority, deployment orchestration with disruption budgets, event tracking, REST API, Raft consensus, node attestation
- **`ekafleet agent`** — Data plane: system activation, service supervision with lifecycle hooks, liveness/readiness/startup probes, config templating, DNS resolver, secret injection, mesh networking, SPIFFE Workload API, L7/L4 proxy with circuit breaking, persistent volumes

Server mode embeds all agent capabilities, meaning a server node can also run workloads. This follows the same pattern as k3s and Nomad.

## Why ekafleet?

Running a production fleet typically requires deploying and maintaining a dozen separate tools. ekafleet consolidates these into a single, statically-linked binary with no runtime dependencies:

- **Small footprint** — single ~5MB musl-static binary
- **No runtime dependencies** — no JVM, no interpreters, no external daemons
- **Predictable latency** — Rust's zero-cost abstractions and no GC
- **Nix-native** — fleet configuration is pure Nix, consumed via `nix eval`
- **OS deployment** — activates full EkaOS/NixOS system closures, not just services
- **OCI container support** — run container images via systemd-nspawn alongside native services, with a built-in registry client and content-verified image store
- **Secure by default** — mTLS everywhere, SPIFFE workload identity with standard Workload API, node attestation, encrypted secrets at rest, proper CSR flow (private keys never leave the workload)

## Design Principles

1. **Convention over configuration** — sensible defaults for everything, override when needed
2. **Reconciliation model** — desired state is declared in Nix, ekafleet continuously converges actual state to match
3. **Graceful degradation** — agents continue operating when the server is unreachable
4. **Defense in depth** — mTLS (SPIFFE SVIDs) for identity, nftables for network policy, WireGuard for transport encryption, AES-256-GCM for secrets at rest
5. **OS-level deployments** — manages full system closures and OCI containers, both as systemd units

## Key Features

| Category | Capabilities |
|----------|-------------|
| Scheduling | Priority-based placement with preemption, constraints, affinities, spread, taints/tolerations, node pools, disruption budgets, resource quotas |
| Deployment | Rolling, canary, blue-green; health-gated; auto-revert; auto-promote; deployment history; policy engine; OS activation; OCI containers via systemd-nspawn |
| Health | Separate liveness, readiness, and startup probes; configurable thresholds |
| Security | RBAC (admin/operator/viewer), SPIFFE X.509-SVIDs with trust domain federation, Workload API, node attestation, mTLS, audit logging, namespaces |
| Secrets | Static (encrypted), dynamic (PostgreSQL/MySQL credential rotation), transit encryption, versioned rollback, rotation notification |
| Networking | WireGuard mesh, DNS authority + resolver + external service registration, nftables ingress + egress policy |
| Proxy | L7 HTTP + L4 TCP proxy; circuit breaking; retries; rate limiting; session affinity; traffic splitting; distributed tracing |
| Config | Config file templating with service discovery, secrets, and fleet metadata interpolation |
| Lifecycle | Pre-stop/post-start hooks, configurable stop signal, termination grace period |
| Storage | Persistent volumes with provisioning, snapshots, data migration, reclaim policies |
| Observability | Prometheus scraping, node metrics, fleet-wide aggregation, event timeline, SSE streaming, alerting rules, webhook notifications, REST API, audit trail |
| Scaling | Metric-based autoscaling, manual scaling, pool-level scaling, node maintenance windows, descheduler/rebalancer |
| Operations | Structured CLI output (`-o json`), shell completions, disaster recovery (snapshot/restore), local dev mode |
| Federation | Multi-region cluster federation, cross-cluster service discovery, SPIFFE trust domain federation |
| HA | Raft consensus for server state, gossip for failure detection |
