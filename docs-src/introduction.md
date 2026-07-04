# ekafleet

ekafleet is a single Rust binary that replaces the entire HashiCorp stack (Nomad + Consul + Vault) and supporting infrastructure tools with one purpose-built application for managing [ekaos](https://github.com/ekala-project/ekapkgs-roadmap) fleets.

## One Binary, Two Modes

- **`ekafleet server`** — Control plane: scheduling, CA, secrets, DNS authority, deployment orchestration, Raft consensus
- **`ekafleet agent`** — Data plane: service supervision, health checks, DNS resolver, secret injection, mesh networking, L7 proxy

Server mode embeds all agent capabilities, meaning a server node can also run workloads. This follows the same pattern as k3s and Nomad.

## Why ekafleet?

Running a production fleet typically requires deploying and maintaining a dozen separate tools. ekafleet consolidates these into a single, statically-linked binary with no runtime dependencies:

- **Small footprint** — single ~5MB musl-static binary
- **No runtime dependencies** — no JVM, no interpreters, no container runtimes
- **Predictable latency** — Rust's zero-cost abstractions and no GC
- **Nix-native** — fleet configuration is pure Nix, consumed via `nix eval`
- **Secure by default** — mTLS, encrypted secrets, workload attestation via Nix store paths

## Design Principles

1. **Convention over configuration** — sensible defaults for everything, override when needed
2. **Reconciliation model** — desired state is declared in Nix, ekafleet continuously converges actual state to match
3. **Graceful degradation** — agents continue operating when the server is unreachable
4. **Defense in depth** — mTLS for identity, nftables for network policy, encrypted secrets at rest
