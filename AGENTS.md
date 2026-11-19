# AGENTS.md

## Project

ekafleet is a single Rust binary (edition 2024, MPL-2.0) replacing the HashiCorp stack
(Nomad + Consul + Vault) for managing ekaOS fleets. Two modes: `ekafleet server` (control
plane, embeds agent) and `ekafleet agent` (data plane).

## Build — Nix Required

All tooling is provided by the Nix dev shell. Do **not** use system Rust/cargo directly.

```sh
nix develop                                          # enter dev shell
nix develop --command cargo build                    # build
nix develop --command cargo test                     # test
nix develop --command cargo clippy -- -D warnings    # lint — ALL warnings are errors
nix fmt .                                            # format (rustfmt + nixfmt) — run after every edit
```

CI (`.github/workflows/rust.yml`) enforces build, test, format, clippy, and `cargo audit` on
every push/PR to `master`. Your changes must pass all four.

## Code Conventions

- **Errors**: `anyhow::Result` at top-level boundaries. Per-subsystem `thiserror` enum named
  `<Subsystem>Error` (e.g. `CaError`, `WgError`, `SecretStoreError`).
- **Shared state**: `Arc<RwLock<T>>` wrapping a private inner struct. See `FleetState`,
  `SecretStore`, `RootCa` for the pattern.
- **Async**: tokio throughout. `tokio::spawn` for background tasks.
- **Logging**: `tracing` macros only (`info!`, `warn!`, `error!`) with structured fields.
  Never `println!` — stdout is reserved for user-facing output (e.g. token generation).
- **CLI**: `clap` derive with `#[arg(long, env = "...")]` for env var support.
- **Crypto**: `ring` for cryptographic operations. Wrap key material in `zeroize::Zeroizing<T>`.
- **Edition 2024**: Let-chains and other recently stabilized features are valid and in use.
  Do not "fix" syntax like `if cond && let Some(x) = expr { ... }`.

## Security-Sensitive Areas

These subsystems handle cryptographic material and authentication. Changes require extra care —
never weaken cryptographic guarantees, always zeroize key material, and preserve existing
validation checks.

| Area | Path | What to protect |
|------|------|-----------------|
| Certificate Authority | `src/ca/` | Root + intermediate CA keys, leaf issuance, SPIFFE SVIDs |
| Secret Storage | `src/secrets/`, `src/server/dynamic.rs` | AES-256-GCM encryption, per-agent HKDF key derivation, AAD binding, dynamic DB admin URLs (never logged) |
| Auth & RBAC | `src/server/api.rs`, `src/server/rbac.rs` | mTLS SPIFFE ID extraction, bearer tokens, namespace-scoped RBAC |
| Transit Encryption | `src/secrets/transit.rs`, `src/server/transit.rs` | Keys sealed under the fleet key, name+version AAD, workload access limited to declared `transitKeys` |
| Seal Module | `src/server/seal.rs` | PBKDF2+AES-256-GCM envelope encryption for key material at rest |
| Workload Attestation | `src/spiffe/workload_attestor.rs` | Cgroup-only attestation (no env var fallback), PID→service mapping |
| Raft Storage | `src/raft/storage.rs` | AES-256-GCM encrypted log + snapshots, restore-on-boot |
| WireGuard Keys | `src/mesh/wireguard.rs` | Private key handling (stdin, never argv), `Zeroizing<String>` |
| OCI Signatures | `src/agent/oci/signature.rs` | Cosign/sigstore image signature verification |
| Token Generation | `src/commands.rs` | 256-bit random via `ring::rand::SystemRandom` |

## Architecture

```
src/
├── main.rs              # CLI entry, subcommand dispatch, tracing init
├── commands.rs          # CLI command implementations (plan, apply, status, drain, acl, etc.)
├── client_config.rs     # Client-side connection config
├── lib.rs               # Re-exports all modules for integration tests
├── types.rs             # Shared type definitions
├── config/
│   ├── mod.rs           # FleetConfig, ServiceConfig, MachineConfig (serde, from nix eval JSON)
│   └── scheduling.rs    # Scheduling, update strategy, disruption budget types
├── server/
│   ├── mod.rs           # Server startup, CA init, fleet key, restore-on-boot
│   ├── api.rs           # gRPC service (tonic), TLS, SPIFFE ID extraction, RBAC interceptor
│   ├── api_system.rs    # System-level RPC handlers (gc, reboot, rebuild, inspect, generations)
│   ├── rest.rs          # HTTP/REST API (axum) + embedded dashboard
│   ├── rbac.rs          # Roles, permissions, namespace-scoped tokens, require_permission()
│   ├── seal.rs          # PBKDF2+AES-256-GCM envelope encryption for key material at rest
│   ├── state.rs         # FleetState: in-memory agent registry, heartbeats, mesh IPs, command relay
│   ├── reconciler.rs    # Desired-vs-actual reconciliation, ServiceConfig→ServiceSpec, namespace topology
│   ├── deployer.rs      # Rolling / canary / blue-green deployment orchestration
│   ├── scheduler/       # Filter + score placement (constraints, affinity, spread, preemption)
│   ├── scaling.rs       # Service + pool autoscaling logic
│   ├── nix.rs           # nix eval/build/copy subprocess wrapper (configurable timeouts)
│   ├── namespace.rs     # Namespace registry with resource quotas
│   ├── quota.rs         # Per-pool/namespace resource quota enforcement
│   ├── audit.rs         # Structured audit trail with actor attribution
│   ├── events.rs        # Fleet event timeline and deployment history
│   ├── policy.rs        # Organizational policy engine for admission control
│   ├── webhook.rs       # Outbound webhook notifications
│   ├── federation.rs    # Peer clusters: mTLS document exchange, federated bundles, exported services
│   ├── identity.rs      # Server SVID, renewed at 2/3 lifetime, resolved per TLS handshake
│   ├── dns.rs           # Builds per-node DNS records (services, nodes, external, federation)
│   ├── external.rs      # Health checks for `externalServices`
│   ├── ingress.rs       # Per-node ingress routes + serving backends → IngressUpdate
│   ├── dynamic.rs       # Lease manager: issue/renew/drop dynamic DB users; lease RPCs
│   ├── rebalance.rs     # Stateful drift: `ekafleet rebalance` move plan/apply + settle
│   ├── secrets.rs       # Secret RPCs, delivery to agents, fleet key rotation + reseal
│   ├── transit.rs       # Transit key RPCs; workload SVIDs limited to declared `transitKeys`
│   ├── agent_msg.rs     # Inbound agent message dispatch
│   └── cloud/
│       ├── mod.rs       # Cloud provider registry
│       ├── actuator.rs  # Scaling actuator (provision/destroy VMs)
│       ├── aws.rs       # AWS EC2 provider
│       ├── azure.rs     # Azure VM provider
│       ├── gcp.rs       # GCP Compute Engine provider
│       ├── bootstrap.rs # Cloud VM agent bootstrap (join token, user-data)
│       ├── image.rs     # NixOS cloud image building + registration
│       ├── image_tracker.rs # Image version tracking in Raft state
│       └── instance_tracker.rs # Cloud VM ↔ fleet node correlation
├── agent/
│   ├── mod.rs           # Agent main loop, gRPC client, bidirectional stream
│   ├── handlers.rs      # Server message dispatch (DesiredState, Deploy, Secret, etc.)
│   ├── supervisor.rs    # systemd unit management, cgroup enforcement, GC roots
│   ├── health.rs        # Liveness/readiness/startup probes (HTTP, TCP, exec)
│   ├── activation.rs    # NixOS system closure activation, generation pruning
│   ├── types.rs         # Agent-side state types (LocalState, NodeIdentity)
│   ├── helpers.rs       # SVID installation helpers
│   ├── netns.rs         # Per-namespace network isolation (netns, bridge, veth, VXLAN overlay)
│   ├── template.rs      # Config file template rendering
│   ├── exec.rs          # Remote command execution in service cgroups
│   ├── logs.rs          # Journal log streaming
│   ├── storage.rs       # Persistent volume provisioning
│   ├── migrate.rs       # Volume data migration (rsync)
│   ├── snapshot.rs      # Volume snapshots
│   └── oci/
│       ├── mod.rs       # OCI container lifecycle (pull, unpack, run via nspawn)
│       ├── registry.rs  # OCI registry client with TLS + custom CA bundle
│       ├── auth.rs      # Registry authentication (token, basic)
│       ├── manifest.rs  # OCI manifest parsing (v2, list)
│       ├── pull.rs      # Layer pulling with content verification
│       ├── unpack.rs    # Layer unpacking (tar+gzip)
│       ├── store.rs     # Content-addressable image store
│       ├── reference.rs # Image reference parsing
│       ├── digest.rs    # SHA-256 digest types
│       ├── bundle.rs    # OCI bundle assembly for nspawn
│       ├── signature.rs # Cosign/sigstore image signature verification
│       └── gc.rs        # Image garbage collection
├── attestation/
│   ├── mod.rs           # Attestation framework
│   └── join_token.rs    # One-time join token store (persisted)
├── ca/
│   ├── mod.rs           # CA trait definitions (CaSigner)
│   ├── root.rs          # Root CA with short-lived intermediate (90-day rotation)
│   ├── issuer.rs        # Certificate issuance (SPIFFE SVIDs)
│   ├── csr.rs           # CSR generation (ECDSA P-256)
│   ├── signer.rs        # Direct + remote (Unix socket) CA signer implementations
│   ├── client.rs        # CA client for remote signer
│   └── pki.rs           # PKI utilities
├── secrets/
│   ├── mod.rs           # Secrets module
│   ├── store.rs         # AES-256-GCM encrypted secret store with AAD binding
│   ├── key_derivation.rs# Per-agent HKDF-SHA256 key derivation + re-encryption
│   ├── injector.rs      # Agent-side secret file injection (mode 0400)
│   ├── dynamic.rs       # Dynamic DB credentials: generation, roles, backend trait
│   ├── db_driver.rs     # PostgreSQL/MySQL user create/drop (sqlx)
│   └── transit.rs       # Transit ciphertext format (versioned AES-256-GCM, AAD-bound)
├── dns/
│   ├── mod.rs           # DNS module
│   ├── authority.rs     # Authoritative DNS server for fleet domain (namespace-scoped zones)
│   ├── resolver.rs      # Caching resolver (agent-side, namespace-scoped lookups)
│   └── listener.rs      # UDP DNS listener
├── mesh/
│   ├── mod.rs           # Mesh module
│   ├── wireguard.rs     # Kernel WireGuard interface management (Zeroizing keys)
│   ├── peers.rs         # Peer list management
│   └── advert.rs        # Peer key advertisement with SPIFFE ID verification
├── proxy/
│   ├── mod.rs           # Proxy module
│   ├── router.rs        # L7 HTTP reverse proxy
│   ├── routes.rs        # Ingress routes file (agent writes, proxy polls)
│   ├── l4.rs            # L4 TCP proxy
│   ├── circuit.rs       # Circuit breaker
│   ├── ratelimit.rs     # Rate limiting
│   ├── affinity.rs      # Session affinity
│   ├── splitting.rs     # Traffic splitting
│   ├── upstream.rs      # Upstream health tracking
│   ├── mtls.rs          # mTLS + SPIFFE ID extraction from peer certs
│   ├── listener.rs      # Proxy listener management
│   ├── standalone.rs    # Standalone proxy process mode
│   └── tracing_ctx.rs   # Distributed tracing context propagation
├── policy/
│   ├── mod.rs           # Policy module
│   └── nftables.rs      # nftables rule generation, namespace NAT, VXLAN input rules
├── metrics/
│   ├── mod.rs           # Metrics module
│   ├── aggregator.rs    # Fleet-wide metrics aggregation
│   ├── alerting.rs      # Threshold-based alerting with webhook delivery
│   ├── collector.rs     # Prometheus endpoint scraping
│   └── node.rs          # Node-level resource metrics (/proc)
├── raft/
│   ├── mod.rs           # Raft module
│   ├── state.rs         # FleetStateMachine (deployments, secrets, DNS, KV, cloud instances, namespace IPs)
│   └── storage.rs       # Encrypted log + snapshot persistence (AES-256-GCM)
└── spiffe/
    ├── mod.rs           # SPIFFE module
    ├── workload_api.rs  # Workload API manager (SVID store, trust bundles)
    ├── workload_server.rs # gRPC Workload API v2 server
    ├── workload_attestor.rs # Cgroup-based PID→service attestation (no env var fallback)
    └── socket.rs        # Unix domain socket management

nix/
├── module.nix           # NixOS module (server + agent + ca-signer + workload-api + proxy services)
├── package.nix          # Package derivation
├── overlay.nix          # Nixpkgs overlay
├── dev-shell.nix        # Development shell
├── lib/
│   ├── fleet-module.nix # Typed fleet config schema (NixOS-style options)
│   ├── eval-fleet.nix   # Fleet config evaluation helper
│   └── catalog.nix      # Service catalog helpers (mkWebService, mkStaticSite, mkResources, mkHealthCheck)
└── tests/               # NixOS VM integration tests

examples/
├── self-hosted/         # Bare-metal fleet (3 nodes, no cloud)
├── single-cloud/        # AWS with autoscaled worker pool
├── multi-cloud/         # Multi-region across AWS + GCP
├── standalone-nonnixos/ # Agent on non-NixOS host with Nix
└── custodial-hosting/   # Multi-tenant hosting platform using service catalog

tests/
├── cli.rs               # CLI integration tests (assert_cmd)
└── server_agent.rs      # gRPC workflow integration tests (TLS, auth, RBAC, streaming)
```

## gRPC / Proto

- Single proto: `proto/fleet.proto` (package `fleet`)
- Generated by `tonic-build` via `build.rs` — **never edit generated code**
- Access types via `crate::proto::*`
- Main RPC: `StreamControl` — bidirectional agent↔server channel
- Auth: `Bearer <token>` in `authorization` header, or mTLS with SPIFFE SVID (SPIFFE ID extracted from peer cert SAN, mapped to role: `/server/*`→Admin, `/agent/*`→Agent, `/service/*`→Workload (transit only))
- RBAC: every handler calls `require_permission()` — see `Permission` enum in `rbac.rs`
- Proto module carries `#![allow(clippy::result_large_err)]` in `lib.rs`
- `ServerMessage` has 25 variants: 13 fire-and-forget + 12 correlated commands
- `AgentMessage` has 10 variants: 9 reports/requests + `AgentCommandResponse` (with nested result oneof)
- Request-response pattern: server sends command with `correlation_id`, agent returns
  `AgentCommandResponse` with the same ID. Correlation managed by `FleetState::send_command()`

## Testing

- Unit tests: inline `#[cfg(test)]` modules (448+ tests across state, reconciler, scheduler,
  policy, config, rbac, secrets, CA, seal, supervisor, attestor, OCI, etc.)
- Integration tests: `tests/cli.rs` (assert_cmd, 37 tests) and `tests/server_agent.rs`
  (gRPC workflows with TLS + RBAC, 23 tests)
- NixOS VM tests: `nix/tests/` (module-basic, rest-api, cli-operations, server-agent,
  lifecycle, fleet-module, oci-container)
- Helpers: `free_port()` (bind port 0), `start_server()` (spawn with tempdir + Role::Admin
  in interceptor for RBAC)
- Always use `tempfile::tempdir()` for isolation — never write to fixed paths
- `doCheck = false` in `nix/package.nix` — tests run via `cargo test`, not nix build
- Run NixOS VM tests: `nix flake check` (requires KVM)

## Adding a New Module

1. Create `src/<module>/mod.rs`
2. Add `#[allow(dead_code)] pub mod <module>;` to `src/lib.rs`
3. Define a `<Module>Error` enum with `thiserror` if the module can fail
4. Run `nix fmt .` then `cargo clippy -- -D warnings`

## Pre-Commit Checklist

After every edit, before committing:

1. `nix develop --command cargo build` — fix all warnings
2. `nix develop --command cargo clippy -- -D warnings` — fix all clippy lints
3. `nix fmt .` — format Rust and Nix files

Do not commit with attribution lines (no `Co-Authored-By`).

## Key Details

- **Branch**: `master` (not main)
- **Binary name**: `ekafleet` — **Nix attr**: `ekaos-fleet`
- **Deps**: Semver ranges in `Cargo.toml` (`"1"`, `"0.13"`) with committed `Cargo.lock`.
  Don't change dependency versions without reason.
- **`#[allow(dead_code)]`** on modules in `lib.rs` is intentional during buildout.
  Do not remove these unless you've verified all items in the module are used.
- **CLI commands**: `server`, `agent`, `dev`, `plan`, `apply`, `status`, `drift`,
  `rollback`, `capacity`, `services`, `drain`, `scale`, `rebalance`, `logs`, `ssh`, `snapshot`,
  `restore`, `upgrade`, `dispatch`, `exec`, `inspect`, `events`, `top`, `node`,
  `acl token create/list/revoke`, `secret set/list/delete/versions/rollback/leases/revoke`,
  `transit key create/rotate/list/delete`, `transit encrypt/decrypt`, `generation list/switch/diff`,
  `system gc/reboot/rebuild`, `token create`, `completions` — all functional.
