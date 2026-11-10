# ekafleet Roadmap

> Prioritized gap analysis for reaching Kubernetes/HashiCorp-grade orchestration
> that is deeply Nix-native and SPIFFE-native, with optional OCI support.
>
> Every item below was re-verified against source. Pointers use `file:line` or
> `file` + symbol name. Line numbers drift, so the symbol is authoritative. Items
> are ranked by severity. Earlier editions of this file are in git history.

Severity legend: **P0** = blocks production / security hole · **P1** = ship-blocker
for the stated goal · **P2** = correctness/UX gap · **P3** = polish.

Status legend: **Done** = implemented, wired into the runtime, and tested ·
**Partial** = real code exists, but part of the item is missing or not wired end to end ·
**Open** = not implemented.

## Status at a glance

| Item | Status | One-line summary |
|------|--------|------------------|
| P0.1 gRPC auth bypass | Done | Peer-cert SPIFFE ID, header stripping, RBAC on every handler |
| P0.2 Plaintext CA / fleet keys | Done | `seal.rs` envelope + `Zeroizing` |
| P0.3 GC roots for closures | Done | Supervisor adds and removes indirect roots |
| P0.4 Multi-node Raft | **Open** | Single-node durable state only; `--peers` is logged and nothing else |
| P1.1 Event-driven reconcile | **Partial** | Trigger exists, but the loop only runs during `apply --follow` |
| P1.2 Workload attestation env var | Done | Cgroup-only attestation |
| P1.3 Node attestation is TOFU | **Partial** | Join-token flow wired end to end (create → Attest → node SVID → mTLS); no node SVID renewal; no TPM or instance binding |
| P1.4 WireGuard keys / gossip | **Partial** | SVID-signed WireGuard adverts are verified and relayed by the server and re-verified by agents; gossip runs with a shared HMAC key; mesh addresses are assigned by hand |
| P1.5 Non-NixOS support | **Partial** | Example + `nix profile` fallback; no VM/container test |
| P1.6 Generation retention | Done | `GenerationRetention` + module options (one bug: combining both bounds fails) |
| P2.1 Promote/fail RPCs | Done | Pending-canary registry, real promote/fail |
| P2.2 Blue-green | **Partial** | All-or-nothing in-place cutover; no parallel blue/green or traffic switch |
| P2.3 Migration failure handling | **Partial** | Partial-failure semantics done; no destination health gate |
| P2.4 cgroup enforcement | Done | `to_cgroup_controls` → systemd directives |
| P2.5 Agent re-adopts units | Done | `adopt_existing_units` at agent startup |
| P2.6 Nix invocation flexibility | Done | `NixOptions` timeouts + `--option` passthrough + module options |
| P2.7 fleet.nix module system | **Partial** | Typed module exists and is CI-checked; the CLI still evaluates raw `#fleet` |
| P2.8 CLI context file | **Partial** | Contexts + `--namespace` done; no `context use/set`; nix stderr still untrimmed |
| P2.9 REST TLS + pagination | **Partial** | Opt-in TLS + offset/limit; TLS not enforced or exposed in the module; no filtering |
| P2.10 Intermediate CA | Done | 90-day intermediate signs all leaves |
| P3 polish | Done | See list |

---

## P0 — Security & correctness show-stoppers

### ~~P0.1 gRPC auth is bypassable via client-set metadata~~ (Done)

The gRPC interceptor (`src/server/api.rs`, around line 1957):
- Strips client-supplied `x-ekafleet-mtls` / `x-ekafleet-attest` headers at entry.
- Derives mTLS identity from the rustls-verified peer certificate chain via
  `req.peer_certs()` and extracts the SPIFFE ID from the leaf cert URI SAN.
- Maps SPIFFE ID paths to roles (`src/server/rbac.rs`): `/server/*` → Admin,
  `/agent/*` → Operator, others → Viewer.
- Every gRPC handler calls `require_permission()` before doing any work.
- Audit logs record the full SPIFFE URI for mTLS peers.

Tests: `tests/server_agent.rs` (`grpc_rejects_unauthenticated_client`,
`grpc_rejects_wrong_token`), unit tests in `src/server/rbac.rs`.

### ~~P0.2 CA private key and fleet master key stored in plaintext~~ (Done)

At-rest sealing in `src/server/seal.rs` (PBKDF2-HMAC-SHA256 + AES-256-GCM
envelope) encrypts the root and intermediate CA keys and the fleet master key
when `EKAFLEET_SEAL_PASSPHRASE` is set. In-memory key material is wrapped in
`zeroize::Zeroizing<T>`.

### ~~P0.3 Deployed service closures are not GC-rooted~~ (Done)

`src/agent/supervisor.rs`: `add_gc_root` (line 414) creates indirect roots at
`{data_dir}/gcroots/{service}` via `nix-store --add-root ... --realise`, and
`remove_gc_root` (line 447) removes them on teardown. `adopt_existing_units`
recovers state from those roots after an agent restart (see P2.5).

### P0.4 No multi-node Raft consensus — **Open**

**Where**: `src/raft/` (`state.rs`, `storage.rs`; `mod.rs` only declares the two
modules). `--peers` is parsed in `src/main.rs` and stored in `ServerConfig.peers`,
but its only use is a log field (`src/server/mod.rs:53`).

There is no leader election, log replication, or membership change, and the
crate has no consensus dependency. The system is honestly scoped to single-node
with durable state: `FleetStateMachine` is persisted as AES-256-GCM encrypted
snapshots plus a log (`src/raft/storage.rs`), and `restore_raft_state`
(`src/server/mod.rs:332`) replays the latest snapshot and trailing log entries at
boot. Two servers today would be two independent brains.

**Exists**: restore-on-boot; periodic snapshot + log compaction in the
housekeeping task (`src/server/mod.rs`, around line 440); `ekafleet snapshot` /
`restore`. The VM test `nix/tests/lifecycle.nix` only checks that the CA, the
fleet key, and the API survive a server restart. It does not cover Raft state
contents.

**Remaining**: multi-node consensus (leader election, log replication across
`--peers`, membership changes, follower read/forward semantics), plus a 3-node VM
test (this is also the `todo.md` "3 node ekaos HA" example). One candidate
approach is to integrate `openraft`, wrap `FleetStateMachine` as the state
machine, and use the existing encrypted storage as the log and snapshot store.

---

## P1 — Foundational gaps for the stated goal

### P1.1 Reconciliation is timer/`apply`-driven, not event-driven — **Partial**

**Exists** (commit 13a8aba): `ReconcileTrigger` (`src/server/state.rs:18`, a
coalescing `tokio::sync::Notify`) fires on:
- agent disconnect (`deregister_agent`),
- heartbeat-timeout eviction (`evict_dead_nodes`),
- a service newly reporting `ServiceFailed` (`update_status`).

The reconcile loop in `src/server/api.rs` (around line 594) `select!`s on the 30s
tick or the trigger. Unit tests in `src/server/state.rs`:
`eviction_fires_reconcile_trigger`, `newly_failed_service_fires_trigger`.

**Remaining**:
- The loop is only spawned inside the `Apply` handler when `req.watch` is set
  (`src/server/api.rs:479`). With no open `apply --follow` stream, no
  reconciliation happens at all, event-driven or periodic. Move it to a
  server-owned background task started in `src/server/mod.rs`.
  `reconciler::reconcile_loop` (`src/server/reconciler.rs:170`) exists for this
  but has no callers, and it ignores the trigger.
- Dead-node eviction is still hardcoded to 300s in the 60s housekeeping loop
  (`src/server/mod.rs:409`). Make it configurable.
- There is no trigger on config change (no watch on `fleet.nix` or the flake).
- There is no integration or VM test that kills an agent and asserts a reschedule.

### ~~P1.2 Workload attestation trusts a spoofable env var~~ (Done)

`src/spiffe/workload_attestor.rs` is cgroup-only. The service name comes from
`/proc/<pid>/cgroup` (`attest_from_cgroup_content`). `EKAFLEET_SERVICE` is still
set in units for the service's own use but is never trusted. There are unit tests
in the same file.

### P1.3 Node attestation is pure TOFU — **Partial**

**Exists** (commit 14b8bf7), in `src/attestation/join_token.rs`:
- Persistence: `JoinTokenStore::with_persistence` + `load()`, wired at
  `src/server/mod.rs:217`. Both live tokens and a consumed-token audit trail are
  persisted, so a replay after restart is rejected.
- Rate limiting: 20 failures per 60s window (`RATE_LIMIT_MAX_FAILURES`, checked in
  `consume`).
- Optional node binding: `register_bound`.
- Richer selectors: `attestation_type`, `join_token:bound`, `node_id`.
- Unit tests in the same file: replay, rate limit, binding mismatch, expiry, and
  persistence round-trip.

**Wired end to end** (branch `jonringer/fix-join-tokens`):
- `ekafleet token create [--node-id ID]` calls the new `CreateJoinToken` RPC
  (needs `ManageTokens`), which generates the token server-side and registers it
  (optionally bound to a node ID). Non-`agent` types are refused.
- `Attest` is the one RPC the gRPC interceptor admits without a bearer token or
  client cert (tagged by path in a tower layer); the join token in the body is the
  credential. The server's TLS config makes client certs optional so credential-less
  clients can complete the handshake.
- The agent proposes its node ID (`--node-id`, or a UUID persisted in
  `<data-dir>/node-id` on first start). `attest` validates it, enforces token
  binding, and refuses an unbound token for a node ID that has already attested
  (no identity takeover). The server generates the node key pair and SVID for
  `spiffe://<domain>/agent/<node_id>`; the identity never comes from a CSR.
- The agent (`src/agent/join.rs`) persists the SVID (key mode 0600) and uses it for
  mTLS. `StreamControl` refuses heartbeats whose `node_id` differs from the SVID's.
- Tests: `tests/join_token.rs` (real `serve_grpc`: flow, replay, binding, takeover,
  wrong node, RBAC), unit tests in `join_token.rs`, `agent/helpers.rs`,
  `agent/types.rs`, and the `server-agent` VM test (real join across two VMs,
  restart keeps the node ID and SVID, replay refused).

**Remaining**:
- Node SVIDs are not renewed. They use the CA default TTL (1h); after expiry the
  agent can only reconnect with a new bound token (`token create --node-id <id>`).
  The `NODE_CERT` certificate request type is still unhandled.
- `--type server` join tokens do not exist (server SVIDs come from the CA directly).
- There is no hardware or instance binding: no TPM, cloud instance-identity
  document, or host-key attestor.

### P1.4 WireGuard peer keys are identity-bound; gossip uses a shared key — **Partial**

**Done**:
- Agents run with `--wireguard-endpoint ip:port --mesh-index N` (module:
  `services.ekafleet.agent.wireguard`). The agent brings up `wg-fleet`, then
  signs an advert `(node_id, public_key, endpoint, allowed_ip, issued_at)` with
  its node SVID key (ECDSA P-256, domain-separated by
  `ekafleet-wireguard-advert-v1`), attaches its SVID chain and sends it as
  `AgentMessage::PeerAdvert` (`src/agent/mod.rs`, `src/mesh/advert.rs`).
- The server (`src/server/peers.rs`) accepts an advert only from an mTLS stream
  whose SVID names the advertised node (bearer-token streams are refused). It
  checks that the SVID chains to the fleet CA, the SPIFFE ID matches, the
  signature is valid, `issued_at` is fresh and newer than the node's last
  advert, the address is a single `/32`, and the key and address are not
  another node's. It then relays the full set as `PeerUpdate`, and withdraws
  a node's advert when its stream ends.
- Agents re-verify every relayed advert against their pinned `--ca-cert` and
  the trust domain from their own SVID (no longer hardcoded), skip their own,
  refuse older adverts per node and duplicate keys or addresses, and then
  configure WireGuard (`src/mesh/peers.rs`).
- Gossip runs: the server starts SWIM on UDP `--gossip-listen` (default
  `0.0.0.0:7401`) with an HMAC key derived from the fleet key and sends it to
  agents over the control stream (`ServerMessage::GossipConfig`).
- Tests: unit tests for verification (unsigned, tampered fields, self-signed
  and foreign-CA certs, another node's SVID, server SVIDs, expiry, malformed
  fields), the server registry and the agent's selection; `tests/peers.rs`
  against the real server; `server-agent.nix` brings up a two-node mesh and
  pings across it.

**Remaining**:
- Mesh addresses come from a hand-assigned `--mesh-index`; the server does
  not allocate them (it does refuse duplicates).
- Adverts are re-signed only when the agent connects. Node SVIDs last 1h and
  are not renewed (P1.3), so a long-lived advert stops verifying when its SVID
  expires.
- Gossip is authenticated only by a shared key: any agent can claim any node
  ID in gossip. It is advisory and is not used for peer keys. It is not
  encrypted. `ServiceCatalog` is not wired in.

### P1.5 Non-NixOS-with-Nix support is claimed but does not exist — **Partial**

**Exists** (commit db7eaa4):
- `examples/standalone-nonnixos/` (README + `fleet.nix`) documents per-service
  systemd supervision on a foreign distro with no NixOS module.
- `set_system_profile` (`src/agent/activation.rs:364`) falls back to
  `nix profile install --profile` when `nix-env` is absent.
- Unit tests `run_profile_set_reports_missing_binary_as_notfound` and
  `run_profile_set_reports_nonzero_exit_as_profile_failed`.
- The example `fleet.nix` is schema-checked by `nix/tests/fleet-module.nix`, which
  evaluates every `examples/*`.

**Remaining**: there is no VM or container test that runs the agent on a non-NixOS
userland (Nix + systemd, no NixOS module), as originally asked. The `todo.md` item
is marked done on the strength of the example alone.

### P1.6 Old system generations accumulate unbounded — **Done** (one bug)

**Exists** (commit e16375d), in `src/agent/activation.rs`:
- `GenerationRetention` (line 71) defaults to keeping the last 10 generations.
- `GenerationRetention::from_env` reads `EKAFLEET_KEEP_GENERATIONS` /
  `EKAFLEET_KEEP_GENERATIONS_DAYS`.
- `activate_system` calls `prune_generations` (line 240) after a successful
  activation. A pruning failure is non-fatal.
- `nix profile wipe-history --older-than` is the fallback when `nix-env` is absent.

Wiring: `src/agent/handlers.rs:60`. NixOS module options
`services.ekafleet.agent.keepGenerations` / `keepGenerationsDays`
(`nix/module.nix:156,166`). Unit tests are in `activation.rs`.

**Remaining**:
- When both bounds are set, `prune_generations` passes two selectors
  (`--delete-generations 10d +10`). `nix-env` only accepts `Nd` or `+N` as a
  *single* argument and fails with `invalid generation number '10d'` (reproduced
  locally). Pruning then silently does nothing beyond a warning. Either apply the
  bounds in two invocations or document that they are mutually exclusive.
- On flakes-only hosts, count-based pruning is skipped. Only the age bound is
  expressible there.
- There is no VM test of pruning.

---

## P2 — Correctness & UX gaps

### ~~P2.1 `promote_deployment` / `fail_deployment` RPCs are stubs~~ (Done)

Implemented in commit 06ec91a:
- When a canary is healthy and `autoPromote = false`, `execute_canary` records a
  `PendingCanary` in `PendingCanaryStore` (`src/server/deployer.rs:44`), held on
  `FleetState`.
- `promote_deployment` (`src/server/api.rs:1557`) calls `deployer::promote_canary`
  (`deployer.rs:472`). If promotion fails, the entry is re-registered so the
  operator can retry or fail it.
- `fail_deployment` (`api.rs:1612`) calls `deployer::fail_canary` (`deployer.rs:540`)
  to roll the canary back.
- CLI: `ekafleet deployment promote|fail <service>` (`src/main.rs`).
- Unit tests in `deployer.rs`: `pending_store_insert_take_is_one_shot`, the
  `promote_*` tests, and `fail_canary_does_not_panic_without_previous_path`.

Follow-ups:
- Pending canaries are in memory only and are lost on server restart.
- `fail` only acts on a canary awaiting promotion, although the CLI help says
  "Fail a stuck deployment".
- There is no RPC-level or VM test.

### P2.2 Blue-green deployment incomplete — **Partial**

**Exists** (commit b6547d7): `execute_blue_green` (`src/server/deployer.rs:588`)
sends the new version to every target node, gates on all instances becoming
healthy (`wait_healthy`), and on an unreachable node or health timeout calls
`abort_blue_green` (`deployer.rs:661`) to roll every node that received green back
to the previous store path. Unit tests: `blue_green_empty_plan_is_noop`,
`blue_green_unreachable_green_aborts_cutover`,
`blue_green_unhealthy_green_aborts_cutover`.

**Remaining**: this is an all-or-nothing *in-place* update, not true blue-green.
- The agent does nothing strategy-specific with `DeployStrategy::BlueGreen`.
  Green replaces blue on each node, so blue is not kept running alongside green.
- There is no proxy or DNS traffic switch.
- There is no post-cutover window to switch back while blue is still warm.

Docs (`configuration.md`, `comparison.md`) describe "deploy all, then switch
traffic".

### P2.3 Reschedule volume-migration failure handling is thin — **Partial**

Migrations are computed and executed for reschedules (`src/server/reconciler.rs`).
Commit ef22738 added per-instance `MigrationResult` collection and
`summarize_migration_failure` (`reconciler.rs:86`). A reschedule is all-or-nothing:
if any instance fails, the service stays on its untouched source nodes, and
destinations holding partial copies are logged. There are unit tests in
`reconciler.rs`, e.g. `all_migrations_succeed_allows_reschedule`.

**Remaining**:
- There is no health gate on the destination before cutover.
- Orphaned partial copies are logged but not cleaned up.
- There is no integration or VM test of a real rsync migration.

### ~~P2.4 No cgroup resource enforcement~~ (Done)

`ResourceConfig::to_cgroup_controls` (`src/config/mod.rs:539`) is called while
building `ServiceSpec` (`src/server/reconciler.rs:528`). Full `DesiredState` is sent
before `DeployCommand`. The supervisor renders `CPUQuota`, `MemoryMax`, `CPUWeight`,
`MemoryHigh`, `IOWeight`, `TasksMax`, and `OOMPolicy` directives
(`src/agent/supervisor.rs`, around line 599).

### ~~P2.5 Agent does not re-adopt services on restart~~ (Done)

`Supervisor::adopt_existing_units` (`src/agent/supervisor.rs:67`) is called at agent
startup (`src/agent/mod.rs:140`). It scans the unit dir for `ekafleet-*.service`,
recovers the version key from the GC root (falling back to `ExecStart`), and queries
the live unit state. The next `DesiredState` can then tear down true orphans. Unit
tests: `adopt_existing_units_recovers_state_from_gc_root`,
`adopt_existing_units_falls_back_to_exec_start`,
`adopt_existing_units_ignores_foreign_and_missing_dir`. There is no VM test that
restarts the agent.

### ~~P2.6 Nix invocation is inflexible~~ (Done)

`NixOptions` (`src/server/nix.rs`) adds:
- configurable eval/build/copy timeouts (`EKAFLEET_NIX_{EVAL,BUILD,COPY}_TIMEOUT`),
- `--option name value` passthrough (`EKAFLEET_NIX_OPTIONS`), installed at server
  start (`src/server/mod.rs:65`).

The NixOS module exposes `services.ekafleet.server.nixEvalTimeout` /
`nixBuildTimeout` / `nixCopyTimeout` / `nixOptions` (`nix/module.nix:63-90,256`).
There are unit tests in `nix.rs`.

### P2.7 No fleet.nix module system — **Partial**

**Exists** (commit 05acfdd):
- `nix/lib/fleet-module.nix` is a NixOS-style typed options module mirroring
  `FleetConfig`, with `nix/lib/eval-fleet.nix` (`lib.evalModules`) as the eval
  helper.
- The flake exports `lib.fleetModule` / `lib.evalFleet` (`flake.nix:57`).
- `nix/tests/fleet-module.nix` evaluates every example and asserts that unknown
  fields and type mismatches are rejected.
- Rust test `module_shaped_json_deserializes` (`src/config/mod.rs:1020`) keeps the
  serde and Nix schemas in lockstep.

**Remaining**:
- The module is opt-in. `eval_fleet` (`src/server/nix.rs:137`) still runs
  `nix eval --json <flake>#fleet` on the raw attrset, and no example routes its
  config through `evalFleet`. A typo outside CI still surfaces as a serde error at
  `plan`/`apply` time.
- The book (`docs-src/reference/fleet-config.md`) does not document `evalFleet`.
- There is no generated options reference.

### P2.8 No CLI context/config file — **Partial**

**Exists** (commit 8dbafa0):
- `src/client_config.rs` adds a kubeconfig-style JSON file of named contexts
  (`server`, `token`, `caCert`, `namespace`) with `currentContext`.
- The file is found via `EKAFLEET_CONFIG`, `$XDG_CONFIG_HOME/ekafleet/config.json`,
  or `~/.config/ekafleet/config.json`.
- Precedence, lowest to highest: built-in defaults, then the file, then
  `EKAFLEET_*` env vars, then the global flags `--context` / `--server` / `--token`
  / `--namespace` / `--ca-cert` (`src/main.rs`).
- `connect_server` (`src/commands.rs:51`) builds TLS from the context and injects
  the bearer token and `x-ekafleet-namespace` metadata.
- `ekafleet context show|list`. There are unit tests in `client_config.rs`.

**Remaining**:
- There is no `context use` / `set` / `delete`. The file must be hand-edited.
- Raw `nix eval` / `build` / `copy` stderr is still returned untrimmed in
  `NixError` (`src/server/nix.rs`, `EvalFailed(stderr.to_string())`).
- Per-subcommand `--server` defaults still shadow the context unless left at the
  default value. This is a workaround in `connect_server`.

### P2.9 REST/HTTP TLS and pagination — **Partial**

**Exists** (commit f4f7e97):
- Opt-in HTTPS reusing the server SVID when `EKAFLEET_HTTP_TLS` is set
  (`src/server/mod.rs:157`).
- Shared `PageQuery` offset/limit pagination, capped at 1000
  (`src/server/rest.rs:454`), on the services, capacity, cloud-instance, and
  silence lists, plus `offset` on events and deployment history.

**Remaining**:
- TLS is off by default and not enforced.
- `EKAFLEET_HTTP_TLS` is not exposed as a NixOS module option or documented in the
  book.
- There is no field filtering on list endpoints.
- There are no REST pagination tests.

### ~~P2.10 No intermediate CA~~ (Done)

`RootCa::initialize_with_intermediate` (`src/ca/root.rs:80`) mints or loads a 90-day,
path-length-0 intermediate that signs all leaves. It is re-minted at boot when it
has fewer than 7 days of validity left. Its key is sealed at rest
(`src/server/mod.rs:77-133`). Tests are in `src/ca/root_tests.rs`.

Follow-ups:
- `rotate_intermediate` (`root.rs:184`) is only called from tests, so a
  long-running server does not rotate without a restart.
- There is no revocation (CRL/OCSP).

---

## P3 — Polish (Done)

- [x] OCI: keyless (Fulcio/Rekor) signature verification; custom registry CA
  bundle; fleet-wide (not per-service) image signature policy; per-layer pull
  timeouts. Per-layer timeouts come from the per-request deadline that
  `RegistryClient::with_timeout` (`src/agent/oci/registry.rs`) applies to every
  manifest, blob, and token fetch.
- [x] CLI: flag-name consistency (`--follow` vs `--watch`); add `ekafleet
  version`. `apply` now uses `--follow`, with `--watch` as a visible alias, matching
  `logs`/`events`.
- [x] Audit log records *which* token performed each action, via the non-secret
  `TokenIdentity` (`src/server/rbac.rs`) derived server-side from the verified
  bearer token.
- [x] `top` RPC populates service cpu/mem request fields from the
  `service_requests` map (`src/server/state.rs`).
- [x] Constant-time comparison for bearer tokens: the ACL token store is keyed
  by SHA-256 digest, so lookups compare fixed-length digest bytes, and the
  persisted `tokens.json` no longer stores raw secrets.

---

## Corrections to prior/agent-reported findings (do not re-file)

- **OCI parse panics** (`src/agent/oci/manifest.rs`) are inside `#[cfg(test)]`
  (from line 208), so they are not a runtime crash. Ignore.
- **"Volume migrations never execute"** is false; see P2.3. They run for reschedules.
- **`Completions` / shell completion** is already implemented (`Command::Completions`
  in `src/main.rs`, `cmd_completions` in `src/commands.rs`). Not a gap.
- **"P1.3/P1.5/P1.6/P2.1/P2.2/P2.5/P2.7/P2.8 are open"** (previous edition of this
  file) was stale. See the per-item status above. Several are only Partial.

---

## Suggested sequencing

1. ~~**P0.1**, **P0.2**, **P0.3**~~: done.
2. **P0.4** (multi-node consensus): restore-on-boot is done; Raft replication and a
   3-node test remain.
3. **P1.1**: run reconciliation as a server-owned task, not only under
   `apply --follow`.
4. **P1.3 / P1.4**: SVID renewal and server-allocated mesh addresses, then
   hardware/instance attestation and identity-bound or encrypted gossip.
5. Remaining Partial P1/P2 items (P1.6 dual-bound bug, P2.2 true blue-green, P2.7
   default to `evalFleet`, P2.8/P2.9 UX), then tests for each.
