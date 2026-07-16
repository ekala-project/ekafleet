# ekafleet Roadmap

> Prioritized gap analysis for reaching Kubernetes/HashiCorp-grade orchestration
> that is deeply Nix-native and SPIFFE-native, with optional OCI support.
>
> Every item below was verified against source at the cited `file:line`. Items are
> ranked by severity. The previous edition of this file (24 "all done" features)
> is preserved in git history — most of those landed, but the audit below found
> deeper gaps in the *foundations* (consensus, identity trust, closure GC) that
> the feature checklist did not cover.

Severity legend: **P0** = blocks production / security hole · **P1** = ship-blocker
for the stated goal · **P2** = correctness/UX gap · **P3** = polish.

---

## P0 — Security & correctness show-stoppers

### P0.1 gRPC auth is bypassable via client-set metadata
**Where**: `src/server/api.rs:1757-1774`, agent side `src/agent/mod.rs:118-125`.

The gRPC interceptor authenticates a request if it carries `x-ekafleet-mtls: true`
**or** `x-ekafleet-attest: true`. Both are ordinary gRPC metadata headers that the
*client* sets on itself (`agent/mod.rs:121`). The server never inspects the real
TLS peer certificate — it trusts a self-asserted flag. Any client that can reach
the gRPC port can send `x-ekafleet-mtls: true` and obtain full, unauthenticated
control-plane access (deploy, drain, rotate keys, mint ACL tokens).

**Fix**:
- Derive the mTLS identity from the actual rustls peer certificate chain
  (tonic exposes `Certificates` via connection info / `TlsConnectInfo`), not a header.
- Extract the SPIFFE ID from the verified client cert SAN and map it to a role.
- Gate the unauthenticated `attest` path by **RPC method name**, not a client claim.
- Strip incoming `x-ekafleet-*` auth headers at the server boundary before trusting them.

### P0.2 CA private key and fleet master key stored in plaintext
**Where**: `src/server/mod.rs:69` (`ca-key.pem`), `src/server/mod.rs:220-250` (`fleet-key`).

Both are written to `data_dir` as unencrypted PEM/hex with only `0o600` perms
(`mod.rs:98`, `:247`). Filesystem read (backup leak, stolen disk, path traversal,
misconfigured volume) = total fleet compromise: forge any SVID, decrypt every
secret. SPIRE/Vault seal these behind a KEK or HSM.

**Fix** (in priority order):
- Minimum: seal both with a passphrase-derived KEK (Argon2id) or host-bound key (age/TPM).
- Better: pluggable seal provider (env passphrase → TPM → KMS/HSM).
- Zeroize in-memory copies on drop (WireGuard key already uses `Zeroizing`; CA/fleet keys do not — inconsistent).

### P0.3 Deployed service closures are not GC-rooted
**Where**: no `gcroots` / `nix-store --add-root` / `--indirect` anywhere in `src/`.

`nix-copy-closure` ships store paths to agents, but nothing pins them. A routine
`nix-collect-garbage` on an agent deletes live service closures out from under
running services. Only the *system* profile is rooted (via `nix-env --profile`,
`src/agent/activation.rs`). This directly contradicts the reproducibility promise.

**Fix**:
- Create an indirect GC root per deployed service path:
  `nix-store --add-root /nix/var/nix/gcroots/ekafleet/<service-id> --indirect <path>`.
- Remove the root on service teardown.
- Optional NixOS module timer for `nix-collect-garbage` that is aware of ekafleet roots.

### P0.4 No Raft consensus despite HA claims
**Where**: `src/raft/mod.rs` is two lines (`state`, `storage`). `--peers` is parsed
(`src/main.rs`) but never wired. `FleetStateMachine::new()` is a single in-memory
instance (`src/server/mod.rs:146`).

There is no leader election, no log replication, no membership changes. The README
advertises "Raft consensus" and the module hardens a multi-server story, but two
servers today = two independent brains and silent state divergence on partition.

**Fix** — pick one:
- Integrate `openraft`: wrap `FleetStateMachine` as the state machine, use the
  existing encrypted `raft/storage.rs` as the log/snapshot store, wire `--peers`
  to the transport, restore-on-startup from snapshot + log replay.
- **Or** honestly scope to single-node HA (leader + warm standby via snapshot ship)
  and correct the README until real consensus lands.

Also: on restart the state machine starts empty — snapshots are taken but never
replayed at boot. Fix restore-on-startup regardless of which path is chosen.

---

## P1 — Foundational gaps for the stated goal

### P1.1 Reconciliation is timer/`apply`-driven, not event-driven
**Where**: `src/server/api.rs:556-618` (30s watch loop), dead-node eviction at 300s
(`src/server/state.rs`).

A node death does not trigger a reschedule; orphaned workloads wait up to the next
30s tick (and only if `apply --watch` is running) after a 5-minute eviction delay.
k8s/Nomad reconcile on events. Add a reconcile trigger channel fired on: agent
disconnect, heartbeat timeout, service crash report, and config change.

### P1.2 Workload attestation trusts a spoofable env var
**Where**: `src/spiffe/workload_attestor.rs:52-69`.

Identity falls back to reading `EKAFLEET_SERVICE=<name>` from `/proc/<pid>/environ`.
Any workload can set that variable and be issued another service's SVID. The cgroup
strategy (`:29-48`) is sounder but is only tried first, not enforced.

**Fix**: make cgroup/systemd-unit attestation authoritative; drop the env fallback
or restrict it to a signed selector. Re-verify PID→unit on each SVID fetch to
handle PID reuse.

### P1.3 Node attestation is pure TOFU
**Where**: join token store is in-memory (`src/attestation/join_token.rs`), lost on
restart, no machine binding, no rate limit, single generic selector.

**Fix**: persist consumed-token audit; bind tokens to a cloud instance ID / TPM /
host key; add attempt rate-limiting; include richer selectors in the attestation result.

### P1.4 WireGuard peer keys are not identity-bound; gossip is plaintext
**Where**: `src/mesh/wireguard.rs`, gossip in `src/gossip/`.

Peer public keys are distributed via unencrypted SWIM gossip with no cryptographic
proof of identity. A leaked/observed public key lets an attacker present as a peer,
and discovery/topology is eavesdroppable.

**Fix**: sign peer key advertisements with the node SVID; distribute over the
authenticated control channel or an encrypted gossip transport.

### P1.5 Non-NixOS-with-Nix support is claimed but does not exist
**Where**: `todo.md` ("non nixos + nix example"), README/quickstart imply support.

No test, no example, the NixOS module is NixOS-only, and activation uses `nix-env`
which is unavailable on flakes-only installs. Either build + test the standalone
(Nix + systemd on a foreign distro) path, or remove the claim.

**Fix**: standalone agent example on a non-NixOS host; `nix profile` fallback where
`nix-env` is absent; a VM/container test covering it.

### P1.6 Old system generations accumulate unbounded
**Where**: `src/agent/activation.rs` — each activation bumps the profile generation,
none are trimmed. Long-lived fleets fill disk. Add a retention policy
(`keep last N` / `older than D`) after successful activation, plus a module option.

---

## P2 — Correctness & UX gaps

### P2.1 `promote_deployment` / `fail_deployment` RPCs are stubs
`src/server/api.rs:1459-1489` return success and do nothing. Canary auto-promote
works in the deployer, but the manual promote/fail controls are non-functional.

### P2.2 Blue-green deployment incomplete
Skeleton only in `src/server/deployer.rs`; rolling and canary are real.

### P2.3 Reschedule volume-migration failure handling is thin
**Corrected finding**: migrations *are* computed and executed for reschedules
(`src/server/reconciler.rs:265-309, 382-406`) — the earlier "never runs" claim was
wrong. Remaining gap: partial-failure semantics and health-gating of the destination
before cutover need hardening and a test. (Creates/updates/destroys correctly carry
no migrations.)

### P2.4 No cgroup resource enforcement
`cgroup_controls` is always `None`; declared CPU/memory requests/limits are not
translated to systemd `CPUQuota`/`MemoryMax`. Services can exceed their "limits"
and OOM the host. Wire limits into generated unit properties.

### P2.5 Agent does not re-adopt services on restart
On agent restart, prior systemd units survive but supervisor state is lost; orphans
persist until the next `DesiredState`. Reconcile against actually-running
`ekafleet-*.service` units at startup.

### P2.6 Nix invocation is inflexible
`src/server/nix.rs:10-16` hardcodes eval/build/copy timeouts (120/600/300s) with no
override, and passes no `--option` (can't add substituters, trusted keys, or the IFD
flag). Large or cache-dependent builds fail opaquely. Add configurable timeouts and
an option passthrough (surface via the NixOS module too).

### P2.7 No fleet.nix module system
Config is a raw attrset → JSON → serde (`src/config/`). Type errors surface late as
serde failures, not as typed Nix option errors; there is no Nix-side schema, defaults,
or `nix flake show` docs. A NixOS-style `lib.types` module would catch mistakes at
eval time and self-document.

### P2.8 No CLI context/config file
Every command needs `--server`/`--token`; there is no kubeconfig-equivalent context
store. Namespaces exist in code but no `--namespace` flag is exposed. Raw `nix eval`
stderr is dumped untrimmed to the CLI (`src/server/nix.rs:64`).

### P2.9 REST/HTTP TLS and pagination
Bearer tokens travel in plaintext unless a reverse proxy terminates TLS; list
endpoints are unpaginated. Document/enforce TLS; add pagination + filtering.

### P2.10 No intermediate CA
A 10-year root signs leaves directly (`src/ca/root.rs`). Introduce short-lived
intermediates so root rotation and revocation are practical.

---

## P3 — Polish (complete)

- [x] OCI: keyless (Fulcio/Rekor) signature verification; custom registry CA
  bundle; fleet-wide (not per-service) image signature policy; per-layer pull
  timeouts. (Per-layer timeouts are covered by the per-request deadline applied
  to every manifest/blob/token fetch in `RegistryClient::send_with_timeout`.)
- [x] CLI: flag-name consistency (`--follow` vs `--watch`); add `ekafleet
  version`. (`apply` now uses `--follow` with `--watch` as a visible alias,
  matching `logs`/`events`; `version` command already present.)
- [x] Audit log records *which* token performed each action via the non-secret
  `TokenIdentity` derived server-side from the verified bearer token.
- [x] `top` RPC populates service cpu/mem request fields from the
  `service_request` join (`src/server/state.rs`).
- [x] Constant-time comparison for bearer tokens: the ACL token store is keyed
  by SHA-256 digest, so lookups compare fixed-length digest bytes and the
  persisted `tokens.json` no longer stores raw secrets.

---

## Corrections to prior/agent-reported findings (do not re-file)

- **OCI parse panics** (`src/agent/oci/manifest.rs:233,267`) are inside
  `#[cfg(test)]` — not a runtime crash. Ignore.
- **"Volume migrations never execute"** — false; see P2.3. They run for reschedules.
- **`Completions` / shell completion** — already implemented
  (`src/main.rs:395`, `src/commands.rs:541`). Not a gap.

---

## Suggested sequencing

1. **P0.1** (auth bypass) — highest value, smallest blast radius, fully local fix.
2. **P0.2 / P0.3** (key sealing, GC roots) — protect against catastrophic loss.
3. **P0.4** (consensus *or* honest single-node scoping + restore-on-boot).
4. **P1.1 / P1.2** (event reconcile, real attestation) — core orchestration + identity.
5. Remaining P1, then P2, then P3.
