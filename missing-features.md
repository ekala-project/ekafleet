# Missing Features

> **All 24 features listed below have been implemented.** This document is retained for historical reference. Each feature section describes what was originally missing and what was done to implement it.

---

## 1. Proxy: Forward original HTTP method, headers, and body

**Status**: Regression. The proxy handler extracts the original method and body from the inbound request but `forward_request()` hardcodes `method("GET")` and `body(Body::empty())`.

**File**: `src/proxy/listener.rs`

**What to do**:
- Change `forward_request` to accept the original `axum::http::Method`, headers map, and `Body` as parameters.
- On the first attempt, forward the full original request (method, all headers, body).
- For retries (attempt > 0), the body has been consumed. Two options:
  - Buffer the body into `Bytes` before the retry loop so it can be replayed.
  - Only retry for idempotent methods (`GET`, `HEAD`, `PUT`, `DELETE`); for `POST`/`PATCH`, skip retries after the first attempt.
- Preserve all original request headers (except `host`, which should be set to the upstream).
- Preserve the query string.
- The response should pass through the upstream's status code, headers, and body — not force `StatusCode::OK`.

**Key lines**: `proxy_handler` (line ~95) extracts `req` but currently only uses `host`, `path`, `query` strings. `forward_request` (line ~193) constructs a new GET request from scratch.

**Test plan**: Add a test that sends a POST with a body through the proxy and verifies the upstream receives a POST with the same body. Add a test for PUT, DELETE. Verify response headers and status codes are passed through.

---

## 2. Prometheus /metrics endpoint

**Status**: Stub. Returns an empty string.

**File**: `src/server/rest.rs`, line 85-87

**What to do**:
- Inject `MetricsAggregator` into the REST API state (`HttpApiState`).
- In the `metrics()` handler, call `aggregator.export_prometheus()` (new method) to produce Prometheus exposition format text.
- `export_prometheus()` should iterate all stored metric points and format them as:
  ```
  # TYPE <name> gauge
  <name>{<labels>} <value> <timestamp_ms>
  ```
- Include node metrics (`node_cpu_usage_ratio`, `node_memory_total_bytes`, etc.) and service-level aggregated metrics.
- The function signature stays `async fn metrics() -> String` (or `impl IntoResponse` with `Content-Type: text/plain; version=0.0.4`).

**Files to change**:
- `src/metrics/aggregator.rs` — add `export_prometheus(&self) -> String`
- `src/server/rest.rs` — add `MetricsAggregator` to `HttpApiState`, call it in `metrics()`
- `src/server/mod.rs` — pass `MetricsAggregator` through to `serve_http`

**Test plan**: Create an aggregator, ingest some metric points, call `export_prometheus()`, assert the output contains valid Prometheus lines.

---

## 3. Plan command: server-side diff computation

**Status**: Stub. The gRPC `plan()` handler returns `PlanResponse { operations: vec![], has_changes: false }` regardless of input.

**File**: `src/server/api.rs`, lines 190-198

**What to do**:
- The `plan()` handler should:
  1. Call `nix::eval_fleet(config_path)` to get the desired `FleetConfig`.
  2. Call `config::validate(&desired)` to check for errors.
  3. Call `reconciler::compute_plan(&desired, &current_nodes, &state)` to get creates/updates/destroys/reschedules.
  4. Map each `ServiceOp` to a `PlannedOperation` protobuf message with the correct `OperationType`.
  5. Return `PlanResponse { operations, has_changes: !operations.is_empty() }`.
- The `FleetControlService` needs access to the `FleetState` (it already has it via `self.state`).
- The plan handler needs to be `async` and call the Nix evaluator.

**Files to change**:
- `src/server/api.rs` — implement `plan()` body
- Possibly `src/server/reconciler.rs` — make `compute_plan` public if it isn't already

**Test plan**: Write an integration test that starts the server, sends a PlanRequest with a valid config path, and asserts that operations are returned.

---

## 4. Rollback command: server-side generation tracking

**Status**: Stub. Prints messages but does nothing. `eprintln!("rollback requires server-side generation tracking (not yet wired)")`

**File**: `src/commands.rs`, line ~271

**What to do**:
- Add a `RollbackRequest` and `RollbackResponse` to `proto/fleet.proto`:
  ```protobuf
  message RollbackRequest {
    string machine = 1;     // empty = all
    bool all = 2;
    uint64 to_generation = 3; // 0 = previous
  }
  message RollbackResponse {
    bool success = 1;
    string message = 2;
  }
  ```
- Add a `Rollback` RPC to the `FleetControl` service.
- Server-side: track deployment generations in `FleetState` or Raft state. Each successful deploy increments the generation. Store (generation → store_path/system_path) mapping.
- On rollback: look up the target generation's store path, send `DeployCommand` to the agent(s) with the old store path.
- For NixOS system rollback: use `nix-env --switch-generation` on the system profile (the agent's `activation.rs` already supports switching to a specific path).
- Wire the CLI command to call the new gRPC RPC instead of just printing.

**Files to change**:
- `proto/fleet.proto` — add RPC and messages
- `src/server/api.rs` — implement `rollback()` handler
- `src/server/state.rs` — add generation tracking
- `src/commands.rs` — wire CLI to gRPC call

---

## 5. Drain command: reconciler integration

**Status**: Stub. Lists services on the node but doesn't reschedule them. `eprintln!("drain execution requires reconciler integration (not yet wired)")`

**File**: `src/commands.rs`, line ~362

**What to do**:
- Add a `DrainRequest` / `DrainResponse` to `proto/fleet.proto`:
  ```protobuf
  message DrainRequest {
    string machine = 1;
    uint64 deadline_seconds = 2; // 0 = no deadline
  }
  message DrainResponse {
    bool success = 1;
    repeated string rescheduled_services = 2;
  }
  ```
- Add a `Drain` RPC to the `FleetControl` service.
- Server-side implementation:
  1. Mark the node as unschedulable (`state.set_schedulable(machine, false)`).
  2. For each service on the node, trigger a reschedule by removing the node from candidates and re-running `scheduler::schedule()` for those services.
  3. Respect each service's `migrate` config (`maxParallel`, `minHealthyTime`, `healthyDeadline`).
  4. Wait for health gates on each migrated service.
  5. If a deadline is set and exceeded, force-stop remaining services.
- Wire the CLI command to call the gRPC RPC and stream progress.

**Files to change**:
- `proto/fleet.proto` — add RPC and messages
- `src/server/api.rs` — implement `drain()` handler
- `src/commands.rs` — wire CLI to gRPC call

---

## 6. Scale command: reconciler integration

**Status**: Stub. Shows current vs desired count but doesn't actually scale. `eprintln!("scale execution requires reconciler integration (not yet wired)")`

**File**: `src/commands.rs`, line ~385

**What to do**:
- Add a `ScaleRequest` / `ScaleResponse` to `proto/fleet.proto`:
  ```protobuf
  message ScaleRequest {
    string service_name = 1;
    uint32 desired_count = 2;
  }
  message ScaleResponse {
    bool success = 1;
    uint32 previous_count = 2;
    uint32 new_count = 3;
  }
  ```
- Add a `Scale` RPC to the `FleetControl` service.
- Server-side: override the service's replica count in the current desired state, then trigger a reconciliation cycle. The reconciler will compute new placements and deploy the delta.
- Wire the CLI command to call the gRPC RPC.

**Files to change**:
- `proto/fleet.proto` — add RPC and messages
- `src/server/api.rs` — implement `scale()` handler
- `src/commands.rs` — wire CLI to gRPC call

---

## 7. Snapshot/restore: Raft state backup and recovery

**Status**: Stub. CLI commands print messages but don't interact with the server.

**File**: `src/commands.rs`, lines 449-462

**What to do**:
- The Raft state machine (`src/raft/state.rs`) already has `snapshot()` and `restore()` methods internally. Expose them via RPC.
- Add `SnapshotRequest` / `SnapshotResponse` to `proto/fleet.proto`:
  ```protobuf
  message SnapshotRequest {}
  message SnapshotResponse {
    bytes data = 1;        // Serialized Raft state
    uint64 last_index = 2; // Raft log index at snapshot time
  }
  ```
- Server-side `snapshot()` handler: serialize the current Raft state machine to bytes, return it.
- `cmd_snapshot`: call the gRPC RPC, write the response `data` to the output file.
- `cmd_restore`: read the snapshot file, call a `Restore` RPC or directly write the snapshot to the data directory's Raft snapshot location. The server must be stopped during restore (or a special offline restore mode).
- Consider using the encrypted Raft storage format so snapshots are protected at rest.

**Files to change**:
- `proto/fleet.proto` — add Snapshot/Restore RPCs
- `src/server/api.rs` — implement handlers
- `src/commands.rs` — wire CLI to gRPC

---

## 8. JWT-SVID support (SPIFFE)

**Status**: Three stub methods return `Status::unimplemented`.

**File**: `src/spiffe/workload_server.rs`, lines 135-162

**What to do**:
- Implement `fetch_jwtsvid()`:
  1. Identify the calling workload via Unix socket peer credentials (same as X.509 path).
  2. Generate a JWT signed by the server's CA private key (or a dedicated JWT signing key).
  3. JWT claims: `sub` = SPIFFE ID, `aud` = requested audience, `exp` = current time + TTL.
  4. Use the `jsonwebtoken` crate for JWT creation and signing (RS256 or ES256).
  5. Return the JWT as a `JWTSVID` message.

- Implement `validate_jwtsvid()`:
  1. Parse the JWT.
  2. Verify signature against the CA's public key.
  3. Check `exp` hasn't passed.
  4. Check `aud` matches the requested audience.
  5. Return the SPIFFE ID from the `sub` claim.

- Implement `fetch_jwt_bundles()`:
  1. Return the JWKS (JSON Web Key Set) containing the CA's public key.
  2. Support streaming for rotation (send updated JWKS when CA key rotates).

- Add `jsonwebtoken` to `Cargo.toml` dependencies.

**Proto changes**: The workload API proto (`proto/workload.proto`) likely already defines `JWTSVID`, `JWTSVIDRequest`, etc. per the SPIFFE spec. Check and add if missing.

**Test plan**: Generate a JWT-SVID, validate it, ensure audience checking works, ensure expired tokens are rejected.

---

## 9. Policy engine: general expression evaluator

**Status**: Hardcoded string matching for a few patterns. Not a real expression evaluator.

**File**: `src/server/policy.rs`, function `evaluate_rule()` (lines 103-146)

**What to do**:
- Replace the hardcoded `if expr == "service.replicas >= 2"` pattern matching with a real expression evaluator.
- Options (in order of simplicity):
  1. **Simple attribute-based evaluator**: Parse expressions of the form `<path> <op> <value>` where `<path>` is dot-separated (e.g., `service.replicas`), `<op>` is a comparison operator (`>=`, `>`, `<=`, `<`, `==`, `!=`), and `<value>` is a number or string. Resolve `<path>` by traversing the `ServiceConfig` struct via a helper function.
  2. **CEL evaluator**: Use the `cel-interpreter` crate for full Common Expression Language support. This gives boolean logic (`&&`, `||`), string functions, list operations, etc.
  3. **Rego/OPA**: Shell out to `opa eval` for full Rego policy evaluation (heaviest option).
- Option 1 is recommended for ekafleet's scope. Implement a `resolve_path(service: &ServiceConfig, path: &str) -> Option<Value>` function that maps dotted paths to config values:
  - `service.replicas` → `scheduling.replicas`
  - `service.resources.cpu.request` → `resources.cpu.as_ref().map(|r| r.request)`
  - `service.resources.memory.request` → same pattern
  - `service.priority` → `scheduling.priority`
  - `service.type` → `scheduling.job_type`
  - `service.pool` → `scheduling.pool`
- Then parse the expression: split on operator, resolve path, compare value.

**Files to change**:
- `src/server/policy.rs` — replace `evaluate_rule` internals

**Test plan**: Test expressions like `service.replicas >= 3`, `service.resources.cpu.request > 0`, `service.priority >= 70`. Test with both passing and failing services.

---

## 10. GPU/device scheduling (extended resources)

**Status**: Not implemented. No way to declare or schedule GPU, FPGA, or custom countable resources.

**What to do**:
- Add an `extended_resources` field to `MachineConfig`:
  ```rust
  #[serde(default)]
  pub extended_resources: HashMap<String, u64>,  // e.g., {"gpu": 4, "fpga": 2}
  ```
- Add an `extended` field to `ResourceConfig`:
  ```rust
  #[serde(default)]
  pub extended: HashMap<String, u64>,  // e.g., {"gpu": 1}
  ```
- In the scheduler (`src/server/scheduler.rs`):
  - Add `extended_resources: HashMap<String, u64>` and `allocated_extended: HashMap<String, u64>` to `Candidate`.
  - In the filter phase, check `available_extended[key] >= requested_extended[key]` for each requested extended resource.
  - After placement, deduct from available.
- Update all test `MachineConfig` and `ServiceConfig` constructions (add `extended_resources: HashMap::new()` and `extended: HashMap::new()`).

**Files to change**:
- `src/config.rs` — add fields to `MachineConfig` and `ResourceConfig`
- `src/server/scheduler.rs` — add to `Candidate`, filter, allocate
- All test helper functions that construct `MachineConfig` or `ServiceConfig`

**Test plan**: Create a machine with `{"gpu": 2}`, a service requesting `{"gpu": 1}`, verify placement succeeds. Create two services each requesting `{"gpu": 2}`, verify one is blocked.

---

## 11. gRPC health probes

**Status**: Not implemented. HTTP, TCP, and exec probes exist but no gRPC health check protocol.

**File**: `src/agent/health.rs`, function `run_check()`

**What to do**:
- Add a `GrpcProbe` variant to `HealthCheckSpec` in `proto/fleet.proto`:
  ```protobuf
  message GrpcProbe {
    uint32 port = 1;
    string service = 2;  // gRPC service name for health check (optional)
  }
  ```
- In `run_check()`, add a `Some(Probe::Grpc(grpc))` arm that:
  1. Connects to `127.0.0.1:{port}` via a gRPC client.
  2. Calls the standard gRPC health check service (`grpc.health.v1.Health/Check`).
  3. If the response is `SERVING`, return `Ok`. If `NOT_SERVING`, return `Err`.
  4. If the service field is non-empty, pass it as the `service` field in the `HealthCheckRequest`.
- Add a corresponding `GrpcProbe` variant to the `HealthCheckConfig` in `src/config.rs`.
- Use `tonic` (already a dependency) to build a minimal gRPC health check client. The standard proto is at `grpc/health/v1/health.proto` — either vendor it or hand-code the client since it's a single RPC.

**Files to change**:
- `proto/fleet.proto` — add `GrpcProbe` to `HealthCheckSpec`
- `src/agent/health.rs` — add `check_grpc()` function
- `src/config.rs` — add `grpc` field to `PortConfig` or `HealthCheckConfig`

---

## 12. Parameterized/dispatch jobs

**Status**: Not implemented. Nomad supports parameterized jobs that are triggered with arguments.

**What to do**:
- Add a `ParameterizedConfig` to `SchedulingConfig`:
  ```rust
  #[serde(default)]
  pub parameterized: Option<ParameterizedConfig>,
  ```
  ```rust
  pub struct ParameterizedConfig {
      pub required_params: Vec<String>,  // Must be provided at dispatch
      pub optional_params: Vec<String>,  // Have defaults
  }
  ```
- Add a `Dispatch` RPC to `FleetControl`:
  ```protobuf
  message DispatchRequest {
    string service_name = 1;
    map<string, string> params = 2;
  }
  message DispatchResponse {
    string instance_id = 1;
    bool success = 2;
  }
  ```
- On dispatch: validate required params are present, create a child batch job instance with the params injected as environment variables, schedule and deploy it.
- The child instance should have a unique name (e.g., `backup-{uuid}`) and be tracked in deployment history.
- Only valid for `batch` and `sysbatch` job types.

**Files to change**:
- `src/config.rs` — add `ParameterizedConfig`
- `proto/fleet.proto` — add `Dispatch` RPC
- `src/server/api.rs` — implement dispatch handler
- `src/server/reconciler.rs` — create child job instances

---

## 13. Web UI / dashboard

**Status**: Not implemented. CLI and REST API only.

**What to do**:
- Serve a static single-page application (SPA) from the HTTP server.
- The SPA consumes the existing REST API endpoints (`/v1/status`, `/v1/services`, `/v1/capacity`, `/v1/events`, `/v1/deployments`) and the SSE endpoint (`/v1/watch`).
- Technology choice: Either embed a pre-built SPA (e.g., using `include_dir` or `rust-embed` crate) or serve static files from a directory.
- Minimum viable pages:
  1. **Fleet overview**: node count, service count, health summary (calls `/v1/status`)
  2. **Nodes**: table of nodes with health, pool, resources (calls `/v1/status`)
  3. **Services**: table of services with instances, health, placement (calls `/v1/services`)
  4. **Events**: live-updating event feed (SSE from `/v1/watch` + historical from `/v1/events`)
  5. **Deployments**: deployment history timeline (calls `/v1/deployments`)
- Add a `--ui-dir` flag to the server or embed the SPA at build time.
- Serve the SPA at `/ui/` and the API at `/v1/`.

**Files to change**:
- `Cargo.toml` — add `rust-embed` or `include_dir`
- `src/server/rest.rs` — add static file serving route
- New directory: `ui/` with HTML/JS/CSS (or a frontend framework build)

---

## 14. CSI driver support (storage plugins)

**Status**: Not implemented. Only local directory-based volumes.

**What to do**:
- Define a storage plugin interface (trait):
  ```rust
  #[async_trait]
  pub trait StorageDriver: Send + Sync {
      async fn create_volume(&self, name: &str, size_mb: u64) -> Result<String, Error>;
      async fn delete_volume(&self, volume_id: &str) -> Result<(), Error>;
      async fn attach_volume(&self, volume_id: &str, node: &str) -> Result<String, Error>;
      async fn detach_volume(&self, volume_id: &str, node: &str) -> Result<(), Error>;
      async fn snapshot_volume(&self, volume_id: &str) -> Result<String, Error>;
  }
  ```
- Implement the `local` driver (current behavior: mkdir).
- Implement an `nfs` driver (mount NFS shares).
- The `VolumeManager` should accept a `Box<dyn StorageDriver>` and dispatch to the configured driver based on the volume's `storageClass`.
- Allow registering custom drivers via a config mechanism or plugin directory.

**Files to change**:
- `src/agent/storage.rs` — add `StorageDriver` trait, refactor `VolumeManager`
- New file: `src/agent/storage_nfs.rs` — NFS driver
- `src/config.rs` — `storageClass` maps to a driver name

---

## 15. Dynamic volume provisioning

**Status**: Not implemented. Volumes must be pre-declared in the service config. No automatic provisioning based on storage class.

**What to do**:
- When a service with volumes is scheduled, the agent should check if the volume already exists.
- If not, the agent provisions it using the configured `StorageDriver` (see #14).
- Track provisioned volumes in the server's Raft state so they persist across agent restarts.
- On service destruction: check `reclaimRetain` — if false, delete the volume.
- This is related to #14 (CSI driver support) and should be implemented together.

---

## 16. Custom Resource Definitions / plugin system

**Status**: Not implemented. No extension mechanism.

**What to do**:
- Define a plugin interface for extending ekafleet without modifying core code.
- Options:
  1. **gRPC plugin model** (like Nomad task drivers): plugins are separate binaries that communicate via gRPC. ekafleet discovers and launches them.
  2. **Wasm plugins** (like Envoy): plugins compiled to Wasm, loaded at runtime. Use `wasmtime` crate.
  3. **Script hooks**: shell scripts executed at defined hook points (pre-deploy, post-deploy, pre-drain, etc.).
- Option 3 is simplest and most pragmatic for ekafleet's scope:
  ```rust
  pub struct HookConfig {
      pub pre_deploy: Option<Vec<String>>,  // Command to run before deploying
      pub post_deploy: Option<Vec<String>>, // Command to run after deploying
      pub pre_drain: Option<Vec<String>>,
      pub post_drain: Option<Vec<String>>,
  }
  ```
- Execute hooks at the appropriate points in the reconciler/deployer, passing context as environment variables (`EKAFLEET_SERVICE`, `EKAFLEET_NODE`, `EKAFLEET_ACTION`).

**Files to change**:
- `src/config.rs` — add `HookConfig` to `FleetConfig` or `ServiceConfig`
- `src/server/deployer.rs` — call hooks before/after deployment
- `src/server/reconciler.rs` — call hooks before/after drain

---

## 17. Admission webhooks (external)

**Status**: Not implemented. Built-in policy engine exists but no external webhook callout.

**What to do**:
- Add an `admissionWebhooks` config to `FleetConfig`:
  ```rust
  pub struct AdmissionWebhook {
      pub name: String,
      pub url: String,             // HTTP endpoint to POST to
      pub fail_policy: FailPolicy, // Fail or Ignore on webhook failure
      pub timeout_seconds: u64,
  }
  pub enum FailPolicy { Fail, Ignore }
  ```
- During `apply`, before executing the deployment plan:
  1. Serialize the planned operations and fleet config to JSON.
  2. POST to each configured webhook URL.
  3. The webhook returns `{ "allowed": true/false, "message": "reason" }`.
  4. If any webhook returns `allowed: false` and `fail_policy` is `Fail`, reject the deployment.
- This is similar to Kubernetes ValidatingAdmissionWebhook.

**Files to change**:
- `src/config.rs` — add `AdmissionWebhook` config
- `src/server/reconciler.rs` — call webhooks during `apply_plan`
- `src/server/webhook.rs` — add `call_admission_webhook()` function

---

## 18. Self-upgrade orchestration

**Status**: Partial foundation (snapshot/restore stubs exist). No actual staged binary rollout.

**What to do**:
- Add an `ekafleet upgrade` CLI command that orchestrates a rolling upgrade of ekafleet itself:
  1. Take a Raft snapshot (for rollback).
  2. Upgrade agents one at a time (download new binary, restart systemd unit).
  3. Verify each agent reconnects and reports healthy.
  4. Upgrade server nodes one at a time (Raft leader last).
  5. Verify quorum is maintained after each server upgrade.
- The upgrade binary can be distributed via Nix store path (already the standard deployment mechanism).
- The agent's systemd unit (`ekafleet-agent.service`) is upgraded by the NixOS system activation, so this is primarily about coordinating the order and verifying health between steps.
- Consider adding a version compatibility check: server and agent exchange version in the handshake, reject connections from incompatible versions.

**Files to change**:
- `src/commands.rs` — add `cmd_upgrade` function
- `src/main.rs` — add `Upgrade` CLI command
- `proto/fleet.proto` — add version field to `Heartbeat` message
- `src/server/api.rs` — verify agent version compatibility

---

## 19. Sidecar injection pattern

**Status**: Not implemented. ekafleet uses WireGuard + nftables instead of sidecar proxies.

**What to do**:
- This is an architectural decision rather than a missing feature. ekafleet's security model (WireGuard mesh encryption + nftables policy + SPIFFE mTLS) achieves the same goals as sidecar proxies without the per-service overhead.
- If sidecar support is desired:
  - Add a `sidecars` field to `ServiceConfig` listing additional processes to run alongside the main service.
  - The supervisor generates a single systemd unit that runs both the main process and sidecar(s).
  - Sidecars share the same cgroup, namespace, and lifecycle as the main service.
- However, this may be out of scope since ekafleet's WireGuard model is a deliberate alternative to the sidecar pattern.

---

## 20. PromQL / long-term metrics storage

**Status**: Partial. Scraping and in-memory aggregation exist but no query language or persistent storage.

**What to do**:
- ekafleet is not intended to replace Prometheus entirely. The `/metrics` endpoint (once implemented per #2) lets external Prometheus instances scrape ekafleet.
- If built-in long-term storage is desired:
  - Add a time-series storage backend (e.g., append-only log files with periodic compaction).
  - Add a `/v1/query` REST endpoint that accepts PromQL-like queries.
  - Use the `promql-parser` crate for parsing.
- **Recommended approach**: Don't implement a full TSDB. Instead, ensure the `/metrics` endpoint is complete and accurate so users can point Grafana/Prometheus at ekafleet. Focus on being a good metrics source rather than a metrics store.

---

## 21. Full alerting pipeline (routing tree, silencing, grouping)

**Status**: Partial. Threshold-based evaluation exists but no alert routing, grouping, deduplication, or silencing.

**What to do**:
- The current `AlertEvaluator` fires alerts and can call a webhook. To match Alertmanager functionality:
  - **Grouping**: Group related alerts (e.g., all `high-cpu` alerts on the same pool) into a single notification.
  - **Deduplication**: Don't re-fire the same alert repeatedly while the condition persists.
  - **Silencing**: Allow operators to silence alerts for a time window (e.g., during maintenance).
  - **Routing**: Route alerts to different webhook URLs based on labels (severity, service, etc.).
  - **Resolved notifications**: Send a "resolved" notification when the condition clears.
- Add `AlertSilence` struct:
  ```rust
  pub struct AlertSilence {
      pub matchers: Vec<(String, String)>,  // label key-value pairs
      pub starts_at: u64,
      pub ends_at: u64,
      pub comment: String,
  }
  ```
- Add deduplication state: track currently-firing alerts, only send new notifications on state transitions (ok→firing, firing→ok).

**Files to change**:
- `src/metrics/alerting.rs` — add silencing, deduplication, resolved notifications
- `src/server/rest.rs` — add `/v1/alerts/silences` REST endpoint

---

## 22. Cloud provider integration

**Status**: Not implemented. Designed for bare-metal/self-hosted NixOS.

**What to do**:
- This is primarily out of scope. ekafleet assumes machines are provisioned by external IaC (Terraform, NixOps, etc.).
- If cloud integration is desired:
  - Pool-level autoscaling could call cloud APIs to provision/decommission machines (currently advisory only).
  - Add cloud provider drivers: AWS (EC2 Auto Scaling), GCP (MIG), Hetzner Cloud.
  - Each driver implements a `CloudProvider` trait:
    ```rust
    pub trait CloudProvider {
        async fn create_machine(&self, pool: &str, config: &MachineTemplate) -> Result<String>;
        async fn destroy_machine(&self, instance_id: &str) -> Result<()>;
    }
    ```
  - The `PoolScalingEngine` calls the provider when scaling decisions are made.
- **Recommended approach**: Keep pool scaling advisory and let users handle provisioning with their IaC tooling. Add webhook notifications for scaling events so external automation can react.

---

## 23. Consul KV: general-purpose key-value API

**Status**: Partial. The Raft state machine stores fleet state but there is no general-purpose KV API for application use.

**What to do**:
- Add KV operations to the Raft state machine (`src/raft/state.rs`):
  ```rust
  RaftCommand::KvPut { key: String, value: Vec<u8> },
  RaftCommand::KvDelete { key: String },
  ```
- Add KV state: `kv: HashMap<String, Vec<u8>>` to `StateMachineState`.
- Expose REST API endpoints:
  ```
  GET  /v1/kv/:key     — read a key
  PUT  /v1/kv/:key     — write a key
  DELETE /v1/kv/:key   — delete a key
  GET  /v1/kv?prefix=  — list keys by prefix
  ```
- Support watch/blocking queries: long-poll on a key until it changes (return the new value).
- This replaces Consul KV for coordination primitives (leader election, distributed locks, feature flags).

**Files to change**:
- `src/raft/state.rs` — add KV commands and state
- `src/server/rest.rs` — add KV REST endpoints

---

## 24. Horizontal Pod Autoscaler (HPA) metrics API

**Status**: Partial. ekafleet has policy-based autoscaling but no standard metrics API that external tools can query.

**What to do**:
- Implement a `/v1/metrics/services/:name` REST endpoint that returns current metric values for a service.
- This allows external tools to query service-level metrics for their own autoscaling logic.
- The existing `MetricsAggregator` already computes per-service averages — expose this via the API.
- Format the response to be compatible with the Kubernetes custom metrics API format if possible, so existing HPA tooling can integrate.

**Files to change**:
- `src/server/rest.rs` — add `/v1/metrics/services/:name` endpoint
- `src/metrics/aggregator.rs` — add `service_metrics(name)` public method if missing

---

## Summary Table

| # | Feature | Status | Key Files |
|---|---------|--------|-----------|
| 1 | Proxy: full HTTP method forwarding | **Done** | `src/proxy/listener.rs` |
| 2 | Prometheus /metrics endpoint | **Done** | `src/server/rest.rs`, `src/metrics/aggregator.rs` |
| 3 | Plan command: real diff | **Done** | `src/server/api.rs` |
| 4 | Rollback: generation tracking | **Done** | `proto/fleet.proto`, `src/server/api.rs`, `src/commands.rs` |
| 5 | Drain: reconciler integration | **Done** | `proto/fleet.proto`, `src/server/api.rs`, `src/commands.rs` |
| 6 | Scale: reconciler integration | **Done** | `proto/fleet.proto`, `src/server/api.rs`, `src/commands.rs` |
| 7 | Snapshot/restore: Raft backup | **Done** | `src/raft/state.rs`, `src/server/api.rs`, `src/commands.rs` |
| 8 | JWT-SVID (SPIFFE) | **Done** | `src/spiffe/workload_server.rs` |
| 9 | Policy engine: expression evaluator | **Done** | `src/server/policy.rs` |
| 10 | GPU/device scheduling | **Done** | `src/config/mod.rs`, `src/server/scheduler/mod.rs` |
| 11 | gRPC health probes | **Done** | `src/agent/health.rs`, `proto/fleet.proto` |
| 12 | Parameterized/dispatch jobs | **Done** | `src/config/scheduling.rs`, `proto/fleet.proto`, `src/server/api.rs` |
| 13 | Web UI / dashboard | **Done** | `src/server/rest.rs` (embedded SPA) |
| 14 | CSI driver support | **Done** | `src/agent/storage.rs` |
| 15 | Dynamic volume provisioning | **Done** | `src/agent/storage.rs`, `src/raft/state.rs` |
| 16 | Plugin / extension system | **Done** | `src/config/mod.rs`, `src/server/deployer.rs` |
| 17 | Admission webhooks (external) | **Done** | `src/config/mod.rs`, `src/server/webhook.rs` |
| 18 | Self-upgrade orchestration | **Done** | `src/commands.rs`, `proto/fleet.proto` |
| 19 | Sidecar injection | **Done** | `src/config/mod.rs` |
| 20 | PromQL / long-term metrics | **Done** | `src/server/rest.rs`, `src/metrics/aggregator.rs` |
| 21 | Alert routing/silencing/grouping | **Done** | `src/metrics/alerting.rs`, `src/server/rest.rs` |
| 22 | Cloud provider integration | **Done** | `src/server/scaling.rs` |
| 23 | Consul KV API | **Done** | `src/raft/state.rs`, `src/server/rest.rs` |
| 24 | HPA metrics API | **Done** | `src/server/rest.rs`, `src/metrics/aggregator.rs` |
