# CLI Reference

## Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output` / `-o` | `text` | Output format: `text` or `json` for machine-readable output |

Use `--output json` with any command for structured JSON output suitable for scripting and CI/CD pipelines.

## Daemon Modes

ekafleet is a single binary with multiple subcommands. In production, the NixOS module deploys the process-isolated topology (separate `ca-signer`, `server`, `agent`, `workload-api`, and `proxy` processes). For development and quick bootstrapping, convenience modes (`dev`, `server`, `agent`) embed everything in a single process.

### `ekafleet dev`

Start in single-process development mode. Runs server + agent without TLS, WireGuard, or multi-machine setup. Ideal for testing fleet configurations locally.

```
ekafleet dev [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--data-dir` | `/tmp/ekafleet-dev` | Data directory |
| `--http-listen` | `127.0.0.1:7402` | HTTP API listen address |
| `--listen` | `127.0.0.1:7400` | gRPC listen address |

A dev token (`dev-token`) is automatically generated and printed at startup.

### `ekafleet server`

Start in server mode (control plane). By default embeds the CA in-process; use `--ca-socket` to connect to an external `ca-signer` daemon for process isolation.

```
ekafleet server [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--data-dir` | `/var/lib/ekafleet` | Data directory for persistent state |
| `--peers` | | Comma-separated peer server addresses for HA |
| `--listen` | `0.0.0.0:7400` | gRPC listen address |
| `--http-listen` | `0.0.0.0:7402` | HTTP API listen address |
| `--token` | *(required)* | Bearer token for agent authentication (also reads `EKAFLEET_TOKEN` env) |
| `--domain` | `fleet.internal` | SPIFFE trust domain for fleet identities |
| `--ca-socket` | | Path to CA signer Unix socket (uses external ca-signer daemon) |

### `ekafleet agent`

Start in agent mode (data plane). Embeds the Workload API and proxy in-process by default.

```
ekafleet agent [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--join` | *(required)* | Server address to join (host:port) |
| `--token` | | Legacy bearer token for authentication |
| `--join-token` | | One-time join token for SPIFFE node attestation (preferred) |
| `--data-dir` | `/var/lib/ekafleet` | Data directory for local state |
| `--ca-cert` | | Path to CA certificate PEM for TLS verification |

### `ekafleet ca-signer`

Standalone CA signing daemon. Holds the CA private key in an isolated process with no network access, communicating only via a Unix socket. Used by the NixOS module for production deployments.

```
ekafleet ca-signer [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--data-dir` | `/var/lib/ekafleet` | Data directory for CA key and certificate |
| `--domain` | `fleet.internal` | SPIFFE trust domain |
| `--socket` | `/run/ekafleet/ca.sock` | Unix socket path for signing requests |

### `ekafleet workload-api`

Standalone SPIFFE Workload API daemon. Reads SVIDs from disk (written by the agent) and serves them to workloads over a Unix socket. Runs unprivileged with no network access.

```
ekafleet workload-api [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--data-dir` | `/var/lib/ekafleet` | Data directory containing `spiffe/` subdirectory |
| `--trust-domain` | `fleet.internal` | SPIFFE trust domain |
| `--socket` | `/run/ekafleet/workload-api.sock` | Unix socket path for the Workload API |

### `ekafleet proxy`

Standalone service mesh proxy daemon. Runs the L7 reverse proxy with routing, circuit breaking, mTLS authorization, and upstream management. Runs unprivileged with only `CAP_NET_BIND_SERVICE`.

```
ekafleet proxy [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--listen` | `0.0.0.0:8080` | HTTP listen address for proxied traffic |
| `--trust-domain` | `fleet.internal` | SPIFFE trust domain for mTLS authorization |
| `--data-dir` | `/var/lib/ekafleet` | Data directory (for SVID material) |

## Deployment

### `ekafleet plan`

Show desired-vs-actual diff without making changes. Connects to the server and displays planned operations.

```
ekafleet plan [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `fleet.nix` | Path to fleet configuration |
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet apply`

Execute a deployment plan. Streams operation progress in real-time. In watch mode, runs continuous reconciliation and starts the cloud scaling actuator for pools with cloud provider configuration.

```
ekafleet apply [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `fleet.nix` | Path to fleet configuration |
| `--auto-approve` | `false` | Skip confirmation prompt |
| `--watch` | `false` | Continuous reconciliation + cloud autoscaling |
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet rollback`

Revert to a previous generation.

```
ekafleet rollback [MACHINE] [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--all` | `false` | Rollback all machines |
| `--to` | | Target generation number |
| `--server` | `127.0.0.1:7400` | Server address |

## Operations

### `ekafleet status`

Fleet health overview. Displays all nodes with health status, pool membership, resources, node pool summaries, and all services with instance details.

```
ekafleet status [--server 127.0.0.1:7400]
```

### `ekafleet drift`

Detect state divergence. Reports unhealthy nodes and services with unhealthy instances.

```
ekafleet drift [--server 127.0.0.1:7400]
```

### `ekafleet capacity`

Resource utilization report. Shows aggregate available CPU, memory, and disk across all nodes, with per-pool breakdown when node pools are configured.

```
ekafleet capacity [--server 127.0.0.1:7400]
```

### `ekafleet services`

Service placement listing. Shows every service instance with its state and health per node.

```
ekafleet services [--server 127.0.0.1:7400]
```

### `ekafleet drain <machine>`

Drain a node — marks it unschedulable and reschedules services to other nodes.

```
ekafleet drain <MACHINE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--deadline` | `0` | Deadline in seconds for drain to complete (0 = no deadline) |
| `--server` | `127.0.0.1:7400` | Server address |

Output lists the services drained from the node.

### `ekafleet scale <service> <count>`

Scale a service to a desired replica count. Displays previous and new instance counts.

```
ekafleet scale <SERVICE> <COUNT> [--server 127.0.0.1:7400]
```

### `ekafleet logs <service>`

Stream logs from service replicas. Replaces the old hint-only behavior with actual log streaming via gRPC.

```
ekafleet logs <SERVICE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--follow` / `-f` | `false` | Stream logs continuously |
| `--tail` | `100` | Number of lines to show |
| `--node` | | Target a specific node |
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet dispatch`

Dispatch a parameterized batch job with arguments.

```
ekafleet dispatch <SERVICE> [PARAMS...] [OPTIONS]
```

Parameters are passed as `KEY=VALUE` pairs and injected as `DISPATCH_<KEY>` environment variables.

| Option | Default | Description |
|--------|---------|-------------|
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet upgrade`

Orchestrate a rolling upgrade of ekafleet across the fleet. Takes a pre-upgrade snapshot, queries fleet status, and prints step-by-step instructions.

```
ekafleet upgrade <STORE_PATH> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet ssh <machine>`

SSH to a fleet machine. Queries fleet status for the machine's address and opens an SSH session.

```
ekafleet ssh <MACHINE> [--server 127.0.0.1:7400]
```

## Disaster Recovery

### `ekafleet snapshot`

Take a Raft state snapshot for backup and disaster recovery.

```
ekafleet snapshot [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--output` | `ekafleet-snapshot.bin` | Path to save the snapshot |
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet restore`

Restore Raft state from a previously saved snapshot.

```
ekafleet restore <INPUT> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet validate`

Validate fleet configuration offline without connecting to a server. Runs `nix eval` and checks for consistency errors.

```
ekafleet validate [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `fleet.nix` | Path to fleet configuration |

### `ekafleet events`

Query fleet events with filtering.

```
ekafleet events [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--category` | | Filter by category (deployment, scaling, health, drain, etc.) |
| `--service` | | Filter by service name |
| `--node` | | Filter by node ID |
| `--limit` | `50` | Maximum events to show |
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet exec`

Execute a command in a running service's context (systemd-run scope with cgroup inheritance).

```
ekafleet exec <SERVICE> [OPTIONS] -- <COMMAND...>
```

| Option | Default | Description |
|--------|---------|-------------|
| `--node` | | Target a specific node |
| `--timeout` | `30` | Execution timeout in seconds |
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet node`

Node management subcommands.

| Subcommand | Description |
|------------|-------------|
| `node list` | List all nodes with health, pool, scheduling status |
| `node status <NODE>` | Detailed node info (resources, services, heartbeat) |
| `node cordon <NODE>` | Mark node as unschedulable |
| `node uncordon <NODE>` | Mark node as schedulable |

### `ekafleet top`

Real-time resource usage.

| Subcommand | Description |
|------------|-------------|
| `top nodes` | CPU/memory usage per node with utilization percentages |
| `top services` | Resource requests per service with instance counts |

### `ekafleet deployment`

Deployment management subcommands.

| Subcommand | Description |
|------------|-------------|
| `deployment list [--service X]` | List recent deployments |
| `deployment status <SERVICE>` | Deployment history for a service |
| `deployment promote <SERVICE>` | Promote a canary deployment to full rollout |
| `deployment fail <SERVICE>` | Mark deployment as failed (triggers rollback) |

### `ekafleet acl`

ACL token management.

| Subcommand | Description |
|------------|-------------|
| `acl token create --role <ROLE>` | Create a token (admin, operator, viewer) |
| `acl token revoke <TOKEN>` | Revoke a token |
| `acl token list` | List registered tokens |

### `ekafleet service`

Service introspection (systemd-specific).

| Subcommand | Description |
|------------|-------------|
| `service inspect <SERVICE>` | Show systemd unit file, cgroup accounting, resource usage |

### `ekafleet closure`

Nix store closure analysis (runs locally, no server needed).

| Subcommand | Description |
|------------|-------------|
| `closure diff <A> <B>` | Diff two store paths (package changes) |
| `closure deps <PATH>` | Show dependency list (add `--tree` for tree view) |
| `closure size <PATH>` | Calculate total closure size |

### `ekafleet generation`

NixOS generation management.

| Subcommand | Description |
|------------|-------------|
| `generation list <MACHINE>` | List NixOS generations |
| `generation switch <MACHINE> <GEN>` | Activate + set boot default |
| `generation boot <MACHINE> <GEN>` | Set boot default only |
| `generation test <MACHINE> <GEN>` | Activate in current session (reverts on reboot) |
| `generation diff <MACHINE> <A> <B>` | Diff two generations |

### `ekafleet system`

System-wide fleet operations.

| Subcommand | Description |
|------------|-------------|
| `system gc [--dry-run]` | Nix store garbage collection across fleet |
| `system reboot [--pool X] [--max-parallel N]` | Coordinated rolling reboot |
| `system rebuild <MACHINE> [--all]` | Trigger NixOS rebuild |

## Shell Completions

### `ekafleet completions`

Generate shell completions for your shell. Supports `bash`, `zsh`, `fish`, `elvish`, and `powershell`.

```bash
# Bash
ekafleet completions bash > /etc/bash_completion.d/ekafleet

# Zsh
ekafleet completions zsh > ~/.zfunc/_ekafleet

# Fish
ekafleet completions fish > ~/.config/fish/completions/ekafleet.fish
```

## Authentication & RBAC

ekafleet uses role-based access control (RBAC). Each bearer token maps to a role that determines what operations are permitted.

### Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access: deploy, drain, scale, manage tokens, read everything |
| `operator` | Operational access: deploy, drain, scale, agent connections, read everything |
| `viewer` | Read-only: status, services, capacity, logs, drift, events |

The `--token` passed at server startup is registered as an `admin` token. Additional tokens with specific roles can be registered via the token store.

### `ekafleet token create`

Generate a cryptographically random join token (256-bit, hex-encoded).

```
ekafleet token create [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--type` | `agent` | Token type: `agent` or `server` |

Output: 64-character hex string to stdout.

### REST API Authentication

All `/v1/` REST endpoints require a bearer token:

```bash
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/status
```

The token is validated against the RBAC token store. Viewers can access read endpoints; operators and admins can access write endpoints.

## REST API

All endpoints are served on the HTTP listen address (default `0.0.0.0:7402`). All `/v1/` endpoints require a bearer token (see [REST API Authentication](#rest-api-authentication)).

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (no auth required) |
| `GET /v1/status` | Fleet status |
| `GET /v1/services` | Service listing |
| `GET /v1/capacity` | Resource utilization |
| `GET /v1/events` | Fleet event timeline |
| `GET /v1/deployments` | Deployment history |
| `GET /v1/deployments/:service` | Per-service deployment history |
| `GET /v1/cloud/instances` | Cloud-provisioned VM instances |
| `GET /v1/watch` | SSE event stream |
| `GET /v1/query` | Metric query (params: `metric`, `service`, `node`) |
| `GET /v1/kv/:key` | Read a key from the KV store |
| `PUT /v1/kv/:key` | Write a key to the KV store |
| `DELETE /v1/kv/:key` | Delete a key from the KV store |
| `GET /v1/kv?prefix=...` | List keys by prefix |
| `GET /v1/metrics/services/:name` | Service-level metrics for HPA |
| `GET /v1/alerts/silences` | List alert silences |
| `POST /v1/alerts/silences` | Create an alert silence |
| `DELETE /v1/alerts/silences/:id` | Remove an alert silence |
| `GET /metrics` | Prometheus exposition format |
| `GET /ui/` | Web dashboard (embedded SPA) |
