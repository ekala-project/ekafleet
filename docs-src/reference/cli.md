# CLI Reference

## Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output` / `-o` | `text` | Output format: `text` or `json` for machine-readable output |

Use `--output json` with any command for structured JSON output suitable for scripting and CI/CD pipelines.

## Server & Agent

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

Start in server mode (control plane + agent capabilities).

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

### `ekafleet agent`

Start in agent mode (data plane).

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

Execute a deployment plan. Streams operation progress in real-time.

```
ekafleet apply [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `fleet.nix` | Path to fleet configuration |
| `--auto-approve` | `false` | Skip confirmation prompt |
| `--watch` | `false` | Continuous reconciliation mode |
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

Identify services running on a machine that would need rescheduling (e.g., for maintenance).

```
ekafleet drain <MACHINE> [--server 127.0.0.1:7400]
```

### `ekafleet scale <service> <count>`

Show current vs desired replica count for a service.

```
ekafleet scale <SERVICE> <COUNT> [--server 127.0.0.1:7400]
```

### `ekafleet logs <service>`

Show service instances and journal hints for accessing logs on each node.

```
ekafleet logs <SERVICE> [--server 127.0.0.1:7400]
```

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
| `--data-dir` | `/var/lib/ekafleet` | Data directory to restore into |

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
