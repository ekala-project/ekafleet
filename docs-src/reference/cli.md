# CLI Reference

## Server & Agent

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

### `ekafleet agent`

Start in agent mode (data plane).

```
ekafleet agent [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--join` | *(required)* | Server address to join (host:port) |
| `--token` | *(required)* | Authentication token |
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

Fleet health overview. Displays all nodes with health status, resources, and all services with instance details.

```
ekafleet status [--server 127.0.0.1:7400]
```

### `ekafleet drift`

Detect state divergence. Reports unhealthy nodes and services with unhealthy instances.

```
ekafleet drift [--server 127.0.0.1:7400]
```

### `ekafleet capacity`

Resource utilization report. Shows aggregate available CPU, memory, and disk across all nodes.

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

## Authentication

### `ekafleet token create`

Generate a cryptographically random join token (256-bit, hex-encoded).

```
ekafleet token create [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--type` | `agent` | Token type: `agent` or `server` |

Output: 64-character hex string to stdout.
