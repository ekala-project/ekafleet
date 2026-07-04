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

### `ekafleet agent`

Start in agent mode (data plane).

```
ekafleet agent [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--join` | *(required)* | Server address to join |
| `--token` | *(required)* | Authentication token |
| `--data-dir` | `/var/lib/ekafleet` | Data directory for local state |

## Deployment

### `ekafleet plan`

Show desired-vs-actual diff without making changes.

```
ekafleet plan [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `fleet.nix` | Path to fleet configuration |
| `--server` | `127.0.0.1:7400` | Server address |

### `ekafleet apply`

Execute a deployment plan.

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

Fleet health overview.

### `ekafleet drift`

Detect state divergence between desired and actual.

### `ekafleet capacity`

Resource utilization report across the fleet.

### `ekafleet services`

Service placement listing showing where each service is running.

### `ekafleet drain <machine>`

Reschedule all services off a machine (e.g., for maintenance).

### `ekafleet scale <service> <count>`

Manually set the replica count for a service.

### `ekafleet logs <service>`

Aggregate and display logs from all replicas of a service.

## Authentication

### `ekafleet token create`

Generate a join token.

```
ekafleet token create [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--type` | `agent` | Token type: `agent` or `server` |
