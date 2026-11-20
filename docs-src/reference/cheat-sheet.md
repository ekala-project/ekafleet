# CLI Cheat Sheet

Quick reference for all ekafleet commands. All commands accept `--output json` for machine-readable output. Commands that connect to the server accept `--server <addr>` (default: `127.0.0.1:7400`).

## Setup

```bash
ekafleet dev                                    # Dev mode (server + agent, no TLS)
ekafleet server --token $TOKEN --domain fleet.internal  # Production server
ekafleet agent --join server:7400 --join-token $TOKEN    # Join agent to fleet
ekafleet token create --type agent              # Generate join token
```

## Deploy

```bash
ekafleet validate --config fleet.nix            # Validate config offline
ekafleet plan --config fleet.nix                # Preview changes
ekafleet apply --config fleet.nix               # Deploy
ekafleet apply --config fleet.nix --watch       # Continuous reconciliation + autoscaling
ekafleet rollback --all                         # Rollback all to previous generation
ekafleet rollback node-1 --to 5                 # Rollback specific machine to gen 5
```

## Status & Monitoring

```bash
ekafleet status                                 # Fleet overview (nodes, pools, services)
ekafleet status -o json                         # JSON output
ekafleet drift                                  # Detect unhealthy nodes/services
ekafleet capacity                               # Cluster resource utilization
ekafleet services                               # All service placements
ekafleet top nodes                              # CPU/memory usage per node
ekafleet top services                           # Resource requests per service
ekafleet events                                 # Recent fleet events
ekafleet events --category scaling              # Filter by category
ekafleet events --service web --limit 10        # Filter by service
```

## Services

```bash
ekafleet scale web 5                            # Scale to 5 replicas
ekafleet logs web                               # Service logs (last 100 lines)
ekafleet logs web -f                            # Stream logs continuously
ekafleet logs web --tail 50 --node node-1       # Tail from specific node
ekafleet exec web -- curl localhost:8080        # Run command in service context
ekafleet exec web --node node-1 -- ps aux       # Exec on specific node
ekafleet service inspect web                    # Systemd unit, cgroup accounting
```

## Nodes

```bash
ekafleet node list                              # List all nodes
ekafleet node status node-1                     # Detailed node info
ekafleet node cordon node-1                     # Mark unschedulable
ekafleet node uncordon node-1                   # Mark schedulable
ekafleet drain node-1                           # Drain services off node
ekafleet drain node-1 --deadline 300            # Drain with 5 min deadline
ekafleet ssh node-1                             # SSH into node
```

## Deployments

```bash
ekafleet deployment list                        # Recent deployments
ekafleet deployment list --service web          # Filter by service
ekafleet deployment status web                  # History for a service
ekafleet deployment promote web                 # Promote canary to full rollout
ekafleet deployment fail web                    # Fail deployment (trigger rollback)
```

## Batch Jobs

```bash
ekafleet dispatch etl db=prod table=users       # Run parameterized batch job
```

## NixOS Operations

```bash
# Closure analysis (runs locally, no server needed)
ekafleet closure diff /nix/store/old... /nix/store/new...   # Package diff
ekafleet closure deps /nix/store/abc...                     # Dependency list
ekafleet closure deps /nix/store/abc... --tree              # Dependency tree
ekafleet closure size /nix/store/abc...                     # Closure size

# Generation management
ekafleet generation list node-1                 # List NixOS generations
ekafleet generation switch node-1 42            # Activate + set boot default
ekafleet generation boot node-1 42              # Set boot default only
ekafleet generation test node-1 42              # Activate (reverts on reboot)
ekafleet generation diff node-1 41 42           # Diff two generations

# System-wide operations
ekafleet system gc                              # Nix store garbage collection
ekafleet system gc --dry-run                    # Preview GC
ekafleet system reboot                          # Rolling reboot (one at a time)
ekafleet system reboot --pool workers           # Reboot specific pool
ekafleet system reboot --max-parallel 2         # Parallel reboots
ekafleet system rebuild node-1                  # NixOS rebuild on machine
ekafleet system rebuild --all                   # Rebuild all machines
```

## ACL & Security

```bash
ekafleet acl token create --role admin --description "ops"  # Create token
ekafleet acl token create --role viewer --description "ci"  # Read-only token
ekafleet acl token list                         # List tokens (descriptions, not values)
ekafleet acl token revoke $TOKEN                # Revoke a token
```

## Disaster Recovery

```bash
ekafleet snapshot --output backup.bin           # Take Raft snapshot
ekafleet restore backup.bin                     # Restore from snapshot
ekafleet upgrade /nix/store/new-ekafleet        # Rolling upgrade with safety snapshot
```

## REST API

```bash
# All /v1/ endpoints require: -H "Authorization: Bearer $TOKEN"
curl $API/health                                # Health check (no auth)
curl $API/v1/status                             # Fleet status
curl $API/v1/services                           # Service placements
curl $API/v1/capacity                           # Resource utilization
curl $API/v1/events                             # Event timeline
curl $API/v1/deployments                        # Deployment history
curl $API/v1/cloud/instances                    # Cloud-provisioned VMs
curl $API/v1/watch                              # SSE event stream
curl $API/v1/query?metric=cpu&service=web       # Metric query
curl $API/metrics                               # Prometheus metrics
curl $API/ui/                                   # Web dashboard

# KV store
curl -X PUT -d 'value' $API/v1/kv/my-key       # Write
curl $API/v1/kv/my-key                          # Read
curl -X DELETE $API/v1/kv/my-key                # Delete
curl "$API/v1/kv?prefix=config/"                # List by prefix

# Alert silences
curl -X POST -d '{"matchers":[...],...}' $API/v1/alerts/silences
curl $API/v1/alerts/silences                    # List
curl -X DELETE $API/v1/alerts/silences/0        # Remove
```

## Shell Completions

```bash
ekafleet completions bash > /etc/bash_completion.d/ekafleet
ekafleet completions zsh > ~/.zfunc/_ekafleet
ekafleet completions fish > ~/.config/fish/completions/ekafleet.fish
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EKAFLEET_TOKEN` | Server authentication token (alternative to `--token`) |
| `RUST_LOG` | Log level filter (e.g., `info`, `debug`, `ekafleet=trace`) |

## Event Categories

Use with `ekafleet events --category <name>`:

| Category | Events |
|----------|--------|
| `deployment` | Service deployments, rollbacks |
| `scaling` | Cloud instance create/destroy, manual scaling |
| `health` | Health status changes |
| `drain` | Node drain operations |
| `node_join` | Agent connections |
| `node_leave` | Agent disconnections |
| `secret_rotation` | Secret updates |
| `attestation` | SPIFFE node attestation |

## RBAC Roles

| Role | Can do |
|------|--------|
| `admin` | Everything: deploy, scale, drain, manage tokens |
| `operator` | Operations: deploy, scale, drain, read |
| `viewer` | Read-only: status, services, events, logs |
