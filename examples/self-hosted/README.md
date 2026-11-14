# Self-Hosted Fleet Example

A bare-metal fleet with three statically declared NixOS machines. No cloud provider, no autoscaling -- just direct machine management.

## What this demonstrates

- Static machine inventory with rack-zone labels
- Spread scheduling across physical racks
- Rolling updates with automatic rollback
- Disruption budget (2 of 3 instances must stay up)

## Prerequisites

- Three NixOS machines accessible via SSH
- ekafleet binary installed on all machines

## Try it locally

`<your-fleet-flake>` is a flake that exposes this `fleet.nix` as its `fleet` output (see the quickstart, step 4); the server evaluates it.

```bash
ekafleet dev
ekafleet plan --flake <your-fleet-flake> --server 127.0.0.1:7400
```

## Deploy for real

```bash
# Start the server on one machine
ekafleet server --data-dir /var/lib/ekafleet --domain fleet.internal

# Generate join tokens and start agents on each machine
TOKEN=$(ekafleet token create --type=agent)
ekafleet agent --join server-ip:7400 --join-token $TOKEN --ca-cert /path/to/ca.pem

# Apply the configuration
ekafleet apply --flake <your-fleet-flake>
```
