# Single Cloud (AWS) Fleet Example

A hybrid fleet with two static controller machines and an autoscaled AWS worker pool. Workers are provisioned and destroyed based on CPU utilization.

## What this demonstrates

- AWS cloud provider integration with autoscaling
- Mixed static (controllers) and dynamic (workers) machine pools
- Bin-packing for cost-efficient worker utilization
- Canary deployment strategy with auto-promotion
- Startup probes for slow-starting services

## Prerequisites

- AWS CLI installed and configured with IAM credentials
- A NixOS AMI with the ekafleet agent binary (see [cloud provider docs](../../docs-src/operations/cloud-providers.md))
- VPC, subnet, and security group allowing inbound gRPC (port 7400)
- Two static NixOS machines for controllers

## How autoscaling works

1. The pool scaling engine evaluates CPU utilization every 30 seconds
2. When utilization exceeds `targetValue * scaleUpThreshold`, a new VM is provisioned
3. The VM boots with a cloud-init script that starts the ekafleet agent with a one-time join token
4. The agent joins the fleet and the scheduler places services on it
5. When utilization drops below `targetValue * scaleDownThreshold`, the least-loaded worker is drained and terminated

## Try it locally

```bash
ekafleet dev
ekafleet plan --config examples/single-cloud/fleet.nix --server 127.0.0.1:7400
```

Cloud autoscaling is a no-op in dev mode, but the configuration validates normally.

## Deploy for real

```bash
# Start server on a controller
ekafleet server --data-dir /var/lib/ekafleet --domain fleet.internal

# Join controller machines
TOKEN=$(ekafleet token create --type=agent)
ekafleet agent --join ctrl-1:7400 --join-token $TOKEN --ca-cert /path/to/ca.pem

# Apply with --watch to enable continuous reconciliation and cloud autoscaling
ekafleet apply --config examples/single-cloud/fleet.nix --watch
```
