# Multi-Cloud Fleet Example (AWS + GCP)

A fleet spanning AWS and GCP with services distributed across both providers for geographic redundancy. Each provider has its own autoscaled node pool.

## What this demonstrates

- Multiple cloud providers with independent autoscaling
- Cross-provider spread with percentage targets (50/50)
- Provider-specific configuration (`securityGroupIds` for AWS, `project`/`zone` for GCP)
- Blue-green deployment strategy
- Static server machines alongside cloud-provisioned workers

## Prerequisites

- AWS CLI installed and configured
- `gcloud` CLI installed and authenticated
- NixOS images built for both AWS (AMI) and GCP (GCE image)
- Network connectivity between providers (VPN, peering, or public endpoints)
- One static machine in each provider region for the ekafleet server

## How cross-provider placement works

The `labels.provider` spread constraint with `weight = 80` ensures instances are distributed roughly 50/50 across AWS and GCP. The scheduler treats cloud-provisioned machines identically regardless of provider -- placement is driven entirely by labels and spread targets.

If one provider is unavailable, the scheduler will place instances on the remaining provider, degrading gracefully rather than failing.

## Try it locally

```bash
ekafleet dev
ekafleet plan --config examples/multi-cloud/fleet.nix --server 127.0.0.1:7400
```

Cloud autoscaling is a no-op in dev mode, but the configuration validates normally.

## Deploy for real

```bash
# Start server (single-node control plane; multi-node consensus is not yet
# implemented — run one authoritative server with encrypted persistent state)
ekafleet server --data-dir /var/lib/ekafleet --domain fleet.internal

# Join server machines from each provider
TOKEN=$(ekafleet token create --type=agent)
ekafleet agent --join server-aws:7400 --join-token $TOKEN --ca-cert /path/to/ca.pem

# Apply with --watch to enable continuous reconciliation and cloud autoscaling
ekafleet apply --config examples/multi-cloud/fleet.nix --watch
```
