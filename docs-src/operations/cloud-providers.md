# Cloud Providers

ekafleet supports automatic VM provisioning and destruction on AWS, Azure, and GCP for pool-level autoscaling. Cloud-provisioned machines run NixOS with the ekafleet agent and join the fleet automatically via cloud-init.

## Architecture

```text
                    PoolScalingEngine
                          |
                   evaluates pool utilization
                          |
                   ScalingActuator
                    /     |     \
                 AWS    Azure    GCP
                (aws)   (az)   (gcloud)
                          |
                   cloud VM boots with
                   ekafleet agent + join token
                          |
                   agent connects to server
                          |
                   IP correlation links
                   cloud instance to fleet node
                          |
                   scheduler places services
```

The scaling actuator runs as a background task during `ekafleet apply --watch`. It evaluates pool scaling policies every 30 seconds and provisions or destroys VMs accordingly.

## Provider Setup

### AWS

**Prerequisites:**
- `aws` CLI installed and configured (IAM credentials via environment, instance profile, or `~/.aws/credentials`)
- A NixOS AMI with the ekafleet agent binary
- VPC, subnet, and security group allowing inbound gRPC (port 7400)

**Configuration:**

```nix
nodePools.workers.cloud = {
  provider = "aws";
  region = "us-east-1";
  instanceType = "c6i.xlarge";
  imageId = "ami-0123456789abcdef0";
  subnetId = "subnet-abc123";
  securityGroupIds = [ "sg-xyz789" ];
  sshKeyName = "fleet-key";
  diskSizeGb = 50;
  machineCapacity = { cpu = 4000; memory = 8192; disk = 100000; };
};
```

Instances are tagged with `ekafleet=<fleet-name>`, `pool=<pool-name>`, and `managed-by=ekafleet` for identification and orphan cleanup.

### Azure

**Prerequisites:**
- `az` CLI installed and logged in
- A NixOS managed image or VHD
- Resource group, VNet, and NSG allowing inbound gRPC (port 7400)

**Configuration:**

```nix
nodePools.workers.cloud = {
  provider = "azure";
  region = "eastus";
  instanceType = "Standard_D4s_v3";
  imageId = "nixos-ekafleet";
  resourceGroup = "my-fleet-rg";    # Required for Azure
  diskSizeGb = 50;
  machineCapacity = { cpu = 4000; memory = 16384; disk = 100000; };
};
```

VMs are tagged with `ekafleet`, `pool`, and `managed-by` for identification.

### GCP

**Prerequisites:**
- `gcloud` CLI installed and authenticated
- A NixOS GCE image uploaded to the project
- VPC and firewall rule allowing inbound gRPC (port 7400)

**Configuration:**

```nix
nodePools.workers.cloud = {
  provider = "gcp";
  region = "us-central1";
  instanceType = "n2-standard-4";
  imageId = "nixos-ekafleet";
  project = "my-gcp-project";      # Required for GCP
  zone = "us-central1-a";
  subnetId = "default";
  diskSizeGb = 50;
  machineCapacity = { cpu = 4000; memory = 16384; disk = 100000; };
};
```

Instances are labeled with `ekafleet`, `pool`, and `managed-by` (GCE labels are lowercase).

## Building NixOS Images

Cloud VMs need a NixOS image with the ekafleet binary. Use [nixos-generators](https://github.com/nix-community/nixos-generators) to build cloud-specific images:

```nix
# Example NixOS configuration for a cloud image
{ pkgs, ... }: {
  imports = [ ekafleet.nixosModules.ekafleet ];

  services.ekafleet = {
    enable = true;
    mode = "agent";
    # Server address and token are injected via cloud-init user-data
  };

  # Enable cloud-init for user-data processing
  services.cloud-init.enable = true;
}
```

Build commands:

```bash
# AWS AMI
nixos-generators -f amazon -c ./cloud-image.nix

# Azure VHD
nixos-generators -f azure -c ./cloud-image.nix

# GCP image
nixos-generators -f gce -c ./cloud-image.nix
```

On AWS, community NixOS AMIs can be used as a base — the ekafleet binary is installed and started via user-data (slower boot but no custom image required).

## Agent Bootstrap

When the actuator provisions a VM, it generates a cloud-init user-data script that:

1. Writes the server's CA certificate to `/etc/ekafleet/ca.pem`
2. Starts the ekafleet agent with `--join <server-addr> --join-token <token> --ca-cert /etc/ekafleet/ca.pem`

The join token is a one-time-use SPIFFE attestation token generated per instance. After the agent connects and attests, it receives a node SVID and communicates via mTLS.

## Instance Tracking

Cloud instances are tracked in the Raft state machine with:

- Cloud instance ID (e.g., `i-0abc123`)
- Provider name (`aws`, `azure`, `gcp`)
- Pool assignment
- Private IP address
- Fleet node ID (set when the agent joins)
- Timestamps for creation and join

When an agent connects, the server correlates its source IP with tracked cloud instances to link them. This enables the scheduler to treat cloud machines the same as statically declared ones.

## Monitoring

```bash
# List all cloud instances
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/cloud/instances

# View scaling events
curl -H "Authorization: Bearer $TOKEN" "http://server:7402/v1/events?category=scaling"
```

## Orphan Reconciliation

The actuator periodically lists cloud instances tagged as belonging to the fleet and compares them against tracked instances. Orphaned VMs (tagged but not tracked) are terminated automatically. This handles cases where an instance was created but the server crashed before tracking it.
