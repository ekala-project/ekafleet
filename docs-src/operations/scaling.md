# Scaling

ekafleet supports manual scaling, metric-based autoscaling, and pool-level scaling.

## Manual Scaling

```bash
ekafleet scale api-server 5
```

This triggers re-evaluation and deployment of the delta.

## Service Autoscaling

The autoscaling engine evaluates policies against collected metrics and computes desired replica counts.

### Scaling Policies

Policies define min/max bounds and metric-based rules:

| Field | Description |
|-------|-------------|
| `min_replicas` | Floor for scale-down |
| `max_replicas` | Ceiling for scale-up |
| `rules` | List of metric-based scaling rules |

### Scaling Rules

Each rule defines a target metric value and thresholds:

| Field | Description |
|-------|-------------|
| `metric_name` | Prometheus metric to evaluate |
| `target_value` | Desired metric value |
| `scale_up_threshold` | Ratio above which to scale up |
| `scale_down_threshold` | Ratio below which to scale down |

### How It Works

1. Metrics are collected from agents every 15 seconds
2. The scaling engine evaluates policies periodically
3. For each service, it computes the average metric value across instances
4. If the ratio of current to target exceeds the scale-up threshold, it adds replicas
5. If below the scale-down threshold, it removes replicas
6. A cooldown period (default: 60 seconds) prevents thrashing

## Pool-Level Scaling

Node pools can define scaling policies that monitor aggregate pool utilization:

```nix
nodePools.compute = {
  scaling = {
    minCount = 2;
    maxCount = 10;
    rules = [{
      metricName = "pool_cpu_utilization";
      targetValue = 0.7;
      scaleUpThreshold = 1.3;
      scaleDownThreshold = 0.5;
    }];
  };
};
```

Pool scaling decisions can be advisory (logged recommendations) or automated via cloud provider integration. When a pool has a `cloud` configuration, ekafleet provisions and destroys cloud VMs directly in response to scaling decisions.

## Cloud Provider Autoscaling

When a node pool has a `cloud` block, the scaling actuator automatically provisions and destroys cloud VMs based on pool utilization. This is supported on AWS, Azure, and GCP.

### Configuration

```nix
nodePools.workers = {
  labels = { role = "worker"; };
  scaling = {
    minCount = 2;
    maxCount = 10;
    rules = [{
      metricName = "cpu_utilization";
      targetValue = 0.7;
      scaleUpThreshold = 1.2;
      scaleDownThreshold = 0.5;
    }];
  };
  cloud = {
    provider = "aws";              # "aws", "azure", or "gcp"
    region = "us-east-1";
    instanceType = "c6i.xlarge";
    imageId = "ami-0123456789abcdef0";  # NixOS image with ekafleet agent
    subnetId = "subnet-abc123";
    securityGroupIds = [ "sg-xyz789" ];
    sshKeyName = "fleet-key";
    diskSizeGb = 50;
    machineCapacity = {            # Expected capacity for scheduling
      cpu = 4000;
      memory = 8192;
      disk = 100000;
    };
  };
};
```

Azure requires `resourceGroup`, GCP requires `project`:

```nix
# Azure
cloud = {
  provider = "azure";
  region = "eastus";
  instanceType = "Standard_D4s_v3";
  imageId = "nixos-ekafleet";
  resourceGroup = "my-rg";
  machineCapacity = { cpu = 4000; memory = 16384; disk = 100000; };
};

# GCP
cloud = {
  provider = "gcp";
  region = "us-central1";
  instanceType = "n2-standard-4";
  imageId = "nixos-ekafleet";
  project = "my-project";
  zone = "us-central1-a";
  machineCapacity = { cpu = 4000; memory = 16384; disk = 100000; };
};
```

### How It Works

**Scale-up:**

1. The pool scaling engine detects utilization above the threshold
2. The actuator generates a one-time join token for the new instance
3. A cloud-init user-data script is generated with the server address, join token, and CA certificate
4. The cloud provider CLI (`aws`/`az`/`gcloud`) provisions the VM with the user-data
5. The VM boots, runs the ekafleet agent, and joins the fleet automatically
6. The instance is tracked in Raft state and correlated with the agent by IP address
7. The scheduler begins placing services on the new machine

**Scale-down:**

1. The pool scaling engine detects utilization below the threshold
2. The actuator selects a victim (prefers un-joined instances, then newest)
3. The victim node is marked unschedulable (drained)
4. After a 30-second grace period for the reconciler to move services, the VM is terminated
5. The instance is removed from tracking

**Safety features:**

- Maximum 3 instances created per pool per scaling cycle
- 60-second cooldown between scaling actions (from `PoolScalingEngine`)
- `maxCount` in scaling config enforces a hard ceiling
- Graceful drain before termination preserves service availability
- Orphan reconciliation periodically detects and terminates cloud instances that are tagged but not tracked

### NixOS Image Requirements

Cloud-provisioned VMs must run a NixOS image that includes the ekafleet agent binary. Build images using `nixos-generators`:

| Cloud | Format | Command |
|-------|--------|---------|
| AWS | AMI | `nixos-generators -f amazon` then `aws ec2 import-image` |
| Azure | VHD | `nixos-generators -f azure` then upload to storage account |
| GCP | GCE | `nixos-generators -f gce` then upload to GCS |

Community NixOS AMIs on AWS can also be used if the ekafleet binary is installed via user-data (slower boot).

### CLI Requirements

The ekafleet server must have the relevant cloud CLI installed:

- AWS: `aws` CLI
- Azure: `az` CLI
- GCP: `gcloud` CLI

Authentication is handled by the CLI's native credential chain (environment variables, instance profiles, etc.).

### Monitoring Cloud Instances

List all tracked cloud instances:

```bash
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/cloud/instances
```

Scale-up and scale-down actions emit events visible in `/v1/events` with the `scaling` category.

## Node Drain

To remove a machine from the fleet (e.g., for maintenance):

```bash
ekafleet drain app-1 --deadline 300
```

This marks the node as unschedulable and reschedules all services to other nodes. The optional `--deadline` flag (in seconds) sets a time limit for the drain operation. The migration policy on each service controls the pacing:

```nix
scheduling.migrate = {
  maxParallel = 1;       # Migrate one instance at a time
  minHealthyTime = 10;   # New instance must be healthy for 10s
  healthyDeadline = 300;  # 5 minute deadline for migration
};
```

## Node Maintenance Windows

To prevent new workloads from being placed on a node without draining existing services (e.g., scheduled maintenance in the future):

```bash
# Mark node as ineligible for scheduling
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://server:7402/v1/nodes/app-1/schedulable?enabled=false

# Re-enable scheduling
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://server:7402/v1/nodes/app-1/schedulable?enabled=true
```

An ineligible node continues running its existing services but does not receive new placements. This is less disruptive than a full drain — existing workloads are undisturbed until the maintenance window begins.

## Data Migration on Reschedule

When a `stateful` service is rescheduled to a different machine, its volume data is migrated automatically:

1. The reconciler detects that a stateful instance has moved nodes
2. A `MigrateVolumeCommand` is sent to the destination agent
3. The destination agent pulls data via `rsync -avz --delete` from the source node
4. The service is started on the destination machine after migration completes

Migration respects the service's `migrate` config for pacing and health gates (`maxParallel`, `minHealthyTime`, `healthyDeadline`). Disable automatic migration by setting `migrateOnReschedule = false` in the service's `migrate` block.

Migration is skipped automatically for volumes with `storageClass = "nfs"` and `accessMode = "ReadWriteMany"`, since the data is already accessible from any node.

> **Note:** Only services with `type = "stateful"` trigger automatic migration. Services with `type = "service"` are treated as stateless and do not migrate volume data on reschedule.

## Rebalancing

After cluster drift (node failures, recoveries, scale-ups), workloads may concentrate on surviving nodes. The descheduler evaluates whether services would be better placed on different machines by comparing actual placement against ideal (freshly computed) placement:

```bash
# Check for rebalance opportunities
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/rebalance
```

Each suggestion includes the service name, current node, ideal node, and reason. Rebalancing is advisory — the operator reviews suggestions and triggers rescheduling manually.

## Capacity Planning

View resource utilization across the fleet:

```bash
ekafleet capacity
```

Output includes per-pool breakdown when node pools are configured.

View service placement:

```bash
ekafleet services
```
