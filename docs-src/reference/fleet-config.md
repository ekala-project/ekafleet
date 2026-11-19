# Fleet Configuration Reference

Complete reference for the `fleet.nix` configuration schema.

## Top Level

```nix
{
  fleet = {
    name = "string";           # Fleet name (required)
    domain = "string";         # DNS domain, e.g., "fleet.internal" (required)
    services = { ... };        # Service definitions
    machines = { ... };        # Machine inventory
    nodePools = { ... };       # Node pool definitions (optional)
    externalServices = { ... };# Services outside the fleet, in DNS (optional)
    federation = { ... };      # Peer clusters (optional)
    ingress = { ... };         # HTTP routes of the ingress proxy (optional)
  };
}
```

## Service

A service must have either `command` (native Nix process) or `container` (OCI container), but not both.

```nix
services.<name> = {
  command       = "string";              # Command to run (required unless container is set)
  container     = ContainerConfig;       # OCI container config (required unless command is set)
  ports         = { <name> = PortConfig; };
  secrets       = { <name> = SecretConfig; };
  transitKeys   = [ "string" ];          # Transit keys its SVID may use (optional)
  identity      = IdentityConfig;
  resources     = ResourceConfig;
  scheduling    = SchedulingConfig;
  environment   = { <key> = "value"; };
  templates     = { <name> = TemplateConfig; };   # Config file templates (optional)
  lifecycle     = LifecycleConfig;                 # Shutdown hooks (optional)
  volumes       = [ VolumeConfig ];                # Persistent volumes (optional)
};
```

## ContainerConfig

```nix
container = {
  image             = "string";           # OCI image reference (required)
  pullPolicy        = "Always";           # Always | IfNotPresent | Never (default: Always)
  entrypoint        = [ "string" ];       # Override image entrypoint (optional)
  args              = [ "string" ];       # Override image CMD (optional)
  workingDir        = "/app";             # Override working directory (optional)
  bindMounts        = [ "host:container:ro" ];  # Additional bind mounts (optional)
  registryAuthSecret = "secret-name";     # Registry credentials secret (optional)
};
```

Container services run via `systemd-nspawn` with host networking, the same cgroup hierarchy, and SPIFFE identity as native services. See [OCI Containers](../operations/oci-containers.md) for details.

## PortConfig

```nix
ports.<name> = {
  port        = int;           # Port number (required)
  protocol    = "tcp";         # "tcp" or "udp" (default: tcp)
  hostname    = "string";      # For L7 proxy routing (optional)
  healthCheck = HealthCheckConfig;  # Unified health check (see also separate probes below)
  liveness    = HealthCheckConfig;  # Liveness probe — failures trigger restart (optional)
  readiness   = HealthCheckConfig;  # Readiness probe — failures remove from LB (optional)
  startup     = HealthCheckConfig;  # Startup probe — suppresses liveness until passing (optional)
};
```

When `liveness`, `readiness`, or `startup` probes are specified, they take precedence over the unified `healthCheck`. If only `healthCheck` is specified, it is used for both liveness and readiness. A `liveness` probe without a `readiness` probe also serves as the readiness probe.

Probes check the port that declares them (the first port by name that declares any), on loopback, or on the service's namespace IP (from inside its network namespace) in a non-default namespace. How each probe acts:

- Each run of `unhealthy_threshold` consecutive liveness failures restarts the service.
- A startup probe holds back liveness and readiness until it passes, after the first start and after every restart.
- Deployments wait for readiness when a `readiness`, `healthCheck` or `liveness` probe is declared.

## HealthCheckConfig

```nix
healthCheck = {
  path                = "/health";  # HTTP GET expecting 2xx (optional; without it, a TCP connect)
  interval            = 10;         # Seconds between checks (default: 10)
  timeout             = 5;          # Seconds before timeout (default: 5)
  healthy_threshold   = 3;          # Consecutive successes to be healthy (default: 3)
  unhealthy_threshold = 3;          # Consecutive failures to be unhealthy (default: 3)
};
```

## SecretConfig

```nix
secrets.<name> = {
  type   = "static";        # "static" (default) or "dynamic"
  engine = "orders-db";     # Dynamic: a `secretEngines` entry (required)
  role   = "readwrite";     # Dynamic: readonly | readwrite | admin (required)
  ttl    = 86400;           # Dynamic: lease seconds (default 86400, min 300)
};
```

Every secret is delivered at `/run/secrets/<name>`. Dynamic secrets hold JSON with `username`, `password` and `url`. See [Secrets](../operations/secrets.md#dynamic-secrets).

## SecretEngineConfig

```nix
secretEngines.<name> = {
  adminUrlSecret = "orders-db-admin";  # Fleet secret with the admin URL (required)
  database       = "orders";           # Database issued users can access (required)
};
```

The admin URL (`postgres://…` or `mysql://…`) is set with `ekafleet secret set _fleet <adminUrlSecret>`.

## ExternalServiceConfig

```nix
externalServices.<name> = {
  addresses = [ "10.0.0.50:5432" ];  # IPv4 ip:port endpoints (required)
  healthCheck = {                    # optional, checked from the server
    type = "http";                   # "tcp" or "http" (required)
    path = "/health";                # http only (default "/")
    interval = 10;                   # seconds (default 10)
    timeout = 2;                     # seconds (default 2)
  };
};
```

Resolvable as `<name>.external.<domain>`; see [DNS](../operations/dns.md#external-services).

## IdentityConfig

```nix
identity = {
  allowedCallers = [ "service-a" "service-b" ];  # Services that may call this one
  allowedTargets = [ "service-c" ];               # Services this one may call (not enforced by nftables)
  egressRules = [                                 # Outbound allow/deny list; anything else is dropped
    { destCidr = "0.0.0.0/0"; destPorts = [ 443 ]; action = "allow"; }
  ];
};
```

Both are opt-in; see [Network Policy](../operations/network-policy.md).

## ResourceConfig

```nix
resources = {
  cpu = {
    request = 500;     # Millicores requested (used for scheduling)
    limit   = 1000;    # Millicores limit (optional)
  };
  memory = {
    request = 1024;    # MB requested (used for scheduling)
    limit   = 2048;    # MB limit (optional)
  };
  disk = {
    request = 5000;    # MB requested (used for scheduling)
    limit   = 10000;   # MB limit (optional)
  };
  extended = {
    gpu = 1;       # Extended/device resources
    fpga = 2;
  };
};
```

## SchedulingConfig

```nix
scheduling = {
  replicas          = 3;                    # Number of instances (default: 1)
  type              = "service";            # Job type (default: "service")
  priority          = 50;                   # 1-100, higher = first (default: 50)
  pool              = "default";            # Node pool preference (soft, optional)
  constraints       = [ Constraint ];
  spread            = [ SpreadConfig ];
  affinity          = [ AffinityConfig ];
  serviceAffinity   = [ ServiceAffinityConfig ];
  tolerations       = [ Toleration ];
  update            = UpdateConfig;
  restart           = RestartConfig;
  reschedule        = RescheduleConfig;
  migrate           = MigrateConfig;
  periodic          = PeriodicConfig;       # Batch/sysbatch only (optional)
  disruptionBudget  = DisruptionBudget;     # Availability guarantee (optional)
  parameterized     = {                     # For batch/sysbatch jobs only (optional)
    requiredParams = [ "db" "table" ];
    optionalParams = [ "limit" ];
  };
};
```

### Job Types

| Type | Behavior |
|------|----------|
| `service` | Long-running, placed on best N machines |
| `stateful` | Sticky placement, prefers previous machine |
| `system` | Runs on every matching machine (ignores replicas) |
| `batch` | Run-to-completion, exits when done |
| `sysbatch` | Runs once on every matching machine, then completes |

## Constraint

```nix
{
  attribute = "labels.role";    # Dot-separated attribute path
  op        = "=";              # Operator (see table below)
  value     = "app";            # Expected value
}
```

### Operators

| Operator | Description |
|----------|-------------|
| `=` / `==` | Equality |
| `!=` | Not equal |
| `in` | Value in comma-separated list |
| `not_in` | Value not in list |
| `>`, `>=`, `<`, `<=` | Numeric/lexical comparison |
| `regexp` / `matches` | RE2 regular expression |
| `set_contains` | Attribute (comma-separated) contains all listed values |
| `set_contains_any` | Attribute contains any listed value |
| `is_set` | Attribute exists (value ignored) |
| `is_not_set` | Attribute does not exist |
| `version` / `semver` | Semantic version comparison |
| `distinct_hosts` | No two instances of same service on same machine |

### Supported Attributes

| Attribute | Description |
|-----------|-------------|
| `labels.<key>` | Machine label (includes pool-inherited labels) |
| `pool` | Node pool name |
| `name` | Machine name |
| `capacity.cpu` | Total CPU millicores |
| `capacity.memory` | Total memory MB |
| `capacity.disk` | Total disk MB |
| `schedulable.cpu` | CPU after reserved subtracted |
| `schedulable.memory` | Memory after reserved subtracted |
| `available.cpu` | Currently unallocated CPU |
| `available.memory` | Currently unallocated memory |

## SpreadConfig

```nix
# Simple even spread
{ attribute = "labels.zone"; weight = 50; }

# With target percentages
{
  attribute = "labels.zone";
  weight = 50;
  targets = [
    { value = "us-east-1a"; percent = 50; }
    { value = "us-east-1b"; percent = 30; }
    { value = "us-east-1c"; percent = 20; }
  ];
}

# K8s-style topology spread constraint
{
  attribute = "labels.zone";
  maxSkew = 1;       # Max difference between domains
  minDomains = 2;    # Minimum topology domains
  required = true;   # Hard constraint (filter phase)
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `attribute` | *(required)* | Attribute to spread across |
| `weight` | `50` | Score weight |
| `targets` | `[]` | Percentage-based distribution targets |
| `maxSkew` | *none* | Maximum allowed skew between domains |
| `minDomains` | *none* | Minimum number of topology domains |
| `required` | `false` | If true, spread is a hard constraint |

## AffinityConfig

```nix
{
  attribute = "labels.tier";   # Attribute to match
  op        = "=";             # Any constraint operator
  value     = "fast";          # Expected value
  weight    = 50;              # Score weight (-100 to 100, default: 50)
}
```

Negative weights create anti-affinities. Supports all constraint operators.

## ServiceAffinityConfig

```nix
{
  targetService = "redis";        # Service to co-locate with (or avoid)
  topologyKey   = "labels.zone";  # Topology dimension
  weight        = 30;             # Positive = co-locate, negative = separate
}
```

## Toleration

```nix
{
  key    = "hardware";       # Taint key to match (optional; null = all keys)
  op     = "equal";          # "equal" or "exists" (default: "equal")
  value  = "gpu";            # Required for "equal" operator
  effect = "noSchedule";     # "noSchedule", "preferNoSchedule", "noExecute" (optional; null = all)
  tolerationSeconds = 300;   # Grace period for noExecute (optional)
}
```

## UpdateConfig

```nix
update = {
  strategy         = "rolling";  # "rolling", "canary", or "blue-green" (default: "rolling")
  maxParallel      = 1;          # Instances to update at once (default: 1)
  canary           = 1;          # Canary count (for canary strategy)
  minHealthyTime   = 10;         # Seconds instance must be healthy (default: 10)
  healthyDeadline  = 300;        # Seconds to wait for health (default: 300)
  autoRevert       = true;       # Rollback on failure (default: false)
  autoPromote      = false;      # Auto-promote canaries when healthy (default: false)
  progressDeadline = 600;        # Overall deployment timeout in seconds (optional)
  healthCheck      = "checks";   # "checks", "taskStates", or "manual" (default: "checks")
};
```

## RestartConfig

Local restart policy before rescheduling to another machine.

```nix
restart = {
  attempts     = 2;      # Max restarts within interval (default: 2)
  intervalSecs = 1800;   # Time window in seconds (default: 1800)
  delaySecs    = 15;     # Wait before each restart (default: 15)
  mode         = "fail"; # "fail" or "delay" (default: "fail")
};
```

## RescheduleConfig

Cross-node reschedule policy after local restarts are exhausted.

```nix
reschedule = {
  delaySecs     = 30;             # Initial delay (default: 30)
  delayFunction = "exponential";  # "constant", "exponential", "fibonacci" (default: "exponential")
  maxDelaySecs  = 3600;           # Max delay cap (default: 3600)
  attempts      = null;           # null = unlimited (default for service), int for batch
  intervalSecs  = 86400;          # Window for counting attempts (default: 86400)
};
```

## MigrateConfig

Migration policy for node drain and reschedule operations.

```nix
migrate = {
  maxParallel         = 1;    # Concurrent migrations (default: 1)
  minHealthyTime      = 10;   # Seconds before next migration (default: 10)
  healthyDeadline     = 300;  # Seconds to wait for health gate (default: 300)
  migrateOnReschedule = true; # Auto-migrate volumes when stateful services move nodes (default: true)
};
```

When `migrateOnReschedule` is `true` (default), volume data is automatically copied via rsync to the destination node before the service starts there. Set to `false` for NFS-backed or `ReadWriteMany` volumes where data is already accessible from any node.

## PeriodicConfig

Cron schedule for batch and sysbatch jobs.

```nix
periodic = {
  cron                       = "0 3 * * *";  # Cron expression (required)
  timeZone                   = "UTC";         # IANA timezone (default: "UTC")
  concurrencyPolicy          = "forbid";      # "allow", "forbid", "replace" (default: "allow")
  successfulJobsHistoryLimit = 3;             # (default: 3)
  failedJobsHistoryLimit     = 1;             # (default: 1)
};
```

## DisruptionBudget

```nix
disruptionBudget = {
  # Specify one of minAvailable or maxUnavailable (not both):
  minAvailable   = 4;        # Minimum instances that must stay up (absolute or "50%")
  maxUnavailable = 1;        # Maximum instances that can be down (absolute or "25%")
};
```

Values can be absolute counts (`2`) or percentage strings (`"50%"`). The deployer limits rolling update batch sizes to respect the budget.

## TemplateConfig

Configuration file templates rendered with fleet context and written to a destination path.

```nix
templates.nginx-conf = {
  source   = ''
    upstream backend {
      {{ services "api-server" }}
    }
    server {
      listen {{ env.PORT }};
      server_name {{ meta.domain }};
    }
  '';
  destPath = "/etc/nginx/nginx.conf";
  perms    = "0644";                    # File permissions (default: "0644")
  changeSignal = "SIGHUP";             # Signal to send on change (optional)
};
```

### Template Syntax

| Expression | Description |
|------------|-------------|
| `{{ service "name" }}` | First address of a service (e.g., `10.100.1.1:8080`) |
| `{{ services "name" }}` | Comma-separated list of all addresses |
| `{{ secret "name" }}` | Secret value |
| `{{ meta.field }}` | Fleet metadata (e.g., `meta.fleet_name`, `meta.domain`) |
| `{{ env.VAR }}` | Environment variable |

## LifecycleConfig

```nix
lifecycle = {
  preStop   = [ "/usr/bin/drain" "--timeout" "15" ];  # Command before stop signal (optional)
  postStart = [ "/usr/bin/warm-cache" ];               # Command after start (optional)
  stopSignal = "SIGTERM";                              # Shutdown signal (default: "SIGTERM")
  terminationGracePeriodSeconds = 30;                  # Seconds before force-kill (default: 30)
};
```

| Field | systemd Directive | Default |
|-------|------------------|---------|
| `preStop` | `ExecStop=` | none |
| `postStart` | `ExecStartPost=` | none |
| `stopSignal` | `KillSignal=` | `SIGTERM` |
| `terminationGracePeriodSeconds` | `TimeoutStopSec=` | `30` |

## VolumeConfig

Persistent volumes for stateful services.

```nix
volumes = [
  {
    name         = "data";               # Volume name (unique within service)
    mountPath    = "/var/lib/postgresql"; # Mount path
    sizeMb       = 10240;                # Requested size in MB (default: 1024)
    storageClass = "local";              # "local", "nfs", "zfs" (default: "local")
    accessMode   = "ReadWriteOnce";      # "ReadWriteOnce" or "ReadWriteMany" (default: "ReadWriteOnce")
    reclaimRetain = true;                # Keep data on service destroy (default: true)
  }
];
```

The agent's `VolumeManager` provisions directories at `/var/lib/ekafleet/volumes/<service>/<volume>/` and recovers existing volumes on startup.

## SidecarConfig

Sidecar processes that run alongside the main service.

```nix
sidecars = [
  {
    name = "log-shipper";
    command = "${pkgs.fluent-bit}/bin/fluent-bit";
    environment = {
      OUTPUT = "stdout";
    };
  }
];
```

## Namespaces

```nix
namespaces.shop.quota = {
  cpu = 4000;        # total CPU requests, millicores
  memory = 8192;     # total memory requests, MB
  disk = 50000;      # total disk requests, MB
  instances = 20;
  services = 10;
};
```

Quotas are checked at plan and apply. Each service counts at its most
instances: its replicas, or every eligible machine for system jobs. A
namespace that is not listed has no quota. Namespace names are 1-32
lowercase letters, digits and inner dashes.

## Machine

```nix
machines.<name> = {
  targetHost = "10.0.1.1";     # IP or hostname (required)
  pool       = "default";      # Node pool membership (default: "default")
  labels = {                    # Arbitrary key-value labels
    role = "app";
    zone = "us-east-1a";
  };
  capacity = {
    cpu    = 8000;              # Millicores (default: 0)
    memory = 16384;             # MB (default: 0)
    disk   = 100000;            # MB (default: 0)
  };
  reserved = {                  # Reserved for OS/system use
    cpu    = 500;               # Millicores (default: 0)
    memory = 512;               # MB (default: 0)
  };
  taints = [                    # Repel non-tolerating services
    { key = "dedicated"; value = "api"; effect = "noSchedule"; }
  ];
  extendedResources = {
    gpu = 4;        # Extended resources available on this machine
    fpga = 2;
  };
};
```

## NodePoolConfig

```nix
nodePools.<name> = {
  labels = { tier = "general"; };
  schedulerAlgorithm = "binpack";  # "binpack" or "spread" (optional)
  memoryOversubscription = false;  # (default: false)
  scaling = {                      # Pool-level autoscaling (optional)
    minCount = 2;
    maxCount = 10;
    rules = [{
      metricName         = "pool_cpu_utilization";
      targetValue        = 0.7;
      scaleUpThreshold   = 1.3;
      scaleDownThreshold = 0.5;
    }];
  };
  cloud = CloudProviderConfig;     # Cloud autoscaling (optional)
};
```

## CloudProviderConfig

Cloud provider configuration for automatic VM provisioning during pool autoscaling. When present alongside `scaling`, the scaling actuator provisions and destroys cloud VMs instead of producing advisory-only decisions.

```nix
cloud = {
  provider         = "aws";              # "aws", "azure", or "gcp" (required)
  region           = "us-east-1";        # Cloud region (required)
  instanceType     = "c6i.xlarge";       # VM size (required)
  imageId          = "ami-0123456789";   # NixOS machine image (required)
  subnetId         = "subnet-abc";       # Network subnet (optional)
  securityGroupIds = [ "sg-xyz" ];       # Security groups — AWS only (optional)
  sshKeyName       = "fleet-key";        # SSH key for access (optional)
  zone             = "us-east-1a";       # Availability zone (optional)
  diskSizeGb       = 50;                 # Root disk size in GB (optional)
  resourceGroup    = "my-rg";            # Azure resource group — required for Azure
  project          = "my-project";       # GCP project ID — required for GCP
  machineCapacity  = {                   # Expected capacity for scheduling (required)
    cpu    = 4000;                       # Millicores
    memory = 8192;                       # MB
    disk   = 100000;                     # MB
  };
};
```

| Field | Required | Provider | Description |
|-------|----------|----------|-------------|
| `provider` | yes | all | Cloud provider: `"aws"`, `"azure"`, or `"gcp"` |
| `region` | yes | all | Cloud region |
| `instanceType` | yes | all | Instance type / VM size |
| `imageId` | yes | all | NixOS machine image with ekafleet agent |
| `machineCapacity` | yes | all | Expected CPU/memory/disk for scheduler |
| `subnetId` | no | AWS, GCP | Network subnet placement |
| `securityGroupIds` | no | AWS | Security group IDs |
| `sshKeyName` | no | all | SSH key for instance access |
| `zone` | no | all | Availability zone |
| `diskSizeGb` | no | all | Root disk size in GB |
| `resourceGroup` | Azure | Azure | Azure resource group name |
| `project` | GCP | GCP | GCP project ID |

The `machineCapacity` is used by the scheduler to account for cloud machines before the agent connects and reports actual resources. Once the agent joins, real resource data takes over.

## ResourceQuota

Per-pool or per-namespace resource quotas that prevent one service class from consuming all cluster resources:

```nix
resourceQuotas.default = {
  maxCpu      = 16000;   # Maximum total CPU millicores in this scope
  maxMemory   = 65536;   # Maximum total memory MB
  maxDisk     = 500000;  # Maximum total disk MB (optional)
  maxInstances = 50;     # Maximum number of service instances (optional)
};
```

The scheduler checks quotas before allocating resources. If a new placement would exceed the quota, the placement is blocked with a descriptive error.

## PolicyRule

Organizational policies evaluated during `plan` and `apply` to enforce rules like "all production services must have at least 2 replicas":

```nix
policies = [
  {
    name = "min-replicas";
    expression = "service.replicas >= 2";
    message = "Production services must have at least 2 replicas";
    enforcement = "enforce";  # "enforce" (block) or "warn" (log only)
  }
  {
    name = "require-cpu-request";
    expression = "service.resources.cpu.request > 0";
    message = "All services must declare CPU resource requests";
    enforcement = "warn";
  }
];
```

### Expression Paths

| Path | Description |
|------|-------------|
| `service.replicas` | Replica count |
| `service.priority` | Scheduling priority |
| `service.type` | Job type |
| `service.pool` | Pool preference |
| `service.resources.cpu.request` | CPU request |
| `service.resources.memory.request` | Memory request |
| `service.resources.disk.request` | Disk request |
| `service.resources.cpu.limit` | CPU limit |
| `service.resources.memory.limit` | Memory limit |

Operators: `>=`, `>`, `<=`, `<`, `==`, `!=`

## EventWebhook

Webhooks notified of fleet events (see [Deployments](../operations/deployments.md#event-webhooks)), including `external.unhealthy` / `external.healthy` from [external service](../operations/dns.md#external-services) checks:

```nix
webhooks = [
  {
    name = "deploys";
    url = "https://hooks.example.com/ekafleet";
    events = [ "deploy.*" "drain.completed" ];   # types, prefix.* or *
    secret = "hook-key";   # optional: ekafleet secret set _fleet hook-key
  }
];
```

## AdmissionWebhook

External admission webhooks reviewing configurations at plan and apply
(see [Deployments](../operations/deployments.md#admission)).

```nix
admissionWebhooks = [
  {
    name = "security-review";
    url = "https://policy.example.com/validate";
    failPolicy = "fail";      # "fail" or "ignore" (default: "fail")
    timeoutSeconds = 10;      # 1-60 (default: 10)
  }
];
```

The webhook receives an `AdmissionReview` POST. It must return `{"allowed": true}` or `{"allowed": false, "message": "reason"}`.

## AlertRule

Threshold-based alerting on collected metrics:

```nix
alerting.rules = [
  {
    name = "high-cpu";
    metric = "node_cpu_usage_ratio";
    threshold = 0.9;
    op = "gt";
    forSeconds = 300;
    severity = "critical";
    webhook_url = "http://alertmanager:9093/api/v1/alerts";
    labels = { team = "platform"; };     # Labels for routing (optional)
    route = "http://slack-hook:8080";     # Override webhook URL (optional)
  }
];
```

### Alert Silencing

Silence alerts during maintenance windows via the REST API:

```bash
# Create a silence
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"matchers":[["service","api-server"]],"starts_at":1720000000,"ends_at":1720003600,"comment":"maintenance"}' \
  http://server:7402/v1/alerts/silences

# List silences
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/alerts/silences

# Remove a silence
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://server:7402/v1/alerts/silences/0
```

## IngressRouteConfig

```nix
ingress.<name> = {
  host = "www.example.com";  # Host header without port, or "*" (required)
  path = "/";                # path prefix (default "/")
  service = "web";           # default-namespace service (required)
  port = "http";             # name of one of its ports (required)
  pools = [ "edge" ];        # serve on nodes of these pools
  nodes = [ "edge-1" ];      # and on these nodes; with neither, every node
};
```

See [Ingress Proxy](../operations/proxy.md).

## FederationConfig

Trust and service discovery shared with peer ekafleet clusters; see [Trust Domain Federation](../operations/spiffe.md#trust-domain-federation).

```nix
federation = {
  exportServices = [ "api" ];   # default-namespace services peers may discover
  peers.east = {                # local name of the peer (DNS label)
    endpoint = "east-server.example.com:7404";  # the peer's federation listener (required)
    trustDomain = "east.internal";              # the peer's trust domain (required)
    caCert = builtins.readFile ./east-ca.pem;   # the peer's root CA PEM (required)
  };
};
```

The peer's exported services resolve as `<svc>.east.federation.<domain>`. The following are rejected:

- a trust domain equal to this fleet's own;
- two peers with the same trust domain;
- exports of services that are undefined or not in the default namespace.

