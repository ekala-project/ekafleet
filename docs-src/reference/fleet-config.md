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
  };
}
```

## Service

```nix
services.<name> = {
  command       = "string";              # Command to run (required)
  ports         = { <name> = PortConfig; };
  secrets       = { <name> = SecretConfig; };
  identity      = IdentityConfig;
  resources     = ResourceConfig;
  scheduling    = SchedulingConfig;
  environment   = { <key> = "value"; };
  templates     = { <name> = TemplateConfig; };   # Config file templates (optional)
  lifecycle     = LifecycleConfig;                 # Shutdown hooks (optional)
  volumes       = [ VolumeConfig ];                # Persistent volumes (optional)
};
```

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

When `liveness`, `readiness`, or `startup` probes are specified, they take precedence over the unified `healthCheck`. If only `healthCheck` is specified, it is used for both liveness and readiness.

## HealthCheckConfig

```nix
healthCheck = {
  path                = "/health";  # HTTP path (optional, enables HTTP probe)
  interval            = 10;         # Seconds between checks (default: 10)
  timeout             = 5;          # Seconds before timeout (default: 5)
  healthy_threshold   = 3;          # Consecutive successes to be healthy (default: 3)
  unhealthy_threshold = 3;          # Consecutive failures to be unhealthy (default: 3)
};
```

## SecretConfig

```nix
secrets.<name> = {
  type   = "static";        # "static" or "dynamic" (required)
  engine = "postgresql";     # For dynamic: database engine (optional)
  role   = "rw";             # For dynamic: credential role (optional)
};
```

## IdentityConfig

```nix
identity = {
  allowedCallers = [ "service-a" "service-b" ];  # Services that may call this one
  allowedTargets = [ "service-c" ];               # Services this one may call
};
```

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

Migration policy for node drain operations.

```nix
migrate = {
  maxParallel     = 1;    # Concurrent migrations (default: 1)
  minHealthyTime  = 10;   # Seconds (default: 10)
  healthyDeadline = 300;  # Seconds (default: 300)
};
```

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
};
```

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

## WebhookConfig

Outbound webhook notifications triggered by fleet events:

```nix
webhooks = [
  {
    name = "slack-deploys";
    url = "http://webhook-proxy:8080/deploy";
    events = [ "deployment" "rollback" ];
    timeout_seconds = 10;
  }
];
```

## AlertRule

Threshold-based alerting on collected metrics:

```nix
alerting.rules = [
  {
    name = "high-memory";
    metric = "node_memory_usage_ratio";
    threshold = 0.9;
    op = "gt";
    forSeconds = 300;
    severity = "critical";
    webhook_url = "http://alertmanager:9093/api/v1/alerts";
  }
];
```

## FederatedCluster

Configuration for multi-region federation with peer clusters:

```nix
federation = [
  {
    name = "us-west";
    address = "us-west-server:7400";
    trustDomain = "us-west.fleet.internal";
    discoveryEnabled = true;
  }
];
```
