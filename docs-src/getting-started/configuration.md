# Configuration

Fleet configuration is pure Nix. ekafleet consumes it by running `nix eval --json .#fleet` and operating on the resulting JSON.

## Fleet Structure

A fleet configuration has four top-level keys:

```nix
{
  fleet = {
    name = "production";       # Fleet name
    domain = "fleet.internal"; # DNS domain for service discovery

    services = { ... };        # Service definitions
    machines = { ... };        # Machine inventory
    nodePools = { ... };       # Node pool definitions (optional)
  };
}
```

## Service Configuration

Each service defines what to run and how to run it:

```nix
services.api-server = {
  # Required: command to execute
  command = "${pkgs.api-server}/bin/server";

  # Port declarations with optional health checks
  ports.http = {
    port = 8080;
    protocol = "tcp";           # default: tcp
    hostname = "api.example.com"; # for L7 proxy routing
    healthCheck = {
      path = "/ready";          # HTTP health check path
      interval = 10;            # seconds (default: 10)
      timeout = 5;              # seconds (default: 5)
      healthy_threshold = 3;    # consecutive successes (default: 3)
      unhealthy_threshold = 3;  # consecutive failures (default: 3)
    };
  };

  # Resource requirements (millicores for CPU, MB for memory/disk)
  resources = {
    cpu = { request = 500; limit = 1000; };
    memory = { request = 1024; limit = 2048; };
    disk = { request = 5000; };
  };

  # Environment variables
  environment = {
    LOG_LEVEL = "info";
    DB_HOST = "postgres.service.fleet.internal";
  };

  # Secrets (fetched from the built-in secret store)
  secrets.db = {
    type = "dynamic";
    engine = "postgresql";
    role = "rw";
  };

  # Identity contracts for service mesh
  identity = {
    allowedCallers = [ "web-frontend" ]; # who can call this service
    allowedTargets = [ "postgres" ];     # what this service calls
  };

  # Scheduling configuration
  scheduling = {
    replicas = 3;
    type = "service";  # service | stateful | system | batch | sysbatch
    priority = 50;     # 1-100, higher = scheduled first (default: 50)

    # Node pool preference (soft affinity)
    pool = "default";

    # Hard constraints (must be satisfied)
    constraints = [
      { attribute = "labels.role"; op = "="; value = "app"; }
      { attribute = "capacity.cpu"; op = ">="; value = "4000"; }
    ];

    # Spread across topology domains
    spread = [
      { attribute = "labels.zone"; weight = 50; }
    ];

    # Soft preferences (influence scoring)
    affinity = [
      { attribute = "labels.tier"; op = "="; value = "fast"; weight = 50; }
    ];

    # Inter-service affinity
    serviceAffinity = [
      { targetService = "redis"; topologyKey = "labels.zone"; weight = 30; }
    ];

    # Tolerate machine taints
    tolerations = [
      { key = "dedicated"; op = "equal"; value = "api"; effect = "noSchedule"; }
    ];

    # Update strategy
    update = {
      strategy = "rolling";  # rolling | canary | blue-green
      maxParallel = 1;
      canary = 1;
      minHealthyTime = 10;   # seconds
      healthyDeadline = 300; # seconds
      autoRevert = true;
      autoPromote = false;   # auto-promote canaries when healthy
      progressDeadline = 600; # overall deployment timeout (optional)
      healthCheck = "checks"; # checks | taskStates | manual
    };

    # Local restart policy
    restart = {
      attempts = 2;
      intervalSecs = 1800;
      delaySecs = 15;
      mode = "fail";  # fail | delay
    };

    # Cross-node reschedule policy
    reschedule = {
      delaySecs = 30;
      delayFunction = "exponential";  # constant | exponential | fibonacci
      maxDelaySecs = 3600;
      # attempts = null;  # null = unlimited (default for service)
    };

    # Migration policy for node drain
    migrate = {
      maxParallel = 1;
      minHealthyTime = 10;
      healthyDeadline = 300;
    };
  };
};
```

## Machine Configuration

Each machine defines its address, labels, capacity, and optional taints:

```nix
machines.app-1 = {
  targetHost = "10.0.1.1";
  pool = "default";            # Node pool membership (default: "default")
  labels = {
    role = "app";
    zone = "us-east-1a";
    tier = "fast";
  };
  capacity = {
    cpu = 8000;     # millicores
    memory = 16384; # MB
    disk = 100000;  # MB
  };
  reserved = {                  # Reserved for OS/system use
    cpu = 500;
    memory = 512;
  };
  taints = [                    # Repel non-tolerating services
    { key = "dedicated"; value = "api"; effect = "noSchedule"; }
  ];
};
```

## Node Pool Configuration

Node pools group machines with shared properties:

```nix
nodePools.compute = {
  labels = { tier = "compute-optimized"; };
  schedulerAlgorithm = "binpack";  # binpack | spread
  memoryOversubscription = false;
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

## Periodic Jobs

Batch jobs can run on a cron schedule:

```nix
services.nightly-backup = {
  command = "${pkgs.backup}/bin/run";
  scheduling = {
    type = "batch";
    periodic = {
      cron = "0 3 * * *";          # daily at 3 AM
      timeZone = "UTC";
      concurrencyPolicy = "forbid"; # allow | forbid | replace
      successfulJobsHistoryLimit = 3;
      failedJobsHistoryLimit = 1;
    };
  };
};
```

## Job Types

| Type | Behavior |
|------|----------|
| `service` | Long-running, replicated across selected machines |
| `stateful` | Sticky placement, migrates only when necessary |
| `system` | Runs on every machine matching constraints |
| `batch` | Run-to-completion, exits when done |
| `sysbatch` | Runs once on every matching machine, then completes |

## Update Strategies

| Strategy | Behavior |
|----------|----------|
| `rolling` | Replace instances in batches of `maxParallel`, health-gated |
| `canary` | Deploy to one instance first, verify health, then roll out |
| `blue-green` | Deploy all new instances, verify health, then switch traffic |

## Constraint Operators

| Operator | Meaning |
|----------|---------|
| `=` / `==` | Attribute equals value |
| `!=` | Attribute does not equal value |
| `in` | Attribute is one of comma-separated values |
| `not_in` | Attribute is not one of comma-separated values |
| `>`, `>=`, `<`, `<=` | Numeric/lexical comparison |
| `regexp` | RE2 regular expression match |
| `is_set` | Attribute exists (value ignored) |
| `is_not_set` | Attribute does not exist |
| `set_contains` | Attribute (comma-separated) contains all listed values |
| `set_contains_any` | Attribute contains any listed value |
| `version` / `semver` | Semantic version comparison |
| `distinct_hosts` | No two instances on same machine (hard constraint) |

## Taint Effects

| Effect | Behavior |
|--------|----------|
| `noSchedule` | Don't place services that don't tolerate the taint |
| `preferNoSchedule` | Scoring penalty for non-tolerating services |
| `noExecute` | Evict running non-tolerating services |
