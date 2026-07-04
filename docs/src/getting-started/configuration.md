# Configuration

Fleet configuration is pure Nix. ekafleet consumes it by running `nix eval --json .#fleet` and operating on the resulting JSON.

## Fleet Structure

A fleet configuration has three top-level keys:

```nix
{
  fleet = {
    name = "production";       # Fleet name
    domain = "fleet.internal"; # DNS domain for service discovery

    services = { ... };        # Service definitions
    machines = { ... };        # Machine inventory
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

  # Resource requirements (millicores for CPU, MB for memory)
  resources = {
    cpu = { request = 500; limit = 1000; };
    memory = { request = 1024; limit = 2048; };
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
    type = "service";  # service | stateful | system | batch

    # Hard constraints (must be satisfied)
    constraints = [
      { attribute = "labels.role"; op = "="; value = "app"; }
    ];

    # Soft preferences (influence scoring)
    spread = { attribute = "labels.zone"; };
    affinity = [
      { attribute = "labels.tier"; op = "="; value = "fast"; weight = 50; }
    ];

    # Update strategy
    update = {
      strategy = "rolling";  # rolling | canary | blue-green
      maxParallel = 1;
      canary = 1;
      minHealthyTime = 10;   # seconds
      healthyDeadline = 300; # seconds
      autoRevert = true;
    };
  };
};
```

## Machine Configuration

Each machine defines its address, labels, and capacity:

```nix
machines.app-1 = {
  targetHost = "10.0.1.1";
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
};
```

## Job Types

| Type | Behavior |
|------|----------|
| `service` | Long-running, replicated across selected machines |
| `stateful` | Sticky placement, migrates only when necessary |
| `system` | Runs on every machine matching constraints |
| `batch` | Run-to-completion, exits when done |

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
