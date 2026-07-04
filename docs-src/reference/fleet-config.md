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
};
```

## PortConfig

```nix
ports.<name> = {
  port        = int;           # Port number (required)
  protocol    = "tcp";         # "tcp" or "udp" (default: tcp)
  hostname    = "string";      # For L7 proxy routing (optional)
  healthCheck = HealthCheckConfig;
};
```

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
};
```

## SchedulingConfig

```nix
scheduling = {
  replicas    = 3;                    # Number of instances (default: 1)
  type        = "service";            # Job type (default: "service")
  constraints = [ Constraint ];
  spread      = SpreadConfig;
  affinity    = [ AffinityConfig ];
  update      = UpdateConfig;
};
```

## Constraint

```nix
{
  attribute = "labels.role";    # Dot-separated attribute path
  op        = "=";              # Operator: =, ==, !=, in, not_in
  value     = "app";            # Expected value
}
```

## SpreadConfig

```nix
spread = {
  attribute = "labels.zone";   # Attribute to spread across
  weight    = 50;              # Score weight (default: 50)
};
```

## AffinityConfig

```nix
{
  attribute = "labels.tier";   # Attribute to match
  op        = "=";             # Operator
  value     = "fast";          # Expected value
  weight    = 50;              # Score weight (default: 50)
}
```

## UpdateConfig

```nix
update = {
  strategy        = "rolling";  # "rolling", "canary", or "blue-green" (default: "rolling")
  maxParallel     = 1;          # Instances to update at once (default: 1)
  canary          = 1;          # Canary count (for canary strategy)
  minHealthyTime  = 10;         # Seconds instance must be healthy (default: 10)
  healthyDeadline = 300;        # Seconds to wait for health (default: 300)
  autoRevert      = true;       # Rollback on failure (default: false)
};
```

## Machine

```nix
machines.<name> = {
  targetHost = "10.0.1.1";     # IP or hostname (required)
  labels = {                    # Arbitrary key-value labels
    role = "app";
    zone = "us-east-1a";
  };
  capacity = {
    cpu    = 8000;              # Millicores (default: 0)
    memory = 16384;             # MB (default: 0)
    disk   = 100000;            # MB (default: 0)
  };
};
```
