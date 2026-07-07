# Deployments

ekafleet orchestrates deployments with dependency ordering, health gates, and automatic rollback.

## Deployment Flow

1. **Evaluate** — `nix eval` produces the desired fleet state
2. **Schedule** — Placement engine assigns services to machines
3. **Order** — Services are sorted into dependency tiers (data → app → web)
4. **Deploy** — Each tier is deployed according to its update strategy
5. **Verify** — Health checks gate progression between batches

## Update Strategies

### Rolling

Updates instances in batches of `maxParallel`. Each batch must pass the health gate before the next batch begins.

```nix
update = {
  strategy = "rolling";
  maxParallel = 1;
  minHealthyTime = 10;
  healthyDeadline = 300;
  autoRevert = true;
};
```

### Canary

Deploys to a single instance first. After the canary passes health checks, the remaining instances are updated via rolling deployment.

```nix
update = {
  strategy = "canary";
  canary = 1;
  minHealthyTime = 30;
  autoRevert = true;
};
```

### Blue-Green

Deploys all new instances simultaneously. Once all are healthy, traffic switches from old to new.

```nix
update = {
  strategy = "blue-green";
  minHealthyTime = 10;
  healthyDeadline = 300;
};
```

### Auto-promote

Canary deployments can auto-promote when the canary is healthy:

```nix
update = {
  strategy = "canary";
  canary = 1;
  autoPromote = true;
  autoRevert = true;
};
```

## Health Gates

Between deployment batches, ekafleet waits for:

1. **minHealthyTime** — Instances must be healthy for at least this duration
2. **healthyDeadline** — Maximum time to wait for instances to become healthy
3. **progressDeadline** — Overall deployment timeout (if set, the entire deployment fails if not complete within this window)

Health check modes:
- `checks` (default) — Health check endpoints must pass
- `taskStates` — Only requires the process to be running
- `manual` — Operator marks healthy via API

If the deadline expires before instances are healthy, the deployment fails. With `autoRevert = true`, ekafleet automatically rolls back to the previous version.

## Dependency Ordering

Services are deployed in topological order based on their `identity.allowedTargets`. Services that call other services are deployed after their dependencies:

```text
Tier 1: postgres, redis        (no dependencies)
Tier 2: api-server              (depends on postgres)
Tier 3: web-frontend            (depends on api-server)
```

## Manual Operations

```bash
# Preview changes
ekafleet plan --config fleet.nix

# Apply with confirmation
ekafleet apply --config fleet.nix

# Apply without confirmation
ekafleet apply --config fleet.nix --auto-approve

# Continuous reconciliation
ekafleet apply --config fleet.nix --watch

# Rollback a specific machine
ekafleet rollback app-1

# Rollback all machines
ekafleet rollback --all

# Rollback to a specific generation
ekafleet rollback --all --to=5
```
