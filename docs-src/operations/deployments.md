# Deployments

ekafleet orchestrates deployments with dependency ordering, health gates, and automatic rollback. All deployment strategies work identically for both native Nix services and OCI container services.

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

## Disruption Budgets

Disruption budgets guarantee minimum availability during voluntary disruptions (rolling updates, drains). The deployer limits batch sizes to respect the budget:

```nix
scheduling = {
  replicas = 6;
  disruptionBudget = {
    minAvailable = 4;          # At least 4 instances must stay up
    # OR
    # maxUnavailable = 2;      # At most 2 can be down simultaneously
    # OR
    # maxUnavailable = "25%";  # Percentage of replicas
  };
};
```

If `maxParallel` exceeds the disruption budget's allowance, the effective batch size is reduced automatically. If the budget allows 0 disruptions (e.g., `minAvailable` equals the total replica count), the deployment is rejected.

## Deployment History

ekafleet tracks per-service deployment history including start time, completion time, strategy, instance count, store path, and outcome (succeeded, failed, rolled back). Query via the REST API:

```bash
# All deployments
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/deployments

# Per-service history
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/deployments/api-server
```

## Dependency Ordering

Services are deployed in topological order based on their `identity.allowedTargets`. Services that call other services are deployed after their dependencies:

```text
Tier 1: postgres, redis        (no dependencies)
Tier 2: api-server              (depends on postgres)
Tier 3: web-frontend            (depends on api-server)
```

## Event Webhooks

The server POSTs fleet events to webhooks as JSON. It never runs commands
from the fleet configuration.

```nix
webhooks = [
  {
    name = "deploys";
    url = "https://hooks.example.com/ekafleet";
    events = [ "deploy.*" "config.*" "drain.completed" ];
    secret = "hook-key";   # ekafleet secret set _fleet hook-key
  }
];
```

Event types:

| Type | When |
|------|------|
| `config.applied`, `config.rolled_back`, `config.failed` | A new revision is first reconciled |
| `config.rejected` | Admission rejects an apply |
| `deploy.started`, `deploy.succeeded`, `deploy.failed`, `deploy.rolled_back` | Per-service deployments |
| `drain.started`, `drain.completed` | A node is drained, and later has no instances left |
| `node.connected`, `node.left` | Agents connect, or are evicted after missing heartbeats |

Each body is the event (`id`, `type`, `timestamp`, `fleet`, `level`,
`category`, `service`, `node`, `message`). Headers include
`X-Ekafleet-Event` and `X-Ekafleet-Delivery` (the `id`). With `secret` set,
`X-Ekafleet-Signature: sha256=<hex>` carries the HMAC-SHA256 of the raw
body, keyed by that fleet-level secret. Receivers should check it. While
the secret has no value, no events are sent to that webhook. Failed
deliveries are retried with backoff (5 attempts).

## Admission

Plan and apply admit a configuration after validating it and before
building anything. A rejected apply never becomes a revision, and it is
recorded in the audit log. Admission checks, in order:

1. **Policies**: an `enforce` violation rejects; `warn` only warns.
2. **Namespace quotas**: each namespace's total requests, with every
   service counted at its most instances.
3. **Admission webhooks**, which see the change:

```nix
admissionWebhooks = [
  {
    name = "security-review";
    url = "https://policy.example.com/validate";
    failPolicy = "fail";     # or "ignore": failures only warn
    timeoutSeconds = 10;
  }
];
```

Each webhook receives a POST of an `AdmissionReview`:

```json
{
  "apiVersion": "ekafleet/v1", "kind": "AdmissionReview",
  "dryRun": false, "actor": "token:3f2a… (ci)", "flakeRef": "github:org/fleet/abc123",
  "fleet": "prod", "previousRevision": 41,
  "changes": {"created": ["web"], "updated": ["api"], "deleted": []},
  "services": { "...": "every service's configuration" },
  "namespaces": {"shop": {"cpu": 600, "memory": 256, "disk": 0, "instances": 4, "services": 2}}
}
```

It must answer 2xx with `{"allowed": true}`, or with `{"allowed": false,
"message": "reason"}` to reject. Any other answer, or no answer, rejects
the change unless `failPolicy = "ignore"`. Plan sends the same review with
`"dryRun": true`. Rollbacks restore an already-admitted revision and are
not reviewed again.

## Dispatch Jobs

Parameterized batch jobs can be triggered with arguments:

```bash
ekafleet dispatch backup db=production table=users limit=1000
```

Parameters are injected as `DISPATCH_<KEY>` environment variables (e.g., `DISPATCH_DB=production`). Only `batch` and `sysbatch` job types support dispatch.

Configure parameterized jobs in the fleet config:

```nix
services.backup = {
  scheduling = {
    type = "batch";
    parameterized = {
      requiredParams = [ "db" "table" ];
      optionalParams = [ "limit" ];
    };
  };
};
```

## Manual Operations

```bash
# Preview changes (the server evaluates the flake's `fleet` output)
ekafleet plan --flake github:my-org/my-fleet

# Apply with confirmation
ekafleet apply --flake github:my-org/my-fleet

# Apply without confirmation
ekafleet apply --flake github:my-org/my-fleet --auto-approve

# Apply and keep streaming the server's later reconciles
ekafleet apply --flake github:my-org/my-fleet --auto-approve --follow

# List configuration revisions
ekafleet history

# Re-apply the previous revision
ekafleet rollback

# Re-apply revision 5
ekafleet rollback --to 5
```

Each apply records a configuration revision in Raft: the locked flake
reference and the evaluated configuration. The server reconciles toward the
current revision on its own (every 30 seconds, on fleet events, and after
restarts), so the CLI does not need to stay connected. A rollback re-applies
an earlier revision's whole configuration as a new revision; the last 10 are
kept.
