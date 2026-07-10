# Tutorial

This tutorial walks through a complete workflow: setting up a fleet, deploying services, scaling, inspecting, and performing system operations. It uses dev mode so you can follow along on a single machine.

## 1. Start Dev Mode

```bash
ekafleet dev
```

This starts a combined server + agent on localhost. Note the dev token printed at startup (`dev-token`).

Set the token for convenience:

```bash
export EKAFLEET_TOKEN=dev-token
```

## 2. Write a Fleet Configuration

Create `fleet.nix`:

```nix
{ pkgs }:
{
  fleet = {
    name = "tutorial";
    domain = "fleet.internal";

    nodePools.default = {
      labels = { env = "dev"; };
    };

    machines.local = {
      targetHost = "127.0.0.1";
      pool = "default";
      capacity = { cpu = 4000; memory = 8192; disk = 100000; };
      reserved = { cpu = 500; memory = 512; };
    };

    services.web = {
      command = "${pkgs.python3}/bin/python3 -m http.server 8080";
      ports.http = {
        port = 8080;
        healthCheck = { path = "/"; interval = 5; };
      };
      resources = {
        cpu = { request = 500; };
        memory = { request = 256; };
        cgroupControls = {
          cpuWeight = 100;
          memoryMax = 512;
          tasksMax = 64;
        };
      };
      scheduling = {
        replicas = 2;
        type = "service";
      };
    };
  };
}
```

## 3. Validate the Configuration

Before deploying, validate offline:

```bash
ekafleet validate --config fleet.nix
```

This evaluates the Nix expression and checks for errors (undefined pools, invalid resources, etc.) without contacting the server.

## 4. Plan the Deployment

See what would change:

```bash
ekafleet plan --config fleet.nix
```

Output shows each planned operation: services to create, update, or destroy.

## 5. Apply the Deployment

Deploy for real:

```bash
ekafleet apply --config fleet.nix --auto-approve
```

For continuous reconciliation (re-applies on drift, runs cloud autoscaling):

```bash
ekafleet apply --config fleet.nix --watch
```

## 6. Check Fleet Status

Overview of nodes, pools, and services:

```bash
ekafleet status
```

For machine-readable output:

```bash
ekafleet status --output json
```

## 7. Inspect Services

List all service placements:

```bash
ekafleet services
```

Deep systemd introspection (unit file, cgroup accounting):

```bash
ekafleet service inspect web
```

Stream logs from a service:

```bash
ekafleet logs web --follow --tail 50
```

Execute a command in a service's context:

```bash
ekafleet exec web -- ls /tmp
```

## 8. Node Operations

List all nodes with health and scheduling status:

```bash
ekafleet node list
```

Detailed info for a specific node:

```bash
ekafleet node status <NODE_ID>
```

Mark a node as unschedulable (cordon) before maintenance:

```bash
ekafleet node cordon <NODE_ID>
```

Drain all services off a node:

```bash
ekafleet drain <NODE_ID> --deadline 300
```

Re-enable scheduling:

```bash
ekafleet node uncordon <NODE_ID>
```

## 9. Scaling

Manual scaling:

```bash
ekafleet scale web 5
```

View resource usage across nodes:

```bash
ekafleet top nodes
```

View resource usage by service:

```bash
ekafleet top services
```

## 10. Deployment Management

List recent deployments:

```bash
ekafleet deployment list
```

View deployment history for a specific service:

```bash
ekafleet deployment status web
```

Promote a canary deployment:

```bash
ekafleet deployment promote web
```

Fail a stuck deployment (triggers rollback):

```bash
ekafleet deployment fail web
```

Rollback to a previous generation:

```bash
ekafleet rollback --all
```

## 11. Events and Observability

Query fleet events:

```bash
ekafleet events --limit 20
```

Filter by category:

```bash
ekafleet events --category scaling
ekafleet events --category deployment --service web
```

Check for state drift:

```bash
ekafleet drift
```

View cluster capacity:

```bash
ekafleet capacity
```

## 12. NixOS-Specific Operations

### Closure Analysis

Diff two Nix store paths to see what changed:

```bash
ekafleet closure diff /nix/store/abc...-system /nix/store/def...-system
```

Show the dependency tree of a store path:

```bash
ekafleet closure deps /nix/store/abc...-system --tree
```

Calculate total closure size:

```bash
ekafleet closure size /nix/store/abc...-system
```

### Generation Management

List NixOS generations on a machine:

```bash
ekafleet generation list <MACHINE>
```

Switch to a specific generation (activate + set boot default):

```bash
ekafleet generation switch <MACHINE> 42
```

Test a generation (activate without persisting to boot):

```bash
ekafleet generation test <MACHINE> 42
```

Diff two generations:

```bash
ekafleet generation diff <MACHINE> 41 42
```

### System-Wide Operations

Garbage-collect unused Nix store paths across the fleet:

```bash
ekafleet system gc
ekafleet system gc --dry-run    # preview only
```

Coordinated rolling reboot:

```bash
ekafleet system reboot --max-parallel 1
ekafleet system reboot --pool workers
```

Trigger NixOS rebuild:

```bash
ekafleet system rebuild <MACHINE>
ekafleet system rebuild --all
```

## 13. ACL Token Management

Create a new operator token:

```bash
ekafleet acl token create --role operator --description "CI pipeline"
```

List registered tokens:

```bash
ekafleet acl token list
```

Revoke a token:

```bash
ekafleet acl token revoke <TOKEN>
```

## 14. Disaster Recovery

Take a snapshot:

```bash
ekafleet snapshot --output backup.bin
```

Restore from a snapshot:

```bash
ekafleet restore backup.bin
```

Rolling upgrade with safety snapshot:

```bash
ekafleet upgrade /nix/store/new-ekafleet
```

## 15. Batch Jobs

Dispatch a parameterized batch job:

```bash
ekafleet dispatch etl-job db=production table=users limit=1000
```

## Next Steps

- [Fleet Configuration Reference](../reference/fleet-config.md) for all config options
- [CLI Cheat Sheet](../reference/cheat-sheet.md) for a quick reference
- [Scheduling Reference](../reference/scheduling.md) for constraint, affinity, and spread details
- [Cloud Providers](../operations/cloud-providers.md) for AWS/Azure/GCP autoscaling
