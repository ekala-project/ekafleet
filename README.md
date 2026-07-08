# ekafleet

A single Rust binary that replaces the HashiCorp stack (Nomad + Consul + Vault) and supporting infrastructure tools for managing [ekaos](https://github.com/ekala-project/ekapkgs-roadmap) fleets.

## Two Modes

- **`ekafleet server`** — control plane: priority-based scheduling, RBAC, CA, secrets, DNS authority, deployment orchestration with disruption budgets, event tracking, REST API, Raft consensus, node attestation
- **`ekafleet agent`** — data plane: service supervision with lifecycle hooks, liveness/readiness/startup probes, config templating, DNS resolver, secret injection, mesh networking, SPIFFE Workload API, L7/L4 proxy with circuit breaking, persistent volumes

Server mode embeds all agent capabilities and can run workloads directly.

## What It Replaces

| Tool | ekafleet Subsystem |
|------|-------------------|
| Nomad | `scheduler` + `deployer` + `scaling` |
| Consul (DNS, Connect, KV) | `dns_authority` + `dns_resolver` + `wireguard` + `certs` + `raft` |
| Vault (KV, PKI, Dynamic) | `secrets_store` + `ca_root` + `certs` |
| SPIRE | `ca_root` + `attestation` + `workload_api` (SPIFFE Workload API, node attestation) |
| cert-manager | `certs` (auto-renewal) |
| external-dns | `dns_authority` |
| nginx/Traefik | `proxy_l7` + `proxy_l4` (circuit breaking, retries) |
| deploy-rs | `deployer` + `nix_eval` |
| Cilium/Calico | `nftables` |

## Quick Start

```bash
# Install
nix profile install .#ekafleet

# Start server (with custom trust domain)
ekafleet server --data-dir /var/lib/ekafleet --domain fleet.internal

# Join an agent via SPIFFE node attestation (one-time join token)
TOKEN=$(ekafleet token create --type=agent)
ekafleet agent --join server:7400 --join-token $TOKEN --ca-cert /path/to/ca.pem

# Or join with legacy bearer token auth
ekafleet agent --join server:7400 --token $TOKEN

# Deploy
ekafleet apply --config ./fleet.nix
```

## Configuration

Fleet configuration is pure Nix, consumed via `nix eval`:

```nix
{ pkgs }:
{
  fleet = {
    name = "production";
    domain = "fleet.internal";

    # Node pools group machines with shared scheduling properties
    nodePools.default = { labels = { tier = "general"; }; };
    nodePools.compute = {
      labels = { tier = "compute-optimized"; };
      schedulerAlgorithm = "binpack";  # or "spread"
    };

    services.api-server = {
      command = "${pkgs.api-server}/bin/server";
      ports.http = {
        port = 8080;
        liveness.path = "/healthz";      # restart if this fails
        readiness.path = "/ready";       # stop routing if this fails
        startup = { path = "/ready"; interval = 2; };  # suppress liveness during init
      };
      resources = { cpu.request = 500; memory.request = 1024; };
      scheduling = {
        replicas = 3;
        type = "service";
        priority = 70;                   # higher = scheduled first
        pool = "default";                # soft pool preference
        spread = [{ attribute = "labels.zone"; }];
        constraints = [
          { attribute = "labels.role"; op = "="; value = "app"; }
        ];
        update = {
          strategy = "rolling";
          autoRevert = true;
          autoPromote = true;
        };
        disruptionBudget.minAvailable = 2;  # at least 2 must stay up during updates
      };
      lifecycle = {
        preStop = [ "/usr/bin/drain-connections" ];
        terminationGracePeriodSeconds = 60;
      };
      templates.config = {
        source = ''
          db_url={{ secret "db-url" }}
          cache={{ service "redis" }}
        '';
        destPath = "/etc/api-server/config.env";
      };
      volumes = [{
        name = "cache";
        mountPath = "/var/cache/api";
        sizeMb = 2048;
      }];
    };

    machines.app-1 = {
      targetHost = "10.0.1.1";
      pool = "default";
      labels = { role = "app"; zone = "us-east-1a"; };
      capacity = { cpu = 8000; memory = 16384; };
      reserved = { cpu = 500; memory = 512; };  # OS overhead
    };
  };
}
```

## CLI

```
ekafleet server    Start control plane
ekafleet agent     Start data plane
ekafleet plan      Show desired-vs-actual diff
ekafleet apply     Execute plan (--watch for continuous)
ekafleet status    Fleet health overview
ekafleet drain     Reschedule services off a machine
ekafleet rollback  Revert to previous generation
ekafleet scale     Manual replica scaling
ekafleet logs      Aggregate logs from replicas
```

## License

[MPL-2.0](LICENSE)
