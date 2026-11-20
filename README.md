# ekafleet

A single Rust binary that replaces the HashiCorp stack (Nomad + Consul + Vault) and supporting infrastructure tools for managing [ekaos](https://github.com/ekala-project/ekapkgs-roadmap) fleets.

## Two Modes

- **`ekafleet server`** — control plane: priority-based scheduling, RBAC, CA, secrets, DNS authority, deployment orchestration with disruption budgets, event tracking, REST API, encrypted persistent state with restore-on-boot, node attestation, namespace IP allocation
- **`ekafleet agent`** — data plane: service supervision with lifecycle hooks, liveness/readiness/startup probes, config templating, DNS resolver, secret injection, mesh networking, SPIFFE Workload API, L7/L4 proxy with circuit breaking, persistent volumes, per-namespace network isolation with VXLAN overlay

Server mode embeds all agent capabilities and can run workloads directly.

## What It Replaces

| Tool | ekafleet Subsystem |
|------|-------------------|
| Nomad | `scheduler` + `deployer` + `scaling` |
| Consul (DNS, Connect, KV) | `dns_authority` + `dns_resolver` + `wireguard` + `certs` + `state` |
| Vault (KV, PKI, Dynamic) | `secrets_store` + `ca_root` + `certs` |
| SPIRE | `ca_root` + `attestation` + `workload_api` (SPIFFE Workload API, node attestation) |
| cert-manager | `certs` (auto-renewal) |
| external-dns | `dns_authority` |
| nginx/Traefik | `proxy_l7` + `proxy_l4` (circuit breaking, retries) |
| deploy-rs | `deployer` + `nix_eval` |
| Cilium/Calico | `nftables` + `netns` + `vxlan` |

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

## Namespace Networking

Services can be isolated into namespaces with dedicated network stacks. Each non-default namespace gets its own Linux network namespace with a bridge and per-service veth pairs. Services in the same namespace can communicate freely; services in different namespaces are isolated by default.

```nix
services.customer-a-web = {
  command = "${pkgs.web}/bin/server";
  namespace = "customer-a";           # isolated network namespace
  ports.http.port = 8080;
};

services.customer-a-db = {
  command = "${pkgs.postgres}/bin/postgres";
  namespace = "customer-a";           # same namespace, reachable from web
};

services.customer-b-app = {
  namespace = "customer-b";           # different namespace, fully isolated
};
```

**How it works:**

- **Same node**: Services in the same namespace share a bridge (`10.200.{ns}.0/24`). The server assigns globally unique IPs via Raft so there are no conflicts.
- **Cross node**: When a namespace spans multiple nodes, VXLAN tunnels carry traffic through the WireGuard mesh (`10.100.0.0/16`). The server populates tunnel endpoints automatically from agent heartbeats.
- **DNS**: Namespace-scoped DNS records ensure `web.service.fleet.internal` resolves to the correct IP within each namespace. Fleet-wide records remain visible to all.
- **Default namespace**: Services without a `namespace` field (or `namespace = "default"`) use host networking, preserving backward compatibility for infrastructure services.

```
Node 1                                    Node 2
┌─────────────────────────┐              ┌─────────────────────────┐
│ netns: ekafleet-cust-a  │              │ netns: ekafleet-cust-a  │
│ ┌─────────────────────┐ │              │ ┌─────────────────────┐ │
│ │ br-a (10.200.1.1)   │ │              │ │ br-a (10.200.1.1)   │ │
│ │  ├─ web  10.200.1.2 │ │  VXLAN/WG   │ │  ├─ db   10.200.1.3 │ │
│ │  └─ vxlan (VNI 1)  ─┼─┼─────────────┼─┤  └─ vxlan (VNI 1)   │ │
│ └─────────────────────┘ │              │ └─────────────────────┘ │
│                         │              │                         │
│ wg-fleet 10.100.0.1/16  │              │ wg-fleet 10.100.0.2/16  │
└─────────────────────────┘              └─────────────────────────┘
```

## CLI

```
ekafleet dev         Local development mode (no TLS/WireGuard)
ekafleet server      Start control plane
ekafleet agent       Start data plane
ekafleet plan        Show desired-vs-actual diff
ekafleet apply       Execute plan (--watch for continuous)
ekafleet status      Fleet health overview (--output json for scripting)
ekafleet drain       Reschedule services off a machine
ekafleet rollback    Revert to previous generation
ekafleet scale       Manual replica scaling
ekafleet logs        Aggregate logs from replicas
ekafleet snapshot    Backup Raft state for disaster recovery
ekafleet restore     Restore from snapshot
ekafleet completions Generate shell completions (bash/zsh/fish)
```

## License

[MPL-2.0](LICENSE)
