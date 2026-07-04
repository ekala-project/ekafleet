# ekafleet

A single Rust binary that replaces the HashiCorp stack (Nomad + Consul + Vault) and supporting infrastructure tools for managing [ekaos](https://github.com/ekaos) fleets.

## Two Modes

- **`ekafleet server`** — control plane: scheduling, CA, secrets, DNS authority, deployment orchestration, Raft consensus
- **`ekafleet agent`** — data plane: service supervision, health checks, DNS resolver, secret injection, mesh networking, L7 proxy

Server mode embeds all agent capabilities and can run workloads directly.

## What It Replaces

| Tool | ekafleet Subsystem |
|------|-------------------|
| Nomad | `scheduler` + `deployer` + `scaling` |
| Consul (DNS, Connect, KV) | `dns_authority` + `dns_resolver` + `wireguard` + `certs` + `raft` |
| Vault (KV, PKI, Dynamic) | `secrets_store` + `ca_root` + `certs` |
| SPIRE | `ca_root` (Nix store path attestation) |
| cert-manager | `certs` (auto-renewal) |
| external-dns | `dns_authority` |
| nginx/Traefik | `proxy_l7` |
| deploy-rs | `deployer` + `nix_eval` |
| Cilium/Calico | `nftables` |

## Quick Start

```bash
# Install
nix profile install .#ekafleet

# Start server
ekafleet server --data-dir /var/lib/ekafleet

# Join an agent
TOKEN=$(ekafleet token create --type=agent)
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

    services.api-server = {
      command = "${pkgs.api-server}/bin/server";
      ports.http = { port = 8080; healthCheck.path = "/ready"; };
      resources = { cpu.request = 500; memory.request = 1024; };
      scheduling = { replicas = 3; type = "service"; };
    };

    machines.app-1 = {
      targetHost = "10.0.1.1";
      labels = { role = "app"; zone = "us-east-1a"; };
      capacity = { cpu = 8000; memory = 16384; };
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
