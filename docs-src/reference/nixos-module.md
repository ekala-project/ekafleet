# NixOS Module

ekafleet provides a NixOS module at `nix/module.nix` for declarative deployment on EkaOS and NixOS machines.

The module always deploys the **process-isolated topology**: security-sensitive subsystems (CA signer, Workload API, proxy) run as separate systemd services with maximum hardening. There is no toggle for monolithic mode — the NixOS module is the production deployment path.

## Server Node

Enable `services.ekafleet.server` to deploy the control plane. This creates two systemd services:

- **ekafleet-ca-signer** — holds the CA private key in an isolated process with `PrivateNetwork=true`, no capabilities, and restricted syscalls
- **ekafleet-server** — the control plane (Raft, scheduler, API), connecting to the CA signer via Unix socket

```nix
{ inputs, ... }:
{
  imports = [ inputs.ekaos-fleet.nixosModules.default ];

  services.ekafleet.server = {
    enable = true;
    token = "fleet-admin-token";
    domain = "fleet.internal";
    peers = [ "10.0.0.2:7400" "10.0.0.3:7400" ];
  };
}
```

### Server Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable the control plane |
| `token` | string | *(required)* | Authentication token |
| `dataDir` | path | `/var/lib/ekafleet` | Data directory for persistent state |
| `peers` | list of string | `[]` | Peer server addresses for HA |
| `grpcListen` | string | `0.0.0.0:7400` | gRPC listen address |
| `httpListen` | string | `0.0.0.0:7402` | HTTP API listen address |
| `domain` | string | `fleet.internal` | SPIFFE trust domain |
| `caSocketPath` | string | `/run/ekafleet/ca.sock` | Unix socket for CA signer |

## Agent Node

Enable `services.ekafleet.agent` to deploy the data plane. This creates three systemd services:

- **ekafleet-agent** — the data plane (systemd unit management, WireGuard, nftables, secrets), runs as root
- **ekafleet-workload-api** — serves SPIFFE SVIDs to workloads, unprivileged with `PrivateNetwork=true`
- **ekafleet-proxy** — service mesh proxy, unprivileged with only `CAP_NET_BIND_SERVICE`

```nix
{ inputs, ... }:
{
  imports = [ inputs.ekaos-fleet.nixosModules.default ];

  services.ekafleet.agent = {
    enable = true;
    serverAddr = "10.0.0.1:7400";
    token = "agent-token";
  };
}
```

### Agent Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable the data plane |
| `serverAddr` | string | *(required)* | Server address to join |
| `token` | string | `""` | Authentication token (legacy) |
| `dataDir` | path | `/var/lib/ekafleet` | Data directory for persistent state |
| `domain` | string | `fleet.internal` | SPIFFE trust domain |
| `caCert` | path or null | `null` | CA certificate PEM for TLS verification |
| `workloadApiSocketPath` | string | `/run/ekafleet/workload-api.sock` | Workload API socket path |
| `proxyListen` | string | `0.0.0.0:8080` | Proxy listen address |

## Combined Node (Server + Agent)

A server that also runs workloads enables both:

```nix
services.ekafleet.server = {
  enable = true;
  token = "fleet-admin-token";
};
services.ekafleet.agent = {
  enable = true;
  serverAddr = "127.0.0.1:7400";
};
```

This creates all five systemd services on the same machine.

## Systemd Services

### Server-Side

| Service | User | Hardening |
|---------|------|-----------|
| `ekafleet-ca-signer` | DynamicUser | `PrivateNetwork`, no capabilities, `MemoryDenyWriteExecute`, `IPAddressDeny=any` |
| `ekafleet-server` | DynamicUser | `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `NoNewPrivileges` |

### Agent-Side

| Service | User | Hardening |
|---------|------|-----------|
| `ekafleet-agent` | root | `ProtectHome`, `PrivateTmp` (needs root for systemd, WireGuard, nftables) |
| `ekafleet-workload-api` | DynamicUser | `PrivateNetwork`, no capabilities, `ProtectSystem=strict` |
| `ekafleet-proxy` | DynamicUser | `CAP_NET_BIND_SERVICE` only, `ProtectSystem=strict`, `NoNewPrivileges` |

## Integration with Flakes

```nix
{
  inputs.ekaos-fleet.url = "github:your-org/ekaos-fleet";

  outputs = { self, nixpkgs, ekaos-fleet, ... }: {
    nixosConfigurations.server-1 = nixpkgs.lib.nixosSystem {
      modules = [
        ekaos-fleet.nixosModules.default
        {
          services.ekafleet.server = {
            enable = true;
            token = "token-from-vault-or-sops";
          };
        }
      ];
    };

    nixosConfigurations.app-1 = nixpkgs.lib.nixosSystem {
      modules = [
        ekaos-fleet.nixosModules.default
        {
          services.ekafleet.agent = {
            enable = true;
            serverAddr = "server-1.fleet.internal:7400";
            token = "token-from-vault-or-sops";
          };
        }
      ];
    };
  };
}
```
