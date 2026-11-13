# NixOS Module

ekafleet provides a NixOS module at `nix/module.nix` for declarative deployment on EkaOS and NixOS machines.

The module always deploys the **process-isolated topology**: security-sensitive subsystems (CA signer, proxy) run as separate systemd services with maximum hardening. There is no toggle for monolithic mode — the NixOS module is the production deployment path.

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
| `dataDir` | path | `/var/lib/ekafleet-server` | Control-plane state directory (must be under `/var/lib/`) |
| `sealPassphraseFile` | null or string | `null` | Passphrase file that seals key material at rest, delivered to both units via `LoadCredential` (may be root-only) |
| `peers` | list of string | `[]` | Peer server addresses for HA |
| `grpcListen` | string | `0.0.0.0:7400` | gRPC listen address |
| `httpListen` | string | `0.0.0.0:7402` | HTTP API listen address |
| `domain` | string | `fleet.internal` | SPIFFE trust domain |
| `caSocketPath` | string | `/run/ekafleet-ca/ca.sock` | Unix socket for CA signer (group `ekafleet-ca`, mode 0660) |

The two server units run as separate static users with disjoint state:

| Unit | User | State | Notes |
|------|------|-------|-------|
| `ekafleet-ca-signer` | `ekafleet-ca` | `/var/lib/ekafleet-ca` (0700) | Holds the CA keys; no network |
| `ekafleet-server` | `ekafleet` (+ group `ekafleet-ca`) | `dataDir` (0700) | Reaches the CA only via `caSocketPath` |

The agent runs as root and owns `/var/lib/ekafleet` and `/run/ekafleet`, so a combined server+agent node never shares key material between users.

## Agent Node

Enable `services.ekafleet.agent` to deploy the data plane. This creates two systemd services:

- **ekafleet-agent** — the data plane (systemd unit management, WireGuard, nftables, secrets), runs as root. It also serves the SPIFFE Workload API at `/run/ekafleet/workload-api.sock`; the socket is world-connectable and every call is attested from the caller's `SO_PEERCRED` PID and systemd cgroup.
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
