# NixOS Module

ekafleet provides a NixOS module at `nix/module.nix` for declarative deployment on EkaOS and NixOS machines.

## Usage

```nix
{ inputs, ... }:
{
  imports = [ inputs.ekaos-fleet.nixosModules.default ];

  services.ekafleet = {
    enable = true;
    mode = "agent";
    token = "your-join-token";
    serverAddr = "10.0.0.1:7400";
  };
}
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable the ekafleet service |
| `mode` | enum | `"agent"` | Operating mode: `"server"` or `"agent"` |
| `token` | string | *(required)* | Authentication token |
| `serverAddr` | string | `""` | Server address (required for agent mode) |
| `dataDir` | path | `/var/lib/ekafleet` | Data directory for persistent state |
| `peers` | list of string | `[]` | Peer server addresses (server mode HA) |

## Server Mode

```nix
services.ekafleet = {
  enable = true;
  mode = "server";
  token = "fleet-admin-token";
  peers = [ "10.0.0.2:7400" "10.0.0.3:7400" ];
};
```

Starts ekafleet in server mode with:
- gRPC on `0.0.0.0:7400`
- HTTP API on `0.0.0.0:7402`
- Data stored in `/var/lib/ekafleet`

## Agent Mode

```nix
services.ekafleet = {
  enable = true;
  mode = "agent";
  token = "agent-join-token";
  serverAddr = "10.0.0.1:7400";
};
```

Starts ekafleet in agent mode, connecting to the specified server.

## Systemd Service

The module generates a systemd service `ekafleet.service` with:
- `Type=simple`
- `Restart=always`
- `RestartSec=5`
- State directory at the configured `dataDir`

## Integration with clan.lol / deploy-rs

Use your preferred machine provisioning tool to deploy the NixOS configuration containing the ekafleet module. Once the machine boots with ekafleet enabled, it joins the fleet automatically.

Example with flakes:

```nix
{
  inputs.ekaos-fleet.url = "github:your-org/ekaos-fleet";

  outputs = { self, nixpkgs, ekaos-fleet, ... }: {
    nixosConfigurations.app-1 = nixpkgs.lib.nixosSystem {
      modules = [
        ekaos-fleet.nixosModules.default
        {
          services.ekafleet = {
            enable = true;
            mode = "agent";
            token = "token-from-vault-or-sops";
            serverAddr = "server.fleet.internal:7400";
          };
        }
      ];
    };
  };
}
```
