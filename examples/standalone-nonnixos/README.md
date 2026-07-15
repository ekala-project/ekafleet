# Standalone Fleet on Non-NixOS Hosts (Nix + systemd)

Run ekafleet on ordinary Linux distributions (Debian, Ubuntu, Fedora, Arch,
...) that have the **Nix package manager** and **systemd**, without NixOS and
without the NixOS module.

## What this demonstrates

- Deploying services on a non-NixOS host using only Nix + systemd
- Per-service supervision as generated systemd units (no full-OS activation)
- Service closures materialized directly from the Nix store
- `nix profile` fallback on flakes-only installs where `nix-env` is absent

## How it differs from the NixOS path

| | NixOS module | Standalone (this example) |
|---|---|---|
| Init system | systemd | systemd |
| Unit management | ekafleet agent | ekafleet agent |
| OS activation | `system.build.toplevel` + `activate` | none — per-service units only |
| Store paths | Nix store | Nix store |
| Host OS | NixOS / EkaOS | any Linux distro with Nix |

The agent supervises each service as an individual systemd unit and realizes
its runtime closure from the Nix store. It never performs a full-OS switch on a
foreign distro, so no `/run/current-system` or NixOS module is required.

## Prerequisites (each host)

- [Nix](https://nixos.org/download) installed (the flakes-enabled `nix` CLI is
  sufficient; `nix-env` is optional)
- `systemd` as the init system (`systemctl` available)
- the `ekafleet` binary:

  ```bash
  nix profile install github:ekala-project/ekaos-fleet
  ```

## Try it locally

```bash
ekafleet dev
ekafleet plan --config examples/standalone-nonnixos/fleet.nix --server 127.0.0.1:7400
```

## Deploy for real

```bash
# Start the server on one host (can itself be non-NixOS with Nix + systemd)
ekafleet server --data-dir /var/lib/ekafleet --domain fleet.internal

# On each worker host: install Nix, install ekafleet, then join
TOKEN=$(ekafleet token create --type=agent)
ekafleet agent --join server-ip:7400 --join-token "$TOKEN" --ca-cert /path/to/ca.pem

# Apply the configuration from the control host
ekafleet apply --config examples/standalone-nonnixos/fleet.nix
```

## Flakes-only hosts

On installs that ship only the modern `nix` CLI (no `nix-env` on `PATH`), the
agent automatically falls back to `nix profile install --profile ...` when it
needs to update a Nix profile. No extra configuration is required.
