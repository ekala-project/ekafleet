# Installation

## From Nix Flake

The recommended way to install ekafleet:

```bash
nix profile install github:ekala-project/ekaos-fleet
```

Or add it to a NixOS configuration:

```nix
{
  inputs.ekaos-fleet.url = "github:ekala-project/ekaos-fleet";

  outputs = { self, nixpkgs, ekaos-fleet, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        # ekaos-fleet.nixosModules.default
        ({ pkgs, ... }: {
          environment.systemPackages = [ ekaos-fleet.packages.${pkgs.system}.default ];
        })
      ];
    };
  };
}
```

## From Source

```bash
git clone https://github.com/ekala-project/ekaos-fleet
cd ekaos-fleet
nix build .
# Binary is at ./result/bin/ekafleet
```

Or with cargo directly (requires protobuf compiler):

```bash
cargo build --release
# Binary is at ./target/release/ekafleet
```

## Development Shell

For contributors, the flake provides a development shell with all dependencies:

```bash
cd ekaos-fleet
nix develop
# or with direnv:
direnv allow
```

This provides Rust toolchain (via fenix), protobuf compiler, pkg-config, and OpenSSL.

## Verify Installation

```bash
ekafleet --help
```
