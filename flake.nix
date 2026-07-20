{
  description = "EkaOS Fleet";

  inputs = {
    utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
      treefmt-nix,
      fenix,
    }:
    let
      localOverlay = import ./nix/overlay.nix;
    in
    utils.lib.eachDefaultSystem (system: rec {
      legacyPackages = import nixpkgs {
        inherit system;
        overlays = [
          localOverlay
          fenix.overlays.default
        ];
      };

      packages = {
        default = legacyPackages.ekaos-fleet;
        ekaos-fleet = legacyPackages.ekaos-fleet;
      };
      devShells.default = legacyPackages.dev-shell;
      formatter =
        let
          fmt = treefmt-nix.lib.evalModule legacyPackages {
            programs.rustfmt.enable = true;
            programs.nixfmt.enable = true;
          };
        in
        fmt.config.build.wrapper;
    })
    // {
      overlays.default = localOverlay;

      nixosModules.default = import ./nix/module.nix;
      nixosModules.ekafleet = import ./nix/module.nix;

      # Typed fleet-configuration schema and eval helper. `fleetModule` is a
      # NixOS-style options module describing the fleet config; `evalFleet`
      # runs a raw `fleet` attrset through it and returns the checked result
      # ready for `builtins.toJSON` / `nix eval --json`.
      lib = {
        fleetModule = import ./nix/lib/fleet-module.nix;
        evalFleet =
          { lib, userConfig }:
          (import ./nix/lib/eval-fleet.nix { inherit lib; }) { inherit userConfig; };
        # Service catalog: curated templates for common service types.
        # Usage: `let catalog = ekafleet.lib.catalog { inherit pkgs; };`
        catalog = import ./nix/lib/catalog.nix;
      };
    }
    // (
      let
        testSystems = [
          "x86_64-linux"
          "aarch64-linux"
        ];
      in
      utils.lib.eachSystem testSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ localOverlay ];
          };
        in
        {
          checks = import ./nix/tests {
            inherit pkgs;
            inherit (pkgs) lib;
          };
        }
      )
    );
}
