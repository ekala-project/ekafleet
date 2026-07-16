# Evaluate a raw fleet configuration through the typed option module and yield
# the checked `fleet` attrset ready for `builtins.toJSON` / `nix eval --json`.
#
# Usage (in a flake or example):
#
#   fleet = (import ./nix/lib/eval-fleet.nix { inherit lib; }) {
#     userConfig = (import ./fleet.nix { inherit pkgs; }).fleet;
#   };
#
# `userConfig` is the raw `fleet` attrset the user writes. It is checked
# against `fleet-module.nix`, so type errors, unknown fields, and missing
# required options surface here as Nix eval errors instead of downstream serde
# failures.
{ lib }:

{ userConfig }:

let
  evaluated = lib.evalModules {
    modules = [
      (import ./fleet-module.nix { inherit lib; })
      { fleet = userConfig; }
    ];
  };
in
evaluated.config.fleet
