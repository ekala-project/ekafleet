# Pure-eval test for the typed fleet-config schema (nix/lib/fleet-module.nix).
#
# Asserts that every bundled example evaluates cleanly through the module and
# that the module actually enforces its schema (unknown fields and type
# mismatches are rejected at eval time). No VM is needed — this is a fast
# `runCommand` that succeeds only if all assertions hold.
{ pkgs, lib }:

let
  evalFleet = userConfig: (import ../lib/eval-fleet.nix { inherit lib; }) { inherit userConfig; };

  examplesDir = ../../examples;

  # Evaluate every examples/*/fleet.nix through the module and force the
  # result to JSON so any schema error surfaces here.
  exampleNames = builtins.attrNames (
    lib.filterAttrs (_: t: t == "directory") (builtins.readDir examplesDir)
  );

  evalExample =
    name:
    let
      raw = (import (examplesDir + "/${name}/fleet.nix") { inherit pkgs; }).fleet;
    in
    builtins.toJSON (evalFleet raw);

  exampleJsons = map evalExample exampleNames;

  # `builtins.tryEval` returns { success = false; } when evaluation throws,
  # which is how option-module type/unknown-field errors manifest.
  rejects = expr: !(builtins.tryEval (builtins.deepSeq expr expr)).success;

  # A config with an unknown field must be rejected (deny_unknown_fields).
  unknownFieldRejected = rejects (evalFleet {
    name = "bad";
    domain = "d";
    bogusTopLevel = true;
  });

  # A wrong-typed field must be rejected.
  wrongTypeRejected = rejects (evalFleet {
    name = "bad";
    domain = "d";
    services.api = {
      command = "run";
      scheduling.replicas = "not-a-number";
    };
  });

  # A valid minimal config must succeed and default-fill.
  minimalOk =
    (evalFleet {
      name = "ok";
      domain = "fleet.internal";
      services.api.command = "run";
    }).services.api.scheduling.replicas == 1;

  allChecks =
    (builtins.deepSeq exampleJsons true) && unknownFieldRejected && wrongTypeRejected && minimalOk;
in
assert allChecks;
pkgs.runCommand "ekafleet-fleet-module-test" { } ''
  echo "fleet-module schema checks passed for examples: ${lib.concatStringsSep ", " exampleNames}" > $out
''
