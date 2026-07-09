{ pkgs, lib }:

pkgs.testers.nixosTest {
  name = "ekafleet-cli-operations";

  nodes.machine =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet = {
        enable = true;
        mode = "server";
        token = "cli-test-token";
      };

      networking.firewall.allowedTCPPorts = [
        7400
        7402
      ];

      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.jq
      ];
    };

  testScript = ''
    machine.wait_for_unit("ekafleet.service")
    machine.wait_for_open_port(7402)

    # --- CLI binary tests (no server connection needed) ---

    # Help output
    machine.succeed("ekafleet --help | grep -q 'Unified fleet management'")

    # Token generation produces 64 hex characters
    token = machine.succeed("ekafleet token create").strip()
    assert len(token) == 64, f"Expected 64 hex chars, got {len(token)}: '{token}'"

    # Shell completions
    machine.succeed("ekafleet completions bash | grep -q 'ekafleet'")

    # --- REST API queries (equivalent to CLI status/capacity/services) ---

    # Status endpoint returns valid JSON with fleet_name
    machine.succeed(
        "curl -sf "
        "-H 'Authorization: Bearer cli-test-token' "
        "http://localhost:7402/v1/status | jq -e '.fleet_name'"
    )

    # Capacity endpoint returns valid JSON with node_count
    machine.succeed(
        "curl -sf "
        "-H 'Authorization: Bearer cli-test-token' "
        "http://localhost:7402/v1/capacity | jq -e '.node_count != null'"
    )

    # Services endpoint returns valid JSON
    machine.succeed(
        "curl -sf "
        "-H 'Authorization: Bearer cli-test-token' "
        "http://localhost:7402/v1/services | jq -e '.'")

    # Events endpoint returns valid JSON
    machine.succeed(
        "curl -sf "
        "-H 'Authorization: Bearer cli-test-token' "
        "http://localhost:7402/v1/events | jq -e '.'")

    # Deployments endpoint returns valid JSON
    machine.succeed(
        "curl -sf "
        "-H 'Authorization: Bearer cli-test-token' "
        "http://localhost:7402/v1/deployments | jq -e '.'"
    )
  '';
}
