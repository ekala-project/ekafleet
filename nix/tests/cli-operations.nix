{ pkgs, lib }:

pkgs.testers.nixosTest {
  name = "ekafleet-cli-operations";

  nodes.machine =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet.server = {
        enable = true;
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
    machine.wait_for_unit("ekafleet-server.service")
    machine.wait_for_open_port(7402)

    # --- CLI binary tests (no server connection needed) ---

    # Help output
    machine.succeed("ekafleet --help | grep -q 'Unified fleet management'")

    # Token generation produces 64 hex characters
    token = machine.succeed("ekafleet token create").strip()
    assert len(token) == 64, f"Expected 64 hex chars, got {len(token)}: '{token}'"

    # Shell completions (write to file first to avoid broken pipe panic in clap_complete)
    machine.succeed("ekafleet completions bash > /tmp/completions.bash && grep -q 'ekafleet' /tmp/completions.bash")

    # --- REST API queries (equivalent to CLI status/capacity/services) ---

    AUTH = "-H 'Authorization: Bearer cli-test-token'"

    # Status endpoint returns valid JSON with fleet_name
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/status | jq -e '.fleet_name'"
    )

    # Capacity endpoint returns valid JSON with node_count
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/capacity | jq -e '.node_count != null'"
    )

    # Services endpoint returns valid JSON
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/services | jq -e '.'")

    # Events endpoint returns valid JSON array
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/events | jq -e 'type == \"array\"'")

    # Deployments endpoint returns valid JSON
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/deployments | jq -e '.'"
    )

    # --- ACL token lifecycle via CLI ---

    # Create a viewer token via the CLI
    cli_token = machine.succeed(
        "ekafleet token create --type server"
    ).strip()
    assert len(cli_token) == 64, f"Expected 64 hex chars, got {len(cli_token)}"

    # --- Additional REST endpoints ---

    # Alerts/silences endpoint
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/alerts/silences | jq -e 'type == \"array\"'"
    )

    # Cloud instances endpoint
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/cloud/instances | jq -e '.'"
    )

    # Metrics for a specific service
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/metrics/services/test-svc | jq -e '.'"
    )
  '';
}
