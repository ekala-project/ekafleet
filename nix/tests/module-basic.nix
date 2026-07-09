{ pkgs, lib }:

pkgs.testers.nixosTest {
  name = "ekafleet-module-basic";

  nodes.machine =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet = {
        enable = true;
        mode = "server";
        token = "test-token-12345";
      };

      networking.firewall.allowedTCPPorts = [
        7400
        7402
      ];
    };

  testScript = ''
    machine.wait_for_unit("ekafleet.service")
    machine.wait_for_open_port(7402)

    # Verify the systemd unit is active
    machine.succeed("systemctl is-active ekafleet.service")

    # Verify the ekafleet process is running
    machine.succeed("pgrep -x ekafleet")

    # Verify /health returns "ok" (unauthenticated)
    result = machine.succeed("curl -sf http://localhost:7402/health")
    assert result.strip() == "ok", f"Expected 'ok', got '{result.strip()}'"

    # Verify /metrics returns 401 without auth
    machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' http://localhost:7402/metrics | grep -q '401'"
    )

    # Verify /metrics returns 200 with auth
    machine.succeed(
        "curl -sf -o /dev/null -w '%{http_code}' "
        "-H 'Authorization: Bearer test-token-12345' "
        "http://localhost:7402/metrics | grep -q '200'"
    )

    # Verify gRPC port is listening
    machine.wait_for_open_port(7400)
  '';
}
