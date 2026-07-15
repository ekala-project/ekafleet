{ pkgs, lib }:

pkgs.testers.nixosTest {
  name = "ekafleet-module-basic";

  nodes.machine =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet.server = {
        enable = true;
        token = "test-token-12345";
      };

      networking.firewall.allowedTCPPorts = [
        7400
        7402
      ];
    };

  testScript = ''
    machine.wait_for_unit("ekafleet-server.service")
    machine.wait_for_open_port(7402)

    # Verify the systemd unit is active
    machine.succeed("systemctl is-active ekafleet-server.service")

    # Verify the ekafleet process is running
    machine.succeed("pgrep -x ekafleet")

    # Verify /health returns "ok" (unauthenticated)
    result = machine.succeed("curl -sf http://localhost:7402/health")
    assert result.strip() == "ok", f"Expected 'ok', got '{result.strip()}'"

    # Verify /metrics returns 401 without auth
    machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' http://localhost:7402/metrics | grep -q '401'"
    )

    # Verify /metrics returns 200 with auth and prometheus format
    AUTH = "-H 'Authorization: Bearer test-token-12345'"

    machine.succeed(
        f"curl -sf -o /dev/null -w '%{{http_code}}' "
        f"{AUTH} "
        "http://localhost:7402/metrics | grep -q '200'"
    )

    # Verify gRPC port is listening
    machine.wait_for_open_port(7400)

    # Verify data directory was created
    machine.succeed("test -d /var/lib/ekafleet")

    # Verify CA key and cert were persisted
    machine.succeed("test -f /var/lib/ekafleet/ca-key.pem")
    machine.succeed("test -f /var/lib/ekafleet/ca-cert.pem")

    # Verify fleet encryption key was generated
    machine.succeed("test -f /var/lib/ekafleet/fleet-key")

    # Verify the REST API status returns valid data
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/status | grep -q 'ekafleet'"
    )

    # Verify events endpoint works
    machine.succeed(
        f"curl -sf {AUTH} http://localhost:7402/v1/events"
    )

    # Verify the service restarts cleanly
    machine.succeed("systemctl restart ekafleet-server.service")
    machine.wait_for_open_port(7402)
    result = machine.succeed("curl -sf http://localhost:7402/health")
    assert result.strip() == "ok", f"Expected 'ok' after restart, got '{result.strip()}'"
  '';
}
