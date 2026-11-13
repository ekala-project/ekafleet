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
        sealPassphraseFile = "/etc/ekafleet-seal";
      };

      # Root-only; the units receive it via LoadCredential.
      environment.etc."ekafleet-seal" = {
        text = "vm-test-seal-passphrase\n";
        mode = "0400";
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

    # CA material belongs to the CA signer alone; server state to the server.
    machine.succeed("test -f /var/lib/ekafleet-ca/ca-key.pem")
    machine.succeed("test -f /var/lib/ekafleet-ca/ca-cert.pem")
    machine.succeed("stat -c '%U %a' /var/lib/ekafleet-ca | grep -qx 'ekafleet-ca 700'")
    machine.succeed("stat -c '%U %a' /var/lib/ekafleet-ca/ca-key.pem | grep -qx 'ekafleet-ca 600'")
    machine.succeed("test -f /var/lib/ekafleet-server/fleet-key")
    machine.succeed("stat -c '%U %a' /var/lib/ekafleet-server | grep -qx 'ekafleet 700'")

    # With a seal passphrase, no key is stored in plaintext.
    machine.fail("grep -q 'PRIVATE KEY' /var/lib/ekafleet-ca/ca-key.pem")
    machine.fail("grep -q 'PRIVATE KEY' /var/lib/ekafleet-ca/ca-intermediate-key.pem")
    machine.fail("journalctl -u ekafleet-ca-signer -u ekafleet-server | grep -q UNSEALED")

    # The CA socket is reachable by the server's group only.
    machine.succeed("stat -c '%G %a' /run/ekafleet-ca/ca.sock | grep -qx 'ekafleet-ca 660'")

    # Verify the REST API status returns valid data
    machine.succeed(
        f"curl -sf {AUTH} "
        "http://localhost:7402/v1/status | grep -q 'ekafleet'"
    )

    # Verify events endpoint works
    machine.succeed(
        f"curl -sf {AUTH} http://localhost:7402/v1/events"
    )

    # Both services restart cleanly and the CA survives (sealed keys reload).
    ca_before = machine.succeed("sha256sum /var/lib/ekafleet-ca/ca-cert.pem")
    machine.succeed("systemctl restart ekafleet-ca-signer.service")
    machine.succeed("systemctl restart ekafleet-server.service")
    machine.wait_for_open_port(7402)
    result = machine.succeed("curl -sf http://localhost:7402/health")
    assert result.strip() == "ok", f"Expected 'ok' after restart, got '{result.strip()}'"
    ca_after = machine.succeed("sha256sum /var/lib/ekafleet-ca/ca-cert.pem")
    assert ca_before == ca_after, "CA root changed across a restart"
  '';
}
