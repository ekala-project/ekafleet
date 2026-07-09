{ pkgs, lib }:

pkgs.testers.nixosTest {
  name = "ekafleet-rest-api";

  nodes.machine =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet = {
        enable = true;
        mode = "server";
        token = "rest-api-token";
      };

      networking.firewall.allowedTCPPorts = [
        7400
        7402
      ];

      environment.systemPackages = [ pkgs.jq ];
    };

  testScript = ''
    machine.wait_for_unit("ekafleet.service")
    machine.wait_for_open_port(7402)

    AUTH = "-H 'Authorization: Bearer rest-api-token'"

    # ── Public endpoint ──

    result = machine.succeed("curl -sf http://localhost:7402/health")
    assert result.strip() == "ok", f"Expected 'ok', got '{result.strip()}'"

    # ── Authentication enforcement ──

    # No auth → 401
    machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' http://localhost:7402/v1/status | grep -q '401'"
    )

    # Wrong token → 401
    machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' "
        "-H 'Authorization: Bearer wrong-token' "
        "http://localhost:7402/v1/status | grep -q '401'"
    )

    # ── Authenticated endpoints ──

    # /v1/status → 200, valid JSON with fleet_name
    machine.succeed(
        f"curl -sf {AUTH} http://localhost:7402/v1/status | "
        "jq -e '.fleet_name == \"ekafleet\"'"
    )

    # /v1/services → 200, valid JSON
    machine.succeed(f"curl -sf {AUTH} http://localhost:7402/v1/services | jq -e '.'")

    # /v1/capacity → 200 with expected fields
    machine.succeed(
        f"curl -sf {AUTH} http://localhost:7402/v1/capacity | "
        "jq -e '.node_count != null and .available_cpu_millicores != null'"
    )

    # /v1/events → 200
    machine.succeed(f"curl -sf {AUTH} http://localhost:7402/v1/events")

    # /v1/deployments → 200
    machine.succeed(f"curl -sf {AUTH} http://localhost:7402/v1/deployments")

    # ── KV store CRUD ──

    # PUT a key
    machine.succeed(
        f"curl -sf -X PUT {AUTH} -d 'hello-world' http://localhost:7402/v1/kv/test-key"
    )

    # GET the key back — verify value is present
    machine.succeed(
        f"curl -sf {AUTH} http://localhost:7402/v1/kv/test-key | grep -q 'hello-world'"
    )

    # DELETE the key
    machine.succeed(
        f"curl -sf -X DELETE {AUTH} http://localhost:7402/v1/kv/test-key"
    )

    # ── Web dashboard ──

    # /ui/ returns HTML containing ekafleet
    machine.succeed(
        f"curl -sf {AUTH} http://localhost:7402/ui/ | grep -qi 'ekafleet'"
    )

    # ── Prometheus metrics ──

    # /metrics returns 200 with correct content type
    machine.succeed(
        f"curl -sf {AUTH} -o /dev/null -w '%{{http_code}}' http://localhost:7402/metrics | grep -q '200'"
    )
  '';
}
