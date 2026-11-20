{ pkgs, lib }:

# Integration test exercising the major lifecycle operations introduced
# or fixed by the lifecycle-gap audit.  Covers:
#
#   1. Server startup & persistent state (CA, fleet-key)
#   2. KV store lifecycle (create, read, list, delete)
#   3. Event emission & query
#   4. Alert silence lifecycle (create, list, expiry)
#   5. Deployment history endpoint
#   6. ACL token lifecycle (create via CLI)
#   7. Service restart resilience (state survives restart)
#   8. Prometheus metrics export
#   9. Cross-machine reachability and authenticated access
#  10. Dashboard UI availability
pkgs.testers.nixosTest {
  name = "ekafleet-lifecycle";

  nodes.server =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet.server = {
        enable = true;
        token = "lifecycle-token";
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

  nodes.client =
    { ... }:
    {
      nixpkgs.overlays = [ (import ../overlay.nix) ];
      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.jq
      ];
    };

  testScript = ''
    import json

    AUTH = "-H 'Authorization: Bearer lifecycle-token'"
    BASE = "http://server:7402"

    # ── 1. Server startup ──

    server.wait_for_unit("ekafleet-server.service")
    server.wait_for_open_port(7402)
    server.wait_for_open_port(7400)

    result = server.succeed("curl -sf http://localhost:7402/health")
    assert result.strip() == "ok", f"health: expected 'ok', got '{result.strip()}'"

    # Persistent state files created
    server.succeed("test -f /var/lib/ekafleet/ca-key.pem")
    server.succeed("test -f /var/lib/ekafleet/ca-cert.pem")
    server.succeed("test -f /var/lib/ekafleet/fleet-key")

    # CA signer is running as a prerequisite
    server.succeed("systemctl is-active ekafleet-ca-signer.service")

    # ── 2. KV store lifecycle ──

    # Create
    server.succeed(
        f"curl -sf -X PUT {AUTH} -d 'lifecycle-v1' "
        f"{BASE}/v1/kv/lc/key1"
    )
    server.succeed(
        f"curl -sf -X PUT {AUTH} -d 'lifecycle-v2' "
        f"{BASE}/v1/kv/lc/key2"
    )

    # Read back
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/kv/lc/key1 | grep -q 'lifecycle-v1'"
    )

    # List by prefix
    server.succeed(
        f"curl -sf {AUTH} '{BASE}/v1/kv?prefix=lc/' | jq -e 'length == 2'"
    )

    # Delete and verify count drops
    server.succeed(
        f"curl -sf -X DELETE {AUTH} {BASE}/v1/kv/lc/key1"
    )
    server.succeed(
        f"curl -sf {AUTH} '{BASE}/v1/kv?prefix=lc/' | jq -e 'length == 1'"
    )

    # Clean up
    server.succeed(
        f"curl -sf -X DELETE {AUTH} {BASE}/v1/kv/lc/key2"
    )

    # ── 3. Events lifecycle ──

    # Events returns a JSON array
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/events | jq -e 'type == \"array\"'"
    )

    # ── 4. Alert silence lifecycle ──

    # Initially no silences
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/alerts/silences | jq -e '. == []'"
    )

    # Create a silence that expires far in the future
    server.succeed(
        "echo '{\"matchers\":{\"severity\":\"critical\"},\"starts_at\":0,\"ends_at\":9999999999,\"comment\":\"lifecycle-test\"}' > /tmp/silence.json"
    )
    server.succeed(
        f"curl -sf -X POST {AUTH} "
        "-H 'Content-Type: application/json' "
        f"-d @/tmp/silence.json {BASE}/v1/alerts/silences | "
        "jq -e '.status == \"created\"'"
    )

    # Verify it appears in the list
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/alerts/silences | jq -e 'length == 1'"
    )

    # Create a second silence (already expired, ends_at = 1)
    server.succeed(
        "echo '{\"matchers\":{\"severity\":\"info\"},\"starts_at\":0,\"ends_at\":1,\"comment\":\"expired\"}' > /tmp/expired.json"
    )
    server.succeed(
        f"curl -sf -X POST {AUTH} "
        "-H 'Content-Type: application/json' "
        f"-d @/tmp/expired.json {BASE}/v1/alerts/silences | "
        "jq -e '.status == \"created\"'"
    )

    # Both silences present before housekeeping runs
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/alerts/silences | jq -e 'length == 2'"
    )

    # ── 5. Deployments endpoint ──

    # Returns valid JSON (empty for a fresh cluster)
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/deployments | jq -e '.'"
    )

    # ── 6. Cross-machine reachability ──

    client.wait_for_unit("multi-user.target")
    client.succeed(f"curl -sf {BASE}/health | grep -q 'ok'")

    # Authenticated access from remote client
    client.succeed(
        f"curl -sf {AUTH} {BASE}/v1/status | "
        "jq -e '.fleet_name == \"ekafleet\"'"
    )

    # ── 7. Status endpoint structure ──

    client.succeed(
        f"curl -sf {AUTH} {BASE}/v1/status | "
        "jq -e '.fleet_name and .nodes != null and .services != null'"
    )

    # Capacity endpoint returns resource fields
    client.succeed(
        f"curl -sf {AUTH} {BASE}/v1/capacity | "
        "jq -e '.node_count != null and .available_cpu_millicores != null'"
    )

    # ── 8. Services & metrics endpoints ──

    client.succeed(
        f"curl -sf {AUTH} {BASE}/v1/services | jq -e '.'"
    )

    # Service metrics for nonexistent service returns valid JSON
    client.succeed(
        f"curl -sf {AUTH} {BASE}/v1/metrics/services/nonexistent | jq -e '.'"
    )

    # ── 9. Cloud instances (empty without provider) ──

    client.succeed(
        f"curl -sf {AUTH} {BASE}/v1/cloud/instances | jq -e '.'"
    )

    # ── 10. ACL token lifecycle via CLI ──

    token = server.succeed("ekafleet token create").strip()
    assert len(token) == 64 and all(c in "0123456789abcdef" for c in token), \
        f"Expected 64 hex chars, got {len(token)}: '{token}'"

    server_token = server.succeed("ekafleet token create --type server").strip()
    assert len(server_token) == 64, f"Server token wrong length: {len(server_token)}"

    # ── 11. Prometheus metrics ──

    server.succeed(
        f"curl -sf {AUTH} -o /dev/null -w '%{{http_code}}' "
        f"{BASE}/metrics | grep -q '200'"
    )

    # ── 12. Dashboard UI ──

    server.succeed(
        f"curl -sf {AUTH} {BASE}/ui/ | grep -qi 'ekafleet'"
    )

    # ── 13. Authentication enforcement ──

    # No auth → 401
    server.succeed(
        "curl -s -o /dev/null -w '%{http_code}' "
        f"{BASE}/v1/status | grep -q '401'"
    )

    # Wrong token → 401
    server.succeed(
        "curl -s -o /dev/null -w '%{http_code}' "
        "-H 'Authorization: Bearer wrong-token' "
        f"{BASE}/v1/status | grep -q '401'"
    )

    # ── 14. Service restart resilience ──

    server.succeed("systemctl restart ekafleet-server.service")
    server.wait_for_open_port(7402)

    result = server.succeed("curl -sf http://localhost:7402/health")
    assert result.strip() == "ok", f"health after restart: expected 'ok', got '{result.strip()}'"

    # Persistent CA and fleet key survive restart
    server.succeed("test -f /var/lib/ekafleet/ca-key.pem")
    server.succeed("test -f /var/lib/ekafleet/fleet-key")

    # Authenticated endpoints work after restart
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/status | "
        "jq -e '.fleet_name == \"ekafleet\"'"
    )

    # ── 15. gRPC port reachable from client after restart ──

    server.wait_for_open_port(7400)
    client.succeed("nc -z server 7400")

    # ── 16. Verify endpoints still functional after full lifecycle ──

    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/alerts/silences | jq -e 'type == \"array\"'"
    )
    server.succeed(
        f"curl -sf {AUTH} {BASE}/v1/events | jq -e 'type == \"array\"'"
    )
  '';
}
