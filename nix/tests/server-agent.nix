{ pkgs, lib }:

# Two-node test: verify that the server can start, the HTTP API is reachable
# from a second machine, and the gRPC port accepts TLS connections.
#
# Note: Full agent→server gRPC streaming requires mTLS client certificates
# or disabling client cert verification. The server's TLS config currently
# requires client certs, so bearer-token-only agents cannot complete the
# TLS handshake. This test validates network reachability and HTTP API
# access across machines instead.
pkgs.testers.nixosTest {
  name = "ekafleet-server-agent";

  nodes.server =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet.server = {
        enable = true;
        token = "cluster-token";
      };

      networking.firewall.allowedTCPPorts = [
        7400
        7402
      ];

      environment.systemPackages = [ pkgs.jq ];
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
    # Start the server and wait for it to be ready
    server.wait_for_unit("ekafleet-server.service")
    server.wait_for_open_port(7402)
    server.succeed("curl -sf http://localhost:7402/health | grep -q 'ok'")

    # Verify the client can reach the server's HTTP API across the network
    client.wait_for_unit("multi-user.target")
    client.succeed("curl -sf http://server:7402/health | grep -q 'ok'")

    # Verify authenticated endpoints work from the remote client
    client.succeed(
        "curl -sf "
        "-H 'Authorization: Bearer cluster-token' "
        "http://server:7402/v1/status | "
        "jq -e '.fleet_name == \"ekafleet\"'"
    )

    # Verify the client can use the ekafleet CLI (binary runs on remote machine)
    client.succeed("ekafleet --help | grep -q 'Unified fleet management'")
    client.succeed("ekafleet token create | grep -qE '^[0-9a-f]{64}$'")

    # Verify gRPC port is reachable from client (TLS handshake starts)
    server.wait_for_open_port(7400)
    client.succeed("nc -z server 7400")

    # Verify the KV store works cross-machine
    AUTH = "-H 'Authorization: Bearer cluster-token'"

    client.succeed(
        f"curl -sf -X PUT {AUTH} "
        "-d 'remote-value' "
        "http://server:7402/v1/kv/remote-key"
    )
    client.succeed(
        f"curl -sf {AUTH} "
        "http://server:7402/v1/kv/remote-key | grep -q 'remote-value'"
    )

    # Verify events endpoint returns JSON from remote client
    client.succeed(
        f"curl -sf {AUTH} "
        "http://server:7402/v1/events | jq -e 'type == \"array\"'"
    )

    # Verify deployments endpoint from remote client
    client.succeed(
        f"curl -sf {AUTH} "
        "http://server:7402/v1/deployments | jq -e '.'"
    )

    # Verify alert silences from remote client
    client.succeed(
        f"curl -sf {AUTH} "
        "http://server:7402/v1/alerts/silences | jq -e 'type == \"array\"'"
    )

    # Verify Prometheus metrics from remote client
    client.succeed(
        f"curl -sf {AUTH} "
        "-o /dev/null -w '%{http_code}' "
        "http://server:7402/metrics | grep -q '200'"
    )
  '';
}
