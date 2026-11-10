{ pkgs, lib }:

# Two-node test: the server runs from the NixOS module; a second machine joins
# it as an agent with a one-time join token. Covers token creation over the
# API, join-token attestation, mTLS with the issued node SVID, a stable node ID
# across restarts, token replay rejection, SWIM gossip between the two
# machines, SVID-signed WireGuard peer distribution with traffic over the
# mesh, and HTTP API access across machines.
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
      networking.firewall.allowedUDPPorts = [
        7401
        51820
      ];

      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.jq
        pkgs.wireguard-tools
      ];
    };

  nodes.client =
    { ... }:
    {
      nixpkgs.overlays = [ (import ../overlay.nix) ];
      networking.firewall.allowedUDPPorts = [
        7401
        51820
      ];
      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.jq
        pkgs.openssl
        pkgs.wireguard-tools
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

    # Verify gRPC port is reachable from client (TLS handshake starts)
    server.wait_for_open_port(7400)
    client.succeed("nc -z server 7400")

    # ── Join-token attestation ──

    # The client trusts the fleet CA out of band (copied from the server).
    ca_pem = server.succeed("cat /var/lib/ekafleet/ca-cert.pem")
    client.succeed(f"mkdir -p /etc/ekafleet && cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}EOF")
    server_ip = client.succeed("getent ahostsv4 server | head -n1 | cut -d' ' -f1").strip()
    # Resolve each machine from the other: a host's own name may map to 127.0.0.2.
    client_ip = server.succeed("getent ahostsv4 client | head -n1 | cut -d' ' -f1").strip()
    CLI = f"EKAFLEET_TOKEN=cluster-token ekafleet --ca-cert /etc/ekafleet/ca.pem --server {server_ip}:7400"

    # Without the admin token, the server refuses to create a join token.
    client.fail(f"ekafleet --ca-cert /etc/ekafleet/ca.pem --server {server_ip}:7400 token create")

    # The admin creates a join token over the API; it is registered server-side.
    join_token = client.succeed(f"{CLI} token create").strip()
    assert len(join_token) == 64, f"Expected 64 hex chars, got {len(join_token)}"

    AGENT = (
        f"ekafleet agent --join {server_ip}:7400 --ca-cert /etc/ekafleet/ca.pem "
        "--data-dir /var/lib/ekafleet-agent"
    )
    client.succeed(
        f"systemd-run --unit=ekafleet-join -E EKAFLEET_JOIN_TOKEN={join_token} {AGENT}"
    )
    client.wait_until_succeeds("test -s /var/lib/ekafleet-agent/node-svid.pem", timeout=60)
    node_id = client.succeed("cat /var/lib/ekafleet-agent/node-id").strip()
    client.succeed(
        "openssl x509 -noout -ext subjectAltName -in /var/lib/ekafleet-agent/node-svid.pem "
        f"| grep -q 'URI:spiffe://fleet.internal/agent/{node_id}'"
    )
    assert client.succeed("stat -c %a /var/lib/ekafleet-agent/node-svid-key.pem").strip() == "600"
    server.wait_until_succeeds(
        f"journalctl -u ekafleet-server | grep -q 'Agent connected node_id={node_id}.*mtls=true'",
        timeout=60,
    )

    # The server hands the agent the gossip key over the control stream; the
    # agent starts SWIM, and the server admits it once its HMAC-signed pings
    # arrive.
    client.wait_until_succeeds("journalctl -u ekafleet-join | grep -q 'Gossip started'", timeout=60)
    server.wait_until_succeeds(
        f"journalctl -u ekafleet-server | grep -q 'Gossip member joined node_id={node_id}'",
        timeout=60,
    )

    # Restart without the join token: same node ID, same SVID, still mTLS.
    client.succeed("systemctl stop ekafleet-join")
    svid_before = client.succeed("sha256sum /var/lib/ekafleet-agent/node-svid.pem")
    client.succeed(f"systemd-run --unit=ekafleet-rejoin {AGENT}")
    client.wait_until_succeeds("journalctl -u ekafleet-rejoin | grep -q 'Node SVID loaded from disk'", timeout=60)
    assert client.succeed("cat /var/lib/ekafleet-agent/node-id").strip() == node_id
    assert client.succeed("sha256sum /var/lib/ekafleet-agent/node-svid.pem") == svid_before
    server.wait_until_succeeds(
        f"[ $(journalctl -u ekafleet-server | grep -c 'Agent connected node_id={node_id}.*mtls=true') -ge 2 ]",
        timeout=60,
    )

    # The consumed token cannot attest another node.
    out = client.fail(
        f"EKAFLEET_JOIN_TOKEN={join_token} ekafleet agent --join {server_ip}:7400 "
        "--ca-cert /etc/ekafleet/ca.pem --data-dir /var/lib/ekafleet-agent-2 2>&1"
    )
    assert "already consumed" in out, out

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

    # WireGuard mesh: a second agent runs on the server machine. Each agent
    # advertises its WireGuard key signed with its node SVID; the server
    # verifies and relays the adverts, and each agent verifies them again
    # before installing the peer.
    SERVER_CLI = (
        "EKAFLEET_TOKEN=cluster-token ekafleet --ca-cert /var/lib/ekafleet/ca-cert.pem "
        "--server 127.0.0.1:7400"
    )
    mesh_token = server.succeed(f"{SERVER_CLI} token create --node-id mesh-1").strip()
    server.succeed(
        f"systemd-run --unit=ekafleet-mesh-agent -E PATH=/run/current-system/sw/bin "
        f"-E EKAFLEET_JOIN_TOKEN={mesh_token} "
        "ekafleet agent --join 127.0.0.1:7400 --ca-cert /var/lib/ekafleet/ca-cert.pem "
        "--data-dir /var/lib/ekafleet-mesh-agent --node-id mesh-1 --gossip-listen off "
        f"--wireguard-endpoint {server_ip}:51820 --mesh-index 1"
    )
    client.succeed("systemctl stop ekafleet-rejoin")
    client.succeed(
        f"systemd-run --unit=ekafleet-mesh -E PATH=/run/current-system/sw/bin {AGENT} "
        f"--wireguard-endpoint {client_ip}:51820 --mesh-index 2"
    )

    server.wait_until_succeeds(
        "journalctl -u ekafleet-server | grep -q 'WireGuard peer advert accepted node_id=mesh-1'",
        timeout=60,
    )
    server.wait_until_succeeds(
        f"journalctl -u ekafleet-server | grep -q 'WireGuard peer advert accepted node_id={node_id}'",
        timeout=60,
    )
    client_key = client.succeed("wg show wg-fleet public-key").strip()
    server_key = server.succeed("wg show wg-fleet public-key").strip()
    server.wait_until_succeeds(f"wg show wg-fleet peers | grep -qF '{client_key}'", timeout=60)
    client.wait_until_succeeds(f"wg show wg-fleet peers | grep -qF '{server_key}'", timeout=60)
    # Traffic flows over the mesh addresses.
    client.wait_until_succeeds("ping -c1 -W2 10.100.0.1", timeout=60)
    server.succeed("ping -c1 -W2 10.100.0.2")

    # When an agent leaves, its peer is withdrawn from the others.
    server.succeed("systemctl stop ekafleet-mesh-agent")
    client.wait_until_succeeds(
        f"! wg show wg-fleet peers | grep -qF '{server_key}'", timeout=60
    )
  '';
}
