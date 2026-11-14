{ pkgs, lib }:

# Two-node join workflow over the real network:
#
#   operator creates a join token bound to "client" (CLI over TLS + bearer,
#   no client certificate) → the client's agent attests with it and a
#   locally generated key → node SVID spiffe://fleet.internal/agent/client
#   (0400 key) → mTLS control stream. Restarts reuse the SVID; the spent
#   token, a token bound to another name, and bearer-token agents are all
#   refused. The HTTP API is also exercised across machines.
pkgs.testers.nixosTest {
  name = "ekafleet-server-agent";

  nodes.server =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      environment.etc."ekafleet-admin-token" = {
        text = "cluster-token";
        mode = "0400";
      };

      services.ekafleet.server = {
        enable = true;
        tokenFile = "/etc/ekafleet-admin-token";
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
    { nodes, ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      # Provisioned by the test script below; until then the agent exits
      # (no node SVID, no join token) and systemd retries it.
      services.ekafleet.agent = {
        enable = true;
        serverAddr = "${nodes.server.networking.primaryIPAddress}:7400";
        caCert = "/etc/ekafleet/ca.pem";
        joinTokenFile = "/etc/ekafleet/join-token";
      };

      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.jq
        pkgs.openssl
      ];
    };

  testScript =
    { nodes, ... }:
    let
      serverAddr = "${nodes.server.networking.primaryIPAddress}:7400";
    in
    ''
      SERVER = "${serverAddr}"
      CLI = (
          "EKAFLEET_TOKEN=cluster-token "
          "EKAFLEET_CA_CERT=/var/lib/ekafleet-ca/ca-cert.pem "
          f"EKAFLEET_SERVER={SERVER} ekafleet"
      )

      start_all()
      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_open_port(7400)
      server.wait_for_open_port(7402)

      with subtest("HTTP API across machines"):
          client.wait_for_unit("multi-user.target")
          client.succeed("curl -sf http://server:7402/health | grep -q 'ok'")
          AUTH = "-H 'Authorization: Bearer cluster-token'"
          client.succeed(
              f"curl -sf {AUTH} http://server:7402/v1/status | "
              "jq -e '.fleet_name == \"ekafleet\"'"
          )
          client.succeed(f"curl -sf -X PUT {AUTH} -d 'remote-value' http://server:7402/v1/kv/remote-key")
          client.succeed(f"curl -sf {AUTH} http://server:7402/v1/kv/remote-key | grep -q 'remote-value'")
          client.succeed(f"curl -sf {AUTH} http://server:7402/v1/events | jq -e 'type == \"array\"'")
          client.succeed(f"curl -sf {AUTH} -o /dev/null -w '%{{http_code}}' http://server:7402/metrics | grep -q '200'")

      with subtest("CLI talks gRPC with a bearer token and no client certificate"):
          server.succeed(f"{CLI} status")
          server.succeed("ekafleet token create | grep -qE '^[0-9a-f]{64}$'")
          # Join tokens are created by the server and need a node name.
          server.fail(f"{CLI} token create --type agent")

      ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")
      client.succeed("mkdir -p /etc/ekafleet")
      client.succeed(f"cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}\nEOF")

      with subtest("a token bound to another name cannot join"):
          other = server.succeed(f"{CLI} token create --type agent --node other").strip()
          assert len(other) == 64, other
          out = client.fail(
              f"ekafleet agent --join {SERVER} --node-name rogue --join-token {other} "
              "--ca-cert /etc/ekafleet/ca.pem --data-dir /tmp/rogue 2>&1"
          )
          assert "different node name" in out, out
          client.fail("test -e /tmp/rogue/node-svid.pem")

      with subtest("bearer-token agents are refused"):
          out = client.fail(
              f"ekafleet agent --join {SERVER} --node-name rogue --token cluster-token "
              "--ca-cert /etc/ekafleet/ca.pem --data-dir /tmp/rogue 2>&1"
          )
          assert "node SVID" in out, out

      with subtest("the agent joins with its one-time token"):
          token = server.succeed(f"{CLI} token create --type agent --node client --ttl 10m").strip()
          client.succeed(f"(umask 077; printf '%s' {token} > /etc/ekafleet/join-token)")
          client.systemctl("restart ekafleet-agent.service")
          client.wait_until_succeeds("test -s /var/lib/ekafleet/node-svid.pem", timeout=60)
          client.wait_for_unit("ekafleet-agent.service")
          client.succeed("[ \"$(stat -c %a /var/lib/ekafleet/node-svid-key.pem)\" = 400 ]")
          client.succeed(
              "openssl x509 -in /var/lib/ekafleet/node-svid.pem -noout -ext subjectAltName "
              "| grep -q 'URI:spiffe://fleet.internal/agent/client'"
          )
          server.wait_until_succeeds(
              "journalctl -u ekafleet-server -o cat | grep 'Agent connected' "
              "| grep 'node_id=client' | grep -q 'mtls=true'",
              timeout=60,
          )
          server.succeed("journalctl -u ekafleet-server -o cat | grep -q 'Node attested'")

      with subtest("the token is spent and restarts reuse the SVID"):
          out = client.fail(
              f"ekafleet agent --join {SERVER} --node-name client --join-token {token} "
              "--ca-cert /etc/ekafleet/ca.pem --data-dir /tmp/again 2>&1"
          )
          assert "already used" in out, out
          svid = client.succeed("sha256sum /var/lib/ekafleet/node-svid.pem")
          client.succeed("rm /etc/ekafleet/join-token")
          client.systemctl("restart ekafleet-agent.service")
          client.wait_for_unit("ekafleet-agent.service")
          server.wait_until_succeeds(
              "[ $(journalctl -u ekafleet-server -o cat | grep 'Agent connected' "
              "| grep 'node_id=client' | grep -c 'mtls=true') -ge 2 ]",
              timeout=60,
          )
          assert client.succeed("sha256sum /var/lib/ekafleet/node-svid.pem") == svid
    '';
}
