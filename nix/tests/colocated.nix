{ pkgs, lib }:

# Server and agent on one host: the module points the agent at the local
# server over loopback with the fleet CA and mints its join token on first
# start. The agent rides out a server restart by reconnecting, and its own
# restarts reuse the node SVID without minting another token.
pkgs.testers.nixosTest {
  name = "ekafleet-colocated";

  nodes.machine =
    { ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      environment.etc."ekafleet-admin-token" = {
        text = "colocated-token";
        mode = "0400";
      };

      services.ekafleet.server = {
        enable = true;
        tokenFile = "/etc/ekafleet-admin-token";
      };
      services.ekafleet.agent = {
        enable = true;
        nodeName = "solo";
      };

      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.openssl
      ];
    };

  testScript = ''
    CLI = (
        "EKAFLEET_TOKEN=colocated-token "
        "EKAFLEET_CA_CERT=/var/lib/ekafleet-ca/ca-cert.pem "
        "EKAFLEET_SERVER=127.0.0.1:7400 ekafleet"
    )

    def connections():
        return int(machine.succeed(
            "journalctl -u ekafleet-server -o cat | grep 'Agent connected' "
            "| grep 'node_id=solo' | grep -c 'mtls=true' || true"
        ).strip())

    machine.wait_for_unit("ekafleet-server.service")

    with subtest("the local agent joins with a provisioned token"):
        machine.wait_until_succeeds("test -s /var/lib/ekafleet/node-svid.pem", timeout=90)
        machine.succeed(
            "openssl x509 -in /var/lib/ekafleet/node-svid.pem -noout -ext subjectAltName "
            "| grep -q 'URI:spiffe://fleet.internal/agent/solo'"
        )
        machine.wait_until_succeeds("[ $(journalctl -u ekafleet-server -o cat | grep 'Agent connected' | grep 'node_id=solo' | grep -c 'mtls=true') -ge 1 ]", timeout=60)
        machine.wait_until_succeeds(f"{CLI} status | grep -q solo", timeout=30)
        machine.succeed("[ \"$(stat -c %a /run/ekafleet/join-token)\" = 600 ]")

    with subtest("the agent reconnects after a server restart"):
        pid = machine.succeed("systemctl show -p MainPID --value ekafleet-agent").strip()
        before = connections()
        machine.systemctl("restart ekafleet-server.service")
        machine.wait_until_succeeds(f"[ $(journalctl -u ekafleet-server -o cat | grep 'Agent connected' | grep 'node_id=solo' | grep -c 'mtls=true') -gt {before} ]", timeout=120)
        assert machine.succeed("systemctl show -p MainPID --value ekafleet-agent").strip() == pid, "agent restarted"
        machine.wait_until_succeeds(f"{CLI} status | grep -q solo", timeout=30)

    with subtest("agent restarts reuse the SVID without a new token"):
        svid = machine.succeed("sha256sum /var/lib/ekafleet/node-svid.pem")
        before = connections()
        machine.systemctl("restart ekafleet-agent.service")
        machine.wait_for_unit("ekafleet-agent.service")
        machine.wait_until_succeeds(f"[ $(journalctl -u ekafleet-server -o cat | grep 'Agent connected' | grep 'node_id=solo' | grep -c 'mtls=true') -gt {before} ]", timeout=60)
        machine.fail("test -e /run/ekafleet/join-token")
        assert machine.succeed("sha256sum /var/lib/ekafleet/node-svid.pem") == svid
  '';
}
