{ pkgs, lib }:

# Two agents join the WireGuard mesh:
#
#   on connect the server assigns each node an address in 10.100.0.0/16 →
#   the agent brings up wg-fleet and sends an advertisement signed with its
#   node SVID → the server checks it against the stream's certificate and the
#   assignment and sends every agent its peers → the nodes reach each other
#   over the tunnel.
let
  agentNode =
    { nodes, ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet.agent = {
        enable = true;
        serverAddr = "${nodes.server.networking.primaryIPAddress}:7400";
        caCert = "/etc/ekafleet/ca.pem";
        joinTokenFile = "/etc/ekafleet/join-token";
      };

      environment.systemPackages = [ pkgs.wireguard-tools ];
    };
in
pkgs.testers.nixosTest {
  name = "ekafleet-mesh";

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

      networking.firewall.allowedTCPPorts = [ 7400 ];
      environment.systemPackages = [ pkgs.ekaos-fleet ];
    };

  nodes.alpha = agentNode;
  nodes.beta = agentNode;

  testScript =
    { nodes, ... }:
    ''
      SERVER = "${nodes.server.networking.primaryIPAddress}:7400"
      CLI = (
          "EKAFLEET_TOKEN=cluster-token "
          "EKAFLEET_CA_CERT=/var/lib/ekafleet-ca/ca-cert.pem "
          f"EKAFLEET_SERVER={SERVER} ekafleet"
      )
      AGENTS = {"alpha": alpha, "beta": beta}

      def mesh_ip(machine):
          return machine.succeed(
              "ip -4 -o addr show wg-fleet | awk '{print $4}' | cut -d/ -f1"
          ).strip()

      start_all()
      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_open_port(7400)
      ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")

      with subtest("both agents join"):
          for name, machine in AGENTS.items():
              machine.succeed("mkdir -p /etc/ekafleet")
              machine.succeed(f"cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}\nEOF")
              token = server.succeed(
                  f"{CLI} token create --type agent --node {name}"
              ).strip()
              machine.succeed(
                  f"(umask 077; printf '%s' {token} > /etc/ekafleet/join-token)"
              )
              machine.systemctl("restart ekafleet-agent.service")
          for name in AGENTS:
              server.wait_until_succeeds(
                  "journalctl -u ekafleet-server -o cat "
                  f"| grep 'Mesh peer advertisement accepted' | grep -qE 'node_id=\"?{name}\"?( |$)'",
                  timeout=90,
              )

      with subtest("each node has a distinct mesh address and the other as its peer"):
          ips = {}
          for name, machine in AGENTS.items():
              machine.wait_until_succeeds("ip link show wg-fleet | grep -q UP", timeout=30)
              ips[name] = mesh_ip(machine)
              assert ips[name].startswith("10.100."), ips
          assert ips["alpha"] != ips["beta"], ips
          for name, machine in AGENTS.items():
              other = "beta" if name == "alpha" else "alpha"
              machine.wait_until_succeeds(
                  f"wg show wg-fleet allowed-ips | grep -q '{ips[other]}/32'",
                  timeout=60,
              )
              assert machine.succeed("wg show wg-fleet peers | wc -l").strip() == "1"
          # The private key never reaches argv or disk.
          alpha.fail("grep -rqs PrivateKey /var/lib/ekafleet")

      with subtest("the nodes reach each other through the tunnel"):
          alpha.wait_until_succeeds(f"ping -c1 -W2 {ips['beta']}", timeout=60)
          beta.succeed(f"ping -c1 -W2 {ips['alpha']}")
          alpha.succeed("wg show wg-fleet latest-handshakes | awk '{print $2}' | grep -vq '^0$'")

      with subtest("a restarted agent re-keys, keeps its address, and peers follow"):
          old_key = alpha.succeed("wg show wg-fleet public-key").strip()
          alpha.systemctl("restart ekafleet-agent.service")
          alpha.wait_until_succeeds(
              f"test \"$(wg show wg-fleet public-key)\" != {old_key}", timeout=60
          )
          assert mesh_ip(alpha) == ips["alpha"]
          new_key = alpha.succeed("wg show wg-fleet public-key").strip()
          beta.wait_until_succeeds(f"wg show wg-fleet peers | grep -qF {new_key}", timeout=60)
          beta.fail(f"wg show wg-fleet peers | grep -qF {old_key}")
          beta.wait_until_succeeds(f"ping -c1 -W2 {ips['alpha']}", timeout=60)
    '';
}
