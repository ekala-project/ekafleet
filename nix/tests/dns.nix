{ pkgs, lib }:

# Fleet DNS and config templates on two mesh nodes:
#
#   the server turns assignments, replica status and mesh addresses into a
#   record snapshot per node → each agent answers on 127.0.0.1:53 (the host's
#   first nameserver) for `<svc>.service` and `<node>.node`, and on the
#   bridge gateway inside each namespace network, where the namespace's own
#   services are visible too.
let
  inherit (pkgs) coreutils;

  # No derivations: the services run coreutils, which every node has.
  fleetFlake = pkgs.writeTextDir "flake.nix" ''
    {
      outputs = _: {
        fleet = {
          name = "dns-test";
          domain = "fleet.internal";
          machines.alpha = {
            targetHost = "alpha";
            capacity = { cpu = 2000; memory = 1024; };
          };
          machines.beta = {
            targetHost = "beta";
            capacity = { cpu = 2000; memory = 1024; };
          };
          services.web = {
            command = "${coreutils}/bin/sleep infinity";
            ports.http.port = 8080;
            # SIGCONT: a reload signal sleep(1) survives.
            templates.peers = {
              destPath = "/etc/web/peers";
              source = "peers={{ services \"web\" }} node={{ meta.node }}";
              changeSignal = "SIGCONT";
            };
            resources = { cpu.request = 100; memory.request = 64; };
            scheduling = {
              replicas = 2;
              update = { minHealthyTime = 0; healthyDeadline = 60; };
            };
          };
          services.db = {
            namespace = "acme";
            command = "${coreutils}/bin/sleep infinity";
            ports.pg.port = 5432;
            resources = { cpu.request = 100; memory.request = 64; };
            scheduling = {
              replicas = 1;
              update = { minHealthyTime = 0; healthyDeadline = 60; };
            };
          };
        };
      };
    }
  '';
  flakeLock = pkgs.writeText "flake.lock" (
    builtins.toJSON {
      nodes.root = { };
      root = "root";
      version = 7;
    }
  );

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

      environment.systemPackages = [
        pkgs.dig
        pkgs.iproute2
      ];
    };
in
pkgs.testers.nixosTest {
  name = "ekafleet-dns";

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

      nix.settings = {
        experimental-features = [
          "nix-command"
          "flakes"
        ];
        flake-registry = "";
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

      def answers(machine, name, kind="A", at="127.0.0.1", netns=None):
          prefix = f"ip netns exec {netns} " if netns else ""
          out = machine.succeed(f"{prefix}dig +short +time=2 +tries=1 @{at} {name} {kind}")
          return sorted(out.split("\n")[:-1]) if out.strip() else []

      def rcode(machine, name, at="127.0.0.1", netns=None):
          prefix = f"ip netns exec {netns} " if netns else ""
          return machine.succeed(
              f"{prefix}dig +time=2 +tries=1 @{at} {name} | grep -o 'status: [A-Z]*'"
          ).strip()

      start_all()
      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_open_port(7400)
      ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")

      with subtest("both agents join the mesh"):
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
          ips = {}
          for name, machine in AGENTS.items():
              machine.wait_until_succeeds("ip -4 addr show wg-fleet | grep -q 10.100.", timeout=90)
              ips[name] = mesh_ip(machine)

      with subtest("the host resolves node names through the agent"):
          for machine in AGENTS.values():
              machine.succeed("grep -m1 nameserver /etc/resolv.conf | grep -q 127.0.0.1")
              machine.wait_until_succeeds(
                  f"getent hosts beta.node.fleet.internal | grep -q {ips['beta']}", timeout=60
              )
              assert answers(machine, "alpha.node.fleet.internal") == [ips["alpha"]]
              assert rcode(machine, "nope.node.fleet.internal") == "status: NXDOMAIN"

      with subtest("apply deploys web to both nodes and db into acme"):
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${fleetFlake}/flake.nix ${flakeLock} /var/lib/fleet/")
          server.succeed("mv /var/lib/fleet/*-flake.lock /var/lib/fleet/flake.lock")
          server.succeed("chmod -R a+rX /var/lib/fleet")
          server.succeed(f"{CLI} apply --flake /var/lib/fleet --auto-approve")
          for machine in AGENTS.values():
              machine.wait_for_unit("ekafleet-web.service", timeout=120)
          db_host = None
          for _ in range(120):
              for name, machine in AGENTS.items():
                  if machine.execute("systemctl is-active ekafleet-db.service")[0] == 0:
                      db_host = name
              if db_host:
                  break
              alpha.sleep(1)
          assert db_host, "db never started"
          db_node = AGENTS[db_host]

      with subtest("services resolve to the mesh addresses of their replicas"):
          for machine in AGENTS.values():
              machine.wait_until_succeeds(
                  "test $(dig +short @127.0.0.1 web.service.fleet.internal | wc -l) = 2",
                  timeout=60,
              )
              assert answers(machine, "web.service.fleet.internal") == sorted(ips.values())
              assert answers(machine, "web.service.fleet.internal", "SRV") == [
                  "0 1 8080 alpha.node.fleet.internal.",
                  "0 1 8080 beta.node.fleet.internal.",
              ]
              machine.succeed("getent hosts web.service.fleet.internal")
              # Namespaced services are invisible on the host.
              assert rcode(machine, "db.service.fleet.internal") == "status: NXDOMAIN"

      def rendered(machine, service, dest):
          pid = machine.succeed(f"systemctl show -p MainPID --value ekafleet-{service}.service").strip()
          return pid, machine.succeed(f"cat /proc/{pid}/root{dest}").strip()

      both = ",".join(f"{ips[n]}:8080" for n in sorted(ips))
      with subtest("templates render service addresses into the service only"):
          for name, machine in AGENTS.items():
              machine.wait_until_succeeds(
                  "pid=$(systemctl show -p MainPID --value ekafleet-web.service); "
                  f"grep -qx 'peers={both} node={name}' /proc/$pid/root/etc/web/peers",
                  timeout=60,
              )
              # The host's own /etc is not written (at most an empty mount point).
              machine.succeed("test ! -s /etc/web/peers")

      with subtest("services in a namespace resolve against its gateway"):
          gateway = db_node.succeed(
              "ip netns exec ekafleet-acme ip -4 -o addr "
              "| grep -o '10\\.200\\.[0-9]*\\.1/' | head -1 | tr -d /"
          ).strip()
          assert gateway, "no acme gateway"
          db_node.wait_until_succeeds(
              f"ip netns exec ekafleet-acme dig +short @{gateway} db.service.fleet.internal "
              "| grep -q '^10\\.200\\.'",
              timeout=60,
          )
          # Fleet-wide names resolve there too.
          assert answers(
              db_node, "web.service.fleet.internal", at=gateway, netns="ekafleet-acme"
          ) == sorted(ips.values())
          # The service's /etc/resolv.conf points at the gateway.
          pid = db_node.succeed("systemctl show -p MainPID --value ekafleet-db.service").strip()
          db_node.succeed(f"grep -q 'nameserver {gateway}' /proc/{pid}/root/etc/resolv.conf")

      with subtest("records and templates follow the replicas"):
          pids = {n: rendered(m, "web", "/etc/web/peers")[0] for n, m in AGENTS.items()}
          server.succeed(f"{CLI} scale web 1 --server {SERVER}")
          alpha.wait_until_succeeds(
              "test $(dig +short @127.0.0.1 web.service.fleet.internal | wc -l) = 1",
              timeout=90,
          )
          survivor = next(
              n for n, m in AGENTS.items()
              if m.execute("systemctl is-active ekafleet-web.service")[0] == 0
          )
          machine = AGENTS[survivor]
          machine.wait_until_succeeds(
              "pid=$(systemctl show -p MainPID --value ekafleet-web.service); "
              f"grep -qx 'peers={ips[survivor]}:8080 node={survivor}' /proc/$pid/root/etc/web/peers",
              timeout=60,
          )
          # The change was signalled, not restarted.
          assert rendered(machine, "web", "/etc/web/peers")[0] == pids[survivor]
          machine.succeed("journalctl -u ekafleet-agent -o cat | grep -q 'Service notified of template change'")
    '';
}
