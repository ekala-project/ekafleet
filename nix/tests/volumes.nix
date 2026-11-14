{ pkgs, lib }:

# Persistent volumes on two mesh nodes:
#
#   a stateful service gets a node-local directory bind-mounted read-write;
#   snapshots are taken and restored on the node holding it; draining the
#   node moves the service with its data (the destination agent pulls it
#   from the source over the mesh with node-SVID mTLS), and the source
#   deletes its copy since `reclaimRetain` is off.
let
  inherit (pkgs) coreutils;

  fleetFlake = pkgs.writeTextDir "flake.nix" ''
    {
      outputs = _: {
        fleet = {
          name = "volumes-test";
          domain = "fleet.internal";
          machines.alpha = {
            targetHost = "alpha";
            capacity = { cpu = 2000; memory = 1024; };
          };
          machines.beta = {
            targetHost = "beta";
            capacity = { cpu = 2000; memory = 1024; };
          };
          services.db = {
            command = "${coreutils}/bin/sleep infinity";
            volumes = [
              {
                name = "data";
                mountPath = "/var/lib/db";
                sizeMb = 64;
                reclaimRetain = false;
              }
            ];
            resources = { cpu.request = 100; memory.request = 64; };
            scheduling = {
              type = "stateful";
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

      environment.systemPackages = [ pkgs.iproute2 ];
    };
in
pkgs.testers.nixosTest {
  name = "ekafleet-volumes";

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
      VOLUME = "/var/lib/ekafleet/volumes/db/data"
      SNAPSHOTS = "/var/lib/ekafleet/volume-snapshots/db/data"

      def main_pid(machine):
          return machine.succeed(
              "systemctl show -p MainPID --value ekafleet-db.service"
          ).strip()

      def in_service(machine, path):
          """Read a file through the service's own mount namespace."""
          return machine.succeed(f"cat /proc/{main_pid(machine)}/root{path}").strip()

      def running_on():
          for name, machine in AGENTS.items():
              if machine.execute("systemctl is-active ekafleet-db.service")[0] == 0:
                  return name
          return None

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
          for machine in AGENTS.values():
              machine.wait_until_succeeds("ip -4 addr show wg-fleet | grep -q 10.100.", timeout=90)

      with subtest("the service runs with its volume mounted read-write"):
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${fleetFlake}/flake.nix ${flakeLock} /var/lib/fleet/")
          server.succeed("mv /var/lib/fleet/*-flake.lock /var/lib/fleet/flake.lock")
          server.succeed("chmod -R a+rX /var/lib/fleet")
          server.succeed(f"{CLI} apply --flake /var/lib/fleet --auto-approve")
          source_name = None
          for _ in range(120):
              source_name = running_on()
              if source_name:
                  break
              alpha.sleep(1)
          assert source_name, "db never started"
          source = AGENTS[source_name]
          dest_name = next(n for n in AGENTS if n != source_name)
          dest = AGENTS[dest_name]

          source.succeed(f"test -d {VOLUME}")
          source.succeed(f"test $(stat -c %a {VOLUME}/..) = 700")
          # The service writes through its mount; the data lands in the volume.
          source.succeed(f"echo v1 > /proc/{main_pid(source)}/root/var/lib/db/state")
          assert source.succeed(f"cat {VOLUME}/state").strip() == "v1"

      with subtest("snapshots are taken, listed and restored on the node"):
          out = server.succeed(f"{CLI} volume snapshot create db data")
          assert f"on {source_name}" in out, out
          snapshot = out.split()[2]
          source.succeed(f"test -f {SNAPSHOTS}/{snapshot}/state")

          source.succeed(f"echo v2 > {VOLUME}/state")
          listing = server.succeed(f"{CLI} volume snapshot list db")
          assert snapshot in listing and source_name in listing, listing

          pid_before = main_pid(source)
          server.succeed(f"{CLI} volume snapshot restore db data {snapshot}")
          source.wait_until_succeeds("systemctl is-active ekafleet-db.service", timeout=60)
          assert main_pid(source) != pid_before, "restore did not restart the service"
          assert in_service(source, "/var/lib/db/state") == "v1"

          # Bad ids are refused by the agent, not interpreted as paths.
          server.fail(f"{CLI} volume snapshot restore db data ../../../etc")
          server.succeed(f"{CLI} volume snapshot delete db data {snapshot}")
          source.succeed(f"test ! -e {SNAPSHOTS}/{snapshot}")

      with subtest("draining moves the service and its data"):
          source.succeed(f"echo moved > {VOLUME}/state")
          source.succeed(f"mkdir -p {VOLUME}/sub && echo nested > {VOLUME}/sub/file")
          server.succeed(f"{CLI} volume snapshot create db data")
          server.succeed(f"{CLI} drain {source_name}")

          dest.wait_until_succeeds("systemctl is-active ekafleet-db.service", timeout=180)
          assert in_service(dest, "/var/lib/db/state") == "moved"
          assert in_service(dest, "/var/lib/db/sub/file") == "nested"
          source.wait_until_fails("systemctl is-active ekafleet-db.service", timeout=60)
          dest.succeed(
              "journalctl -u ekafleet-agent -o cat | grep -q 'Volumes imported'"
          )

      with subtest("the source deletes its copy and snapshots"):
          source.wait_until_succeeds(f"test ! -e {VOLUME}", timeout=60)
          source.succeed(f"test ! -e {SNAPSHOTS}")
          # Snapshots stay with the node that took them.
          assert "No snapshots." in server.succeed(f"{CLI} volume snapshot list db")
    '';
}
