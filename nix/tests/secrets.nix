{ pkgs, lib }:

# Static secrets on one agent:
#
#   a service declaring a secret is planned with a warning and held back by
#   the agent until `ekafleet secret set` stores a value → the value is
#   sealed in Raft, pushed under the agent's derived key, and appears at
#   /run/secrets/<name> inside the service only. A new value restarts the
#   service; deleting it removes the file.
let
  inherit (pkgs) coreutils;

  fleetFlake = pkgs.writeTextDir "flake.nix" ''
    {
      outputs = _: {
        fleet = {
          name = "secrets-test";
          domain = "fleet.internal";
          machines.alpha = {
            targetHost = "alpha";
            capacity = { cpu = 2000; memory = 1024; };
          };
          services.web = {
            command = "${coreutils}/bin/sleep infinity";
            secrets.api-key = { };
            templates.conf = {
              destPath = "/etc/web/conf";
              source = "key={{ secret \"api-key\" }}";
            };
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
in
pkgs.testers.nixosTest {
  name = "ekafleet-secrets";

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

  nodes.alpha =
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
    };

  testScript =
    { nodes, ... }:
    ''
      SERVER = "${nodes.server.networking.primaryIPAddress}:7400"
      ENV = (
          "EKAFLEET_TOKEN=cluster-token "
          "EKAFLEET_CA_CERT=/var/lib/ekafleet-ca/ca-cert.pem "
          f"EKAFLEET_SERVER={SERVER}"
      )
      CLI = f"{ENV} ekafleet"

      def pid():
          return alpha.succeed(
              "systemctl show -p MainPID --value ekafleet-web.service"
          ).strip()

      def inside(path):
          return alpha.succeed(f"cat /proc/{pid()}/root{path}").strip()

      def set_secret(value):
          server.succeed(
              f"printf '%s' {value} | {CLI} secret set web api-key --server {SERVER}"
          )

      start_all()
      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_open_port(7400)
      ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")

      with subtest("the agent joins"):
          alpha.succeed("mkdir -p /etc/ekafleet")
          alpha.succeed(f"cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}\nEOF")
          token = server.succeed(f"{CLI} token create --type agent --node alpha").strip()
          alpha.succeed(f"(umask 077; printf '%s' {token} > /etc/ekafleet/join-token)")
          alpha.systemctl("restart ekafleet-agent.service")
          alpha.wait_until_succeeds("ip -4 addr show wg-fleet | grep -q 10.100.", timeout=90)

      with subtest("plan and apply warn about the missing value"):
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${fleetFlake}/flake.nix ${flakeLock} /var/lib/fleet/")
          server.succeed("mv /var/lib/fleet/*-flake.lock /var/lib/fleet/flake.lock")
          server.succeed("chmod -R a+rX /var/lib/fleet")
          plan = server.succeed(f"{CLI} plan --flake /var/lib/fleet 2>&1")
          assert "declares secret 'api-key', which has no value" in plan, plan
          apply = server.succeed(f"{CLI} apply --flake /var/lib/fleet --auto-approve 2>&1")
          assert "api-key" in apply, apply
          listing = server.succeed(f"{CLI} secret list --server {SERVER}")
          assert "missing" in listing, listing

      with subtest("the service waits for its secret"):
          alpha.wait_until_succeeds(
              "journalctl -u ekafleet-agent -o cat | grep -q 'Service waits for its secrets'",
              timeout=120,
          )
          alpha.sleep(5)
          alpha.fail("systemctl is-active ekafleet-web.service")

      with subtest("setting the value starts it with the secret inside only"):
          set_secret("s3cret")
          alpha.wait_until_succeeds("systemctl is-active ekafleet-web.service", timeout=120)
          assert inside("/run/secrets/api-key") == "s3cret"
          assert inside("/etc/web/conf") == "key=s3cret"
          alpha.succeed(f"test -z \"$(ls -A /proc/{pid()}/root/run/secrets | grep -v '^api-key$')\"")
          # Not on the host's /run/secrets, and private in the agent's directory.
          alpha.succeed("test ! -e /run/secrets/api-key")
          assert alpha.succeed(
              "stat -c %a /run/ekafleet/secrets/web/api-key"
          ).strip() == "400"
          assert alpha.succeed("stat -c %a /run/ekafleet/secrets/web").strip() == "700"
          # The value never reaches the agent's journal.
          alpha.fail("journalctl -u ekafleet-agent -o cat | grep -q s3cret")
          server.fail("journalctl -u ekafleet-server -o cat | grep -q s3cret")

      with subtest("a new value restarts the service"):
          before = pid()
          set_secret("rotated")
          alpha.wait_until_succeeds(
              "p=$(systemctl show -p MainPID --value ekafleet-web.service); "
              "grep -qx rotated /proc/$p/root/run/secrets/api-key",
              timeout=60,
          )
          assert pid() != before
          assert inside("/etc/web/conf") == "key=rotated"
          listing = server.succeed(f"{CLI} secret list web --server {SERVER}")
          assert any(
              l.split()[:3] == ["web", "api-key", "2"] for l in listing.splitlines()
          ), listing

      with subtest("the value survives a server restart"):
          server.systemctl("restart ekafleet-server.service")
          server.wait_for_open_port(7400)
          server.wait_until_succeeds(
              f"{CLI} secret list web --server {SERVER} | grep -q ' set$'", timeout=60
          )

      with subtest("deleting the value removes the file"):
          server.succeed(f"{CLI} secret delete web api-key --server {SERVER}")
          alpha.wait_until_succeeds("test ! -e /run/ekafleet/secrets/web/api-key", timeout=60)
    '';
}
