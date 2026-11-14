{ pkgs, lib }:

# Deploying a service whose closure exists only on the server:
#
#   `ekafleet apply` → the server evaluates the fleet flake, builds the
#   service's derivation and roots it → the joined agent receives the store
#   paths and the cache key in its DesiredState, fetches the closure through
#   its loopback bridge from the server's signed binary cache (gRPC, mTLS),
#   and starts the service from it.
let
  inherit (pkgs) coreutils;

  # The flake builds `web` on the server. It has no inputs (the VMs are
  # offline), so its builder is the sandbox's /bin/sh, using builtins only.
  # The script refers to coreutils by plain path; the client has it.
  fleetFlake = pkgs.writeTextDir "flake.nix" ''
    {
      outputs = _: let
        web = derivation {
          name = "closure-test-web";
          system = "${pkgs.stdenv.hostPlatform.system}";
          builder = "/bin/sh";
          args = [ "-c" "echo 'exec ${coreutils}/bin/sleep infinity' > $out" ];
        };
      in {
        fleet = {
          name = "closure-test";
          domain = "fleet.internal";
          machines.client = {
            targetHost = "client";
            capacity = { cpu = 2000; memory = 1024; };
          };
          services.web = {
            command = "/bin/sh ''${web}";
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
  name = "ekafleet-deploy-closure";

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

  nodes.client =
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

      environment.systemPackages = [ pkgs.ekaos-fleet ];
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

      with subtest("the agent joins"):
          ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")
          client.succeed("mkdir -p /etc/ekafleet")
          client.succeed(f"cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}\nEOF")
          token = server.succeed(f"{CLI} token create --type agent --node client").strip()
          client.succeed(f"(umask 077; printf '%s' {token} > /etc/ekafleet/join-token)")
          client.systemctl("restart ekafleet-agent.service")
          server.wait_until_succeeds(
              "journalctl -u ekafleet-server -o cat | grep 'Agent connected' "
              "| grep -q 'node_id=client'",
              timeout=90,
          )

      with subtest("apply builds the service closure on the server"):
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${fleetFlake}/flake.nix ${flakeLock} /var/lib/fleet/")
          server.succeed("mv /var/lib/fleet/*-flake.lock /var/lib/fleet/flake.lock")
          server.succeed("chmod -R a+rX /var/lib/fleet")
          status, out = server.execute(f"{CLI} apply --flake /var/lib/fleet --auto-approve 2>&1")
          if status != 0:
              print(server.execute(
                  "journalctl -u nix-daemon -o cat | tail -40; "
                  "nix-store --realise /nix/store/*-closure-test-web.drv 2>&1 | tail -40"
              )[1])
          assert status == 0, out
          assert "Building 1 store paths" in out, out
          web = server.succeed(
              "find /var/lib/ekafleet-server/gcroots -type l -exec readlink {} \\; | grep closure-test-web"
          ).strip()
          client.fail(f"test -e {web}")

      with subtest("the agent fetches the closure from the server's cache and runs it"):
          client.wait_until_succeeds(f"test -f {web}", timeout=180)
          client.succeed(f"nix-store --verify-path {web}")
          client.wait_for_unit("ekafleet-web.service", timeout=60)
          client.succeed(f"systemctl show -p ExecStart ekafleet-web.service | grep -q {web}")
          client.succeed("journalctl -u ekafleet-agent -o cat | grep -q 'Service closures fetched'")
          # The fetched closure is rooted against garbage collection.
          client.succeed("nix-collect-garbage >/dev/null 2>&1")
          client.succeed(f"test -f {web}")
    '';
}
