{ pkgs, lib }:

# Namespace networks reach outside networks and are reached by ingress:
#
#   - a namespaced service connects out through its namespace's uplink and
#     is masqueraded behind its node's address;
#   - it reaches neither its node's own ports, nor the mesh, nor another
#     namespace on the same node;
#   - its node reaches it on its namespace address;
#   - an ingress route on another node reaches it over the mesh, to which
#     the server routes the replica's namespace address.
let
  inherit (pkgs) python3;

  fleetFlake = pkgs.writeTextDir "flake.nix" ''
    {
      outputs = _: {
        fleet = {
          name = "namespace-network-test";
          domain = "fleet.internal";
          machines.alpha = {
            targetHost = "alpha";
            capacity = { cpu = 2000; memory = 1024; };
          };
          machines.beta = {
            targetHost = "beta";
            capacity = { cpu = 2000; memory = 1024; };
          };
          services.shop = {
            namespace = "acme";
            command = "${python3}/bin/python3 -m http.server 8081 --directory /srv/shop";
            ports.http.port = 8081;
            resources = { cpu.request = 100; memory.request = 64; };
            scheduling = {
              replicas = 1;
              constraints = [ { attribute = "name"; op = "="; value = "beta"; } ];
              update = { minHealthyTime = 0; healthyDeadline = 60; };
            };
          };
          services.rival = {
            namespace = "rival";
            command = "${python3}/bin/python3 -m http.server 8082 --directory /srv/shop";
            ports.http.port = 8082;
            resources = { cpu.request = 100; memory.request = 64; };
            scheduling = {
              replicas = 1;
              constraints = [ { attribute = "name"; op = "="; value = "beta"; } ];
              update = { minHealthyTime = 0; healthyDeadline = 60; };
            };
          };
          ingress.shop = {
            host = "shop.example.com";
            service = "shop";
            port = "http";
            nodes = [ "alpha" ];
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

  # A plain HTTP server on the host, outside any namespace.
  hostServer = port: {
    wantedBy = [ "multi-user.target" ];
    serviceConfig.ExecStart = "${python3}/bin/python3 -m http.server ${toString port} --directory /srv/host";
  };

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
        proxyOpenFirewall = true;
      };

      systemd.services.host-web = hostServer 9000;
      networking.firewall.allowedTCPPorts = [ 9000 ];
      systemd.tmpfiles.rules = [
        "d /srv/shop 0755 root root -"
        "f /srv/shop/index.html 0644 root root - hello from shop"
        "d /srv/host 0755 root root -"
        "f /srv/host/index.html 0644 root root - hello from host"
      ];

      environment.systemPackages = [
        pkgs.curl
        pkgs.iproute2
        pkgs.jq
        pkgs.nftables
        python3
      ];
    };
in
pkgs.testers.nixosTest {
  name = "ekafleet-namespace-network";

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
      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.curl
      ];
    };

  nodes.alpha = agentNode;
  nodes.beta = agentNode;

  # Stands in for the internet.
  nodes.outside =
    { ... }:
    {
      systemd.services.outside-web = hostServer 8000;
      networking.firewall.allowedTCPPorts = [ 8000 ];
      systemd.tmpfiles.rules = [
        "d /srv/host 0755 root root -"
        "f /srv/host/index.html 0644 root root - hello from outside"
      ];
    };

  testScript =
    { nodes, ... }:
    ''
      SERVER = "${nodes.server.networking.primaryIPAddress}:7400"
      ALPHA = "${nodes.alpha.networking.primaryIPAddress}"
      BETA = "${nodes.beta.networking.primaryIPAddress}"
      OUTSIDE = "${nodes.outside.networking.primaryIPAddress}"
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

      def replica_ip(netns):
          # The address the replica listens on: its veth inside the netns.
          return beta.succeed(
              f"ip netns exec {netns} ip -4 -o addr show "
              "| awk '$2 ~ /^vc-/ {print $4}' | cut -d/ -f1 | head -1"
          ).strip()

      def in_acme(cmd):
          return f"ip netns exec ekafleet-acme {cmd}"

      start_all()
      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_open_port(7400)
      outside.wait_for_open_port(8000)
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
              machine.wait_for_open_port(9000)

      with subtest("apply runs shop in acme and rival in rival, both on beta"):
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${fleetFlake}/flake.nix ${flakeLock} /var/lib/fleet/")
          server.succeed("mv /var/lib/fleet/*-flake.lock /var/lib/fleet/flake.lock")
          server.succeed("chmod -R a+rX /var/lib/fleet")
          server.succeed(f"{CLI} apply --flake /var/lib/fleet --auto-approve")
          beta.wait_until_succeeds("systemctl is-active ekafleet-shop.service", timeout=180)
          beta.wait_until_succeeds("systemctl is-active ekafleet-rival.service", timeout=180)
          beta.wait_until_succeeds(in_acme("curl -sf http://127.0.0.1:8081/"), timeout=60)
          shop_ip = replica_ip("ekafleet-acme")
          rival_ip = replica_ip("ekafleet-rival")
          assert shop_ip.startswith("10.200.") and rival_ip.startswith("10.200."), (shop_ip, rival_ip)
          beta.succeed("nft list table inet ekafleet-uplink")

      with subtest("a namespaced service reaches outside, masqueraded"):
          out = beta.succeed(in_acme(f"curl -sf --max-time 5 http://{OUTSIDE}:8000/"))
          assert "hello from outside" in out, out
          outside.wait_until_succeeds(
              f"journalctl -u outside-web -o cat | grep -q '^{BETA} '", timeout=30
          )
          outside.fail("journalctl -u outside-web -o cat | grep -q '^10\\.200\\.'")
          # The LAN counts as outside too.
          beta.succeed(in_acme(f"curl -sf --max-time 5 http://{ALPHA}:9000/"))

      with subtest("it reaches neither its host, nor the mesh, nor another namespace"):
          # Without the namespace, each of these is reachable.
          beta.succeed(f"curl -sf --max-time 5 http://{BETA}:9000/")
          beta.succeed(f"curl -sf --max-time 5 http://{ips['alpha']}:9000/")
          beta.succeed(f"curl -sf --max-time 5 http://{rival_ip}:8082/")
          for target in [
              f"{BETA}:9000",
              "169.254.1.1:9000",
              f"{ips['beta']}:9000",
              f"{ips['alpha']}:9000",
              f"{rival_ip}:8082",
          ]:
              beta.fail(in_acme(f"curl -sf --max-time 3 http://{target}/"))

      with subtest("its node reaches it on its namespace address"):
          out = beta.succeed(f"curl -sf --max-time 5 http://{shop_ip}:8081/")
          assert "hello from shop" in out, out

      with subtest("alpha's ingress proxy reaches it over the mesh"):
          alpha.wait_until_succeeds(f"ip route show {shop_ip} | grep -q wg-fleet", timeout=60)
          alpha.wait_until_succeeds(
              f"jq -e '.routes[0].backends == [\"{shop_ip}:8081\"]' /run/ekafleet/ingress-routes.json",
              timeout=60,
          )
          server.wait_until_succeeds(
              f"curl -sf -H 'Host: shop.example.com' http://{ALPHA}:8080/ | grep -q 'hello from shop'",
              timeout=60,
          )
          # Only the mesh forwards into a namespace, not the LAN.
          server.fail(f"ip route add {shop_ip}/32 via {BETA} && curl -sf --max-time 3 http://{shop_ip}:8081/")
    '';
}
