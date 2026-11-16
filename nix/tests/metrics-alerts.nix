{ pkgs, lib }:

# Metrics and alerts, end to end:
#
#   the agent samples its node and scrapes a service's Prometheus endpoint
#   on the service's loopback, shipping both to the server every 15s; the
#   server evaluates the fleet config's alert rules per series and POSTs
#   Alertmanager (v4) webhooks when a series fires or resolves. Removing a
#   rule in a new revision resolves its alerts.
let
  inherit (pkgs) python3;

  # Records every POSTed body under /var/lib/hooks, in arrival order.
  receiver = pkgs.writeText "receiver.py" ''
    import http.server, os

    class Hook(http.server.BaseHTTPRequestHandler):
        count = 0

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            Hook.count += 1
            with open(f"/var/lib/hooks/{Hook.count:03}.json", "wb") as f:
                f.write(body)
            self.send_response(200)
            self.end_headers()

    os.makedirs("/var/lib/hooks", exist_ok=True)
    http.server.HTTPServer(("127.0.0.1", 9095), Hook).serve_forever()
  '';

  flakeLock = pkgs.writeText "flake.lock" (
    builtins.toJSON {
      nodes.root = { };
      root = "root";
      version = 7;
    }
  );

  downRule = ''
    ++ [
      {
        name = "ExporterDown";
        metric = "up";
        op = "lt";
        threshold = 1;
        forSeconds = 15;
        webhookUrl = "http://127.0.0.1:9095/hook";
      }
    ]
  '';

  mkFleet =
    withDownRule:
    pkgs.writeText "flake.nix" ''
      {
        outputs = _: {
          fleet = {
            name = "metrics-test";
            domain = "fleet.internal";
            machines.alpha = {
              targetHost = "alpha";
              capacity = { cpu = 2000; memory = 1024; };
            };
            services.exporter = {
              command = "${python3}/bin/python3 -m http.server 9100 --bind 127.0.0.1 --directory /srv/exporter";
              metrics.port = 9100;
              resources = { cpu.request = 100; memory.request = 64; };
              scheduling = {
                replicas = 1;
                update = { minHealthyTime = 0; healthyDeadline = 60; };
              };
            };
            alerts = [
              {
                name = "QueueBacklog";
                metric = "queue_depth";
                op = "gte";
                threshold = 10;
                forSeconds = 0;
                service = "exporter";
                severity = "critical";
                labels.team = "jobs";
                summary = "queue backlog";
                webhookUrl = "http://127.0.0.1:9095/hook";
              }
              {
                name = "NodeHasMemory";
                metric = "node_memory_total_bytes";
                threshold = 0;
                forSeconds = 0;
                node = "alpha";
              }
            ]
            ${lib.optionalString withDownRule downRule};
          };
        };
      }
    '';
in
pkgs.testers.nixosTest {
  name = "ekafleet-metrics-alerts";

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

      systemd.services.hook-receiver = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${python3}/bin/python3 ${receiver}";
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
        pkgs.jq
      ];
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
      import json

      SERVER = "${nodes.server.networking.primaryIPAddress}:7400"
      CLI = (
          "EKAFLEET_TOKEN=cluster-token "
          "EKAFLEET_CA_CERT=/var/lib/ekafleet-ca/ca-cert.pem "
          f"EKAFLEET_SERVER={SERVER} ekafleet"
      )
      AUTH = "-H 'Authorization: Bearer cluster-token'"

      def rest(path):
          return json.loads(server.succeed(f"curl -sf {AUTH} http://localhost:7402{path}"))

      def hooks():
          out = server.succeed(
              "for f in $(ls /var/lib/hooks 2>/dev/null); do cat /var/lib/hooks/$f; echo; done"
          )
          return [json.loads(line) for line in out.splitlines() if line.strip()]

      def wait_hook(alertname, status):
          """The first webhook payload for alertname with status."""
          def find():
              for hook in hooks():
                  if hook["groupLabels"]["alertname"] == alertname and hook["status"] == status:
                      return hook
              return None
          server.wait_until_succeeds(
              "cat /var/lib/hooks/* 2>/dev/null | "
              f"jq -se 'any(.[]; .groupLabels.alertname == \"{alertname}\" and .status == \"{status}\")'",
              timeout=120,
          )
          return find()

      def active():
          return {a["labels"]["alertname"]: a for a in rest("/v1/alerts")}

      def apply(with_down_rule):
          fleet = "${mkFleet true}" if with_down_rule else "${mkFleet false}"
          server.succeed(f"cp {fleet} /var/lib/fleet/flake.nix && chmod -R a+rX /var/lib/fleet")
          server.succeed(f"{CLI} apply --flake /var/lib/fleet --auto-approve 2>&1")

      def expose(text):
          alpha.succeed(f"printf '{text}' > /srv/exporter/metrics.tmp")
          alpha.succeed("mv /srv/exporter/metrics.tmp /srv/exporter/metrics")

      start_all()
      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_unit("hook-receiver.service")
      server.wait_for_open_port(7400)
      server.wait_for_open_port(9095)

      with subtest("the agent joins"):
          ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")
          alpha.succeed("mkdir -p /etc/ekafleet /srv/exporter")
          alpha.succeed(f"cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}\nEOF")
          token = server.succeed(f"{CLI} token create --type agent --node alpha").strip()
          alpha.succeed(f"(umask 077; printf '%s' {token} > /etc/ekafleet/join-token)")
          alpha.systemctl("restart ekafleet-agent.service")
          alpha.wait_until_succeeds("ip -4 addr show wg-fleet | grep -q 10.100.", timeout=90)

      with subtest("node metrics reach the server and node rules fire"):
          server.wait_until_succeeds(
              f"curl -sf {AUTH} 'http://localhost:7402/v1/query?metric=node_disk_usage_ratio&node=alpha' "
              "| jq -e '.value > 0'",
              timeout=60,
          )
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${flakeLock} /var/lib/fleet/flake.lock")
          expose("queue_depth{queue=\"a\"} 4\\nqueue_depth{queue=\"b\"} 8\\n")
          apply(with_down_rule=True)
          alpha.wait_for_unit("ekafleet-exporter.service")
          server.wait_until_succeeds(
              f"curl -sf {AUTH} http://localhost:7402/v1/alerts "
              "| jq -e 'any(.[]; .labels.alertname == \"NodeHasMemory\" and .labels.node == \"alpha\")'",
              timeout=60,
          )

      with subtest("a scraped service series fires its webhook"):
          # The two labelled series are summed per instance.
          server.wait_until_succeeds(
              f"curl -sf {AUTH} 'http://localhost:7402/v1/query?metric=queue_depth&service=exporter' "
              "| jq -e '.value == 12'",
              timeout=60,
          )
          hook = wait_hook("QueueBacklog", "firing")
          assert hook["version"] == "4", hook
          [alert] = hook["alerts"]
          assert alert["labels"] == {
              "alertname": "QueueBacklog",
              "severity": "critical",
              "node": "alpha",
              "service": "exporter",
              "team": "jobs",
          }, alert
          assert alert["annotations"]["summary"] == "queue backlog", alert
          assert alert["endsAt"] == "0001-01-01T00:00:00Z", alert
          assert "QueueBacklog" in active()
          assert "ExporterDown" not in active()

      with subtest("the series recovering resolves the alert"):
          expose("queue_depth 1\\n")
          hook = wait_hook("QueueBacklog", "resolved")
          assert hook["alerts"][0]["endsAt"] != "0001-01-01T00:00:00Z", hook
          assert "QueueBacklog" not in active()

      with subtest("a failing scrape reports the instance down"):
          alpha.succeed("rm /srv/exporter/metrics")
          hook = wait_hook("ExporterDown", "firing")
          assert hook["alerts"][0]["labels"]["service"] == "exporter", hook

      with subtest("removing a rule in a new revision resolves its alerts"):
          apply(with_down_rule=False)
          hook = wait_hook("ExporterDown", "resolved")
          assert hook["alerts"][0]["labels"]["node"] == "alpha", hook
          assert "ExporterDown" not in active()
    '';
}
