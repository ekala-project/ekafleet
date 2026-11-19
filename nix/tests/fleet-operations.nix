{ pkgs, lib }:

# Fleet operations across a server and two agents:
#
#   - admission: an admission webhook and a namespace quota reject applies,
#     which never become revisions;
#   - event webhooks: deliveries carry an HMAC-SHA256 signature keyed by a
#     fleet secret;
#   - rebalance: a stateful service placed before a better node joined is
#     moved there with its data;
#   - ingress: a node's proxy serves a configured route to a service on
#     another node over the mesh;
#   - autoscaling: a scraped per-instance metric scales a service out to a
#     second node and back in.
let
  inherit (pkgs) coreutils python3;

  # /events/<n>: records each event body and its headers.
  # /admit: rejects any configuration with a service named "forbidden".
  receiver = pkgs.writeText "receiver.py" ''
    import http.server, json, os

    class Hook(http.server.BaseHTTPRequestHandler):
        count = 0

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if self.path == "/admit":
                review = json.loads(body)
                if "forbidden" in review["services"]:
                    answer = {"allowed": False, "message": "forbidden services are not allowed"}
                else:
                    answer = {"allowed": True}
                out = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return
            Hook.count += 1
            base = f"/var/lib/hooks/{Hook.count:04}"
            with open(base + ".body", "wb") as f:
                f.write(body)
            with open(base + ".headers", "w") as f:
                json.dump({k.lower(): v for k, v in self.headers.items()}, f)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

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

  # `extra` holds more attribute definitions for the fleet. beta is declared only once
  # it has joined: the scheduler places on declared machines whether or not
  # their agent is connected.
  mkFleet =
    {
      withBeta ? false,
      extra ? "",
    }:
    pkgs.writeText "flake.nix" ''
      {
        outputs = _: {
          fleet = {
            name = "operations-test";
            domain = "fleet.internal";
            machines.alpha = {
              targetHost = "alpha";
              capacity = { cpu = 2000; memory = 1024; };
            };
            ${lib.optionalString withBeta ''
              machines.beta = {
                targetHost = "beta";
                pool = "edge";
                capacity = { cpu = 2000; memory = 1024; };
              };
            ''}
            nodePools.edge = { };

            webhooks = [
              {
                name = "all";
                url = "http://127.0.0.1:9095/events";
                events = [ "*" ];
                secret = "hook-key";
              }
            ];
            admissionWebhooks = [
              { name = "review"; url = "http://127.0.0.1:9095/admit"; }
            ];
            namespaces.shop.quota.instances = 2;

            services.db = {
              command = "${coreutils}/bin/sleep infinity";
              volumes = [
                { name = "data"; mountPath = "/var/lib/db"; sizeMb = 16; reclaimRetain = false; }
              ];
              resources = { cpu.request = 100; memory.request = 64; };
              scheduling = {
                type = "stateful";
                replicas = 1;
                # Prefers the edge pool, which has no node at first.
                affinity = [ { attribute = "pool"; op = "="; value = "edge"; weight = 100; } ];
                update = { minHealthyTime = 0; healthyDeadline = 60; };
              };
            };

            services.web = {
              command = "${python3}/bin/python3 -m http.server 8081 --directory /srv/web";
              ports.http.port = 8081;
              resources = { cpu.request = 100; memory.request = 64; };
              scheduling = {
                replicas = 1;
                constraints = [ { attribute = "name"; op = "="; value = "alpha"; } ];
                update = { minHealthyTime = 0; healthyDeadline = 60; };
              };
            };

            services.worker = {
              command = "${python3}/bin/python3 -m http.server 9100 --bind 127.0.0.1 --directory /srv/worker";
              metrics.port = 9100;
              resources = { cpu.request = 100; memory.request = 64; };
              scheduling = {
                replicas = 1;
                autoscale = {
                  min = 1;
                  max = 2;
                  rules = [ { metric = "queue_depth"; target = 10; } ];
                  scaleDownDelaySeconds = 20;
                };
                update = { minHealthyTime = 0; healthyDeadline = 60; };
              };
            };

            ingress.site = {
              host = "www.example.com";
              service = "web";
              port = "http";
              nodes = [ "beta" ];
            };

            ${extra}
          };
        };
      }
    '';

  baseFleet = mkFleet { };
  fullFleet = mkFleet { withBeta = true; };
  # Rejected by the admission webhook.
  forbiddenFleet = mkFleet {
    extra = ''
      services.forbidden = {
        command = "${coreutils}/bin/sleep infinity";
        resources = { cpu.request = 10; memory.request = 16; };
      };
    '';
  };
  # Three instances in a namespace limited to two.
  overQuotaFleet = mkFleet {
    extra = ''
      services.shop = {
        command = "${coreutils}/bin/sleep infinity";
        namespace = "shop";
        resources = { cpu.request = 10; memory.request = 16; };
        scheduling.replicas = 3;
      };
    '';
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

      environment.systemPackages = [ pkgs.jq ];

      systemd.tmpfiles.rules = [
        "d /srv/web 0755 root root -"
        "d /srv/worker 0755 root root -"
      ];
    };
in
pkgs.testers.nixosTest {
  name = "ekafleet-fleet-operations";

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

  nodes.alpha = agentNode;
  nodes.beta = agentNode;

  testScript =
    { nodes, ... }:
    ''
      import hashlib, hmac, json

      SERVER = "${nodes.server.networking.primaryIPAddress}:7400"
      BETA = "${nodes.beta.networking.primaryIPAddress}"
      CLI = (
          "EKAFLEET_TOKEN=cluster-token "
          "EKAFLEET_CA_CERT=/var/lib/ekafleet-ca/ca-cert.pem "
          f"EKAFLEET_SERVER={SERVER} ekafleet"
      )
      AUTH = "-H 'Authorization: Bearer cluster-token'"
      HOOK_KEY = "s3cret-hook-key"
      VOLUME = "/var/lib/ekafleet/volumes/db/data"
      AGENTS = {"alpha": alpha, "beta": beta}
      ca_pem = None

      def rest(path):
          return json.loads(server.succeed(f"curl -sf {AUTH} http://localhost:7402{path}"))

      def join(name):
          machine = AGENTS[name]
          machine.succeed("mkdir -p /etc/ekafleet")
          machine.succeed(f"cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}\nEOF")
          token = server.succeed(f"{CLI} token create --type agent --node {name}").strip()
          machine.succeed(f"(umask 077; printf '%s' {token} > /etc/ekafleet/join-token)")
          machine.systemctl("restart ekafleet-agent.service")
          machine.wait_until_succeeds("ip -4 addr show wg-fleet | grep -q 10.100.", timeout=90)

      def apply(fleet):
          server.succeed(f"cp {fleet} /var/lib/fleet/flake.nix && chmod -R a+rX /var/lib/fleet")
          return server.execute(f"{CLI} apply --flake /var/lib/fleet --auto-approve 2>&1")

      def revisions():
          return [r["revision"] for r in json.loads(server.succeed(f"{CLI} --output json history"))]

      def events(kind):
          """Delivered events of `kind`, as (body bytes, headers)."""
          out = []
          listing = server.succeed("ls /var/lib/hooks 2>/dev/null || true").split()
          for name in sorted(n for n in listing if n.endswith(".body")):
              base = "/var/lib/hooks/" + name[: -len(".body")]
              body = server.succeed(f"cat {base}.body").encode()
              headers = json.loads(server.succeed(f"cat {base}.headers"))
              if headers.get("x-ekafleet-event") == kind:
                  out.append((body, headers))
          return out

      def wait_event(kind, check=lambda e: True, timeout=120):
          def found(_):
              return any(check(json.loads(body)) for body, _ in events(kind))
          retry(found, timeout_seconds=timeout)
          return next(
              (body, headers)
              for body, headers in events(kind)
              if check(json.loads(body))
          )

      def assert_signed(body, headers):
          expected = "sha256=" + hmac.new(HOOK_KEY.encode(), body, hashlib.sha256).hexdigest()
          assert headers.get("x-ekafleet-signature") == expected, headers

      def instances(service):
          for s in rest("/v1/services"):
              if s["name"] == service:
                  return s["instances"]
          return []

      def running_on(service):
          return sorted(
              name
              for name, machine in AGENTS.items()
              if machine.execute(f"systemctl is-active ekafleet-{service}.service")[0] == 0
          )

      start_all()
      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_unit("hook-receiver.service")
      server.wait_for_open_port(7400)
      server.wait_for_open_port(9095)
      ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")

      with subtest("the base configuration is admitted and runs on alpha"):
          join("alpha")
          server.succeed(f"printf '%s' {HOOK_KEY} | {CLI} secret set _fleet hook-key --server {SERVER}")
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${flakeLock} /var/lib/fleet/flake.lock")
          alpha.succeed("echo 'hello from web' > /srv/web/index.html")
          alpha.succeed("printf 'queue_depth 5\\n' > /srv/worker/metrics")
          status, out = apply("${baseFleet}")
          assert status == 0, out
          for service in ["db", "web", "worker"]:
              alpha.wait_until_succeeds(f"systemctl is-active ekafleet-{service}.service", timeout=180)
          alpha.succeed(f"echo before-move > {VOLUME}/state")

      with subtest("event webhooks are signed with the fleet secret"):
          body, headers = wait_event("config.applied")
          assert_signed(body, headers)
          event = json.loads(body)
          assert event["fleet"] == "operations-test", event
          assert headers["x-ekafleet-delivery"] == event["id"], headers

      with subtest("an admission webhook rejects an apply"):
          before = revisions()
          status, out = apply("${forbiddenFleet}")
          assert status != 0, out
          assert "forbidden services are not allowed" in out, out
          assert revisions() == before, "a rejected apply became a revision"
          body, headers = wait_event(
              "config.rejected", lambda e: "forbidden services" in e["message"]
          )
          assert_signed(body, headers)

      with subtest("a namespace quota rejects an apply"):
          status, out = apply("${overQuotaFleet}")
          assert status != 0, out
          assert "shop" in out and "instances" in out, out
          assert revisions() == before
          wait_event("config.rejected", lambda e: "shop" in e["message"])

      with subtest("rebalance moves the stateful service to the joined edge node"):
          join("beta")
          beta.succeed("printf 'queue_depth 5\\n' > /srv/worker/metrics")
          status, out = apply("${fullFleet}")
          assert status == 0, out
          # Its data keeps db on alpha, though it prefers the edge pool.
          assert running_on("db") == ["alpha"]
          plan = server.succeed(f"{CLI} rebalance 2>&1")
          assert "db" in plan and "alpha -> beta" in plan, plan
          # A dry run changes nothing.
          assert running_on("db") == ["alpha"]
          server.succeed(f"{CLI} rebalance --apply 2>&1")
          beta.wait_until_succeeds("systemctl is-active ekafleet-db.service", timeout=180)
          alpha.wait_until_fails("systemctl is-active ekafleet-db.service", timeout=60)
          assert beta.succeed(f"cat {VOLUME}/state").strip() == "before-move"
          wait_event("rebalance.completed", lambda e: e["service"] == "db")
          alpha.wait_until_succeeds(f"test ! -e {VOLUME}", timeout=60)

      with subtest("beta's ingress proxy routes to web on alpha over the mesh"):
          # Backends follow the replicas' reported state, so they arrive once
          # alpha reports web serving.
          beta.wait_until_succeeds(
              "jq -e '.routes[0].backends | length == 1' /run/ekafleet/ingress-routes.json",
              timeout=60,
          )
          routes = json.loads(beta.succeed("cat /run/ekafleet/ingress-routes.json"))
          [route] = routes["routes"]
          assert route["name"] == "site" and len(route["backends"]) == 1, routes
          assert route["backends"][0].startswith("10.100."), routes
          # Only beta serves the route.
          alpha.wait_until_succeeds(
              "test \"$(jq '.routes | length' /run/ekafleet/ingress-routes.json)\" = 0",
              timeout=60,
          )
          server.wait_until_succeeds(
              f"curl -sf -H 'Host: www.example.com' http://{BETA}:8080/ | grep -q 'hello from web'",
              timeout=60,
          )
          server.succeed(
              f"test $(curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: other.example.com' http://{BETA}:8080/) = 404"
          )

      with subtest("a scraped metric scales the worker out and back in"):
          # 25 per instance against a target of 10: two instances.
          alpha.succeed("printf 'queue_depth 25\\n' > /srv/worker/metrics")
          body, headers = wait_event("service.scaled", lambda e: e["service"] == "worker")
          assert_signed(body, headers)
          server.wait_until_succeeds(
              f"curl -sf {AUTH} http://localhost:7402/v1/services "
              "| jq -e '.[] | select(.name == \"worker\") | .instances | length == 2'",
              timeout=120,
          )
          beta.wait_until_succeeds("systemctl is-active ekafleet-worker.service", timeout=180)
          assert running_on("worker") == ["alpha", "beta"]
          # Hand scaling is refused for autoscaled services.
          server.fail(f"{CLI} scale worker 1")

          for machine in AGENTS.values():
              machine.succeed("printf 'queue_depth 1\\n' > /srv/worker/metrics")
          server.wait_until_succeeds(
              f"curl -sf {AUTH} http://localhost:7402/v1/services "
              "| jq -e '.[] | select(.name == \"worker\") | .instances | length == 1'",
              timeout=180,
          )
    '';
}
