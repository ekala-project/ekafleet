{ pkgs, lib }:

# Container services from a private registry, end to end:
#
#   a TLS registry with basic auth holds cosign-signed images → `apply` pins
#   the tag to a digest (with credentials from the service's static secret)
#   and checks the signature against the fleet signaturePolicy → the agent
#   pulls that digest, verifies it again, and runs it under systemd-nspawn
#   with the service's args, environment and bind mounts. Moving the tag and
#   applying again runs the new digest; rolling back runs the old one even
#   though the tag moved; an unsigned image fails the apply.
let
  certs = pkgs.runCommand "registry-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout ca-key.pem -out ca.pem -days 3650 -subj /CN=test-registry-ca
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout key.pem -out req.pem -subj /CN=registry
    printf '%s\n' \
      'subjectAltName=DNS:registry' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature' \
      'extendedKeyUsage=serverAuth' > ext.cnf
    openssl x509 -req -in req.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
      -out cert.pem -days 3650 -extfile ext.cnf
    chmod 0644 key.pem
  '';

  htpasswd = pkgs.runCommand "registry-htpasswd" { } ''
    ${pkgs.apacheHttpd}/bin/htpasswd -Bbn fleet pullpass > $out
  '';

  # Prints its version, greeting and arguments, then stays up.
  mkImage =
    version:
    pkgs.dockerTools.buildImage {
      name = "web";
      tag = version;
      copyToRoot = pkgs.buildEnv {
        name = "web-root";
        paths = [ pkgs.busybox ];
      };
      config = {
        Entrypoint = [
          "/bin/sh"
          "-c"
          "echo \"started-$VERSION $GREETING $*\"; exec sleep 1000000"
          "web"
        ];
        Cmd = [ "from-image" ];
        Env = [ "VERSION=${version}" ];
      };
    };
  imageV1 = mkImage "v1";
  imageV2 = mkImage "v2";
  imageUnsigned = mkImage "unsigned";

  flakeLock = pkgs.writeText "flake.lock" (
    builtins.toJSON {
      nodes.root = { };
      root = "root";
      version = 7;
    }
  );

  trustRegistry = {
    security.pki.certificateFiles = [ "${certs}/ca.pem" ];
  };
in
pkgs.testers.nixosTest {
  name = "ekafleet-oci-registry";

  nodes.registry =
    { ... }:
    {
      imports = [ trustRegistry ];
      services.dockerRegistry = {
        enable = true;
        listenAddress = "0.0.0.0";
        port = 5000;
        extraConfig = {
          http.tls = {
            certificate = "${certs}/cert.pem";
            key = "${certs}/key.pem";
          };
          auth.htpasswd = {
            realm = "test";
            path = "${htpasswd}";
          };
        };
      };
      networking.firewall.allowedTCPPorts = [ 5000 ];
      environment.systemPackages = [
        pkgs.skopeo
        pkgs.cosign
        pkgs.jq
      ];
    };

  nodes.server =
    { ... }:
    {
      imports = [
        ../module.nix
        trustRegistry
      ];
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
      imports = [
        ../module.nix
        trustRegistry
      ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet.agent = {
        enable = true;
        serverAddr = "${nodes.server.networking.primaryIPAddress}:7400";
        caCert = "/etc/ekafleet/ca.pem";
        joinTokenFile = "/etc/ekafleet/join-token";
      };
      systemd.targets.machines.enable = true;
    };

  testScript =
    { nodes, ... }:
    ''
      import base64
      import json

      SERVER = "${nodes.server.networking.primaryIPAddress}:7400"
      ENV = (
          "EKAFLEET_TOKEN=cluster-token "
          "EKAFLEET_CA_CERT=/var/lib/ekafleet-ca/ca-cert.pem "
          f"EKAFLEET_SERVER={SERVER}"
      )
      CLI = f"{ENV} ekafleet"
      REPO = "registry:5000/team/web"
      CREDS = "fleet:pullpass"

      def push(archive, tag):
          registry.succeed(
              f"skopeo copy --insecure-policy --dest-creds {CREDS} "
              f"docker-archive:{archive} docker://{REPO}:{tag}"
          )
          return registry.succeed(
              f"skopeo inspect --creds {CREDS} docker://{REPO}:{tag} | jq -r .Digest"
          ).strip()

      def sign(digest):
          registry.succeed(
              "cd /root/keys && COSIGN_PASSWORD= cosign sign --key cosign.key "
              "--tlog-upload=false --new-bundle-format=false --use-signing-config=false "
              f"--yes {REPO}@{digest}"
          )

      def write_fleet(tag):
          server.succeed(f"cat > /var/lib/fleet/flake.nix <<'EOF'\n{FLEET.replace('@TAG@', tag)}\nEOF")
          server.succeed("chmod -R a+rX /var/lib/fleet")

      def bundle_hex():
          unit = alpha.succeed("cat /run/systemd/system/ekafleet-web.service")
          return unit.split("--oci-bundle=/var/lib/ekafleet/oci/bundles/web/")[1].split()[0]

      def wait_running(digest, version):
          hex = digest.removeprefix("sha256:")
          alpha.wait_until_succeeds(
              f"grep -q 'oci-bundle=/var/lib/ekafleet/oci/bundles/web/{hex}' "
              "/run/systemd/system/ekafleet-web.service",
              timeout=180,
          )
          alpha.wait_until_succeeds("systemctl is-active ekafleet-web.service", timeout=60)
          alpha.wait_until_succeeds(
              f"journalctl -u ekafleet-web -o cat | grep -q 'started-{version} hello from-args'",
              timeout=60,
          )

      start_all()

      with subtest("signed images are pushed to the registry"):
          registry.wait_for_unit("docker-registry.service")
          registry.wait_for_open_port(5000)
          registry.succeed("cosign login registry:5000 -u fleet -p pullpass")
          registry.succeed(
              "mkdir -p /root/keys && cd /root/keys && COSIGN_PASSWORD= cosign generate-key-pair"
          )
          v1 = push("${imageV1}", "stable")
          sign(v1)
          v2 = push("${imageV2}", "v2")
          sign(v2)
          unsigned = push("${imageUnsigned}", "unsigned")
          assert len({v1, v2, unsigned}) == 3
          public_key = registry.succeed("cat /root/keys/cosign.pub").strip()

      FLEET = f"""
      {{
        outputs = _: {{
          fleet = {{
            name = "oci-test";
            domain = "fleet.internal";
            machines.alpha = {{
              targetHost = "alpha";
              capacity = {{ cpu = 2000; memory = 1024; }};
            }};
            signaturePolicy = {{
              publicKeyPem = '''
      {public_key}
              ''';
              enforce = true;
            }};
            services.web = {{
              container = {{
                image = "{REPO}:@TAG@";
                registryAuthSecret = "registry";
                args = [ "from-args" ];
                bindMounts = [ "/srv/shared:/shared:ro" ];
              }};
              secrets.registry = {{ }};
              environment.GREETING = "hello";
              resources = {{ cpu.request = 100; memory.request = 64; }};
              scheduling = {{
                replicas = 1;
                update = {{ minHealthyTime = 0; healthyDeadline = 120; }};
              }};
            }};
          }};
        }};
      }}
      """

      server.wait_for_unit("ekafleet-server.service")
      server.wait_for_open_port(7400)

      with subtest("the agent joins"):
          ca_pem = server.succeed("cat /var/lib/ekafleet-ca/ca-cert.pem")
          alpha.succeed("mkdir -p /etc/ekafleet /srv/shared")
          alpha.succeed("echo shared-ok > /srv/shared/hello")
          alpha.succeed(f"cat > /etc/ekafleet/ca.pem <<'EOF'\n{ca_pem}\nEOF")
          token = server.succeed(f"{CLI} token create --type agent --node alpha").strip()
          alpha.succeed(f"(umask 077; printf '%s' {token} > /etc/ekafleet/join-token)")
          alpha.systemctl("restart ekafleet-agent.service")
          alpha.wait_until_succeeds("ip -4 addr show wg-fleet | grep -q 10.100.", timeout=90)

      with subtest("registry credentials are a static secret"):
          auth = base64.b64encode(CREDS.encode()).decode()
          docker_config = json.dumps({"auths": {"registry:5000": {"auth": auth}}})
          server.succeed(
              f"printf '%s' '{docker_config}' | {CLI} secret set web registry --server {SERVER}"
          )

      with subtest("apply pins the tag and the agent runs that digest"):
          server.succeed("mkdir -p /var/lib/fleet")
          server.succeed("cp ${flakeLock} /var/lib/fleet/flake.lock")
          write_fleet("stable")
          server.succeed(f"{CLI} apply --flake /var/lib/fleet --auto-approve 2>&1")
          wait_running(v1, "v1")
          leader = alpha.succeed("machinectl show ekafleet-web -p Leader --value").strip()
          assert alpha.succeed(f"cat /proc/{leader}/root/shared/hello").strip() == "shared-ok"
          # The registry password never reaches a journal.
          alpha.fail("journalctl -o cat | grep -q pullpass")
          server.fail("journalctl -o cat | grep -q pullpass")

      with subtest("a moved tag runs the new digest on the next apply"):
          assert push("${imageV2}", "stable") == v2
          server.succeed(f"{CLI} apply --flake /var/lib/fleet --auto-approve 2>&1")
          wait_running(v2, "v2")

      with subtest("rollback runs the digest the earlier revision pinned"):
          server.succeed(f"{CLI} rollback --to 1 --server {SERVER} 2>&1")
          wait_running(v1, "v1")

      with subtest("an unsigned image fails the apply"):
          write_fleet("unsigned")
          out = server.fail(f"{CLI} apply --flake /var/lib/fleet --auto-approve 2>&1")
          assert "not signed" in out, out
          assert bundle_hex() == v1.removeprefix("sha256:")
          alpha.succeed("systemctl is-active ekafleet-web.service")

      with subtest("bundles no revision runs are collected"):
          alpha.wait_until_succeeds(
              "test \"$(ls /var/lib/ekafleet/oci/bundles/web)\" = "
              f"\"{v1.removeprefix('sha256:')}\"",
              timeout=60,
          )
    '';
}
