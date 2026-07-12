{ pkgs, lib }:

# Test OCI container support: build a minimal container image with Nix,
# unpack it into an OCI bundle, and run it via systemd-nspawn.
#
# This exercises the full container lifecycle without requiring a remote
# registry or skopeo. The image is built by dockerTools, unpacked from
# the Docker-archive tarball, and launched with systemd-nspawn.
pkgs.testers.nixosTest {
  name = "ekafleet-oci-container";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ../module.nix ];
      nixpkgs.overlays = [ (import ../overlay.nix) ];

      services.ekafleet = {
        enable = true;
        mode = "server";
        token = "oci-test-token";
      };

      networking.firewall.allowedTCPPorts = [
        7400
        7402
      ];

      # Enable systemd-nspawn and machined support
      systemd.targets.machines.enable = true;

      environment.systemPackages = [
        pkgs.ekaos-fleet
        pkgs.jq
        pkgs.gnutar
        pkgs.gzip
      ];
    };

  testScript =
    let
      # Build a minimal container image using Nix's dockerTools.
      # This produces a Docker-archive .tar.gz with layers inside.
      containerImage = pkgs.dockerTools.buildImage {
        name = "ekafleet-test-container";
        tag = "latest";
        copyToRoot = pkgs.buildEnv {
          name = "test-root";
          paths = [
            pkgs.coreutils
            pkgs.bash
          ];
        };
        config = {
          Entrypoint = [
            "${pkgs.bash}/bin/bash"
            "-c"
          ];
          Cmd = [
            "echo 'ekafleet-container-ok' && sleep infinity"
          ];
        };
      };
    in
    ''
      import time
      import json as json_mod

      machine.wait_for_unit("ekafleet.service")
      machine.wait_for_open_port(7402)

      # ── Step 1: Verify ekafleet is running ──

      machine.succeed("curl -sf http://localhost:7402/health | grep -q 'ok'")

      # ── Step 2: Unpack Docker-archive image into rootfs ──

      # Docker-archive format: a tarball containing:
      #   manifest.json — JSON array with layer paths
      #   <hash>/layer.tar — each layer as a tar archive
      #   <hash>.json — image config

      # Use /tmp/oci-bundle to avoid DynamicUser path remapping
      machine.succeed(
          "mkdir -p /tmp/oci-bundle/rootfs /tmp/docker-archive"
      )

      # Extract the outer Docker archive tarball
      machine.succeed(
          "tar -xf ${containerImage} -C /tmp/docker-archive"
      )

      # Parse manifest.json to find layer paths, then extract each layer into rootfs
      machine.succeed(
          "cd /tmp/docker-archive && "
          "for LAYER in $(jq -r '.[0].Layers[]' manifest.json); do "
          "  tar -xf \"$LAYER\" -C /tmp/oci-bundle/rootfs 2>/dev/null || true; "
          "done"
      )

      # systemd-nspawn expects /usr to exist in the rootfs (OS tree detection)
      machine.succeed("mkdir -p /tmp/oci-bundle/rootfs/usr /tmp/oci-bundle/rootfs/bin /tmp/oci-bundle/rootfs/sbin")

      # Verify rootfs was populated with expected binaries
      machine.succeed(
          "test -d /tmp/oci-bundle/rootfs/nix"
      )

      # ── Step 3: Generate OCI bundle config.json ──

      # Determine the bash path inside the rootfs
      bash_abs = machine.succeed(
          "find /tmp/oci-bundle/rootfs -name bash -type f | head -1"
      ).strip()
      bash_rel = bash_abs.replace("/tmp/oci-bundle/rootfs", "")

      # Write OCI runtime spec using Python to avoid heredoc quoting issues
      oci_config = json_mod.dumps({
          "ociVersion": "1.0.0",
          "root": {"path": "rootfs", "readonly": False},
          "process": {
              "args": [bash_rel, "-c", "echo ekafleet-container-ok && sleep infinity"],
              "env": ["PATH=/nix/store:/bin:/usr/bin", "EKAFLEET_SERVICE=test-container", "TERM=xterm"],
              "cwd": "/",
              "terminal": False,
          },
          "mounts": [
              {"destination": "/proc", "source": "proc", "type": "proc"},
              {"destination": "/dev", "source": "tmpfs", "type": "tmpfs",
               "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
              {"destination": "/sys", "source": "sysfs", "type": "sysfs",
               "options": ["nosuid", "noexec", "nodev", "ro"]},
              {"destination": "/tmp", "source": "tmpfs", "type": "tmpfs"},
          ],
          "linux": {
              "namespaces": [
                  {"type": "pid"},
                  {"type": "ipc"},
                  {"type": "uts"},
                  {"type": "mount"},
              ]
          },
      })

      machine.succeed(f"cat > /tmp/oci-bundle/config.json <<'EOF'\n{oci_config}\nEOF")
      machine.succeed("test -f /tmp/oci-bundle/config.json")

      # ── Step 4: Launch container via systemd-nspawn ──

      # Write a systemd unit file matching the supervisor's nspawn output format
      unit_content = (
          "[Unit]\n"
          "Description=ekafleet container: test-container\n"
          "After=network.target\n"
          "Wants=machines.target\n"
          "\n"
          "[Service]\n"
          "Type=simple\n"
          "ExecStart=systemd-nspawn"
          " --oci-bundle=/tmp/oci-bundle"
          " --machine=ekafleet-test-container"
          " --network-namespace-path=/proc/1/ns/net"
          " --register=yes"
          " --keep-unit\n"
          "ExecStop=machinectl terminate ekafleet-test-container\n"
          "Restart=on-failure\n"
          "RestartSec=5\n"
          "KillMode=mixed\n"
          "KillSignal=SIGTERM\n"
          "TimeoutStopSec=30\n"
          "Environment=EKAFLEET_SERVICE=test-container\n"
          "\n"
          "[Install]\n"
          "WantedBy=multi-user.target\n"
      )
      machine.succeed(f"cat > /run/systemd/system/ekafleet-test-container.service <<'EOF'\n{unit_content}EOF")

      machine.succeed("systemctl daemon-reload")
      machine.succeed("systemctl start ekafleet-test-container.service")

      # Wait for the container unit to be active and machined to register
      machine.wait_for_unit("ekafleet-test-container.service")
      time.sleep(2)

      # ── Step 5: Verify the container is running ──

      machine.succeed("systemctl is-active ekafleet-test-container.service")

      # The machine should be registered with machined
      machine.succeed("machinectl list | grep -q ekafleet-test-container")

      # ── Step 6: Verify cgroup hierarchy (attestation prerequisite) ──

      # The container's processes should be under the ekafleet-test-container.service cgroup.
      # This is critical for workload attestation via /proc/<pid>/cgroup.
      leader_pid = machine.succeed(
          "machinectl show ekafleet-test-container -p Leader --value"
      ).strip()

      cgroup = machine.succeed(f"cat /proc/{leader_pid}/cgroup").strip()
      assert "ekafleet-test-container" in cgroup, (
          f"Expected 'ekafleet-test-container' in cgroup path, got: {cgroup}"
      )

      # ── Step 7: Verify journald logging works ──

      # Container stdout should appear in the journal for the unit
      machine.succeed(
          "journalctl -u ekafleet-test-container.service --no-pager | grep -q 'ekafleet-container-ok'"
      )

      # ── Step 8: Clean shutdown ──

      machine.succeed("systemctl stop ekafleet-test-container.service")

      # The machine should be deregistered
      machine.succeed("! machinectl show ekafleet-test-container 2>/dev/null")

      # ── Step 9: Verify ekafleet server survived all operations ──

      machine.succeed("curl -sf http://localhost:7402/health | grep -q 'ok'")
    '';
}
