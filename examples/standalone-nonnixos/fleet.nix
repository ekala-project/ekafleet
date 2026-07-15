# Standalone fleet on non-NixOS hosts that have the Nix package manager.
#
# This targets machines running an ordinary Linux distribution (Debian,
# Ubuntu, Fedora, Arch, ...) that have Nix installed and systemd as PID 1.
# There is NO NixOS module and NO full-OS `system.build.toplevel` activation
# here: the agent supervises individual services as systemd units, and every
# service's runtime closure is materialized from the Nix store. This is the
# distro-agnostic deployment path.
#
# Requirements on each host:
#   - Nix (flakes-enabled `nix` CLI is sufficient; `nix-env` is optional —
#     the agent falls back to `nix profile` when `nix-env` is absent)
#   - systemd as the init system
#   - the ekafleet binary (e.g. `nix profile install github:.../ekaos-fleet`)

{ pkgs }:
{
  fleet = {
    name = "standalone-nonnixos-example";
    domain = "fleet.internal";

    nodePools.default = {
      labels = {
        env = "production";
        os = "non-nixos";
      };
      schedulerAlgorithm = "spread";
    };

    # -- Service ----------------------------------------------------------
    #
    # The command references a package from the Nix store. On a non-NixOS
    # host the agent realizes this closure from the store and runs it under a
    # generated systemd unit — no NixOS activation involved.

    services.web = {
      command = "${pkgs.python3}/bin/python3 -m http.server 8080";

      ports.http = {
        port = 8080;
        liveness = {
          path = "/";
          interval = 10;
          timeout = 5;
        };
        readiness = {
          path = "/";
          interval = 5;
        };
      };

      resources = {
        cpu = {
          request = 250;
          limit = 500;
        };
        memory = {
          request = 128;
          limit = 256;
        };
      };

      scheduling = {
        replicas = 2;
        type = "service";
        pool = "default";

        update = {
          strategy = "rolling";
          maxParallel = 1;
          minHealthyTime = 10;
          healthyDeadline = 300;
          autoRevert = true;
        };

        disruptionBudget = {
          minAvailable = 1;
        };
      };
    };

    # -- Machines ---------------------------------------------------------
    #
    # Ordinary Linux hosts reached over SSH. `targetHost` is any distro with
    # Nix + systemd; ekafleet does not assume NixOS here.

    machines.debian-1 = {
      targetHost = "10.0.2.1";
      pool = "default";
      labels = {
        role = "app";
        distro = "debian";
      };
      capacity = {
        cpu = 4000;
        memory = 8192;
        disk = 100000;
      };
      reserved = {
        cpu = 500;
        memory = 512;
      };
    };

    machines.ubuntu-1 = {
      targetHost = "10.0.2.2";
      pool = "default";
      labels = {
        role = "app";
        distro = "ubuntu";
      };
      capacity = {
        cpu = 4000;
        memory = 8192;
        disk = 100000;
      };
      reserved = {
        cpu = 500;
        memory = 512;
      };
    };
  };
}
