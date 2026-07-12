# Self-hosted bare-metal fleet.
#
# Three physical NixOS machines with no cloud autoscaling.
# Machines are statically declared and managed out-of-band.
# Focus: simple setup, rolling updates, rack-aware spread, disruption budget.

{ pkgs }:
{
  fleet = {
    name = "self-hosted-example";
    domain = "fleet.internal";

    nodePools.default = {
      labels = {
        env = "production";
      };
      # Spread evenly across a small, fixed set of machines
      schedulerAlgorithm = "spread";
    };

    # -- Service ----------------------------------------------------------

    services.api-server = {
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
          request = 500;
          limit = 1000;
        };
        memory = {
          request = 256;
          limit = 512;
        };
      };

      environment = {
        LOG_LEVEL = "info";
      };

      scheduling = {
        replicas = 3; # One per machine for high availability
        type = "service";
        pool = "default";

        # Place instances in different rack zones when possible
        spread = [
          {
            attribute = "labels.zone";
            weight = 50;
          }
        ];

        update = {
          strategy = "rolling";
          maxParallel = 1;
          minHealthyTime = 10;
          healthyDeadline = 300;
          autoRevert = true; # Roll back automatically on failure
        };

        # At least 2 of 3 instances must stay up during updates/drains
        disruptionBudget = {
          minAvailable = 2;
        };
      };
    };

    # -- Machines ---------------------------------------------------------

    machines.node-1 = {
      targetHost = "10.0.1.1";
      pool = "default";
      labels = {
        role = "app";
        zone = "rack-a";
      };
      capacity = {
        cpu = 8000;
        memory = 16384;
        disk = 200000;
      };
      reserved = {
        cpu = 500;
        memory = 512;
      }; # Reserved for OS
    };

    machines.node-2 = {
      targetHost = "10.0.1.2";
      pool = "default";
      labels = {
        role = "app";
        zone = "rack-b";
      };
      capacity = {
        cpu = 8000;
        memory = 16384;
        disk = 200000;
      };
      reserved = {
        cpu = 500;
        memory = 512;
      };
    };

    machines.node-3 = {
      targetHost = "10.0.1.3";
      pool = "default";
      labels = {
        role = "app";
        zone = "rack-a";
      };
      capacity = {
        cpu = 8000;
        memory = 16384;
        disk = 200000;
      };
      reserved = {
        cpu = 500;
        memory = 512;
      };
    };
  };
}
