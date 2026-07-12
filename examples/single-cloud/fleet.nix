# Single-cloud fleet on AWS.
#
# Two static controller machines plus an autoscaled worker pool.
# Workers are provisioned and destroyed automatically based on CPU utilization.
# Focus: cloud provider integration, pool autoscaling, canary deployments.

{ pkgs }:
{
  fleet = {
    name = "single-cloud-example";
    domain = "fleet.internal";

    # -- Node Pools -------------------------------------------------------

    # Controllers run the ekafleet server; statically managed.
    nodePools.controllers = {
      labels = {
        tier = "control";
      };
      schedulerAlgorithm = "spread"; # Spread across controllers for HA
    };

    # Workers run application services; cloud-autoscaled.
    nodePools.workers = {
      labels = {
        tier = "compute";
      };
      schedulerAlgorithm = "binpack"; # Pack tight for cost efficiency

      scaling = {
        minCount = 2;
        maxCount = 8;
        rules = [
          {
            metricName = "pool_cpu_utilization";
            targetValue = 0.7;
            scaleUpThreshold = 1.3; # Scale up when 30% over target
            scaleDownThreshold = 0.5; # Scale down when 50% below target
          }
        ];
      };

      cloud = {
        provider = "aws";
        region = "us-east-1";
        instanceType = "c6i.xlarge";
        imageId = "ami-0123456789abcdef0"; # NixOS AMI with ekafleet agent
        subnetId = "subnet-abc123";
        securityGroupIds = [ "sg-fleet-workers" ];
        sshKeyName = "fleet-key";
        diskSizeGb = 50;
        # Expected capacity for scheduling before the agent reports real resources
        machineCapacity = {
          cpu = 4000;
          memory = 8192;
          disk = 100000;
        };
      };
    };

    # -- Service ----------------------------------------------------------

    services.api-server = {
      command = "${pkgs.python3}/bin/python3 -m http.server 8080";

      ports.http = {
        port = 8080;
        liveness = {
          path = "/";
          interval = 10;
        };
        readiness = {
          path = "/";
          interval = 5;
        };
        # Suppress liveness checks during slow startup
        startup = {
          path = "/";
          interval = 2;
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
        replicas = 4;
        type = "service";
        priority = 60;
        pool = "workers"; # Prefer the autoscaled worker pool

        constraints = [
          {
            attribute = "labels.tier";
            op = "=";
            value = "compute";
          }
        ];

        update = {
          strategy = "canary"; # Deploy to one instance first, then roll out
          canary = 1;
          maxParallel = 2;
          minHealthyTime = 30;
          healthyDeadline = 300;
          autoRevert = true;
          autoPromote = true; # Auto-promote once canary passes health checks
        };

        disruptionBudget = {
          maxUnavailable = 1;
        };
      };
    };

    # -- Static Machines --------------------------------------------------
    # Only controllers are static. Worker VMs are created by the cloud
    # provider and join the fleet automatically via agent bootstrap.

    machines.ctrl-1 = {
      targetHost = "10.0.1.1";
      pool = "controllers";
      labels = {
        role = "controller";
        zone = "us-east-1a";
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

    machines.ctrl-2 = {
      targetHost = "10.0.1.2";
      pool = "controllers";
      labels = {
        role = "controller";
        zone = "us-east-1b";
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
