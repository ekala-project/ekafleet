# Multi-cloud fleet spanning AWS and GCP.
#
# Services are spread across both providers for geographic redundancy.
# Each provider has its own autoscaled node pool.
# Focus: cross-provider spread, provider-specific config, blue-green deploys.

{ pkgs }:
{
  fleet = {
    name = "multi-cloud-example";
    domain = "fleet.internal";

    # -- Node Pools -------------------------------------------------------

    nodePools.aws-workers = {
      labels = {
        provider = "aws";
        region = "us-east-1";
      };
      schedulerAlgorithm = "binpack";

      scaling = {
        minCount = 2;
        maxCount = 6;
        rules = [
          {
            metricName = "pool_cpu_utilization";
            targetValue = 0.7;
            scaleUpThreshold = 1.3;
            scaleDownThreshold = 0.5;
          }
        ];
      };

      cloud = {
        provider = "aws";
        region = "us-east-1";
        instanceType = "c6i.xlarge";
        imageId = "ami-0123456789abcdef0";
        subnetId = "subnet-abc123";
        securityGroupIds = [ "sg-fleet-workers" ];
        sshKeyName = "fleet-key";
        diskSizeGb = 50;
        machineCapacity = {
          cpu = 4000;
          memory = 8192;
          disk = 100000;
        };
      };
    };

    nodePools.gcp-workers = {
      labels = {
        provider = "gcp";
        region = "us-central1";
      };
      schedulerAlgorithm = "binpack";

      scaling = {
        minCount = 2;
        maxCount = 6;
        rules = [
          {
            metricName = "pool_cpu_utilization";
            targetValue = 0.7;
            scaleUpThreshold = 1.3;
            scaleDownThreshold = 0.5;
          }
        ];
      };

      cloud = {
        provider = "gcp";
        region = "us-central1";
        instanceType = "n2-standard-4";
        imageId = "nixos-ekafleet";
        project = "my-gcp-project"; # Required for GCP
        zone = "us-central1-a";
        subnetId = "default";
        diskSizeGb = 50;
        machineCapacity = {
          cpu = 4000;
          memory = 16384;
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
        replicas = 6;
        type = "service";
        priority = 70;

        spread = [
          # Spread across cloud providers for geographic redundancy.
          # Each provider gets roughly half the instances.
          {
            attribute = "labels.provider";
            weight = 80; # High weight -- cross-cloud spread is critical
            targets = [
              {
                value = "aws";
                percent = 50;
              }
              {
                value = "gcp";
                percent = 50;
              }
            ];
          }
          # Within each provider, spread across regions for fault tolerance.
          {
            attribute = "labels.region";
            weight = 40;
          }
        ];

        update = {
          strategy = "blue-green"; # Deploy all new instances, verify, then switch
          maxParallel = 6;
          minHealthyTime = 30;
          healthyDeadline = 600;
          autoRevert = true;
        };

        # At least 4 of 6 instances must stay up during disruptions
        disruptionBudget = {
          minAvailable = 4;
        };
      };

      lifecycle = {
        terminationGracePeriodSeconds = 60;
      };
    };

    # -- Static Machines --------------------------------------------------
    # One static machine per provider region for the ekafleet server.
    # In production, run 3+ servers across providers for Raft HA.
    # Worker VMs are created by the cloud providers automatically.

    machines.server-aws = {
      targetHost = "10.0.1.1";
      pool = "aws-workers";
      labels = {
        role = "server";
        provider = "aws";
        region = "us-east-1";
      };
      capacity = {
        cpu = 4000;
        memory = 8192;
        disk = 100000;
      };
      reserved = {
        cpu = 1000;
        memory = 1024;
      };
    };

    machines.server-gcp = {
      targetHost = "10.1.1.1";
      pool = "gcp-workers";
      labels = {
        role = "server";
        provider = "gcp";
        region = "us-central1";
      };
      capacity = {
        cpu = 4000;
        memory = 16384;
        disk = 100000;
      };
      reserved = {
        cpu = 1000;
        memory = 1024;
      };
    };
  };
}
