# Custodial hosting example.
#
# Demonstrates how a hosting platform would use the service catalog
# to generate fleet configuration from customer choices. In production,
# the web frontend or API would generate this Nix expression from
# customer selections (e.g., "I want a web service with 2 replicas").
#
# Each customer gets a namespace for isolation. Namespace-scoped tokens
# ensure customers can only see their own services.

{ pkgs }:

let
  catalog = import ../../nix/lib/catalog.nix { inherit pkgs; };
in
{
  fleet = {
    name = "hosting-platform";
    domain = "hosting.example.com";

    # ── Node pool for customer workloads ────────────────────────────
    nodePools.customers = {
      labels = {
        tier = "customer";
      };
      schedulerAlgorithm = "binpack"; # Pack for cost efficiency

      scaling = {
        minCount = 2;
        maxCount = 20;
        rules = [
          {
            metricName = "pool_cpu_utilization";
            targetValue = 0.7;
            scaleUpThreshold = 1.3;
            scaleDownThreshold = 0.5;
          }
        ];
      };
    };

    # ── Customer A: Web application ───────────────────────────────────
    # Customer selected: Web service, 2 replicas
    services.customer-a-webapp = catalog.mkWebService {
      name = "customer-a-webapp";
      image = "ghcr.io/customer-a/myapp:v1.2.3";
      port = 3000;
      replicas = 2;
      healthPath = "/api/health";
      cpuRequest = 500;
      memoryMb = 512;
      environment = {
        NODE_ENV = "production";
      };
    };

    # ── Customer C: Static site ─────────────────────────────────────
    # Customer selected: Static hosting, 3 replicas for HA
    services.customer-c-site = catalog.mkStaticSite {
      name = "customer-c-site";
      image = "ghcr.io/customer-c/portfolio:latest";
      replicas = 3;
    };

    # ── Infrastructure machines ─────────────────────────────────────
    # (In production, these would be cloud-autoscaled via the node pool)
    machines.host-1 = {
      targetHost = "10.0.1.1";
      pool = "customers";
      labels = {
        role = "customer";
        zone = "us-east-1a";
      };
      capacity = {
        cpu = 8000;
        memory = 32768;
        disk = 500000;
      };
      reserved = {
        cpu = 500;
        memory = 1024;
      };
    };

    machines.host-2 = {
      targetHost = "10.0.1.2";
      pool = "customers";
      labels = {
        role = "customer";
        zone = "us-east-1b";
      };
      capacity = {
        cpu = 8000;
        memory = 32768;
        disk = 500000;
      };
      reserved = {
        cpu = 500;
        memory = 1024;
      };
    };
  };
}
