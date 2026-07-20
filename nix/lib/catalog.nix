# Service catalog: reusable helpers for common service patterns.
#
# Provides generic builders (web services, static sites) and resource /
# health-check helpers.  Domain-specific templates (game servers,
# databases, caches, etc.) belong in downstream configuration repos
# that import this catalog.
#
# Usage:
#   let catalog = import ./catalog.nix { inherit pkgs; };
#   in {
#     fleet.services.my-app = catalog.mkWebService {
#       name = "my-app";
#       image = "registry.example.com/my-app:latest";
#       port = 8080;
#       replicas = 2;
#     };
#   }

{ pkgs }:

let
  # ── Helpers ──────────────────────────────────────────────────────────

  # Convert MB to the millicore-style resource value the fleet schema expects.
  mkResources =
    {
      cpuRequest ? 500,
      cpuLimit ? null,
      memoryRequest ? 512,
      memoryLimit ? null,
    }:
    {
      cpu = {
        request = cpuRequest;
        limit = cpuLimit;
      };
      memory = {
        request = memoryRequest;
        limit = memoryLimit;
      };
    };

  mkHealthCheck =
    {
      port,
      path ? "/",
    }:
    {
      inherit port;
      liveness = {
        inherit path;
        interval = 10;
        timeout = 5;
      };
      readiness = {
        inherit path;
        interval = 5;
      };
    };

in
{
  # ── Shared helpers (for downstream templates) ─────────────────────

  inherit mkResources mkHealthCheck;

  # ── Web service (generic HTTP) ────────────────────────────────────

  # A generic HTTP service backed by an OCI container image.
  #
  # Options:
  #   name        — service name (required)
  #   image       — OCI image reference (required)
  #   port        — HTTP port inside the container (default: 8080)
  #   replicas    — number of instances (default: 1)
  #   healthPath  — HTTP path for health checks (default: "/")
  #   cpuRequest  — CPU millicores requested (default: 250)
  #   memoryMb    — Memory in MB (default: 256)
  #   environment — extra env vars (default: {})
  mkWebService =
    {
      name,
      image,
      port ? 8080,
      replicas ? 1,
      healthPath ? "/",
      cpuRequest ? 250,
      memoryMb ? 256,
      environment ? { },
    }:
    {
      container = {
        inherit image;
      };
      ports.http = mkHealthCheck {
        inherit port;
        path = healthPath;
      };
      resources = mkResources {
        inherit cpuRequest;
        cpuLimit = cpuRequest * 2;
        memoryRequest = memoryMb;
        memoryLimit = memoryMb * 2;
      };
      inherit environment;
      scheduling = {
        inherit replicas;
        type = "service";
        update = {
          strategy = "rolling";
          maxParallel = 1;
          autoRevert = true;
        };
        disruptionBudget = {
          minAvailable = if replicas > 1 then replicas - 1 else 1;
        };
      };
    };

  # ── Static site (nginx) ──────────────────────────────────────────

  # Serve static files via nginx.
  #
  # Options:
  #   name     — service name (required)
  #   image    — OCI image with static content and nginx (required)
  #   replicas — number of instances (default: 2)
  mkStaticSite =
    {
      name,
      image,
      replicas ? 2,
    }:
    {
      container = {
        inherit image;
      };
      ports.http = mkHealthCheck {
        port = 80;
        path = "/";
      };
      resources = mkResources {
        cpuRequest = 100;
        cpuLimit = 500;
        memoryRequest = 64;
        memoryLimit = 256;
      };
      scheduling = {
        inherit replicas;
        type = "service";
        update = {
          strategy = "rolling";
          maxParallel = 1;
          autoRevert = true;
        };
        disruptionBudget = {
          minAvailable = if replicas > 1 then replicas - 1 else 1;
        };
      };
    };
}
