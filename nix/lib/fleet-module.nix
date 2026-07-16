# NixOS-style option module describing the fleet configuration schema.
#
# This mirrors the serde schema in `src/config/` (FleetConfig and friends).
# Evaluating a user config through this module turns a raw attrset into a
# typed, defaulted, self-documenting structure and surfaces mistakes as Nix
# option errors at eval time rather than as opaque serde failures at
# `nix eval --json .#fleet` time.
#
# The field names here are the camelCase JSON names the server expects, so the
# checked `config.fleet` attrset can be serialized straight to the JSON that
# `serde` consumes.
{ lib }:

let
  inherit (lib) types mkOption mkEnableOption;

  # A submodule whose options are exactly enumerated (no free-form extras),
  # matching `#[serde(deny_unknown_fields)]`.
  strictSubmodule = options: types.submodule { inherit options; };

  # ── Leaf value types ────────────────────────────────────────────────

  # request/limit resource pair (`ResourceValue`). `limit` is optional.
  resourceValue = strictSubmodule {
    request = mkOption {
      type = types.ints.unsigned;
      default = 0;
      description = "Requested amount (drives scheduling).";
    };
    limit = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "Hard limit (drives enforcement). null leaves it uncapped.";
    };
  };

  # `CgroupControlsConfig`.
  cgroupControls = strictSubmodule {
    cpuWeight = mkOption {
      type = types.ints.unsigned;
      default = 100;
      description = "CPU scheduling weight (1-10000).";
    };
    memoryHigh = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "Soft memory limit in MB.";
    };
    memoryMax = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "Hard memory limit in MB.";
    };
    ioWeight = mkOption {
      type = types.ints.unsigned;
      default = 100;
      description = "IO scheduling weight (1-10000).";
    };
    tasksMax = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "Maximum number of tasks (threads + processes).";
    };
    oomPolicy = mkOption {
      type = types.enum [
        "stop"
        "kill"
        "continue"
      ];
      default = "stop";
      description = "OOM policy.";
    };
  };

  # `ResourceConfig`.
  resources = strictSubmodule {
    cpu = mkOption {
      type = types.nullOr resourceValue;
      default = null;
      description = "CPU resources in millicores.";
    };
    memory = mkOption {
      type = types.nullOr resourceValue;
      default = null;
      description = "Memory resources in MB.";
    };
    disk = mkOption {
      type = types.nullOr resourceValue;
      default = null;
      description = "Disk resources in MB.";
    };
    extended = mkOption {
      type = types.attrsOf types.ints.unsigned;
      default = { };
      description = "Extended/device resources (e.g. { gpu = 1; }).";
    };
    cgroupControls = mkOption {
      type = types.nullOr cgroupControls;
      default = null;
      description = "Explicit systemd cgroup v2 resource controls.";
    };
  };

  # `HealthCheckConfig`. NOTE: this struct has no `rename_all`, so its JSON
  # keys are snake_case (`healthy_threshold` / `unhealthy_threshold`), unlike
  # most other structs in the schema.
  healthCheck = strictSubmodule {
    path = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "HTTP path to probe.";
    };
    interval = mkOption {
      type = types.ints.unsigned;
      default = 10;
      description = "Seconds between probes.";
    };
    timeout = mkOption {
      type = types.ints.unsigned;
      default = 5;
      description = "Per-probe timeout in seconds.";
    };
    healthy_threshold = mkOption {
      type = types.ints.unsigned;
      default = 3;
      description = "Consecutive successes to be considered healthy.";
    };
    unhealthy_threshold = mkOption {
      type = types.ints.unsigned;
      default = 3;
      description = "Consecutive failures to be considered unhealthy.";
    };
  };

  # `PortConfig`.
  port = strictSubmodule {
    port = mkOption {
      type = types.port;
      description = "Port number.";
    };
    protocol = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Protocol (e.g. tcp, http).";
    };
    hostname = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Virtual hostname for routing.";
    };
    healthCheck = mkOption {
      type = types.nullOr healthCheck;
      default = null;
      description = "Unified health check.";
    };
    liveness = mkOption {
      type = types.nullOr healthCheck;
      default = null;
      description = "Liveness probe (failures restart the service).";
    };
    readiness = mkOption {
      type = types.nullOr healthCheck;
      default = null;
      description = "Readiness probe (failures remove from load balancing).";
    };
    startup = mkOption {
      type = types.nullOr healthCheck;
      default = null;
      description = "Startup probe (suppresses liveness during init).";
    };
  };

  # `SecretConfig` (note: JSON key is `type`).
  secret = strictSubmodule {
    type = mkOption {
      type = types.str;
      description = "Secret backend type.";
    };
    engine = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Secret engine.";
    };
    role = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Secret role.";
    };
  };

  # `IdentityConfig`.
  identity = strictSubmodule {
    allowedCallers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "SPIFFE IDs allowed to call this service.";
    };
    allowedTargets = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "SPIFFE IDs this service may call.";
    };
  };

  # `ContainerConfig`.
  container = strictSubmodule {
    image = mkOption {
      type = types.str;
      description = "OCI image reference.";
    };
    pullPolicy = mkOption {
      type = types.enum [
        "Always"
        "IfNotPresent"
        "Never"
      ];
      default = "Always";
      description = "Image pull policy.";
    };
    entrypoint = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Override the image entrypoint.";
    };
    args = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Override the image CMD.";
    };
    workingDir = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Working directory inside the container.";
    };
    bindMounts = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Additional bind mounts (host:container[:ro]).";
    };
    registryAuthSecret = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Name of a secret holding registry credentials.";
    };
  };

  # `TemplateConfig`.
  template = strictSubmodule {
    source = mkOption {
      type = types.str;
      description = "Template source with {{ }} placeholders.";
    };
    destPath = mkOption {
      type = types.str;
      description = "Destination path for the rendered file.";
    };
    perms = mkOption {
      type = types.str;
      default = "0644";
      description = "Octal file permissions.";
    };
    changeSignal = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Signal to send the service after rendering.";
    };
  };

  # `VolumeConfig`.
  volume = strictSubmodule {
    name = mkOption {
      type = types.str;
      description = "Volume name (unique within the service).";
    };
    mountPath = mkOption {
      type = types.str;
      description = "Mount path inside the service.";
    };
    sizeMb = mkOption {
      type = types.ints.unsigned;
      default = 1024;
      description = "Requested storage size in MB.";
    };
    storageClass = mkOption {
      type = types.str;
      default = "local";
      description = "Storage class (local, nfs, zfs, ...).";
    };
    accessMode = mkOption {
      type = types.enum [
        "ReadWriteOnce"
        "ReadWriteMany"
      ];
      default = "ReadWriteOnce";
      description = "Volume access mode.";
    };
    reclaimRetain = mkOption {
      type = types.bool;
      default = true;
      description = "Retain the volume when the service is destroyed.";
    };
  };

  # `SidecarConfig`.
  sidecar = strictSubmodule {
    name = mkOption {
      type = types.str;
      description = "Sidecar name (unique within the service).";
    };
    command = mkOption {
      type = types.str;
      description = "Command to run for this sidecar.";
    };
    environment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = "Environment variables for the sidecar.";
    };
  };

  # `LifecycleConfig`.
  lifecycle = strictSubmodule {
    preStop = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Pre-stop hook command.";
    };
    postStart = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Post-start hook command.";
    };
    stopSignal = mkOption {
      type = types.str;
      default = "SIGTERM";
      description = "Signal for graceful shutdown.";
    };
    terminationGracePeriodSeconds = mkOption {
      type = types.ints.unsigned;
      default = 30;
      description = "Seconds to wait before force-killing.";
    };
  };

  # ── Scheduling sub-types ────────────────────────────────────────────

  constraint = strictSubmodule {
    attribute = mkOption { type = types.str; };
    op = mkOption { type = types.str; };
    value = mkOption { type = types.str; };
  };

  spreadTarget = strictSubmodule {
    value = mkOption { type = types.str; };
    percent = mkOption { type = types.ints.unsigned; };
  };

  spread = strictSubmodule {
    attribute = mkOption { type = types.str; };
    weight = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
    };
    targets = mkOption {
      type = types.listOf spreadTarget;
      default = [ ];
    };
    maxSkew = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
    };
    minDomains = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
    };
    required = mkOption {
      type = types.bool;
      default = false;
    };
  };

  affinity = strictSubmodule {
    attribute = mkOption { type = types.str; };
    op = mkOption { type = types.str; };
    value = mkOption { type = types.str; };
    weight = mkOption {
      type = types.int;
      default = 50;
    };
  };

  update = strictSubmodule {
    strategy = mkOption {
      type = types.enum [
        "rolling"
        "canary"
        "blue-green"
      ];
      default = "rolling";
    };
    maxParallel = mkOption {
      type = types.ints.unsigned;
      default = 1;
    };
    canary = mkOption {
      type = types.ints.unsigned;
      default = 0;
    };
    minHealthyTime = mkOption {
      type = types.ints.unsigned;
      default = 10;
    };
    healthyDeadline = mkOption {
      type = types.ints.unsigned;
      default = 300;
    };
    autoRevert = mkOption {
      type = types.bool;
      default = false;
    };
    autoPromote = mkOption {
      type = types.bool;
      default = false;
    };
    progressDeadline = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
    };
    healthCheck = mkOption {
      type = types.enum [
        "checks"
        "taskStates"
        "manual"
      ];
      default = "checks";
    };
  };

  toleration = strictSubmodule {
    key = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    op = mkOption {
      type = types.enum [
        "equal"
        "exists"
      ];
      default = "equal";
    };
    value = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    effect = mkOption {
      type = types.nullOr (
        types.enum [
          "noSchedule"
          "preferNoSchedule"
          "noExecute"
        ]
      );
      default = null;
    };
    tolerationSeconds = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
    };
  };

  restart = strictSubmodule {
    attempts = mkOption {
      type = types.ints.unsigned;
      default = 2;
    };
    intervalSecs = mkOption {
      type = types.ints.unsigned;
      default = 1800;
    };
    delaySecs = mkOption {
      type = types.ints.unsigned;
      default = 15;
    };
    mode = mkOption {
      type = types.enum [
        "fail"
        "delay"
      ];
      default = "fail";
    };
  };

  reschedule = strictSubmodule {
    delaySecs = mkOption {
      type = types.ints.unsigned;
      default = 30;
    };
    delayFunction = mkOption {
      type = types.enum [
        "constant"
        "exponential"
        "fibonacci"
      ];
      default = "exponential";
    };
    maxDelaySecs = mkOption {
      type = types.ints.unsigned;
      default = 3600;
    };
    attempts = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
    };
    intervalSecs = mkOption {
      type = types.ints.unsigned;
      default = 86400;
    };
  };

  migrate = strictSubmodule {
    maxParallel = mkOption {
      type = types.ints.unsigned;
      default = 1;
    };
    minHealthyTime = mkOption {
      type = types.ints.unsigned;
      default = 10;
    };
    healthyDeadline = mkOption {
      type = types.ints.unsigned;
      default = 300;
    };
    migrateOnReschedule = mkOption {
      type = types.bool;
      default = true;
    };
  };

  periodic = strictSubmodule {
    cron = mkOption { type = types.str; };
    timeZone = mkOption {
      type = types.str;
      default = "UTC";
    };
    concurrencyPolicy = mkOption {
      type = types.enum [
        "allow"
        "forbid"
        "replace"
      ];
      default = "allow";
    };
    successfulJobsHistoryLimit = mkOption {
      type = types.ints.unsigned;
      default = 3;
    };
    failedJobsHistoryLimit = mkOption {
      type = types.ints.unsigned;
      default = 1;
    };
  };

  serviceAffinity = strictSubmodule {
    targetService = mkOption { type = types.str; };
    topologyKey = mkOption { type = types.str; };
    weight = mkOption {
      type = types.int;
      default = 50;
    };
  };

  # min_available / max_unavailable accept either an integer count or a
  # percentage string ("50%"), matching `DisruptionValue` (untagged).
  disruptionValue = types.either types.ints.unsigned types.str;

  disruptionBudget = strictSubmodule {
    minAvailable = mkOption {
      type = types.nullOr disruptionValue;
      default = null;
    };
    maxUnavailable = mkOption {
      type = types.nullOr disruptionValue;
      default = null;
    };
  };

  parameterized = strictSubmodule {
    requiredParams = mkOption {
      type = types.listOf types.str;
      default = [ ];
    };
    optionalParams = mkOption {
      type = types.listOf types.str;
      default = [ ];
    };
  };

  # `SchedulingConfig` (JSON key for job_type is `type`).
  scheduling = strictSubmodule {
    replicas = mkOption {
      type = types.ints.unsigned;
      default = 1;
    };
    type = mkOption {
      type = types.enum [
        "service"
        "stateful"
        "system"
        "batch"
        "sysbatch"
      ];
      default = "service";
    };
    constraints = mkOption {
      type = types.listOf constraint;
      default = [ ];
    };
    spread = mkOption {
      type = types.listOf spread;
      default = [ ];
    };
    affinity = mkOption {
      type = types.listOf affinity;
      default = [ ];
    };
    update = mkOption {
      type = update;
      default = { };
    };
    pool = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    priority = mkOption {
      type = types.ints.unsigned;
      default = 50;
    };
    tolerations = mkOption {
      type = types.listOf toleration;
      default = [ ];
    };
    restart = mkOption {
      type = restart;
      default = { };
    };
    reschedule = mkOption {
      type = reschedule;
      default = { };
    };
    migrate = mkOption {
      type = migrate;
      default = { };
    };
    periodic = mkOption {
      type = types.nullOr periodic;
      default = null;
    };
    serviceAffinity = mkOption {
      type = types.listOf serviceAffinity;
      default = [ ];
    };
    disruptionBudget = mkOption {
      type = types.nullOr disruptionBudget;
      default = null;
    };
    parameterized = mkOption {
      type = types.nullOr parameterized;
      default = null;
    };
  };

  # ── Service ─────────────────────────────────────────────────────────

  service = strictSubmodule {
    command = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Command for native (Nix) process services.";
    };
    container = mkOption {
      type = types.nullOr container;
      default = null;
      description = "OCI container configuration.";
    };
    ports = mkOption {
      type = types.attrsOf port;
      default = { };
    };
    secrets = mkOption {
      type = types.attrsOf secret;
      default = { };
    };
    identity = mkOption {
      type = identity;
      default = { };
    };
    resources = mkOption {
      type = resources;
      default = { };
    };
    scheduling = mkOption {
      type = scheduling;
      default = { };
    };
    environment = mkOption {
      type = types.attrsOf types.str;
      default = { };
    };
    templates = mkOption {
      type = types.attrsOf template;
      default = { };
    };
    lifecycle = mkOption {
      type = lifecycle;
      default = { };
    };
    volumes = mkOption {
      type = types.listOf volume;
      default = [ ];
    };
    sidecars = mkOption {
      type = types.listOf sidecar;
      default = [ ];
    };
  };

  # ── Machines / node pools ───────────────────────────────────────────

  capacity = strictSubmodule {
    cpu = mkOption {
      type = types.ints.unsigned;
      default = 0;
    };
    memory = mkOption {
      type = types.ints.unsigned;
      default = 0;
    };
    disk = mkOption {
      type = types.ints.unsigned;
      default = 0;
    };
  };

  taint = strictSubmodule {
    key = mkOption { type = types.str; };
    value = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    effect = mkOption {
      type = types.enum [
        "noSchedule"
        "preferNoSchedule"
        "noExecute"
      ];
    };
  };

  machine = strictSubmodule {
    targetHost = mkOption {
      type = types.str;
      description = "SSH host used for deployments.";
    };
    labels = mkOption {
      type = types.attrsOf types.str;
      default = { };
    };
    capacity = mkOption {
      type = capacity;
      default = { };
    };
    pool = mkOption {
      type = types.str;
      default = "default";
    };
    reserved = mkOption {
      type = capacity;
      default = { };
    };
    taints = mkOption {
      type = types.listOf taint;
      default = [ ];
    };
    extendedResources = mkOption {
      type = types.attrsOf types.ints.unsigned;
      default = { };
    };
  };

  poolScalingRule = strictSubmodule {
    metricName = mkOption { type = types.str; };
    targetValue = mkOption { type = types.float; };
    scaleUpThreshold = mkOption { type = types.float; };
    scaleDownThreshold = mkOption { type = types.float; };
  };

  poolScaling = strictSubmodule {
    minCount = mkOption { type = types.ints.unsigned; };
    maxCount = mkOption { type = types.ints.unsigned; };
    rules = mkOption {
      type = types.listOf poolScalingRule;
      default = [ ];
    };
  };

  spot = strictSubmodule {
    enabled = mkOption {
      type = types.bool;
      default = false;
    };
    maxPrice = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    fallbackToOnDemand = mkOption {
      type = types.bool;
      default = true;
    };
  };

  cloudImage = strictSubmodule {
    nixosConfig = mkOption { type = types.str; };
    diskImageAttr = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    namePrefix = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    s3Bucket = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    gcsBucket = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    storageAccount = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    storageContainer = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    retainCount = mkOption {
      type = types.ints.unsigned;
      default = 2;
    };
    maxAgeSeconds = mkOption {
      type = types.ints.unsigned;
      default = 604800;
    };
  };

  cloud = strictSubmodule {
    provider = mkOption {
      type = types.enum [
        "aws"
        "azure"
        "gcp"
      ];
    };
    region = mkOption { type = types.str; };
    instanceType = mkOption { type = types.str; };
    imageId = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    image = mkOption {
      type = types.nullOr cloudImage;
      default = null;
    };
    subnetId = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    securityGroupIds = mkOption {
      type = types.listOf types.str;
      default = [ ];
    };
    sshKeyName = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    zone = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    diskSizeGb = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
    };
    resourceGroup = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    project = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    machineCapacity = mkOption { type = capacity; };
    iamInstanceProfile = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    spot = mkOption {
      type = types.nullOr spot;
      default = null;
    };
    launchTimeoutSeconds = mkOption {
      type = types.ints.unsigned;
      default = 300;
    };
    joinTimeoutSeconds = mkOption {
      type = types.ints.unsigned;
      default = 600;
    };
    drainWaitSeconds = mkOption {
      type = types.ints.unsigned;
      default = 30;
    };
  };

  nodePool = strictSubmodule {
    labels = mkOption {
      type = types.attrsOf types.str;
      default = { };
    };
    scaling = mkOption {
      type = types.nullOr poolScaling;
      default = null;
    };
    schedulerAlgorithm = mkOption {
      type = types.nullOr (
        types.enum [
          "binpack"
          "spread"
        ]
      );
      default = null;
    };
    memoryOversubscription = mkOption {
      type = types.bool;
      default = false;
    };
    cloud = mkOption {
      type = types.nullOr cloud;
      default = null;
    };
  };

  # ── Fleet-level extras ──────────────────────────────────────────────

  hooks = strictSubmodule {
    preDeploy = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
    };
    postDeploy = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
    };
    preDrain = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
    };
    postDrain = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
    };
  };

  admissionWebhook = strictSubmodule {
    name = mkOption { type = types.str; };
    url = mkOption { type = types.str; };
    failPolicy = mkOption {
      type = types.enum [
        "fail"
        "ignore"
      ];
      default = "fail";
    };
    timeoutSeconds = mkOption {
      type = types.ints.unsigned;
      default = 10;
    };
  };
in
{
  options.fleet = {
    name = mkOption {
      type = types.str;
      description = "Fleet name.";
    };
    domain = mkOption {
      type = types.str;
      description = "SPIFFE trust domain for fleet identities.";
    };
    services = mkOption {
      type = types.attrsOf service;
      default = { };
      description = "Services managed by the fleet, keyed by name.";
    };
    machines = mkOption {
      type = types.attrsOf machine;
      default = { };
      description = "Statically declared machines, keyed by name.";
    };
    nodePools = mkOption {
      type = types.attrsOf nodePool;
      default = { };
      description = "Node pools, keyed by name.";
    };
    hooks = mkOption {
      type = hooks;
      default = { };
      description = "Deployment lifecycle script hooks.";
    };
    admissionWebhooks = mkOption {
      type = types.listOf admissionWebhook;
      default = [ ];
      description = "Admission webhooks validating deployments.";
    };
    policies = mkOption {
      # Policy rules are validated server-side; accept opaque attrsets here.
      type = types.listOf (types.attrsOf types.anything);
      default = [ ];
      description = "Organizational policy rules evaluated during plan/apply.";
    };
  };
}
