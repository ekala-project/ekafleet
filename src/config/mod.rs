pub mod scheduling;
pub use scheduling::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level fleet configuration as produced by `nix eval --json .#fleet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FleetConfig {
    pub name: String,
    pub domain: String,
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub machines: HashMap<String, MachineConfig>,
    #[serde(default)]
    pub node_pools: HashMap<String, NodePoolConfig>,
    /// Script hooks executed at deployment lifecycle points.
    #[serde(default)]
    pub hooks: HookConfig,
    /// Admission webhooks for validating deployments.
    #[serde(default)]
    pub admission_webhooks: Vec<AdmissionWebhook>,
    /// Organizational policy rules evaluated during plan/apply.
    #[serde(default)]
    pub policies: Vec<crate::server::policy::PolicyRule>,
}

/// Script hooks executed at various deployment lifecycle points.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HookConfig {
    /// Command executed before deploying a service.
    #[serde(default)]
    pub pre_deploy: Option<Vec<String>>,
    /// Command executed after deploying a service.
    #[serde(default)]
    pub post_deploy: Option<Vec<String>>,
    /// Command executed before draining a node.
    #[serde(default)]
    pub pre_drain: Option<Vec<String>>,
    /// Command executed after draining a node.
    #[serde(default)]
    pub post_drain: Option<Vec<String>>,
}

/// Configuration for an admission webhook that validates deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmissionWebhook {
    /// Unique name for this webhook.
    pub name: String,
    /// URL to POST admission review requests to.
    pub url: String,
    /// Policy when the webhook is unreachable or returns an error.
    #[serde(default)]
    pub fail_policy: FailPolicy,
    /// Request timeout in seconds.
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,
}

/// Policy for handling webhook failures (unreachable, timeout, error).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailPolicy {
    /// Reject the request if the webhook fails.
    #[default]
    Fail,
    /// Allow the request even if the webhook fails.
    Ignore,
}

fn default_webhook_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Command to execute for native (Nix) process services.
    /// Required unless `container` is set.
    #[serde(default)]
    pub command: Option<String>,
    /// OCI container configuration. When set, the service runs as a
    /// systemd-nspawn container instead of a native process.
    #[serde(default)]
    pub container: Option<ContainerConfig>,
    #[serde(default)]
    pub ports: HashMap<String, PortConfig>,
    #[serde(default)]
    pub secrets: HashMap<String, SecretConfig>,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub scheduling: SchedulingConfig,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    /// Configuration file templates to render and inject into the service.
    /// Keys are destination paths, values are template definitions.
    #[serde(default)]
    pub templates: HashMap<String, TemplateConfig>,
    /// Lifecycle hooks and shutdown configuration.
    #[serde(default)]
    pub lifecycle: LifecycleConfig,
    /// Persistent volumes to attach to this service.
    #[serde(default)]
    pub volumes: Vec<VolumeConfig>,
    /// Sidecar processes to run alongside this service.
    #[serde(default)]
    pub sidecars: Vec<SidecarConfig>,
}

/// OCI container configuration for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContainerConfig {
    /// OCI image reference (e.g. "ghcr.io/org/app:v1.0@sha256:...").
    pub image: String,
    /// Pull policy: "Always", "IfNotPresent", or "Never".
    #[serde(default)]
    pub pull_policy: ContainerPullPolicy,
    /// Override the image's entrypoint.
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    /// Override the image's CMD.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Working directory inside the container.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Additional bind mounts (host_path:container_path[:ro]).
    #[serde(default)]
    pub bind_mounts: Vec<String>,
    /// Registry credentials secret name (references a secret in the service's secrets).
    #[serde(default)]
    pub registry_auth_secret: Option<String>,
}

/// Pull policy for OCI container images.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerPullPolicy {
    /// Always check the registry for a newer image.
    #[default]
    Always,
    /// Only pull if the image is not present locally.
    IfNotPresent,
    /// Never pull from the registry; fail if not present locally.
    Never,
}

/// A persistent volume to attach to a stateful service.
/// Volumes survive service restarts and are migrated when a stateful
/// service is rescheduled (if the storage backend supports it).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VolumeConfig {
    /// Volume name (unique within the service).
    pub name: String,
    /// Mount path inside the service's filesystem namespace.
    pub mount_path: String,
    /// Requested storage size in megabytes.
    #[serde(default = "default_volume_size")]
    pub size_mb: u64,
    /// Storage class (e.g., "local", "nfs", "zfs"). Defaults to "local".
    #[serde(default = "default_storage_class")]
    pub storage_class: String,
    /// Access mode: "ReadWriteOnce" (default) or "ReadWriteMany".
    #[serde(default)]
    pub access_mode: VolumeAccessMode,
    /// If true, the volume is not deleted when the service is destroyed.
    #[serde(default = "default_true")]
    pub reclaim_retain: bool,
}

fn default_volume_size() -> u64 {
    1024
}
fn default_storage_class() -> String {
    "local".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum VolumeAccessMode {
    #[default]
    ReadWriteOnce,
    ReadWriteMany,
}

/// A configuration file template that gets rendered with fleet context
/// (service discovery, secrets, metadata) and written to a destination path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TemplateConfig {
    /// Template source: inline content with `{{ }}` placeholders.
    pub source: String,
    /// Destination path where the rendered file is written.
    pub dest_path: String,
    /// File permissions (octal, e.g., "0644"). Defaults to "0644".
    #[serde(default = "default_file_perms")]
    pub perms: String,
    /// If true, signal the service to reload after rendering (SIGHUP).
    #[serde(default)]
    pub change_signal: Option<String>,
}

fn default_file_perms() -> String {
    "0644".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PortConfig {
    pub port: u16,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    /// Unified health check (used when liveness/readiness are not specified separately).
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// Liveness probe: failures trigger a service restart.
    #[serde(default)]
    pub liveness: Option<HealthCheckConfig>,
    /// Readiness probe: failures remove the instance from load balancing
    /// but do not restart it.
    #[serde(default)]
    pub readiness: Option<HealthCheckConfig>,
    /// Startup probe: suppresses liveness checks until the service finishes
    /// initializing. Once the startup probe passes, liveness takes over.
    #[serde(default)]
    pub startup: Option<HealthCheckConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_interval")]
    pub interval: u32,
    #[serde(default = "default_timeout")]
    pub timeout: u32,
    #[serde(default = "default_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_interval() -> u32 {
    10
}
fn default_timeout() -> u32 {
    5
}
fn default_threshold() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretConfig {
    #[serde(rename = "type")]
    pub secret_type: String,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentityConfig {
    #[serde(default)]
    pub allowed_callers: Vec<String>,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceConfig {
    #[serde(default)]
    pub cpu: Option<ResourceValue>,
    #[serde(default)]
    pub memory: Option<ResourceValue>,
    #[serde(default)]
    pub disk: Option<ResourceValue>,
    /// Extended/device resources (e.g., `{"gpu": 1, "fpga": 2}`).
    #[serde(default)]
    pub extended: HashMap<String, u64>,
    /// Systemd cgroup v2 resource controls for fine-grained resource management.
    #[serde(default)]
    pub cgroup_controls: Option<CgroupControlsConfig>,
}

/// Systemd cgroup v2 resource controls. These are translated directly into
/// systemd unit directives for per-service resource management.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CgroupControlsConfig {
    /// CPU scheduling weight (1-10000, default: 100).
    /// Higher values get more CPU time relative to other services.
    #[serde(default = "default_cpu_weight")]
    pub cpu_weight: u32,
    /// Soft memory limit in MB. When exceeded, the kernel reclaims memory
    /// under pressure but does not kill the process.
    #[serde(default)]
    pub memory_high: Option<u64>,
    /// Hard memory limit in MB. Exceeding this triggers OOM based on oomPolicy.
    #[serde(default)]
    pub memory_max: Option<u64>,
    /// IO scheduling weight (1-10000, default: 100).
    #[serde(default = "default_io_weight")]
    pub io_weight: u32,
    /// Maximum number of tasks (threads + processes) for this service.
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// OOM policy: "stop" (default), "kill", or "continue".
    #[serde(default = "default_oom_policy")]
    pub oom_policy: String,
}

fn default_cpu_weight() -> u32 {
    100
}
fn default_io_weight() -> u32 {
    100
}
fn default_oom_policy() -> String {
    "stop".to_string()
}

impl ResourceConfig {
    /// Translate declared resources into the proto [`CgroupControls`] the agent
    /// renders into systemd unit directives. Explicit `cgroupControls` take
    /// precedence; where they are unset, hard limits are derived from the
    /// declared `cpu.limit` (millicores → `CPUQuota` percent-of-a-core) and
    /// `memory.limit` (MB → `MemoryMax`). Returns `None` when nothing at all is
    /// declared, so the agent leaves the service uncapped.
    pub fn to_cgroup_controls(&self) -> Option<crate::proto::CgroupControls> {
        let explicit = self.cgroup_controls.as_ref();

        // Derive a hard CPU cap from cpu.limit (millicores). 1000 mc == 1 core
        // == CPUQuota=100%. A limit below 1 mc rounds up to 1% so a declared
        // limit is never silently dropped to "unlimited".
        let derived_cpu_quota = self
            .cpu
            .as_ref()
            .and_then(|c| c.limit)
            .filter(|&l| l > 0)
            .map(|mc| mc.div_ceil(10).max(1) as u32);

        // Derive a hard memory cap from memory.limit (MB).
        let derived_mem_max = self
            .memory
            .as_ref()
            .and_then(|m| m.limit)
            .filter(|&l| l > 0);

        let cpu_weight = explicit.map(|c| c.cpu_weight).unwrap_or(0);
        let io_weight = explicit.map(|c| c.io_weight).unwrap_or(0);
        let tasks_max = explicit.and_then(|c| c.tasks_max).unwrap_or(0);
        let memory_high_mb = explicit.and_then(|c| c.memory_high).unwrap_or(0);
        let oom_policy = explicit.map(|c| c.oom_policy.clone()).unwrap_or_default();

        // Explicit memory_max wins over the derived limit.
        let memory_max_mb = explicit
            .and_then(|c| c.memory_max)
            .or(derived_mem_max)
            .unwrap_or(0);

        let cpu_quota_percent = derived_cpu_quota.unwrap_or(0);

        // If nothing is declared at all, leave the service uncapped.
        if cpu_weight == 0
            && io_weight == 0
            && tasks_max == 0
            && memory_high_mb == 0
            && memory_max_mb == 0
            && cpu_quota_percent == 0
            && oom_policy.is_empty()
        {
            return None;
        }

        Some(crate::proto::CgroupControls {
            cpu_weight,
            memory_high_mb,
            memory_max_mb,
            io_weight,
            tasks_max,
            oom_policy,
            cpu_quota_percent,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceValue {
    #[serde(default)]
    pub request: u64,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MachineConfig {
    pub target_host: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub capacity: CapacityConfig,
    /// Node pool this machine belongs to. Defaults to "default".
    #[serde(default = "default_pool")]
    pub pool: String,
    /// Capacity reserved for OS/system use. Scheduler uses capacity - reserved.
    #[serde(default)]
    pub reserved: CapacityConfig,
    /// Taints repel services that don't tolerate them.
    #[serde(default)]
    pub taints: Vec<Taint>,
    /// Extended/device resources available on this machine (e.g., `{"gpu": 4, "fpga": 2}`).
    #[serde(default)]
    pub extended_resources: HashMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityConfig {
    #[serde(default)]
    pub cpu: u64,
    #[serde(default)]
    pub memory: u64,
    #[serde(default)]
    pub disk: u64,
}

fn default_pool() -> String {
    "default".to_string()
}

/// Configuration for a node pool — a named group of machines with shared labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodePoolConfig {
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub scaling: Option<PoolScalingConfig>,
    #[serde(default)]
    pub scheduler_algorithm: Option<SchedulerAlgorithm>,
    #[serde(default)]
    pub memory_oversubscription: bool,
    /// Cloud provider configuration for autoscaling this pool.
    /// When set, pool scaling decisions will provision/destroy cloud VMs.
    #[serde(default)]
    pub cloud: Option<CloudProviderConfig>,
}

/// Cloud provider configuration for a node pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloudProviderConfig {
    /// Cloud provider type: "aws", "azure", or "gcp".
    pub provider: CloudProviderType,
    /// Cloud region (e.g., "us-east-1", "eastus", "us-central1").
    pub region: String,
    /// Instance type / VM size (e.g., "c6i.xlarge", "Standard_D4s_v3", "n2-standard-4").
    pub instance_type: String,
    /// Static machine image ID (e.g., AMI ID, managed image name, GCE image name).
    /// Mutually exclusive with `image`. One of `image_id` or `image` must be set.
    #[serde(default)]
    pub image_id: Option<String>,
    /// Managed image configuration. When set, ekafleet builds NixOS disk images
    /// from the referenced Nix configuration and registers them with the cloud
    /// provider automatically. Mutually exclusive with `image_id`.
    #[serde(default)]
    pub image: Option<CloudImageConfig>,
    /// Subnet ID for network placement (AWS/GCP).
    #[serde(default)]
    pub subnet_id: Option<String>,
    /// Security group IDs (AWS).
    #[serde(default)]
    pub security_group_ids: Vec<String>,
    /// SSH key name for instance access.
    #[serde(default)]
    pub ssh_key_name: Option<String>,
    /// Availability zone (e.g., "us-east-1a", "us-central1-a").
    #[serde(default)]
    pub zone: Option<String>,
    /// Root disk size in GB.
    #[serde(default)]
    pub disk_size_gb: Option<u64>,
    /// Azure resource group name (required for Azure).
    #[serde(default)]
    pub resource_group: Option<String>,
    /// GCP project ID (required for GCP).
    #[serde(default)]
    pub project: Option<String>,
    /// Expected machine capacity for scheduling before the agent reports
    /// real resources. CPU in millicores, memory/disk in MB.
    pub machine_capacity: CapacityConfig,
    /// IAM instance profile ARN (AWS), managed identity resource ID (Azure),
    /// or service account email (GCP).
    #[serde(default)]
    pub iam_instance_profile: Option<String>,
    /// Spot/preemptible instance configuration.
    #[serde(default)]
    pub spot: Option<SpotConfig>,
    /// Maximum time (seconds) to wait for an instance to reach running state.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_launch_timeout")]
    pub launch_timeout_seconds: u64,
    /// Maximum time (seconds) to wait for an agent to join after instance
    /// creation. Instances that fail to join within this window are terminated.
    /// Default: 600 (10 minutes).
    #[serde(default = "default_join_timeout")]
    pub join_timeout_seconds: u64,
    /// Seconds to wait after marking a node unschedulable before terminating
    /// it during scale-down. Gives the reconciler time to reschedule services.
    /// Default: 30.
    #[serde(default = "default_drain_wait")]
    pub drain_wait_seconds: u64,
}

/// Configuration for ekafleet-managed cloud images. When present in a pool's
/// cloud config, ekafleet builds NixOS disk images from the referenced Nix
/// configuration, uploads them to cloud storage, and registers them as
/// AMIs / managed images / GCE images.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloudImageConfig {
    /// Nix flake reference for the NixOS system configuration.
    /// Must expose `config.system.build.toplevel` and a disk image attribute.
    /// e.g., ".#nixosConfigurations.cloud-worker"
    pub nixos_config: String,
    /// Nix attribute path for the disk image build under the NixOS config.
    /// Defaults per provider: aws → "amazonImage", azure → "azureImage", gcp → "gceImage".
    #[serde(default)]
    pub disk_image_attr: Option<String>,
    /// Image name prefix for cloud registration. Default: "<fleet-name>-<pool-name>".
    #[serde(default)]
    pub name_prefix: Option<String>,
    /// S3 bucket for AWS image import (required for AWS provider).
    #[serde(default)]
    pub s3_bucket: Option<String>,
    /// GCS bucket for GCP image upload (required for GCP provider).
    #[serde(default)]
    pub gcs_bucket: Option<String>,
    /// Azure storage account name for VHD upload (required for Azure provider).
    #[serde(default)]
    pub storage_account: Option<String>,
    /// Azure storage container name. Default: "ekafleet-images".
    #[serde(default)]
    pub storage_container: Option<String>,
    /// Number of previous images to retain per pool for rollback. Default: 2.
    /// The current active image is always kept; this controls how many older
    /// generations are preserved before cleanup.
    #[serde(default = "default_image_retain_count")]
    pub retain_count: u32,
    /// Maximum age (in seconds) for unused images before automatic cleanup.
    /// Default: 604800 (7 days). Images older than this that are not the
    /// current active image and not within retain_count are deleted.
    #[serde(default = "default_image_max_age")]
    pub max_age_seconds: u64,
}

/// Spot/preemptible instance configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpotConfig {
    /// Whether to use spot/preemptible instances.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum price per hour (AWS spot). If omitted, uses on-demand price cap.
    #[serde(default)]
    pub max_price: Option<String>,
    /// Fallback to on-demand if spot capacity is unavailable. Default: true.
    #[serde(default = "default_true")]
    pub fallback_to_on_demand: bool,
}

fn default_launch_timeout() -> u64 {
    300
}

fn default_join_timeout() -> u64 {
    600
}

fn default_drain_wait() -> u64 {
    30
}

fn default_image_retain_count() -> u32 {
    2
}

fn default_image_max_age() -> u64 {
    604800 // 7 days
}

/// Supported cloud provider types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProviderType {
    Aws,
    Azure,
    Gcp,
}

/// Autoscaling configuration for a node pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PoolScalingConfig {
    pub min_count: u32,
    pub max_count: u32,
    #[serde(default)]
    pub rules: Vec<PoolScalingRule>,
}

/// A pool scaling rule based on aggregate pool metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PoolScalingRule {
    pub metric_name: String,
    pub target_value: f64,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
}

/// Lifecycle hooks and shutdown configuration for a service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LifecycleConfig {
    /// Command to execute before stopping the service (pre-stop hook).
    /// Runs before the shutdown signal is sent. If the command fails,
    /// the service is still stopped.
    #[serde(default)]
    pub pre_stop: Option<Vec<String>>,
    /// Command to execute after the service starts (post-start hook).
    #[serde(default)]
    pub post_start: Option<Vec<String>>,
    /// Signal to send for graceful shutdown. Defaults to "SIGTERM".
    #[serde(default = "default_stop_signal")]
    pub stop_signal: String,
    /// Seconds to wait after sending the stop signal before force-killing.
    /// Defaults to 30 seconds.
    #[serde(default = "default_grace_period")]
    pub termination_grace_period_seconds: u64,
}

fn default_stop_signal() -> String {
    "SIGTERM".to_string()
}
fn default_grace_period() -> u64 {
    30
}

/// A sidecar process that runs alongside the main service.
/// Sidecars share the same lifecycle and are started after the main process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfig {
    /// Sidecar name (unique within the service).
    pub name: String,
    /// Command to execute for this sidecar.
    pub command: String,
    /// Environment variables for the sidecar process.
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

/// Validate a fleet configuration for consistency.
pub fn validate(config: &FleetConfig) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    for (name, machine) in &config.machines {
        if machine.pool != "default" && !config.node_pools.contains_key(&machine.pool) {
            errors.push(format!(
                "machine '{}' references undefined pool '{}'",
                name, machine.pool
            ));
        }
        if machine.reserved.cpu > machine.capacity.cpu {
            errors.push(format!(
                "machine '{}' has reserved CPU ({}) exceeding capacity ({})",
                name, machine.reserved.cpu, machine.capacity.cpu
            ));
        }
        if machine.reserved.memory > machine.capacity.memory {
            errors.push(format!(
                "machine '{}' has reserved memory ({}) exceeding capacity ({})",
                name, machine.reserved.memory, machine.capacity.memory
            ));
        }
    }

    for (name, service) in &config.services {
        if let Some(ref pool) = service.scheduling.pool
            && !config.node_pools.contains_key(pool)
        {
            errors.push(format!(
                "service '{}' prefers undefined pool '{}'",
                name, pool
            ));
        }

        // Exactly one of command or container must be set
        match (&service.command, &service.container) {
            (None, None) => {
                errors.push(format!(
                    "service '{}' must have either 'command' or 'container'",
                    name
                ));
            }
            (Some(_), Some(_)) => {
                errors.push(format!(
                    "service '{}' cannot have both 'command' and 'container'",
                    name
                ));
            }
            _ => {}
        }
    }

    // Validate cloud provider configuration
    for (name, pool) in &config.node_pools {
        if let Some(cloud) = &pool.cloud {
            if cloud.provider == CloudProviderType::Azure && cloud.resource_group.is_none() {
                errors.push(format!(
                    "pool '{}' uses Azure provider but missing 'resourceGroup'",
                    name
                ));
            }
            if cloud.provider == CloudProviderType::Gcp && cloud.project.is_none() {
                errors.push(format!(
                    "pool '{}' uses GCP provider but missing 'project'",
                    name
                ));
            }
            if pool.scaling.is_none() {
                errors.push(format!(
                    "pool '{}' has cloud provider config but no scaling config",
                    name
                ));
            }

            // Exactly one of image_id or image must be set
            match (&cloud.image_id, &cloud.image) {
                (None, None) => {
                    errors.push(format!(
                        "pool '{}' cloud config must have either 'imageId' or 'image'",
                        name
                    ));
                }
                (Some(_), Some(_)) => {
                    errors.push(format!(
                        "pool '{}' cloud config cannot have both 'imageId' and 'image'",
                        name
                    ));
                }
                (None, Some(img)) => {
                    // Validate provider-specific storage requirements for managed images
                    if cloud.provider == CloudProviderType::Aws && img.s3_bucket.is_none() {
                        errors.push(format!(
                            "pool '{}' managed image config requires 's3Bucket' for AWS",
                            name
                        ));
                    }
                    if cloud.provider == CloudProviderType::Gcp && img.gcs_bucket.is_none() {
                        errors.push(format!(
                            "pool '{}' managed image config requires 'gcsBucket' for GCP",
                            name
                        ));
                    }
                    if cloud.provider == CloudProviderType::Azure && img.storage_account.is_none() {
                        errors.push(format!(
                            "pool '{}' managed image config requires 'storageAccount' for Azure",
                            name
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    // Validate periodic is only on batch/sysbatch types
    for (name, service) in &config.services {
        if service.scheduling.periodic.is_some()
            && service.scheduling.job_type != JobType::Batch
            && service.scheduling.job_type != JobType::Sysbatch
        {
            errors.push(format!(
                "service '{}' has periodic config but is not batch/sysbatch type",
                name
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod nix_module_tests {
    use super::*;

    /// The `nix/lib/fleet-module.nix` schema emits every option, including
    /// explicit `null` for unset `Option` fields and camelCase keys. This
    /// round-trip guards that the serde schema stays in lockstep with the Nix
    /// option module: if a field is renamed or its default shape changes on
    /// one side without the other, this deserialization fails.
    #[test]
    fn module_shaped_json_deserializes() {
        // Mirrors the shape produced by evaluating a config through
        // fleet-module.nix (nulls present, renamed keys `type`/secret `type`,
        // nested defaults filled in).
        let json = r#"{
            "name": "example",
            "domain": "fleet.internal",
            "admissionWebhooks": [],
            "policies": [],
            "hooks": {
                "preDeploy": null, "postDeploy": null,
                "preDrain": null, "postDrain": null
            },
            "nodePools": {
                "default": {
                    "labels": {"env": "prod"},
                    "scaling": null,
                    "schedulerAlgorithm": "spread",
                    "memoryOversubscription": false,
                    "cloud": null
                }
            },
            "machines": {
                "node-1": {
                    "targetHost": "10.0.0.1",
                    "labels": {},
                    "capacity": {"cpu": 8000, "memory": 16384, "disk": 200000},
                    "pool": "default",
                    "reserved": {"cpu": 500, "memory": 512, "disk": 0},
                    "taints": [],
                    "extendedResources": {}
                }
            },
            "services": {
                "api": {
                    "command": "run",
                    "container": null,
                    "environment": {"LOG": "info"},
                    "identity": {"allowedCallers": [], "allowedTargets": []},
                    "lifecycle": {
                        "preStop": null, "postStart": null,
                        "stopSignal": "SIGTERM",
                        "terminationGracePeriodSeconds": 30
                    },
                    "ports": {
                        "http": {
                            "port": 8080, "protocol": null, "hostname": null,
                            "healthCheck": null,
                            "liveness": {
                                "path": "/", "interval": 10, "timeout": 5,
                                "healthy_threshold": 3, "unhealthy_threshold": 3
                            },
                            "readiness": null, "startup": null
                        }
                    },
                    "resources": {
                        "cgroupControls": null,
                        "cpu": {"request": 500, "limit": 1000},
                        "disk": null,
                        "extended": {},
                        "memory": {"request": 256, "limit": 512}
                    },
                    "scheduling": {
                        "affinity": [], "constraints": [],
                        "disruptionBudget": {"maxUnavailable": null, "minAvailable": 2},
                        "migrate": {
                            "healthyDeadline": 300, "maxParallel": 1,
                            "migrateOnReschedule": true, "minHealthyTime": 10
                        },
                        "parameterized": null, "periodic": null,
                        "pool": "default", "priority": 50, "replicas": 3,
                        "reschedule": {
                            "attempts": null, "delayFunction": "exponential",
                            "delaySecs": 30, "intervalSecs": 86400, "maxDelaySecs": 3600
                        },
                        "restart": {
                            "attempts": 2, "delaySecs": 15,
                            "intervalSecs": 1800, "mode": "fail"
                        },
                        "serviceAffinity": [],
                        "spread": [{
                            "attribute": "labels.zone", "maxSkew": null,
                            "minDomains": null, "required": false,
                            "targets": [], "weight": 50
                        }],
                        "tolerations": [], "type": "service",
                        "update": {
                            "autoPromote": false, "autoRevert": true,
                            "canary": 0, "healthCheck": "checks",
                            "healthyDeadline": 300, "maxParallel": 1,
                            "minHealthyTime": 10, "progressDeadline": null,
                            "strategy": "rolling"
                        }
                    },
                    "secrets": {},
                    "sidecars": [],
                    "templates": {},
                    "volumes": []
                }
            }
        }"#;

        let config: FleetConfig =
            serde_json::from_str(json).expect("module-shaped JSON must deserialize");
        assert_eq!(config.name, "example");
        assert!(validate(&config).is_ok());
        let svc = &config.services["api"];
        assert_eq!(svc.scheduling.job_type, JobType::Service);
        assert_eq!(svc.scheduling.update.strategy, UpdateStrategy::Rolling);
        assert_eq!(svc.ports["http"].port, 8080);
    }
}

#[cfg(test)]
mod cgroup_tests {
    use super::*;

    fn rv(request: u64, limit: Option<u64>) -> ResourceValue {
        ResourceValue { request, limit }
    }

    #[test]
    fn no_resources_yields_no_controls() {
        let rc = ResourceConfig::default();
        assert!(rc.to_cgroup_controls().is_none());
    }

    #[test]
    fn requests_without_limits_yield_no_controls() {
        // Requests drive scheduling, not enforcement, so a service that only
        // sets requests must be left uncapped.
        let rc = ResourceConfig {
            cpu: Some(rv(500, None)),
            memory: Some(rv(256, None)),
            ..Default::default()
        };
        assert!(rc.to_cgroup_controls().is_none());
    }

    #[test]
    fn cpu_limit_becomes_cpu_quota_percent() {
        // 1500 millicores == 1.5 cores == CPUQuota=150%.
        let rc = ResourceConfig {
            cpu: Some(rv(500, Some(1500))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_quota_percent, 150);
        assert_eq!(cg.memory_max_mb, 0);
    }

    #[test]
    fn sub_core_cpu_limit_rounds_up() {
        // 250 millicores == 25% of a core; a limit must never round to zero.
        let rc = ResourceConfig {
            cpu: Some(rv(0, Some(250))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_quota_percent, 25);
    }

    #[test]
    fn tiny_cpu_limit_rounds_up_to_one_percent() {
        let rc = ResourceConfig {
            cpu: Some(rv(0, Some(1))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_quota_percent, 1);
    }

    #[test]
    fn memory_limit_becomes_memory_max() {
        let rc = ResourceConfig {
            memory: Some(rv(256, Some(1024))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.memory_max_mb, 1024);
        assert_eq!(cg.cpu_quota_percent, 0);
    }

    #[test]
    fn explicit_controls_are_carried_through() {
        let rc = ResourceConfig {
            cgroup_controls: Some(CgroupControlsConfig {
                cpu_weight: 200,
                memory_high: Some(512),
                memory_max: Some(2048),
                io_weight: 150,
                tasks_max: Some(64),
                oom_policy: "kill".to_string(),
            }),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_weight, 200);
        assert_eq!(cg.memory_high_mb, 512);
        assert_eq!(cg.memory_max_mb, 2048);
        assert_eq!(cg.io_weight, 150);
        assert_eq!(cg.tasks_max, 64);
        assert_eq!(cg.oom_policy, "kill");
    }

    #[test]
    fn explicit_memory_max_wins_over_derived_limit() {
        // An explicit memory_max takes precedence over the value derived from
        // memory.limit.
        let rc = ResourceConfig {
            memory: Some(rv(256, Some(1024))),
            cgroup_controls: Some(CgroupControlsConfig {
                cpu_weight: default_cpu_weight(),
                memory_high: None,
                memory_max: Some(4096),
                io_weight: default_io_weight(),
                tasks_max: None,
                oom_policy: default_oom_policy(),
            }),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.memory_max_mb, 4096);
    }

    #[test]
    fn derived_cpu_quota_combines_with_explicit_controls() {
        // cpu.limit provides the hard CPU cap while explicit controls provide
        // the weight — both must appear together.
        let rc = ResourceConfig {
            cpu: Some(rv(500, Some(2000))),
            cgroup_controls: Some(CgroupControlsConfig {
                cpu_weight: 300,
                memory_high: None,
                memory_max: None,
                io_weight: default_io_weight(),
                tasks_max: None,
                oom_policy: default_oom_policy(),
            }),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_weight, 300);
        assert_eq!(cg.cpu_quota_percent, 200);
    }
}
