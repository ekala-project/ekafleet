use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level fleet configuration as produced by `nix eval --json .#fleet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    pub name: String,
    pub domain: String,
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub machines: HashMap<String, MachineConfig>,
    #[serde(default, rename = "nodePools")]
    pub node_pools: HashMap<String, NodePoolConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub command: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortConfig {
    pub port: u16,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default, rename = "healthCheck")]
    pub health_check: Option<HealthCheckConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct SecretConfig {
    #[serde(rename = "type")]
    pub secret_type: String,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityConfig {
    #[serde(default, rename = "allowedCallers")]
    pub allowed_callers: Vec<String>,
    #[serde(default, rename = "allowedTargets")]
    pub allowed_targets: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceConfig {
    #[serde(default)]
    pub cpu: Option<ResourceValue>,
    #[serde(default)]
    pub memory: Option<ResourceValue>,
    #[serde(default)]
    pub disk: Option<ResourceValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceValue {
    #[serde(default)]
    pub request: u64,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingConfig {
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    #[serde(default = "default_job_type", rename = "type")]
    pub job_type: JobType,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub spread: Vec<SpreadConfig>,
    #[serde(default)]
    pub affinity: Vec<AffinityConfig>,
    #[serde(default)]
    pub update: UpdateConfig,
    /// Soft preference for a node pool. Translates to an affinity with weight 50.
    /// Use a constraint with `attribute = "pool"` for hard binding instead.
    #[serde(default)]
    pub pool: Option<String>,
    /// Service priority (1-100). Higher priority services are scheduled first
    /// and can preempt lower priority services (delta >= 10).
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Tolerations allow this service to be scheduled on tainted machines.
    #[serde(default)]
    pub tolerations: Vec<Toleration>,
    /// Local restart policy before rescheduling to another machine.
    #[serde(default)]
    pub restart: RestartConfig,
    /// Cross-node reschedule policy after local restarts are exhausted.
    #[serde(default)]
    pub reschedule: RescheduleConfig,
    /// Migration policy for node drain operations.
    #[serde(default)]
    pub migrate: MigrateConfig,
    /// Periodic/cron schedule for batch jobs.
    #[serde(default)]
    pub periodic: Option<PeriodicConfig>,
    /// Inter-service affinity: prefer or avoid co-location with other services.
    #[serde(default, rename = "serviceAffinity")]
    pub service_affinity: Vec<ServiceAffinityConfig>,
}

impl Default for SchedulingConfig {
    fn default() -> Self {
        Self {
            replicas: default_replicas(),
            job_type: default_job_type(),
            constraints: Vec::new(),
            spread: Vec::new(),
            affinity: Vec::new(),
            update: UpdateConfig::default(),
            pool: None,
            priority: default_priority(),
            tolerations: Vec::new(),
            restart: RestartConfig::default(),
            reschedule: RescheduleConfig::default(),
            migrate: MigrateConfig::default(),
            periodic: None,
            service_affinity: Vec::new(),
        }
    }
}

fn default_replicas() -> u32 {
    1
}
fn default_job_type() -> JobType {
    JobType::Service
}
fn default_priority() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobType {
    Service,
    Stateful,
    System,
    Batch,
    Sysbatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub attribute: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpreadTarget {
    pub value: String,
    pub percent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpreadConfig {
    pub attribute: String,
    #[serde(default)]
    pub weight: Option<u32>,
    #[serde(default)]
    pub targets: Vec<SpreadTarget>,
    /// Maximum allowed skew between topology domains (K8s-style).
    #[serde(default, rename = "maxSkew")]
    pub max_skew: Option<u32>,
    /// Minimum number of topology domains required.
    #[serde(default, rename = "minDomains")]
    pub min_domains: Option<u32>,
    /// If true, spread becomes a hard constraint (filter phase).
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffinityConfig {
    pub attribute: String,
    pub op: String,
    pub value: String,
    #[serde(default = "default_affinity_weight")]
    pub weight: i32,
}

fn default_affinity_weight() -> i32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    #[serde(default = "default_strategy", rename = "strategy")]
    pub strategy: UpdateStrategy,
    #[serde(default = "default_max_parallel", rename = "maxParallel")]
    pub max_parallel: u32,
    #[serde(default)]
    pub canary: u32,
    #[serde(default = "default_min_healthy_time", rename = "minHealthyTime")]
    pub min_healthy_time_secs: u64,
    #[serde(default = "default_healthy_deadline", rename = "healthyDeadline")]
    pub healthy_deadline_secs: u64,
    #[serde(default, rename = "autoRevert")]
    pub auto_revert: bool,
    #[serde(default, rename = "autoPromote")]
    pub auto_promote: bool,
    #[serde(default, rename = "progressDeadline")]
    pub progress_deadline_secs: Option<u64>,
    #[serde(default, rename = "healthCheck")]
    pub health_check: HealthCheckMode,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            strategy: default_strategy(),
            max_parallel: default_max_parallel(),
            canary: 0,
            min_healthy_time_secs: default_min_healthy_time(),
            healthy_deadline_secs: default_healthy_deadline(),
            auto_revert: false,
            auto_promote: false,
            progress_deadline_secs: None,
            health_check: HealthCheckMode::default(),
        }
    }
}

fn default_strategy() -> UpdateStrategy {
    UpdateStrategy::Rolling
}
fn default_max_parallel() -> u32 {
    1
}
fn default_min_healthy_time() -> u64 {
    10
}
fn default_healthy_deadline() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateStrategy {
    Rolling,
    Canary,
    BlueGreen,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfig {
    #[serde(rename = "targetHost")]
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
pub struct NodePoolConfig {
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub scaling: Option<PoolScalingConfig>,
    #[serde(default, rename = "schedulerAlgorithm")]
    pub scheduler_algorithm: Option<SchedulerAlgorithm>,
    #[serde(default, rename = "memoryOversubscription")]
    pub memory_oversubscription: bool,
}

/// Autoscaling configuration for a node pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolScalingConfig {
    #[serde(rename = "minCount")]
    pub min_count: u32,
    #[serde(rename = "maxCount")]
    pub max_count: u32,
    #[serde(default)]
    pub rules: Vec<PoolScalingRule>,
}

/// A pool scaling rule based on aggregate pool metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolScalingRule {
    #[serde(rename = "metricName")]
    pub metric_name: String,
    #[serde(rename = "targetValue")]
    pub target_value: f64,
    #[serde(rename = "scaleUpThreshold")]
    pub scale_up_threshold: f64,
    #[serde(rename = "scaleDownThreshold")]
    pub scale_down_threshold: f64,
}

/// Taint on a machine to repel non-tolerating services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Taint {
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
    pub effect: TaintEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

/// Toleration allows a service to be scheduled on a tainted machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Toleration {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub op: TolerationOp,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub effect: Option<TaintEffect>,
    #[serde(default, rename = "tolerationSeconds")]
    pub toleration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TolerationOp {
    #[default]
    Equal,
    Exists,
}

/// Local restart policy before rescheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartConfig {
    #[serde(default = "default_restart_attempts")]
    pub attempts: u32,
    #[serde(default = "default_restart_interval", rename = "intervalSecs")]
    pub interval_secs: u64,
    #[serde(default = "default_restart_delay", rename = "delaySecs")]
    pub delay_secs: u64,
    #[serde(default)]
    pub mode: RestartMode,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            attempts: default_restart_attempts(),
            interval_secs: default_restart_interval(),
            delay_secs: default_restart_delay(),
            mode: RestartMode::default(),
        }
    }
}

fn default_restart_attempts() -> u32 {
    2
}
fn default_restart_interval() -> u64 {
    1800
}
fn default_restart_delay() -> u64 {
    15
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RestartMode {
    #[default]
    Fail,
    Delay,
}

/// Cross-node reschedule policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescheduleConfig {
    #[serde(default = "default_reschedule_delay", rename = "delaySecs")]
    pub delay_secs: u64,
    #[serde(default, rename = "delayFunction")]
    pub delay_function: DelayFunction,
    #[serde(default = "default_max_delay", rename = "maxDelaySecs")]
    pub max_delay_secs: u64,
    /// None means unlimited attempts.
    #[serde(default)]
    pub attempts: Option<u32>,
    #[serde(default = "default_reschedule_interval", rename = "intervalSecs")]
    pub interval_secs: u64,
}

impl Default for RescheduleConfig {
    fn default() -> Self {
        Self {
            delay_secs: default_reschedule_delay(),
            delay_function: DelayFunction::default(),
            max_delay_secs: default_max_delay(),
            attempts: None,
            interval_secs: default_reschedule_interval(),
        }
    }
}

fn default_reschedule_delay() -> u64 {
    30
}
fn default_max_delay() -> u64 {
    3600
}
fn default_reschedule_interval() -> u64 {
    86400
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DelayFunction {
    Constant,
    #[default]
    Exponential,
    Fibonacci,
}

/// Migration policy for node drain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateConfig {
    #[serde(default = "default_max_parallel", rename = "maxParallel")]
    pub max_parallel: u32,
    #[serde(default = "default_min_healthy_time", rename = "minHealthyTime")]
    pub min_healthy_time_secs: u64,
    #[serde(default = "default_healthy_deadline", rename = "healthyDeadline")]
    pub healthy_deadline_secs: u64,
}

impl Default for MigrateConfig {
    fn default() -> Self {
        Self {
            max_parallel: default_max_parallel(),
            min_healthy_time_secs: default_min_healthy_time(),
            healthy_deadline_secs: default_healthy_deadline(),
        }
    }
}

/// Periodic/cron schedule for batch jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodicConfig {
    pub cron: String,
    #[serde(default = "default_timezone", rename = "timeZone")]
    pub time_zone: String,
    #[serde(default, rename = "concurrencyPolicy")]
    pub concurrency_policy: ConcurrencyPolicy,
    #[serde(
        default = "default_successful_history",
        rename = "successfulJobsHistoryLimit"
    )]
    pub successful_jobs_history_limit: u32,
    #[serde(default = "default_failed_history", rename = "failedJobsHistoryLimit")]
    pub failed_jobs_history_limit: u32,
}

fn default_timezone() -> String {
    "UTC".to_string()
}
fn default_successful_history() -> u32 {
    3
}
fn default_failed_history() -> u32 {
    1
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConcurrencyPolicy {
    #[default]
    Allow,
    Forbid,
    Replace,
}

/// Inter-service affinity/anti-affinity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAffinityConfig {
    #[serde(rename = "targetService")]
    pub target_service: String,
    #[serde(rename = "topologyKey")]
    pub topology_key: String,
    #[serde(default = "default_affinity_weight")]
    pub weight: i32,
}

/// Health check mode for deployments.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum HealthCheckMode {
    #[default]
    Checks,
    TaskStates,
    Manual,
}

/// Scheduler algorithm for node pools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SchedulerAlgorithm {
    Binpack,
    Spread,
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
