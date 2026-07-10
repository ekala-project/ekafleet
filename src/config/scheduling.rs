use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
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
    #[serde(default)]
    pub service_affinity: Vec<ServiceAffinityConfig>,
    /// Disruption budget: minimum availability guarantees during voluntary disruptions
    /// (node drain, rolling updates, scaling down).
    #[serde(default)]
    pub disruption_budget: Option<DisruptionBudget>,
    /// Parameterized job configuration. When set, this job can be dispatched
    /// with parameters that are injected as environment variables.
    /// Only valid for `batch` and `sysbatch` job types.
    #[serde(default)]
    pub parameterized: Option<ParameterizedConfig>,
}

/// Configuration for parameterized (dispatchable) batch jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ParameterizedConfig {
    /// Parameters that must be provided at dispatch time.
    #[serde(default)]
    pub required_params: Vec<String>,
    /// Parameters that have defaults and are optional at dispatch time.
    #[serde(default)]
    pub optional_params: Vec<String>,
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
            disruption_budget: None,
            parameterized: None,
        }
    }
}

pub(crate) fn default_replicas() -> u32 {
    1
}
pub(crate) fn default_job_type() -> JobType {
    JobType::Service
}
pub(crate) fn default_priority() -> u32 {
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
#[serde(deny_unknown_fields)]
pub struct Constraint {
    pub attribute: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadTarget {
    pub value: String,
    pub percent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpreadConfig {
    pub attribute: String,
    #[serde(default)]
    pub weight: Option<u32>,
    #[serde(default)]
    pub targets: Vec<SpreadTarget>,
    /// Maximum allowed skew between topology domains (K8s-style).
    #[serde(default)]
    pub max_skew: Option<u32>,
    /// Minimum number of topology domains required.
    #[serde(default)]
    pub min_domains: Option<u32>,
    /// If true, spread becomes a hard constraint (filter phase).
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateConfig {
    #[serde(default = "default_strategy")]
    pub strategy: UpdateStrategy,
    #[serde(default = "default_max_parallel")]
    pub max_parallel: u32,
    #[serde(default)]
    pub canary: u32,
    #[serde(default = "default_min_healthy_time", rename = "minHealthyTime")]
    pub min_healthy_time_secs: u64,
    #[serde(default = "default_healthy_deadline", rename = "healthyDeadline")]
    pub healthy_deadline_secs: u64,
    #[serde(default)]
    pub auto_revert: bool,
    #[serde(default)]
    pub auto_promote: bool,
    #[serde(default, rename = "progressDeadline")]
    pub progress_deadline_secs: Option<u64>,
    #[serde(default)]
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
pub(crate) fn default_max_parallel() -> u32 {
    1
}
pub(crate) fn default_min_healthy_time() -> u64 {
    10
}
pub(crate) fn default_healthy_deadline() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateStrategy {
    Rolling,
    Canary,
    BlueGreen,
}

/// Toleration allows a service to be scheduled on a tainted machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Toleration {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub op: TolerationOp,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub effect: Option<TaintEffect>,
    #[serde(default)]
    pub toleration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TolerationOp {
    #[default]
    Equal,
    Exists,
}

/// Taint on a machine to repel non-tolerating services.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Local restart policy before rescheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RestartConfig {
    #[serde(default = "default_restart_attempts")]
    pub attempts: u32,
    #[serde(default = "default_restart_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_restart_delay")]
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RescheduleConfig {
    #[serde(default = "default_reschedule_delay")]
    pub delay_secs: u64,
    #[serde(default)]
    pub delay_function: DelayFunction,
    #[serde(default = "default_max_delay")]
    pub max_delay_secs: u64,
    /// None means unlimited attempts.
    #[serde(default)]
    pub attempts: Option<u32>,
    #[serde(default = "default_reschedule_interval")]
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MigrateConfig {
    #[serde(default = "default_max_parallel")]
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PeriodicConfig {
    pub cron: String,
    #[serde(default = "default_timezone")]
    pub time_zone: String,
    #[serde(default)]
    pub concurrency_policy: ConcurrencyPolicy,
    #[serde(default = "default_successful_history")]
    pub successful_jobs_history_limit: u32,
    #[serde(default = "default_failed_history")]
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceAffinityConfig {
    pub target_service: String,
    pub topology_key: String,
    #[serde(default = "default_affinity_weight")]
    pub weight: i32,
}

/// Disruption budget controls how many instances of a service can be
/// unavailable during voluntary disruptions (drain, rolling updates).
/// Specify either `minAvailable` or `maxUnavailable`, not both.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DisruptionBudget {
    /// Minimum number of instances that must remain available during disruptions.
    /// Can be an absolute count (e.g., 2) or a percentage string (e.g., "50%").
    #[serde(default)]
    pub min_available: Option<DisruptionValue>,
    /// Maximum number of instances that can be unavailable during disruptions.
    /// Can be an absolute count (e.g., 1) or a percentage string (e.g., "25%").
    #[serde(default)]
    pub max_unavailable: Option<DisruptionValue>,
}

/// A disruption budget value: either an absolute count or a percentage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DisruptionValue {
    Count(u32),
    Percent(String),
}

impl DisruptionBudget {
    /// Compute how many instances can be disrupted given the total replica count.
    pub fn allowed_disruptions(&self, total_replicas: u32) -> u32 {
        if total_replicas == 0 {
            return 0;
        }

        if let Some(ref min_avail) = self.min_available {
            let min = resolve_value(min_avail, total_replicas);
            total_replicas.saturating_sub(min)
        } else if let Some(ref max_unavail) = self.max_unavailable {
            resolve_value(max_unavail, total_replicas)
        } else {
            // No budget set — allow all disruptions
            total_replicas
        }
    }
}

pub fn resolve_value(value: &DisruptionValue, total: u32) -> u32 {
    match value {
        DisruptionValue::Count(n) => *n,
        DisruptionValue::Percent(pct) => {
            let pct_str = pct.trim_end_matches('%');
            let pct_val: f64 = pct_str.parse().unwrap_or(0.0);
            ((total as f64 * pct_val / 100.0).ceil()) as u32
        }
    }
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
