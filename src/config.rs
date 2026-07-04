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
    pub spread: Option<SpreadConfig>,
    #[serde(default)]
    pub affinity: Vec<AffinityConfig>,
    #[serde(default)]
    pub update: UpdateConfig,
}

impl Default for SchedulingConfig {
    fn default() -> Self {
        Self {
            replicas: default_replicas(),
            job_type: default_job_type(),
            constraints: Vec::new(),
            spread: None,
            affinity: Vec::new(),
            update: UpdateConfig::default(),
        }
    }
}

fn default_replicas() -> u32 {
    1
}
fn default_job_type() -> JobType {
    JobType::Service
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobType {
    Service,
    Stateful,
    System,
    Batch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub attribute: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpreadConfig {
    pub attribute: String,
    #[serde(default)]
    pub weight: Option<u32>,
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
