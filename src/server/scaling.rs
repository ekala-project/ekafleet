#![allow(dead_code)]

use std::collections::HashMap;
use std::time::Duration;

use crate::metrics::aggregator::MetricsAggregator;

/// Autoscaling engine. Evaluates scaling policies against collected
/// metrics and computes desired replica counts.
pub struct ScalingEngine {
    metrics: MetricsAggregator,
    state: crate::server::state::FleetState,
    policies: HashMap<String, ScalingPolicy>,
    cooldown: Duration,
    last_scale: HashMap<String, std::time::Instant>,
}

/// Scaling policy for a service.
#[derive(Debug, Clone)]
pub struct ScalingPolicy {
    pub service_name: String,
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub rules: Vec<ScalingRule>,
}

/// A scaling rule based on a metric target.
#[derive(Debug, Clone)]
pub struct ScalingRule {
    pub metric_name: String,
    pub target_value: f64,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
}

impl ScalingEngine {
    pub fn new(metrics: MetricsAggregator, state: crate::server::state::FleetState) -> Self {
        Self {
            metrics,
            state,
            policies: HashMap::new(),
            cooldown: Duration::from_secs(60),
            last_scale: HashMap::new(),
        }
    }

    /// Register a scaling policy for a service.
    pub fn register_policy(&mut self, policy: ScalingPolicy) {
        self.policies.insert(policy.service_name.clone(), policy);
    }

    /// Evaluate all policies and return scaling decisions.
    pub async fn evaluate(&mut self) -> Vec<ScalingDecision> {
        let mut decisions = Vec::new();

        for (service_name, policy) in &self.policies {
            // Check cooldown
            if let Some(last) = self.last_scale.get(service_name)
                && last.elapsed() < self.cooldown
            {
                continue;
            }

            if let Some(decision) = self.evaluate_policy(service_name, policy).await {
                decisions.push(decision);
            }
        }

        decisions
    }

    async fn evaluate_policy(
        &self,
        service_name: &str,
        policy: &ScalingPolicy,
    ) -> Option<ScalingDecision> {
        let mut scale_up = false;
        let mut scale_down = true;

        for rule in &policy.rules {
            let current = self
                .metrics
                .service_metric_avg(service_name, &rule.metric_name)
                .await?;

            let ratio = current / rule.target_value;

            if ratio > rule.scale_up_threshold {
                scale_up = true;
                scale_down = false;
            } else if ratio > rule.scale_down_threshold {
                scale_down = false;
            }
        }

        let (_, services, _) = self.state.fleet_status().await;
        let current_replicas = services
            .iter()
            .find(|s| s.name == service_name)
            .map(|s| s.instances.len() as u32)
            .unwrap_or(0);

        let desired = if scale_up {
            (current_replicas + 1).min(policy.max_replicas)
        } else if scale_down {
            current_replicas.saturating_sub(1).max(policy.min_replicas)
        } else {
            return None;
        };

        if desired == current_replicas {
            return None;
        }

        tracing::info!(
            service = %service_name,
            current = current_replicas,
            desired,
            direction = if scale_up { "up" } else { "down" },
            "Scaling decision"
        );

        Some(ScalingDecision {
            service_name: service_name.to_string(),
            current_replicas,
            desired_replicas: desired,
        })
    }

    /// Record that a scaling action was taken.
    pub fn record_scale(&mut self, service_name: &str) {
        self.last_scale
            .insert(service_name.to_string(), std::time::Instant::now());
    }
}

#[derive(Debug)]
pub struct ScalingDecision {
    pub service_name: String,
    pub current_replicas: u32,
    pub desired_replicas: u32,
}

/// Pool-level scaling engine. Evaluates aggregate pool utilization and
/// produces advisory scaling decisions (does not provision machines).
pub struct PoolScalingEngine {
    state: crate::server::state::FleetState,
    policies: HashMap<String, crate::config::PoolScalingConfig>,
    cooldown: Duration,
    last_scale: HashMap<String, std::time::Instant>,
}

#[derive(Debug)]
pub struct PoolScalingDecision {
    pub pool_name: String,
    pub current_count: u32,
    pub desired_count: u32,
}

impl PoolScalingEngine {
    pub fn new(state: crate::server::state::FleetState) -> Self {
        Self {
            state,
            policies: HashMap::new(),
            cooldown: Duration::from_secs(60),
            last_scale: HashMap::new(),
        }
    }

    /// Register a scaling policy for a node pool.
    pub fn register_policy(&mut self, pool_name: &str, config: crate::config::PoolScalingConfig) {
        self.policies.insert(pool_name.to_string(), config);
    }

    /// Evaluate all pool policies and return scaling decisions.
    pub async fn evaluate(&mut self) -> Vec<PoolScalingDecision> {
        let mut decisions = Vec::new();
        let (_, _, pools) = self.state.fleet_status().await;

        for (pool_name, policy) in &self.policies {
            if let Some(last) = self.last_scale.get(pool_name)
                && last.elapsed() < self.cooldown
            {
                continue;
            }

            let pool_status = pools.iter().find(|p| &p.name == pool_name);
            let current_count = pool_status.map(|p| p.machine_count).unwrap_or(0);

            // Compute pool utilization from schedulable vs allocated
            let utilization = pool_status.and_then(|p| {
                let sched = p.total_schedulable.as_ref()?;
                let alloc = p.total_allocated.as_ref()?;
                if sched.cpu_millicores == 0 {
                    return None;
                }
                Some(alloc.cpu_millicores as f64 / sched.cpu_millicores as f64)
            });

            if let Some(util) = utilization {
                let mut scale_up = false;
                let mut scale_down = true;

                for rule in &policy.rules {
                    let ratio = util / rule.target_value;
                    if ratio > rule.scale_up_threshold {
                        scale_up = true;
                        scale_down = false;
                    } else if ratio > rule.scale_down_threshold {
                        scale_down = false;
                    }
                }

                let desired = if scale_up {
                    (current_count + 1).min(policy.max_count)
                } else if scale_down {
                    current_count.saturating_sub(1).max(policy.min_count)
                } else {
                    continue;
                };

                if desired != current_count {
                    tracing::info!(
                        pool = %pool_name,
                        current = current_count,
                        desired,
                        utilization = %format!("{:.1}%", util * 100.0),
                        direction = if scale_up { "up" } else { "down" },
                        "Pool scaling decision (advisory)"
                    );

                    decisions.push(PoolScalingDecision {
                        pool_name: pool_name.clone(),
                        current_count,
                        desired_count: desired,
                    });
                }
            }
        }

        decisions
    }

    /// Record that a pool scaling action was taken.
    pub fn record_scale(&mut self, pool_name: &str) {
        self.last_scale
            .insert(pool_name.to_string(), std::time::Instant::now());
    }
}

/// Cloud provider abstraction for machine lifecycle management.
/// Implementations handle provisioning and deprovisioning of machines
/// in response to pool scaling decisions.
pub trait CloudProvider: Send + Sync {
    /// Create a new machine in the given pool with the specified labels.
    /// Returns the instance ID of the newly created machine.
    fn create_machine(
        &self,
        pool: &str,
        labels: &HashMap<String, String>,
    ) -> impl std::future::Future<Output = Result<String, anyhow::Error>> + Send;

    /// Destroy a machine by its instance ID.
    fn destroy_machine(
        &self,
        instance_id: &str,
    ) -> impl std::future::Future<Output = Result<(), anyhow::Error>> + Send;
}

/// Advisory cloud provider that notifies an external system via webhooks.
/// Does not actually provision machines — it POSTs scaling decisions as JSON
/// to a configured URL and lets the external system handle provisioning.
pub struct WebhookCloudProvider {
    webhook_url: String,
}

impl WebhookCloudProvider {
    pub fn new(webhook_url: String) -> Self {
        Self { webhook_url }
    }
}

impl CloudProvider for WebhookCloudProvider {
    async fn create_machine(
        &self,
        pool: &str,
        labels: &HashMap<String, String>,
    ) -> Result<String, anyhow::Error> {
        let payload = serde_json::json!({
            "action": "create",
            "pool": pool,
            "labels": labels,
        });

        tracing::info!(
            pool = %pool,
            url = %self.webhook_url,
            "Sending advisory create_machine webhook"
        );

        let response = post_webhook_json(&self.webhook_url, &payload).await?;

        // Try to parse instance_id from the response
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap_or_default();
        let instance_id = parsed
            .get("instance_id")
            .and_then(|v| v.as_str())
            .unwrap_or("advisory-no-id")
            .to_string();

        Ok(instance_id)
    }

    async fn destroy_machine(&self, instance_id: &str) -> Result<(), anyhow::Error> {
        let payload = serde_json::json!({
            "action": "destroy",
            "instance_id": instance_id,
        });

        tracing::info!(
            instance_id = %instance_id,
            url = %self.webhook_url,
            "Sending advisory destroy_machine webhook"
        );

        post_webhook_json(&self.webhook_url, &payload).await?;
        Ok(())
    }
}

/// Send a JSON POST request to an HTTP URL using raw TCP.
/// Returns the response body as a string.
async fn post_webhook_json(
    url: &str,
    payload: &serde_json::Value,
) -> Result<String, anyhow::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let url_stripped = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// URLs supported for cloud webhooks"))?;
    let (host_port, path_str) = url_stripped.split_once('/').unwrap_or((url_stripped, ""));
    let path = format!("/{path_str}");

    let body = serde_json::to_string(payload)?;

    let mut stream = tokio::net::TcpStream::connect(host_port).await?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let response_str = String::from_utf8_lossy(&response).into_owned();

    // Extract body after HTTP headers
    let body_str = response_str
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or(response_str);

    Ok(body_str)
}
