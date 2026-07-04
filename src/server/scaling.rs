#![allow(dead_code)]

use std::collections::HashMap;
use std::time::Duration;

use crate::metrics::aggregator::MetricsAggregator;

/// Autoscaling engine. Evaluates scaling policies against collected
/// metrics and computes desired replica counts.
pub struct ScalingEngine {
    metrics: MetricsAggregator,
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
    pub fn new(metrics: MetricsAggregator) -> Self {
        Self {
            metrics,
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

        // TODO: get current replica count from fleet state
        let current_replicas = 1u32;

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
