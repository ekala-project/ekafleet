#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

/// Alert rule that evaluates collected metrics and fires when thresholds are breached.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertRule {
    pub name: String,
    /// Metric name to evaluate.
    pub metric: String,
    /// Threshold value. Alert fires when metric exceeds this.
    pub threshold: f64,
    /// Comparison operator: "gt", "lt", "gte", "lte", "eq".
    #[serde(default = "default_op")]
    pub op: String,
    /// Duration the condition must hold before firing.
    #[serde(default = "default_for_duration", rename = "forSeconds")]
    pub for_seconds: u64,
    /// Optional service filter.
    pub service: Option<String>,
    /// Webhook URL to notify when alert fires.
    pub webhook_url: Option<String>,
    /// Severity level.
    #[serde(default)]
    pub severity: AlertSeverity,
}

fn default_op() -> String {
    "gt".to_string()
}
fn default_for_duration() -> u64 {
    60
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    #[default]
    Warning,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FiredAlert {
    pub rule_name: String,
    pub metric: String,
    pub current_value: f64,
    pub threshold: f64,
    pub severity: AlertSeverity,
    pub fired_at: u64,
}

/// Evaluates alert rules against collected metrics.
#[derive(Clone)]
pub struct AlertEvaluator {
    rules: Arc<RwLock<Vec<AlertRule>>>,
    fired: Arc<RwLock<Vec<FiredAlert>>>,
    /// Tracks how long each rule's condition has been true.
    pending: Arc<RwLock<HashMap<String, std::time::Instant>>>,
}

impl Default for AlertEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertEvaluator {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            fired: Arc::new(RwLock::new(Vec::new())),
            pending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register alert rules.
    pub async fn set_rules(&self, rules: Vec<AlertRule>) {
        tracing::info!(count = rules.len(), "Alert rules configured");
        *self.rules.write().await = rules;
    }

    /// Evaluate all rules against current metric values.
    /// Returns newly fired alerts.
    pub async fn evaluate(&self, metrics: &HashMap<String, f64>) -> Vec<FiredAlert> {
        let rules = self.rules.read().await;
        let mut pending = self.pending.write().await;
        let mut fired = self.fired.write().await;
        let mut new_alerts = Vec::new();
        let now = std::time::Instant::now();

        for rule in rules.iter() {
            let value = match metrics.get(&rule.metric) {
                Some(v) => *v,
                None => continue,
            };

            let condition_met = match rule.op.as_str() {
                "gt" => value > rule.threshold,
                "gte" => value >= rule.threshold,
                "lt" => value < rule.threshold,
                "lte" => value <= rule.threshold,
                "eq" => (value - rule.threshold).abs() < f64::EPSILON,
                _ => false,
            };

            if condition_met {
                let first_seen = pending.entry(rule.name.clone()).or_insert(now);
                if first_seen.elapsed() >= Duration::from_secs(rule.for_seconds) {
                    let alert = FiredAlert {
                        rule_name: rule.name.clone(),
                        metric: rule.metric.clone(),
                        current_value: value,
                        threshold: rule.threshold,
                        severity: rule.severity,
                        fired_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    };
                    tracing::warn!(
                        rule = %rule.name,
                        metric = %rule.metric,
                        value,
                        threshold = rule.threshold,
                        severity = ?rule.severity,
                        "Alert fired"
                    );
                    new_alerts.push(alert.clone());
                    fired.push(alert);
                }
            } else {
                pending.remove(&rule.name);
            }
        }

        new_alerts
    }

    /// Get all fired alerts.
    pub async fn fired_alerts(&self) -> Vec<FiredAlert> {
        self.fired.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fires_when_threshold_exceeded() {
        let evaluator = AlertEvaluator::new();
        evaluator
            .set_rules(vec![AlertRule {
                name: "high-cpu".into(),
                metric: "cpu_usage".into(),
                threshold: 0.8,
                op: "gt".into(),
                for_seconds: 0, // fire immediately
                service: None,
                webhook_url: None,
                severity: AlertSeverity::Warning,
            }])
            .await;

        let mut metrics = HashMap::new();
        metrics.insert("cpu_usage".to_string(), 0.95);

        let alerts = evaluator.evaluate(&metrics).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "high-cpu");
    }

    #[tokio::test]
    async fn no_fire_when_below_threshold() {
        let evaluator = AlertEvaluator::new();
        evaluator
            .set_rules(vec![AlertRule {
                name: "high-cpu".into(),
                metric: "cpu_usage".into(),
                threshold: 0.8,
                op: "gt".into(),
                for_seconds: 0,
                service: None,
                webhook_url: None,
                severity: AlertSeverity::Warning,
            }])
            .await;

        let mut metrics = HashMap::new();
        metrics.insert("cpu_usage".to_string(), 0.5);

        let alerts = evaluator.evaluate(&metrics).await;
        assert!(alerts.is_empty());
    }
}
