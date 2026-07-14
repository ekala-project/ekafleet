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
    /// Labels for routing (e.g., `{"team": "platform"}`).
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Route webhook URL by label match. If set, overrides `webhook_url`
    /// when the alert's labels match.
    #[serde(default)]
    pub route: Option<String>,
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

/// A silence rule that suppresses alerts matching certain criteria.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertSilence {
    /// Label matchers: alert labels must contain all of these key-value pairs.
    #[serde(default)]
    pub matchers: HashMap<String, String>,
    /// Unix timestamp when the silence starts.
    pub starts_at: u64,
    /// Unix timestamp when the silence ends.
    pub ends_at: u64,
    /// Human-readable comment explaining the silence.
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FiredAlert {
    pub rule_name: String,
    pub metric: String,
    pub current_value: f64,
    pub threshold: f64,
    pub severity: AlertSeverity,
    pub fired_at: u64,
    /// Whether this alert has been resolved (condition cleared).
    pub resolved: bool,
}

/// Evaluates alert rules against collected metrics.
#[derive(Clone)]
pub struct AlertEvaluator {
    rules: Arc<RwLock<Vec<AlertRule>>>,
    fired: Arc<RwLock<Vec<FiredAlert>>>,
    /// Tracks how long each rule's condition has been true.
    pending: Arc<RwLock<HashMap<String, std::time::Instant>>>,
    /// Silence rules that suppress matching alerts.
    silences: Arc<RwLock<Vec<AlertSilence>>>,
    /// Currently active (firing) alerts, keyed by rule name, for deduplication.
    active_alerts: Arc<RwLock<HashMap<String, FiredAlert>>>,
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
            silences: Arc::new(RwLock::new(Vec::new())),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register alert rules.
    pub async fn set_rules(&self, rules: Vec<AlertRule>) {
        tracing::info!(count = rules.len(), "Alert rules configured");
        *self.rules.write().await = rules;
    }

    /// Evaluate all rules against current metric values.
    /// Returns newly fired alerts (including "resolved" entries when conditions clear).
    /// Supports deduplication (only fires on ok→firing transitions) and silencing.
    pub async fn evaluate(&self, metrics: &HashMap<String, f64>) -> Vec<FiredAlert> {
        let rules = self.rules.read().await;
        let mut pending = self.pending.write().await;
        let mut fired = self.fired.write().await;
        let silences = self.silences.read().await;
        let mut active = self.active_alerts.write().await;
        let mut new_alerts = Vec::new();
        let now = std::time::Instant::now();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for rule in rules.iter() {
            let value = match metrics.get(&rule.metric) {
                Some(v) => *v,
                None => {
                    // If the metric is absent and the rule was previously active, resolve it
                    if let Some(mut prev) = active.remove(&rule.name) {
                        prev.resolved = true;
                        tracing::info!(
                            rule = %rule.name,
                            "Alert resolved (metric absent)"
                        );
                        new_alerts.push(prev.clone());
                        fired.push(prev);
                        pending.remove(&rule.name);
                    }
                    continue;
                }
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
                    // Deduplication: only fire on state transition (ok → firing)
                    if active.contains_key(&rule.name) {
                        continue;
                    }

                    // Check silences: skip if any active silence matches
                    let is_silenced = silences.iter().any(|s| {
                        if now_unix < s.starts_at || now_unix > s.ends_at {
                            return false;
                        }
                        s.matchers
                            .iter()
                            .all(|(k, v)| rule.labels.get(k) == Some(v))
                    });

                    if is_silenced {
                        tracing::debug!(
                            rule = %rule.name,
                            "Alert suppressed by silence"
                        );
                        continue;
                    }

                    let alert = FiredAlert {
                        rule_name: rule.name.clone(),
                        metric: rule.metric.clone(),
                        current_value: value,
                        threshold: rule.threshold,
                        severity: rule.severity,
                        fired_at: now_unix,
                        resolved: false,
                    };
                    tracing::warn!(
                        rule = %rule.name,
                        metric = %rule.metric,
                        value,
                        threshold = rule.threshold,
                        severity = ?rule.severity,
                        "Alert fired"
                    );
                    active.insert(rule.name.clone(), alert.clone());
                    new_alerts.push(alert.clone());
                    fired.push(alert);
                }
            } else {
                pending.remove(&rule.name);
                // Generate "resolved" entry when condition clears
                if let Some(mut prev) = active.remove(&rule.name) {
                    prev.resolved = true;
                    prev.current_value = value;
                    tracing::info!(
                        rule = %rule.name,
                        metric = %rule.metric,
                        value,
                        "Alert resolved"
                    );
                    new_alerts.push(prev.clone());
                    fired.push(prev);
                }
            }
        }

        new_alerts
    }

    /// Get all fired alerts.
    pub async fn fired_alerts(&self) -> Vec<FiredAlert> {
        self.fired.read().await.clone()
    }

    /// Add a silence rule to suppress matching alerts.
    pub async fn add_silence(&self, silence: AlertSilence) {
        tracing::info!(
            comment = %silence.comment,
            matchers = ?silence.matchers,
            "Silence added"
        );
        self.silences.write().await.push(silence);
    }

    /// Remove a silence by index.
    pub async fn remove_silence(&self, index: usize) {
        let mut silences = self.silences.write().await;
        if index < silences.len() {
            let removed = silences.remove(index);
            tracing::info!(
                comment = %removed.comment,
                "Silence removed"
            );
        }
    }

    /// List all active silences.
    pub async fn list_silences(&self) -> Vec<AlertSilence> {
        self.silences.read().await.clone()
    }

    /// Cap the fired alert history to the most recent `max_entries`.
    pub async fn prune_history(&self, max_entries: usize) {
        let mut fired = self.fired.write().await;
        if fired.len() > max_entries {
            let excess = fired.len() - max_entries;
            fired.drain(0..excess);
        }
    }

    /// Remove silences that have expired (past their `ends_at` time).
    pub async fn expire_silences(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut silences = self.silences.write().await;
        let before = silences.len();
        silences.retain(|s| s.ends_at > now);
        let removed = before - silences.len();
        if removed > 0 {
            tracing::debug!(removed, "Expired alert silences");
        }
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
                labels: HashMap::new(),
                route: None,
            }])
            .await;

        let mut metrics = HashMap::new();
        metrics.insert("cpu_usage".to_string(), 0.95);

        let alerts = evaluator.evaluate(&metrics).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "high-cpu");
        assert!(!alerts[0].resolved);
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
                labels: HashMap::new(),
                route: None,
            }])
            .await;

        let mut metrics = HashMap::new();
        metrics.insert("cpu_usage".to_string(), 0.5);

        let alerts = evaluator.evaluate(&metrics).await;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn deduplication_only_fires_once() {
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
                labels: HashMap::new(),
                route: None,
            }])
            .await;

        let mut metrics = HashMap::new();
        metrics.insert("cpu_usage".to_string(), 0.95);

        let alerts1 = evaluator.evaluate(&metrics).await;
        assert_eq!(alerts1.len(), 1);

        // Second evaluation should not fire again (dedup)
        let alerts2 = evaluator.evaluate(&metrics).await;
        assert!(alerts2.is_empty());
    }

    #[tokio::test]
    async fn resolved_when_condition_clears() {
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
                labels: HashMap::new(),
                route: None,
            }])
            .await;

        let mut metrics = HashMap::new();
        metrics.insert("cpu_usage".to_string(), 0.95);

        let alerts = evaluator.evaluate(&metrics).await;
        assert_eq!(alerts.len(), 1);
        assert!(!alerts[0].resolved);

        // Condition clears
        metrics.insert("cpu_usage".to_string(), 0.5);
        let resolved = evaluator.evaluate(&metrics).await;
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
    }
}
