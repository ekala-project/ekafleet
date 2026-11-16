//! Threshold alerts evaluated per series.
//!
//! Rules come from the fleet configuration. Each rule is evaluated against
//! every series of its metric (per node for `node_*` metrics, per service
//! instance otherwise), and each breaching series fires and resolves on its
//! own, labelled with its node and service. Silences are runtime state: an
//! alert whose labels match an active silence does not fire while it lasts.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use super::aggregator::Series;
use crate::config::AlertRuleConfig;

/// A silence suppressing alerts whose labels contain all its matchers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertSilence {
    #[serde(default)]
    pub matchers: HashMap<String, String>,
    /// Unix seconds.
    pub starts_at: u64,
    /// Unix seconds.
    pub ends_at: u64,
    #[serde(default)]
    pub comment: String,
}

impl AlertSilence {
    fn silences(&self, labels: &BTreeMap<String, String>, now: u64) -> bool {
        (self.starts_at..=self.ends_at).contains(&now)
            && self.matchers.iter().all(|(k, v)| labels.get(k) == Some(v))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    Firing,
    Resolved,
}

/// One alert of one series.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub status: AlertStatus,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub value: f64,
    /// Unix seconds when it fired.
    pub starts_at: u64,
    /// Unix seconds when it resolved.
    pub ends_at: Option<u64>,
    /// Where notifications go, from the rule.
    #[serde(skip)]
    pub webhook_url: Option<String>,
}

impl Alert {
    pub fn name(&self) -> &str {
        self.labels.get("alertname").map_or("", String::as_str)
    }

    /// Stable identity of the series: a hash of its labels.
    pub fn fingerprint(&self) -> String {
        let mut text = String::new();
        for (k, v) in &self.labels {
            text.push_str(k);
            text.push('\u{0}');
            text.push_str(v);
            text.push('\u{0}');
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
        digest.as_ref()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// (rule name, node, service)
type SeriesKey = (String, String, Option<String>);

enum SeriesState {
    /// Breaching since this unix second, not yet for long enough (or
    /// silenced).
    Pending(u64),
    Firing(Alert),
}

#[derive(Default)]
struct Inner {
    rules: Vec<AlertRuleConfig>,
    /// Configuration revision the rules came from.
    revision: Option<u64>,
    states: HashMap<SeriesKey, SeriesState>,
    silences: Vec<AlertSilence>,
    /// Firing and resolved transitions, oldest first.
    history: Vec<Alert>,
}

/// Evaluates alert rules against the aggregated series.
#[derive(Clone, Default)]
pub struct AlertEvaluator {
    inner: Arc<RwLock<Inner>>,
}

impl AlertEvaluator {
    pub fn new() -> Self {
        Self::default()
    }

    /// The configuration revision the current rules came from.
    pub async fn revision(&self) -> Option<u64> {
        self.inner.read().await.revision
    }

    /// Replace the rules with those of configuration `revision`. Alerts of
    /// rules that no longer exist resolve on the next evaluation.
    pub async fn set_rules(&self, rules: Vec<AlertRuleConfig>, revision: Option<u64>) {
        tracing::info!(count = rules.len(), ?revision, "Alert rules configured");
        let mut inner = self.inner.write().await;
        inner.rules = rules;
        inner.revision = revision;
    }

    /// Evaluate every rule against `series` at unix time `now` and return
    /// the alerts that fired or resolved.
    pub async fn evaluate(&self, series: &[Series], now: u64) -> Vec<Alert> {
        let mut guard = self.inner.write().await;
        let inner = &mut *guard;
        let mut transitions = Vec::new();
        let mut seen: HashSet<SeriesKey> = HashSet::new();

        for rule in &inner.rules {
            let node_metric = rule.metric.starts_with("node_");
            for s in series.iter().filter(|s| {
                s.metric == rule.metric
                    && s.service.is_some() != node_metric
                    && rule
                        .service
                        .as_ref()
                        .is_none_or(|f| s.service.as_ref() == Some(f))
                    && rule.node.as_ref().is_none_or(|f| &s.node == f)
            }) {
                let key = (rule.name.clone(), s.node.clone(), s.service.clone());
                seen.insert(key.clone());
                if !rule.op.holds(s.value, rule.threshold) {
                    if let Some(SeriesState::Firing(alert)) = inner.states.remove(&key) {
                        transitions.push(resolve(alert, s.value, now));
                    }
                    continue;
                }
                let state = inner.states.entry(key).or_insert(SeriesState::Pending(now));
                match state {
                    SeriesState::Firing(alert) => alert.value = s.value,
                    SeriesState::Pending(since) => {
                        if now.saturating_sub(*since) < rule.for_seconds {
                            continue;
                        }
                        let alert = fire(rule, s, now);
                        if inner
                            .silences
                            .iter()
                            .any(|x| x.silences(&alert.labels, now))
                        {
                            tracing::debug!(alert = %rule.name, node = %s.node, "Alert silenced");
                            continue;
                        }
                        tracing::warn!(
                            alert = %rule.name,
                            node = %s.node,
                            service = s.service.as_deref().unwrap_or(""),
                            value = s.value,
                            threshold = rule.threshold,
                            "Alert firing"
                        );
                        transitions.push(alert.clone());
                        *state = SeriesState::Firing(alert);
                    }
                }
            }
        }

        // Series that disappeared (node gone, service moved, rule removed).
        let gone: Vec<SeriesKey> = inner
            .states
            .keys()
            .filter(|k| !seen.contains(*k))
            .cloned()
            .collect();
        for key in gone {
            if let Some(SeriesState::Firing(alert)) = inner.states.remove(&key) {
                let value = alert.value;
                transitions.push(resolve(alert, value, now));
            }
        }

        for alert in &transitions {
            if alert.status == AlertStatus::Resolved {
                tracing::info!(
                    alert = %alert.name(),
                    node = alert.labels.get("node").map_or("", String::as_str),
                    "Alert resolved"
                );
            }
        }
        inner.history.extend(transitions.iter().cloned());
        transitions
    }

    /// Alerts firing now.
    pub async fn active_alerts(&self) -> Vec<Alert> {
        let inner = self.inner.read().await;
        let mut alerts: Vec<Alert> = inner
            .states
            .values()
            .filter_map(|s| match s {
                SeriesState::Firing(alert) => Some(alert.clone()),
                SeriesState::Pending(_) => None,
            })
            .collect();
        alerts.sort_by(|a, b| a.labels.cmp(&b.labels));
        alerts
    }

    /// Firing and resolved transitions, oldest first.
    pub async fn fired_alerts(&self) -> Vec<Alert> {
        self.inner.read().await.history.clone()
    }

    pub async fn add_silence(&self, silence: AlertSilence) {
        tracing::info!(
            comment = %silence.comment,
            matchers = ?silence.matchers,
            "Silence added"
        );
        self.inner.write().await.silences.push(silence);
    }

    /// Remove a silence by index.
    pub async fn remove_silence(&self, index: usize) {
        let mut inner = self.inner.write().await;
        if index < inner.silences.len() {
            let removed = inner.silences.remove(index);
            tracing::info!(comment = %removed.comment, "Silence removed");
        }
    }

    pub async fn list_silences(&self) -> Vec<AlertSilence> {
        self.inner.read().await.silences.clone()
    }

    /// Keep the most recent `max_entries` transitions.
    pub async fn prune_history(&self, max_entries: usize) {
        let mut inner = self.inner.write().await;
        if inner.history.len() > max_entries {
            let excess = inner.history.len() - max_entries;
            inner.history.drain(..excess);
        }
    }

    /// Drop silences that have ended.
    pub async fn expire_silences(&self) {
        let now = crate::agent::now_epoch();
        let mut inner = self.inner.write().await;
        let before = inner.silences.len();
        inner.silences.retain(|s| s.ends_at > now);
        let removed = before - inner.silences.len();
        if removed > 0 {
            tracing::debug!(removed, "Expired alert silences");
        }
    }
}

fn fire(rule: &AlertRuleConfig, series: &Series, now: u64) -> Alert {
    let mut labels: BTreeMap<String, String> = rule.labels.clone();
    labels.insert("alertname".into(), rule.name.clone());
    labels.insert("severity".into(), rule.severity.as_str().into());
    labels.insert("node".into(), series.node.clone());
    if let Some(service) = &series.service {
        labels.insert("service".into(), service.clone());
    }
    let subject = match &series.service {
        Some(service) => format!("service {service} on node {}", series.node),
        None => format!("node {}", series.node),
    };
    let description = format!(
        "{} of {subject} is {} ({} {})",
        rule.metric,
        series.value,
        rule.op.symbol(),
        rule.threshold
    );
    let mut annotations = BTreeMap::from([("description".to_string(), description.clone())]);
    annotations.insert(
        "summary".into(),
        rule.summary.clone().unwrap_or(description),
    );
    Alert {
        status: AlertStatus::Firing,
        labels,
        annotations,
        value: series.value,
        starts_at: now,
        ends_at: None,
        webhook_url: rule.webhook_url.clone(),
    }
}

fn resolve(mut alert: Alert, value: f64, now: u64) -> Alert {
    alert.status = AlertStatus::Resolved;
    alert.value = value;
    alert.ends_at = Some(now);
    alert
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AlertOp, AlertSeverity};

    fn rule(
        name: &str,
        metric: &str,
        op: AlertOp,
        threshold: f64,
        for_seconds: u64,
    ) -> AlertRuleConfig {
        AlertRuleConfig {
            name: name.into(),
            metric: metric.into(),
            op,
            threshold,
            for_seconds,
            service: None,
            node: None,
            severity: AlertSeverity::Critical,
            labels: BTreeMap::from([("team".to_string(), "ops".to_string())]),
            summary: None,
            webhook_url: None,
        }
    }

    fn node(metric: &str, node: &str, value: f64) -> Series {
        Series {
            metric: metric.into(),
            node: node.into(),
            service: None,
            value,
        }
    }

    fn svc(metric: &str, service: &str, node: &str, value: f64) -> Series {
        Series {
            service: Some(service.into()),
            ..self::node(metric, node, value)
        }
    }

    #[tokio::test]
    async fn each_breaching_series_fires_and_resolves_on_its_own() {
        let evaluator = AlertEvaluator::new();
        evaluator
            .set_rules(
                vec![rule("disk", "node_disk_usage_ratio", AlertOp::Gt, 0.9, 30)],
                Some(1),
            )
            .await;

        let series = [
            node("node_disk_usage_ratio", "a", 0.95),
            node("node_disk_usage_ratio", "b", 0.5),
        ];
        assert!(evaluator.evaluate(&series, 100).await.is_empty(), "pending");
        assert!(evaluator.evaluate(&series, 120).await.is_empty(), "pending");
        let fired = evaluator.evaluate(&series, 130).await;
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].status, AlertStatus::Firing);
        assert_eq!(fired[0].labels["node"], "a");
        assert_eq!(fired[0].labels["severity"], "critical");
        assert_eq!(fired[0].labels["team"], "ops");
        assert!(!fired[0].labels.contains_key("service"));
        assert!(
            evaluator.evaluate(&series, 145).await.is_empty(),
            "deduplicated"
        );

        // b breaches too: a keeps firing, b starts pending.
        let both = [
            node("node_disk_usage_ratio", "a", 0.97),
            node("node_disk_usage_ratio", "b", 0.99),
        ];
        assert!(evaluator.evaluate(&both, 150).await.is_empty());
        let fired = evaluator.evaluate(&both, 180).await;
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].labels["node"], "b");
        assert_eq!(evaluator.active_alerts().await.len(), 2);
        assert_eq!(evaluator.active_alerts().await[0].value, 0.97);

        // a recovers; b's node goes away.
        let recovered = [node("node_disk_usage_ratio", "a", 0.4)];
        let mut resolved = evaluator.evaluate(&recovered, 200).await;
        resolved.sort_by(|x, y| x.labels.cmp(&y.labels));
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().all(|a| a.status == AlertStatus::Resolved));
        assert_eq!(resolved[0].ends_at, Some(200));
        assert_eq!(resolved[0].starts_at, 130);
        assert!(evaluator.active_alerts().await.is_empty());
        assert_eq!(evaluator.fired_alerts().await.len(), 4);
    }

    #[tokio::test]
    async fn service_rules_evaluate_instances_and_honour_filters() {
        let evaluator = AlertEvaluator::new();
        let mut queue = rule("queue", "queue_depth", AlertOp::Gte, 10.0, 0);
        queue.service = Some("worker".into());
        let mut down = rule("down", "up", AlertOp::Lt, 1.0, 0);
        down.node = Some("b".into());
        evaluator.set_rules(vec![queue, down], None).await;

        let series = [
            svc("queue_depth", "worker", "a", 12.0),
            svc("queue_depth", "worker", "b", 3.0),
            svc("queue_depth", "other", "a", 50.0),
            svc("up", "worker", "a", 0.0),
            svc("up", "worker", "b", 0.0),
            // A node series of the same name never matches a service rule.
            node("queue_depth", "a", 99.0),
        ];
        let mut fired = evaluator.evaluate(&series, 10).await;
        fired.sort_by(|x, y| x.labels.cmp(&y.labels));
        let names: Vec<_> = fired
            .iter()
            .map(|a| format!("{}/{}/{}", a.name(), a.labels["service"], a.labels["node"]))
            .collect();
        assert_eq!(names, ["down/worker/b", "queue/worker/a"]);
        assert!(fired[1].annotations["summary"].contains("service worker on node a"));
        assert_ne!(fired[0].fingerprint(), fired[1].fingerprint());
    }

    #[tokio::test]
    async fn silences_hold_alerts_back_while_active() {
        let evaluator = AlertEvaluator::new();
        evaluator
            .set_rules(vec![rule("load", "node_load1", AlertOp::Gt, 4.0, 0)], None)
            .await;
        evaluator
            .add_silence(AlertSilence {
                matchers: HashMap::from([("node".to_string(), "a".to_string())]),
                starts_at: 0,
                ends_at: 100,
                comment: "maintenance".into(),
            })
            .await;
        let series = [node("node_load1", "a", 8.0), node("node_load1", "b", 8.0)];
        let fired = evaluator.evaluate(&series, 50).await;
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].labels["node"], "b");
        // Once the silence ends, a fires.
        let fired = evaluator.evaluate(&series, 101).await;
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].labels["node"], "a");
    }

    #[tokio::test]
    async fn removed_rules_resolve_their_alerts() {
        let evaluator = AlertEvaluator::new();
        evaluator
            .set_rules(
                vec![rule("load", "node_load1", AlertOp::Gt, 4.0, 0)],
                Some(1),
            )
            .await;
        let series = [node("node_load1", "a", 8.0)];
        assert_eq!(evaluator.evaluate(&series, 1).await.len(), 1);
        evaluator.set_rules(vec![], Some(2)).await;
        let resolved = evaluator.evaluate(&series, 2).await;
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].status, AlertStatus::Resolved);
        assert_eq!(evaluator.revision().await, Some(2));
    }

    #[tokio::test]
    async fn summaries_replace_a_nodes_earlier_points() {
        use crate::metrics::aggregator::MetricsAggregator;
        use crate::proto::MetricPoint;
        let point = |name: &str, value: f64, service: Option<&str>| MetricPoint {
            name: name.into(),
            value,
            labels: service
                .map(|s| HashMap::from([("service".to_string(), s.to_string())]))
                .unwrap_or_default(),
            timestamp: 0,
        };
        let aggregator = MetricsAggregator::new();
        aggregator
            .ingest(
                "a",
                vec![
                    point("node_load1", 1.0, None),
                    point("up", 1.0, Some("web")),
                    point("requests", 5.0, Some("web")),
                ],
            )
            .await;
        aggregator
            .ingest("b", vec![point("up", 1.0, Some("web"))])
            .await;
        assert_eq!(aggregator.series().await.len(), 4);
        // web moved off a.
        aggregator
            .ingest("a", vec![point("node_load1", 2.0, None)])
            .await;
        let mut series = aggregator.series().await;
        series.sort_by(|x, y| x.node.cmp(&y.node));
        assert_eq!(
            series,
            vec![node("node_load1", "a", 2.0), svc("up", "web", "b", 1.0)]
        );
        assert_eq!(aggregator.service_metric_avg("web", "up").await, Some(1.0));
        assert_eq!(aggregator.service_metric_avg("web", "requests").await, None);
    }
}
