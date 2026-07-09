use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Server-side metrics aggregation.
/// Collects metrics from all agents, computes fleet-wide views,
/// and provides data for autoscaling decisions.
#[derive(Clone)]
pub struct MetricsAggregator {
    inner: Arc<RwLock<AggregatorState>>,
}

struct AggregatorState {
    /// node_id → metric_name → latest value
    node_metrics: HashMap<String, HashMap<String, f64>>,
    /// service_name → metric_name → list of (node_id, value)
    service_metrics: HashMap<String, HashMap<String, Vec<(String, f64)>>>,
}

impl Default for MetricsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsAggregator {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AggregatorState {
                node_metrics: HashMap::new(),
                service_metrics: HashMap::new(),
            })),
        }
    }

    /// Ingest metric points from an agent.
    pub async fn ingest(&self, node_id: &str, points: Vec<crate::proto::MetricPoint>) {
        let mut state = self.inner.write().await;

        for point in points {
            // Store node-level metrics
            if point.name.starts_with("node_") {
                state
                    .node_metrics
                    .entry(node_id.to_string())
                    .or_default()
                    .insert(point.name.clone(), point.value);
            }

            // Store service-level metrics
            if let Some(service) = point.labels.get("service") {
                state
                    .service_metrics
                    .entry(service.clone())
                    .or_default()
                    .entry(point.name.clone())
                    .or_default()
                    .retain(|(nid, _)| nid != node_id);

                state
                    .service_metrics
                    .entry(service.clone())
                    .or_default()
                    .entry(point.name)
                    .or_default()
                    .push((node_id.to_string(), point.value));
            }
        }
    }

    /// Get average value of a metric across all instances of a service.
    pub async fn service_metric_avg(&self, service_name: &str, metric_name: &str) -> Option<f64> {
        let state = self.inner.read().await;
        let values = state.service_metrics.get(service_name)?.get(metric_name)?;

        if values.is_empty() {
            return None;
        }

        let sum: f64 = values.iter().map(|(_, v)| v).sum();
        Some(sum / values.len() as f64)
    }

    /// Get max value of a metric across all instances of a service.
    pub async fn service_metric_max(&self, service_name: &str, metric_name: &str) -> Option<f64> {
        let state = self.inner.read().await;
        state
            .service_metrics
            .get(service_name)?
            .get(metric_name)?
            .iter()
            .map(|(_, v)| *v)
            .reduce(f64::max)
    }

    /// Get a node's metrics.
    pub async fn node_metrics(&self, node_id: &str) -> HashMap<String, f64> {
        let state = self.inner.read().await;
        state.node_metrics.get(node_id).cloned().unwrap_or_default()
    }

    /// Export all metrics in Prometheus exposition format.
    pub async fn export_prometheus(&self) -> String {
        let state = self.inner.read().await;
        let mut out = String::new();

        // Collect all node metric names
        let mut node_metric_names: Vec<&String> =
            state.node_metrics.values().flat_map(|m| m.keys()).collect();
        node_metric_names.sort();
        node_metric_names.dedup();

        for metric_name in &node_metric_names {
            use std::fmt::Write;
            let _ = writeln!(out, "# TYPE {metric_name} gauge");
            for (node_id, metrics) in &state.node_metrics {
                if let Some(value) = metrics.get(*metric_name) {
                    let _ = writeln!(out, "{metric_name}{{node=\"{node_id}\"}} {value}");
                }
            }
        }

        // Service-level metrics
        let mut svc_metric_names: Vec<&String> = state
            .service_metrics
            .values()
            .flat_map(|m| m.keys())
            .collect();
        svc_metric_names.sort();
        svc_metric_names.dedup();

        for metric_name in &svc_metric_names {
            use std::fmt::Write;
            let _ = writeln!(out, "# TYPE {metric_name} gauge");
            for (service_name, metrics) in &state.service_metrics {
                if let Some(values) = metrics.get(*metric_name) {
                    for (node_id, value) in values {
                        let _ = writeln!(
                            out,
                            "{metric_name}{{service=\"{service_name}\",node=\"{node_id}\"}} {value}"
                        );
                    }
                }
            }
        }

        out
    }

    /// Get a single node metric value by name.
    pub async fn node_metric(&self, node_id: &str, metric_name: &str) -> Option<f64> {
        let state = self.inner.read().await;
        state.node_metrics.get(node_id)?.get(metric_name).copied()
    }

    /// Get all metrics for a service, keyed by metric name with values as
    /// `(node_id, value)` pairs. Used by the HPA metrics API.
    pub async fn service_metrics(&self, service_name: &str) -> HashMap<String, Vec<(String, f64)>> {
        let state = self.inner.read().await;
        state
            .service_metrics
            .get(service_name)
            .cloned()
            .unwrap_or_default()
    }

    /// Get fleet-wide average for a node metric.
    pub async fn fleet_metric_avg(&self, metric_name: &str) -> Option<f64> {
        let state = self.inner.read().await;
        let values: Vec<f64> = state
            .node_metrics
            .values()
            .filter_map(|m| m.get(metric_name))
            .copied()
            .collect();

        if values.is_empty() {
            return None;
        }

        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}
