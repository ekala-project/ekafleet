use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

/// Agent-side metrics collector.
/// Scrapes Prometheus-format metrics from local services.
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<RwLock<CollectorState>>,
}

struct CollectorState {
    /// service_name → latest scraped metrics
    service_metrics: HashMap<String, Vec<MetricSample>>,
}

#[derive(Debug, Clone)]
pub struct MetricSample {
    pub name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub timestamp: u64,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CollectorState {
                service_metrics: HashMap::new(),
            })),
        }
    }

    /// Start scraping a service's metrics endpoint.
    pub fn start_scraping(&self, service_name: String, port: u16, path: String) {
        let inner = self.inner.clone();

        tracing::info!(
            service = %service_name,
            port,
            "Metrics scraping started"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            let url = format!("http://127.0.0.1:{port}{path}");

            loop {
                interval.tick().await;
                match scrape_endpoint(&url).await {
                    Ok(samples) => {
                        let mut state = inner.write().await;
                        state.service_metrics.insert(service_name.clone(), samples);
                    }
                    Err(e) => {
                        tracing::debug!(
                            service = %service_name,
                            error = %e,
                            "Metrics scrape failed"
                        );
                    }
                }
            }
        });
    }

    /// Get latest metrics for all services.
    pub async fn all_metrics(&self) -> HashMap<String, Vec<MetricSample>> {
        let state = self.inner.read().await;
        state.service_metrics.clone()
    }

    /// Get latest metrics for a specific service.
    pub async fn service_metrics(&self, service_name: &str) -> Vec<MetricSample> {
        let state = self.inner.read().await;
        state
            .service_metrics
            .get(service_name)
            .cloned()
            .unwrap_or_default()
    }

    /// Convert to proto MetricPoints for sending to server.
    pub async fn to_proto_points(&self) -> Vec<crate::proto::MetricPoint> {
        let state = self.inner.read().await;
        let mut points = Vec::new();

        for (service_name, samples) in &state.service_metrics {
            for sample in samples {
                let mut labels = sample.labels.clone();
                labels.insert("service".to_string(), service_name.clone());
                points.push(crate::proto::MetricPoint {
                    name: sample.name.clone(),
                    value: sample.value,
                    labels,
                    timestamp: sample.timestamp,
                });
            }
        }

        points
    }
}

/// Scrape a Prometheus-format metrics endpoint.
async fn scrape_endpoint(url: &str) -> Result<Vec<MetricSample>, String> {
    // Simple HTTP fetch — reusing the same pattern as health checks
    let addr = url.strip_prefix("http://").ok_or("invalid url")?;

    let (host_port, path) = addr.split_once('/').unwrap_or((addr, ""));
    let path = format!("/{path}");

    let stream = tokio::net::TcpStream::connect(host_port)
        .await
        .map_err(|e| e.to_string())?;

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut reader, mut writer) = stream.into_split();
    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    writer.shutdown().await.map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    reader
        .read_to_end(&mut response)
        .await
        .map_err(|e| e.to_string())?;

    let body = String::from_utf8_lossy(&response);

    // Find body after headers
    let body = body.split("\r\n\r\n").nth(1).unwrap_or("");

    parse_prometheus(body)
}

/// Parse Prometheus exposition format into MetricSamples.
fn parse_prometheus(body: &str) -> Result<Vec<MetricSample>, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut samples = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse: metric_name{label="value",...} value
        let (name_and_labels, value_str) = match line.rsplit_once(' ') {
            Some(parts) => parts,
            None => continue,
        };

        let value: f64 = match value_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let (name, labels) = if let Some(brace_start) = name_and_labels.find('{') {
            let name = &name_and_labels[..brace_start];
            let labels_str = &name_and_labels[brace_start + 1..name_and_labels.len() - 1];
            let labels = parse_labels(labels_str);
            (name, labels)
        } else {
            (name_and_labels, HashMap::new())
        };

        samples.push(MetricSample {
            name: name.to_string(),
            value,
            labels,
            timestamp: now,
        });
    }

    Ok(samples)
}

fn parse_labels(s: &str) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    for part in s.split(',') {
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim_matches('"');
            labels.insert(key.to_string(), value.to_string());
        }
    }
    labels
}
