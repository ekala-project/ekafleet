//! Shipping node and service metrics to the server.
//!
//! Every 15 seconds the agent samples its node, scrapes the metrics
//! endpoint of every service it runs (inside the service's network
//! namespace), and sends everything in one `MetricsSummary`. A service's
//! series are summed by metric name, so the server sees one value per
//! metric per service instance; `up` is 1 when the scrape succeeded.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::metrics::collector::{self, Target};
use crate::metrics::node::NodeSampler;
use crate::proto::agent_message::Payload;
use crate::proto::{AgentMessage, MetricPoint, MetricsSummary, ServiceSpec};

use super::types::LocalState;

pub const INTERVAL: Duration = Duration::from_secs(15);

/// Scrape targets of the services in `desired`.
pub fn targets(desired: &HashMap<String, ServiceSpec>) -> Vec<Target> {
    let mut targets: Vec<Target> = desired
        .iter()
        .filter_map(|(name, spec)| {
            let metrics = spec.metrics.as_ref()?;
            let port = u16::try_from(metrics.port).ok().filter(|p| *p != 0)?;
            let namespace = (!super::netns::is_default_namespace(&spec.namespace))
                .then(|| spec.namespace.clone());
            Some(Target {
                service: name.clone(),
                port,
                path: metrics.path.clone(),
                namespace,
            })
        })
        .collect();
    targets.sort_by(|a, b| a.service.cmp(&b.service));
    targets
}

/// Points for one collection round.
pub async fn collect(sampler: &mut NodeSampler, targets: Vec<Target>) -> Vec<MetricPoint> {
    let timestamp = super::now_epoch();
    let point = |name: String, value: f64, service: Option<&str>| MetricPoint {
        name,
        value,
        labels: service
            .map(|s| HashMap::from([("service".to_string(), s.to_string())]))
            .unwrap_or_default(),
        timestamp,
    };
    let mut points: Vec<MetricPoint> = sampler
        .sample()
        .into_iter()
        .map(|(name, value)| point(name, value, None))
        .collect();

    let mut scrapes = tokio::task::JoinSet::new();
    for target in targets {
        scrapes.spawn(async move {
            let service = target.service.clone();
            (service, collector::scrape(target).await)
        });
    }
    while let Some(result) = scrapes.join_next().await {
        let Ok((service, result)) = result else {
            continue;
        };
        let up = match result {
            Ok(sums) => {
                points.extend(
                    sums.into_iter()
                        .filter(|(name, _)| name != "up")
                        .map(|(name, value)| point(name, value, Some(&service))),
                );
                1.0
            }
            Err(e) => {
                tracing::debug!(service = %service, error = %e, "Metrics scrape failed");
                0.0
            }
        };
        points.push(point("up".into(), up, Some(&service)));
    }
    points
}

/// Send metrics every [`INTERVAL`] until `shutdown` or the stream closes.
pub(super) fn spawn_reporter(
    node_id: Arc<str>,
    data_dir: PathBuf,
    local_state: Arc<RwLock<LocalState>>,
    tx: mpsc::Sender<AgentMessage>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut sampler = NodeSampler::new(data_dir);
        let mut interval = tokio::time::interval(INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let targets = targets(&local_state.read().await.desired_services);
            let points = collect(&mut sampler, targets).await;
            let msg = AgentMessage {
                payload: Some(Payload::Metrics(MetricsSummary {
                    node_id: node_id.to_string(),
                    points,
                })),
            };
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::MetricsEndpoint;

    fn spec(namespace: &str, port: u32) -> ServiceSpec {
        ServiceSpec {
            namespace: namespace.into(),
            metrics: Some(MetricsEndpoint {
                port,
                path: "/metrics".into(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn targets_scrape_inside_the_service_namespace() {
        let desired = HashMap::from([
            ("api".to_string(), spec("default", 9100)),
            ("db".to_string(), spec("team-a", 9187)),
            ("bad".to_string(), spec("", 70000)),
            ("plain".to_string(), ServiceSpec::default()),
        ]);
        let targets = targets(&desired);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].service, "api");
        assert_eq!(targets[0].namespace, None);
        assert_eq!(targets[1].namespace.as_deref(), Some("team-a"));
    }

    #[tokio::test]
    async fn unreachable_endpoints_report_down() {
        let dir = tempfile::tempdir().unwrap();
        let mut sampler = NodeSampler::new(dir.path().to_path_buf());
        // Nothing listens on a port that was just released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let points = collect(
            &mut sampler,
            vec![Target {
                service: "web".into(),
                port,
                path: "/metrics".into(),
                namespace: None,
            }],
        )
        .await;
        let up = points.iter().find(|p| p.name == "up").expect("an up point");
        assert_eq!(up.value, 0.0);
        assert_eq!(up.labels["service"], "web");
        assert!(points.iter().any(|p| p.name == "node_memory_usage_ratio"));
    }
}
