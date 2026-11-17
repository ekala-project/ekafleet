//! Service autoscaling.
//!
//! Every [`INTERVAL`] the server recommends a replica count for each
//! service of the current configuration with `scheduling.autoscale`, from
//! the metrics its instances reported (see [`crate::config::AutoscaleConfig`]
//! for the rules), and records changes as the service's replica override,
//! which the reconciler schedules. The autoscaler owns the override of an
//! autoscaled service: manual `ekafleet scale` is refused for it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::{AutoscaleConfig, FleetConfig, ServiceConfig};
use crate::metrics::aggregator::{MetricsAggregator, Series};
use crate::metrics::cgroup::{CPU_METRIC, MEMORY_METRIC};
use crate::raft::state::FleetStateMachine;

use super::events::{EventCategory, EventLevel, EventStore};
use super::state::FleetState;

pub const INTERVAL: Duration = Duration::from_secs(15);
/// A rule this close to its target recommends no change.
const TOLERANCE: f64 = 0.1;

pub struct Autoscaler {
    pub raft_state: FleetStateMachine,
    pub state: FleetState,
    pub metrics: MetricsAggregator,
    pub events: EventStore,
}

impl Autoscaler {
    pub fn spawn(self, shutdown: CancellationToken) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut cached: Option<(u64, FleetConfig)> = None;
            let mut history: HashMap<String, VecDeque<(u64, u32)>> = HashMap::new();
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = interval.tick() => {}
                }
                let Some(revision) = self.raft_state.current_config().await else {
                    continue;
                };
                if cached.as_ref().map(|(r, _)| *r) != Some(revision.revision) {
                    match revision.config() {
                        Ok(config) => cached = Some((revision.revision, config)),
                        Err(e) => {
                            tracing::error!(revision = revision.revision, error = %e, "Cannot read the configuration to autoscale");
                            continue;
                        }
                    }
                }
                let Some((_, config)) = &cached else { continue };
                self.cycle(config, &mut history, crate::agent::now_epoch())
                    .await;
            }
        });
    }

    async fn cycle(
        &self,
        config: &FleetConfig,
        history: &mut HashMap<String, VecDeque<(u64, u32)>>,
        now: u64,
    ) {
        history.retain(|name, _| {
            config
                .services
                .get(name)
                .is_some_and(|s| s.scheduling.autoscale.is_some())
        });
        let series = self.metrics.series().await;
        let overrides = self.raft_state.replica_overrides().await;
        let mut names: Vec<_> = config.services.keys().collect();
        names.sort();
        for name in names {
            let service = &config.services[name];
            let Some(autoscale) = &service.scheduling.autoscale else {
                continue;
            };
            let current = overrides
                .get(name)
                .copied()
                .unwrap_or(service.scheduling.replicas);
            let points: Vec<(&str, f64)> = series
                .iter()
                .filter(|s| s.service.as_deref() == Some(name.as_str()))
                .map(|s: &Series| (s.metric.as_str(), s.value))
                .collect();
            let recommended = recommend(service, autoscale, current, &points);
            let entries = history.entry(name.clone()).or_default();
            let desired = stabilize(entries, now, recommended, current, autoscale);
            if desired == current && overrides.contains_key(name) {
                continue;
            }
            if let Err(e) = self.raft_state.set_replica_override(name, desired).await {
                tracing::error!(service = %name, error = %e, "Cannot record an autoscaling decision");
                continue;
            }
            if desired == current {
                // First decision: the count is now the autoscaler's.
                continue;
            }
            tracing::info!(service = %name, from = current, to = desired, "Autoscaling");
            self.events
                .emit_kind(
                    "service.scaled",
                    EventLevel::Info,
                    EventCategory::Scaling,
                    Some(name),
                    None,
                    &format!("Autoscaled {name} from {current} to {desired} replicas"),
                )
                .await;
            self.state.reconcile_trigger().trigger();
        }
    }
}

/// The replica count the rules recommend, clamped to `[min, max]`. With no
/// metrics for any rule, `current` (clamped).
pub fn recommend(
    service: &ServiceConfig,
    autoscale: &AutoscaleConfig,
    current: u32,
    points: &[(&str, f64)],
) -> u32 {
    let request = |r: &Option<crate::config::ResourceValue>| r.as_ref().map_or(0, |r| r.request);
    let cpu_request = request(&service.resources.cpu) as f64;
    let memory_request = request(&service.resources.memory) as f64 * 1024.0 * 1024.0;
    let recommendations = autoscale.rules.iter().filter_map(|rule| {
        let (metric, scale) = match rule.metric.as_str() {
            "cpu" => (CPU_METRIC, cpu_request),
            "memory" => (MEMORY_METRIC, memory_request),
            other => (other, 1.0),
        };
        if scale <= 0.0 {
            return None;
        }
        let values: Vec<f64> = points
            .iter()
            .filter(|(m, v)| *m == metric && v.is_finite())
            .map(|(_, v)| v / scale)
            .collect();
        if values.is_empty() {
            return None;
        }
        let average = values.iter().sum::<f64>() / values.len() as f64;
        let ratio = average / rule.target;
        if (ratio - 1.0).abs() <= TOLERANCE {
            return Some(current);
        }
        let wanted = (f64::from(current.max(1)) * ratio).ceil();
        Some(wanted.clamp(0.0, f64::from(u32::MAX)) as u32)
    });
    recommendations
        .max()
        .unwrap_or(current)
        .clamp(autoscale.min, autoscale.max)
}

/// Apply scale-ups at once and scale-downs only once every recommendation
/// in the last `scaleDownDelaySeconds` (with at least that much history)
/// was at most as high. `history` holds `(time, recommendation)`.
pub fn stabilize(
    history: &mut VecDeque<(u64, u32)>,
    now: u64,
    recommended: u32,
    current: u32,
    autoscale: &AutoscaleConfig,
) -> u32 {
    let window = autoscale.scale_down_delay_seconds;
    history.push_back((now, recommended));
    // Keep one entry older than the window, to know it is covered.
    while history.len() > 1 && history[1].0 + window <= now {
        history.pop_front();
    }
    let current = current.clamp(autoscale.min, autoscale.max);
    if recommended >= current {
        return recommended;
    }
    let covered = history.front().is_some_and(|(t, _)| t + window <= now);
    if !covered {
        return current;
    }
    let highest = history
        .iter()
        .filter(|(t, _)| t + window > now)
        .map(|(_, r)| *r)
        .max()
        .unwrap_or(current);
    highest.min(current)
}

/// Drop replica overrides that no longer apply after a new revision:
/// those of removed services, of services no longer autoscaled, and manual
/// ones of services whose configured `replicas` changed.
pub async fn settle_overrides(
    raft_state: &FleetStateMachine,
    previous: Option<&FleetConfig>,
    desired: &FleetConfig,
) {
    for (name, stale) in stale_overrides(&raft_state.replica_overrides().await, previous, desired) {
        tracing::info!(service = %name, reason = stale, "Clearing the replica override");
        if let Err(e) = raft_state.clear_replica_override(&name).await {
            tracing::error!(service = %name, error = %e, "Cannot clear a replica override");
        }
    }
}

fn stale_overrides(
    overrides: &BTreeMap<String, u32>,
    previous: Option<&FleetConfig>,
    desired: &FleetConfig,
) -> Vec<(String, &'static str)> {
    overrides
        .keys()
        .filter_map(|name| {
            let Some(now) = desired.services.get(name) else {
                return Some((name.clone(), "service removed"));
            };
            if now.scheduling.autoscale.is_some() {
                return None;
            }
            let before = previous.and_then(|p| p.services.get(name));
            if before.is_some_and(|b| b.scheduling.autoscale.is_some()) {
                return Some((name.clone(), "autoscaling removed"));
            }
            if before.is_some_and(|b| b.scheduling.replicas != now.scheduling.replicas) {
                return Some((name.clone(), "configured replicas changed"));
            }
            None
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(json: serde_json::Value) -> ServiceConfig {
        serde_json::from_value(json).unwrap()
    }

    fn autoscaled(rules: serde_json::Value) -> ServiceConfig {
        service(serde_json::json!({
            "command": "/bin/true",
            "resources": {"cpu": {"request": 500}, "memory": {"request": 256}},
            "metrics": {"port": 9100},
            "scheduling": {"replicas": 2, "autoscale": {"min": 1, "max": 10, "rules": rules}},
        }))
    }

    #[test]
    fn rules_recommend_by_utilization_and_custom_metrics() {
        let svc = autoscaled(serde_json::json!([
            {"metric": "cpu", "target": 0.5},
            {"metric": "queue_depth", "target": 100},
        ]));
        let auto = svc.scheduling.autoscale.as_ref().unwrap();
        // CPU 500m of 500m requested = 100% vs 50% target: double.
        let cpu = [(CPU_METRIC, 500.0), (CPU_METRIC, 500.0)];
        assert_eq!(recommend(&svc, auto, 2, &cpu), 4);
        // Queue depth 330 average vs 100 target: ceil(2 × 3.3) = 7, the larger.
        let both = [(CPU_METRIC, 500.0), ("queue_depth", 330.0)];
        assert_eq!(recommend(&svc, auto, 2, &both), 7);
        // Within tolerance: no change.
        assert_eq!(recommend(&svc, auto, 2, &[(CPU_METRIC, 260.0)]), 2);
        // Idle: down to the minimum.
        assert_eq!(recommend(&svc, auto, 2, &[(CPU_METRIC, 1.0)]), 1);
        // Clamped to max; no data keeps the current count.
        assert_eq!(recommend(&svc, auto, 8, &[("queue_depth", 1000.0)]), 10);
        assert_eq!(recommend(&svc, auto, 3, &[]), 3);
        assert_eq!(recommend(&svc, auto, 30, &[]), 10);
    }

    #[test]
    fn memory_targets_utilization_of_the_request() {
        let svc = autoscaled(serde_json::json!([{"metric": "memory", "target": 0.5}]));
        let auto = svc.scheduling.autoscale.as_ref().unwrap();
        let used = 256.0 * 1024.0 * 1024.0; // all of the 256MB request
        assert_eq!(recommend(&svc, auto, 3, &[(MEMORY_METRIC, used)]), 6);
    }

    #[test]
    fn scale_downs_wait_for_the_whole_window() {
        let svc = autoscaled(serde_json::json!([{"metric": "cpu", "target": 0.5}]));
        let mut auto = svc.scheduling.autoscale.clone().unwrap();
        auto.scale_down_delay_seconds = 60;
        let mut history = VecDeque::new();
        // Up at once.
        assert_eq!(stabilize(&mut history, 0, 5, 2, &auto), 5);
        // Down only after 60s of lower recommendations.
        assert_eq!(stabilize(&mut history, 15, 2, 5, &auto), 5);
        assert_eq!(stabilize(&mut history, 30, 3, 5, &auto), 5);
        assert_eq!(stabilize(&mut history, 59, 2, 5, &auto), 5);
        // At 75s the window (15, 75] saw 3, 2, 2: the highest wins.
        assert_eq!(stabilize(&mut history, 75, 2, 5, &auto), 3);
        assert_eq!(stabilize(&mut history, 95, 2, 3, &auto), 2);
    }

    #[test]
    fn applies_clear_overrides_that_no_longer_apply() {
        let config = |services: serde_json::Value| -> FleetConfig {
            serde_json::from_value(serde_json::json!({
                "name": "t", "domain": "d", "services": services,
            }))
            .unwrap()
        };
        let plain = |replicas: u32| serde_json::json!({"command": "/bin/true", "scheduling": {"replicas": replicas}});
        let auto = serde_json::json!({
            "command": "/bin/true",
            "resources": {"cpu": {"request": 100}},
            "scheduling": {"autoscale": {"min": 1, "max": 3, "rules": [{"metric": "cpu", "target": 0.5}]}},
        });
        let previous = config(serde_json::json!({
            "manual": plain(1), "changed": plain(1), "was-auto": auto.clone(), "auto": auto.clone(), "gone": plain(1),
        }));
        let desired = config(serde_json::json!({
            "manual": plain(1), "changed": plain(2), "was-auto": plain(1), "auto": auto,
        }));
        let overrides: BTreeMap<String, u32> = ["manual", "changed", "was-auto", "auto", "gone"]
            .into_iter()
            .map(|n| (n.to_string(), 3))
            .collect();
        let stale: Vec<_> = stale_overrides(&overrides, Some(&previous), &desired)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(stale, vec!["changed", "gone", "was-auto"]);
    }
}
