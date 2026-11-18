//! Health of external services.
//!
//! Every address of an `externalServices` entry with a `healthCheck` is
//! probed from the server every `interval` seconds. An address that fails
//! [`FAILURES_TO_UNHEALTHY`] checks in a row is left out of the
//! `<name>.external` DNS records until a check passes again. Addresses not
//! checked yet, and services without a health check, are served as is.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::{ExternalHealthCheck, FleetConfig};
use crate::raft::state::FleetStateMachine;

use super::events::{EventCategory, EventLevel, EventStore};

/// Consecutive failed checks that take an address out of DNS.
pub const FAILURES_TO_UNHEALTHY: u32 = 2;

/// How often due checks are started.
const TICK: Duration = Duration::from_secs(1);

type Key = (String, SocketAddrV4);

#[derive(Debug)]
struct AddressHealth {
    healthy: bool,
    failures: u32,
    next_due: Instant,
    in_flight: bool,
}

/// Shared health of external service addresses.
#[derive(Clone, Default)]
pub struct ExternalHealth {
    inner: Arc<Mutex<HashMap<Key, AddressHealth>>>,
}

impl ExternalHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// The addresses of each external service in `config` to publish.
    pub async fn serving(&self, config: &FleetConfig) -> BTreeMap<String, Vec<SocketAddrV4>> {
        let health = self.inner.lock().await;
        config
            .external_services
            .iter()
            .map(|(name, service)| {
                let endpoints = service
                    .endpoints()
                    .into_iter()
                    .filter(|addr| {
                        service.health_check.is_none()
                            || health.get(&(name.clone(), *addr)).is_none_or(|h| h.healthy)
                    })
                    .collect();
                (name.clone(), endpoints)
            })
            .collect()
    }

    /// Record a check result; returns the new health if it changed.
    async fn record(&self, key: &Key, passed: bool) -> Option<bool> {
        let mut health = self.inner.lock().await;
        let entry = health.get_mut(key)?;
        entry.in_flight = false;
        let was = entry.healthy;
        if passed {
            entry.failures = 0;
            entry.healthy = true;
        } else {
            entry.failures = entry.failures.saturating_add(1);
            if entry.failures >= FAILURES_TO_UNHEALTHY {
                entry.healthy = false;
            }
        }
        (entry.healthy != was).then_some(entry.healthy)
    }

    /// Forget addresses no longer checked, and claim the checks that are
    /// due at `now`.
    async fn due(
        &self,
        checks: &[(Key, ExternalHealthCheck)],
        now: Instant,
    ) -> Vec<(Key, ExternalHealthCheck)> {
        let mut health = self.inner.lock().await;
        health.retain(|key, _| checks.iter().any(|(k, _)| k == key));
        let mut due = Vec::new();
        for (key, check) in checks {
            let entry = health.entry(key.clone()).or_insert(AddressHealth {
                healthy: true,
                failures: 0,
                next_due: now,
                in_flight: false,
            });
            if !entry.in_flight && entry.next_due <= now {
                entry.in_flight = true;
                entry.next_due = now + Duration::from_secs(check.interval);
                due.push((key.clone(), check.clone()));
            }
        }
        due
    }
}

/// Every checked (service, address) of `config`.
fn checks(config: &FleetConfig) -> Vec<(Key, ExternalHealthCheck)> {
    let mut out = Vec::new();
    for (name, service) in &config.external_services {
        if let Some(check) = &service.health_check {
            for addr in service.endpoints() {
                out.push(((name.clone(), addr), check.clone()));
            }
        }
    }
    out
}

type HttpClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    http_body_util::Empty<hyper::body::Bytes>,
>;

fn http_client() -> HttpClient {
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http()
}

/// Probe `addr` once.
async fn probe(client: &HttpClient, addr: SocketAddrV4, check: &ExternalHealthCheck) -> bool {
    let timeout = Duration::from_secs(check.timeout);
    match check.check_type.as_str() {
        "http" => {
            let path = check.path.as_deref().unwrap_or("/");
            let Ok(uri) = format!("http://{addr}{path}").parse::<axum::http::Uri>() else {
                return false;
            };
            match tokio::time::timeout(timeout, client.get(uri)).await {
                Ok(Ok(resp)) => resp.status().is_success() || resp.status().is_redirection(),
                _ => false,
            }
        }
        _ => matches!(
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
            Ok(Ok(_))
        ),
    }
}

/// Runs the health checks of the current configuration.
pub struct ExternalChecker {
    pub raft_state: FleetStateMachine,
    pub health: ExternalHealth,
    pub events: EventStore,
}

impl ExternalChecker {
    pub fn spawn(self, shutdown: CancellationToken) {
        tokio::spawn(async move {
            let client = http_client();
            let mut tick = tokio::time::interval(TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut cached: Option<(u64, Vec<(Key, ExternalHealthCheck)>)> = None;
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => {}
                }
                let current = self.raft_state.current_config().await;
                let revision = current.as_ref().map(|r| r.revision);
                if cached.as_ref().map(|(r, _)| *r) != revision {
                    let parsed = match current.as_ref().map(|r| r.config()).transpose() {
                        Ok(config) => config.as_ref().map(checks).unwrap_or_default(),
                        Err(e) => {
                            tracing::error!(?revision, error = %e, "Cannot read external services");
                            continue;
                        }
                    };
                    cached = revision.map(|r| (r, parsed));
                }
                let wanted = cached.as_ref().map(|(_, c)| c.as_slice()).unwrap_or(&[]);
                for (key, check) in self.health.due(wanted, Instant::now()).await {
                    let health = self.health.clone();
                    let events = self.events.clone();
                    let client = client.clone();
                    tokio::spawn(async move {
                        let passed = probe(&client, key.1, &check).await;
                        if let Some(healthy) = health.record(&key, passed).await {
                            report(&events, &key, healthy).await;
                        }
                    });
                }
            }
        });
    }
}

async fn report(events: &EventStore, (name, addr): &Key, healthy: bool) {
    let (kind, level, message) = if healthy {
        (
            "external.healthy",
            EventLevel::Info,
            format!("External service {name} address {addr} passes its health check again"),
        )
    } else {
        (
            "external.unhealthy",
            EventLevel::Warning,
            format!(
                "External service {name} address {addr} failed {FAILURES_TO_UNHEALTHY} health checks; removed from DNS"
            ),
        )
    };
    if healthy {
        tracing::info!(service = %name, %addr, "External service address healthy");
    } else {
        tracing::warn!(service = %name, %addr, "External service address unhealthy");
    }
    events
        .emit_kind(
            kind,
            level,
            EventCategory::Health,
            Some(name),
            None,
            &message,
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(check: Option<&str>) -> FleetConfig {
        let mut service = serde_json::json!({
            "addresses": ["10.0.0.1:5432", "10.0.0.2:5432"],
        });
        if let Some(kind) = check {
            service["healthCheck"] = serde_json::json!({"type": kind, "interval": 5});
        }
        serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "externalServices": {"db": service},
        }))
        .unwrap()
    }

    fn addr(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn unhealthy_after_consecutive_failures() {
        let config = config(Some("tcp"));
        let health = ExternalHealth::new();
        let now = Instant::now();
        let due = health.due(&checks(&config), now).await;
        assert_eq!(due.len(), 2);
        // Claimed checks are not due again until they finish and the
        // interval passes.
        assert!(health.due(&checks(&config), now).await.is_empty());

        let key = ("db".to_string(), addr("10.0.0.1:5432"));
        assert_eq!(health.record(&key, false).await, None);
        let serving = health.serving(&config).await;
        assert_eq!(serving["db"].len(), 2, "one failure keeps the address");

        let later = now + Duration::from_secs(5);
        assert_eq!(health.due(&checks(&config), later).await.len(), 1);
        assert_eq!(health.record(&key, false).await, Some(false));
        assert_eq!(
            health.serving(&config).await["db"],
            vec![addr("10.0.0.2:5432")]
        );

        let again = later + Duration::from_secs(5);
        health.due(&checks(&config), again).await;
        assert_eq!(health.record(&key, true).await, Some(true));
        assert_eq!(health.serving(&config).await["db"].len(), 2);
    }

    #[tokio::test]
    async fn unchecked_services_always_serve() {
        let config = config(None);
        let health = ExternalHealth::new();
        assert!(
            health
                .due(&checks(&config), Instant::now())
                .await
                .is_empty()
        );
        assert_eq!(health.serving(&config).await["db"].len(), 2);
    }

    #[tokio::test]
    async fn removed_addresses_are_forgotten() {
        let health = ExternalHealth::new();
        let key = ("db".to_string(), addr("10.0.0.1:5432"));
        health
            .due(&checks(&config(Some("tcp"))), Instant::now())
            .await;
        health.record(&key, false).await;
        health.due(&[], Instant::now()).await;
        assert!(health.inner.lock().await.is_empty());
    }

    #[tokio::test]
    async fn probes_tcp_and_http() {
        let client = http_client();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(open) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        let tcp = ExternalHealthCheck {
            check_type: "tcp".into(),
            path: None,
            interval: 1,
            timeout: 1,
        };
        assert!(probe(&client, open, &tcp).await);

        let app = axum::Router::new()
            .route("/ok", axum::routing::get(|| async { "ok" }))
            .route(
                "/bad",
                axum::routing::get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        let http = |path: &str| ExternalHealthCheck {
            check_type: "http".into(),
            path: Some(path.into()),
            interval: 1,
            timeout: 1,
        };
        assert!(probe(&client, open, &http("/ok")).await);
        assert!(!probe(&client, open, &http("/bad")).await);

        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let std::net::SocketAddr::V4(a) = l.local_addr().unwrap() else {
                unreachable!()
            };
            a
        };
        assert!(!probe(&client, closed, &tcp).await);
    }
}
