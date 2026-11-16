//! Evaluating alert rules and notifying their webhooks.
//!
//! Every [`INTERVAL`] the server takes the alert rules of the configuration
//! it reconciles toward, evaluates them against the latest metrics from all
//! agents, and POSTs each batch of alerts that fired or resolved to the
//! rule's webhook as an Alertmanager webhook (version 4) payload, retrying
//! failed deliveries.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::metrics::aggregator::MetricsAggregator;
use crate::metrics::alerting::{Alert, AlertEvaluator, AlertStatus};
use crate::raft::state::FleetStateMachine;

pub const INTERVAL: Duration = Duration::from_secs(15);
const ATTEMPTS: u32 = 5;
const FIRST_RETRY: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct AlertLoop {
    pub raft_state: FleetStateMachine,
    pub metrics: MetricsAggregator,
    pub evaluator: AlertEvaluator,
}

impl AlertLoop {
    pub fn spawn(self, shutdown: CancellationToken) {
        tokio::spawn(async move {
            let client = WebhookClient::new();
            let mut interval = tokio::time::interval(INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = interval.tick() => {}
                }
                self.load_rules().await;
                let series = self.metrics.series().await;
                let transitions = self
                    .evaluator
                    .evaluate(&series, crate::agent::now_epoch())
                    .await;
                for (url, payload) in notifications(&transitions) {
                    tokio::spawn(deliver(client.clone(), url, payload, FIRST_RETRY));
                }
            }
        });
    }

    /// Take the rules of the current configuration revision, if it changed.
    async fn load_rules(&self) {
        let current = self.raft_state.current_config().await;
        let revision = current.as_ref().map(|r| r.revision);
        if revision == self.evaluator.revision().await {
            return;
        }
        let rules = match current.as_ref().map(|r| r.config()).transpose() {
            Ok(config) => config.map(|c| c.alerts).unwrap_or_default(),
            Err(e) => {
                tracing::error!(?revision, error = %e, "Cannot read alert rules");
                return;
            }
        };
        self.evaluator.set_rules(rules, revision).await;
    }
}

/// Alertmanager webhook payloads for `transitions`: one per webhook,
/// alert name and status.
pub fn notifications(transitions: &[Alert]) -> Vec<(String, serde_json::Value)> {
    let mut groups: BTreeMap<(String, String, bool), Vec<&Alert>> = BTreeMap::new();
    for alert in transitions {
        if let Some(url) = &alert.webhook_url {
            let firing = alert.status == AlertStatus::Firing;
            groups
                .entry((url.clone(), alert.name().to_string(), firing))
                .or_default()
                .push(alert);
        }
    }
    groups
        .into_iter()
        .map(|((url, name, firing), alerts)| (url, payload(&name, firing, &alerts)))
        .collect()
}

fn payload(name: &str, firing: bool, alerts: &[&Alert]) -> serde_json::Value {
    let common = |pick: fn(&Alert) -> &BTreeMap<String, String>| {
        let mut common = pick(alerts[0]).clone();
        for alert in &alerts[1..] {
            common.retain(|k, v| pick(alert).get(k) == Some(v));
        }
        common
    };
    let status = if firing { "firing" } else { "resolved" };
    serde_json::json!({
        "version": "4",
        "groupKey": format!("{{}}:{{alertname={name:?}}}"),
        "truncatedAlerts": 0,
        "status": status,
        "receiver": "ekafleet",
        "groupLabels": { "alertname": name },
        "commonLabels": common(|a| &a.labels),
        "commonAnnotations": common(|a| &a.annotations),
        "externalURL": "",
        "alerts": alerts.iter().map(|a| serde_json::json!({
            "status": status,
            "labels": a.labels,
            "annotations": a.annotations,
            "startsAt": rfc3339(a.starts_at),
            "endsAt": a.ends_at.map_or_else(|| "0001-01-01T00:00:00Z".to_string(), rfc3339),
            "generatorURL": "",
            "fingerprint": a.fingerprint(),
        })).collect::<Vec<_>>(),
    })
}

type HttpsConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

/// HTTP(S) client for webhooks, trusting the platform's root certificates.
#[derive(Clone)]
pub struct WebhookClient {
    http: hyper_util::client::legacy::Client<
        HttpsConnector,
        http_body_util::Full<hyper::body::Bytes>,
    >,
}

impl Default for WebhookClient {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookClient {
    pub fn new() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            http: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https),
        }
    }

    /// POST a JSON body and return the response status.
    async fn post_json(&self, url: &str, body: &str) -> Result<hyper::StatusCode, String> {
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(url)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(
                hyper::header::USER_AGENT,
                concat!("ekafleet/", env!("CARGO_PKG_VERSION")),
            )
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body.to_owned(),
            )))
            .map_err(|e| e.to_string())?;
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.http.request(request))
            .await
            .map_err(|_| format!("timed out after {REQUEST_TIMEOUT:?}"))?
            .map_err(|e| e.to_string())?;
        Ok(response.status())
    }
}

/// POST `payload` to `url`, retrying network errors, 429 and 5xx with
/// exponential backoff starting at `first_retry`.
async fn deliver(
    client: WebhookClient,
    url: String,
    payload: serde_json::Value,
    first_retry: Duration,
) {
    let body = payload.to_string();
    let mut delay = first_retry;
    for attempt in 1..=ATTEMPTS {
        let retry = match client.post_json(&url, &body).await {
            Ok(status) if status.is_success() => {
                tracing::debug!(%url, "Alert notification delivered");
                return;
            }
            Ok(status) => {
                tracing::warn!(%url, %status, attempt, "Alert webhook refused the notification");
                status.is_server_error() || status.as_u16() == 429
            }
            Err(e) => {
                tracing::warn!(%url, error = %e, attempt, "Alert webhook unreachable");
                true
            }
        };
        if !retry || attempt == ATTEMPTS {
            break;
        }
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
    tracing::error!(%url, "Giving up on an alert notification");
}

/// Unix seconds as an RFC 3339 UTC timestamp.
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(name: &str, node: &str, status: AlertStatus, url: Option<&str>) -> Alert {
        Alert {
            status,
            labels: BTreeMap::from([
                ("alertname".to_string(), name.to_string()),
                ("node".to_string(), node.to_string()),
                ("severity".to_string(), "warning".to_string()),
            ]),
            annotations: BTreeMap::from([("summary".to_string(), format!("{node} is hot"))]),
            value: 1.0,
            starts_at: 1_700_000_000,
            ends_at: (status == AlertStatus::Resolved).then_some(1_700_000_060),
            webhook_url: url.map(str::to_string),
        }
    }

    #[test]
    fn timestamps_are_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn notifications_are_alertmanager_payloads_grouped_by_status() {
        let hook = Some("http://hooks.test/alerts");
        let transitions = [
            alert("hot", "a", AlertStatus::Firing, hook),
            alert("hot", "b", AlertStatus::Firing, hook),
            alert("hot", "c", AlertStatus::Resolved, hook),
            alert("quiet", "a", AlertStatus::Firing, None),
        ];
        let sent = notifications(&transitions);
        assert_eq!(sent.len(), 2);
        let (url, firing) = &sent[1];
        assert_eq!(url, "http://hooks.test/alerts");
        assert_eq!(firing["version"], "4");
        assert_eq!(firing["status"], "firing");
        assert_eq!(firing["groupLabels"]["alertname"], "hot");
        assert_eq!(firing["commonLabels"]["severity"], "warning");
        assert!(firing["commonLabels"].get("node").is_none());
        assert!(firing["commonAnnotations"].get("summary").is_none());
        let alerts = firing["alerts"].as_array().unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0]["startsAt"], "2023-11-14T22:13:20Z");
        assert_eq!(alerts[0]["endsAt"], "0001-01-01T00:00:00Z");
        assert_eq!(alerts[0]["fingerprint"].as_str().unwrap().len(), 16);

        let (_, resolved) = &sent[0];
        assert_eq!(resolved["status"], "resolved");
        assert_eq!(resolved["alerts"][0]["endsAt"], "2023-11-14T22:14:20Z");
        assert_eq!(resolved["commonLabels"]["node"], "c");
    }

    #[tokio::test]
    async fn failed_deliveries_are_retried() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut bodies = Vec::new();
            for status in ["503 Service Unavailable", "200 OK"] {
                let (mut conn, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                // Read until the JSON body is complete.
                while !request.ends_with(b"}") {
                    let n = conn.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                }
                bodies.push(String::from_utf8(request).unwrap());
                conn.write_all(
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            }
            bodies
        });
        let delivery = tokio::spawn(deliver(
            WebhookClient::new(),
            url,
            serde_json::json!({"version": "4"}),
            Duration::from_millis(10),
        ));
        let bodies = server.await.unwrap();
        delivery.await.unwrap();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[1].starts_with("POST /hook "));
        assert!(bodies[1].contains("application/json"));
    }
}
