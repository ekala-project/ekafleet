//! Outbound webhooks: the HTTP(S) client shared by alert notifications,
//! event notifications and admission reviews, delivery with retries, and
//! the admission review exchange.

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Bytes;

use crate::config::{AdmissionWebhook, FailPolicy};

/// Delivery attempts before a notification is dropped.
const ATTEMPTS: u32 = 5;
/// Per-request timeout for notifications.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response body read from a webhook.
const MAX_RESPONSE: usize = 64 * 1024;

type HttpsConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

/// HTTP(S) client for webhooks, trusting the platform's root certificates.
#[derive(Clone)]
pub struct WebhookClient {
    http: hyper_util::client::legacy::Client<HttpsConnector, http_body_util::Full<Bytes>>,
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

    /// POST a JSON body; the response status and (at most 64KiB of) body.
    pub async fn post_json(
        &self,
        url: &str,
        body: &str,
        headers: &[(&'static str, String)],
        timeout: Duration,
    ) -> Result<(hyper::StatusCode, Bytes), String> {
        let mut request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(url)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(
                hyper::header::USER_AGENT,
                concat!("ekafleet/", env!("CARGO_PKG_VERSION")),
            );
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let request = request
            .body(http_body_util::Full::new(Bytes::from(body.to_owned())))
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(timeout, async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status();
            let body = http_body_util::Limited::new(response.into_body(), MAX_RESPONSE)
                .collect()
                .await
                .map_err(|e| format!("reading the response: {e}"))?
                .to_bytes();
            Ok((status, body))
        })
        .await
        .map_err(|_| format!("timed out after {timeout:?}"))?
    }
}

/// A notification to POST.
#[derive(Debug, Clone)]
pub struct Notification {
    pub url: String,
    pub body: String,
    pub headers: Vec<(&'static str, String)>,
}

/// POST a notification, retrying network errors, 429 and 5xx with
/// exponential backoff starting at `first_retry`. `what` names the kind of
/// notification in logs.
pub async fn deliver(
    client: WebhookClient,
    notification: Notification,
    first_retry: Duration,
    what: &'static str,
) {
    let Notification { url, body, headers } = notification;
    let mut delay = first_retry;
    for attempt in 1..=ATTEMPTS {
        let retry = match client
            .post_json(&url, &body, &headers, REQUEST_TIMEOUT)
            .await
        {
            Ok((status, _)) if status.is_success() => {
                tracing::debug!(%url, what, "Notification delivered");
                return;
            }
            Ok((status, _)) => {
                tracing::warn!(%url, what, %status, attempt, "Webhook refused a notification");
                status.is_server_error() || status.as_u16() == 429
            }
            Err(e) => {
                tracing::warn!(%url, what, error = %e, attempt, "Webhook unreachable");
                true
            }
        };
        if !retry || attempt == ATTEMPTS {
            break;
        }
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
    tracing::error!(%url, what, "Giving up on a notification");
}

/// Send `review` to each admission webhook in order.
///
/// A webhook admits a change by answering 2xx with `{"allowed": true}`;
/// `{"allowed": false, "message": "..."}` rejects it. A webhook that cannot
/// be reached or answers anything else rejects the change too, unless its
/// fail policy is `ignore`, which turns the failure into a warning.
/// Returns the warnings, or the first rejection.
pub async fn review(
    client: &WebhookClient,
    webhooks: &[AdmissionWebhook],
    review: &serde_json::Value,
) -> Result<Vec<String>, String> {
    let body = review.to_string();
    let mut warnings = Vec::new();
    for webhook in webhooks {
        let timeout = Duration::from_secs(webhook.timeout_seconds);
        let answer = client
            .post_json(&webhook.url, &body, &[], timeout)
            .await
            .and_then(|(status, body)| parse_answer(status, &body));
        match answer {
            Ok(Answer::Allowed) => {}
            Ok(Answer::Denied(message)) => {
                return Err(format!(
                    "admission webhook '{}' rejected the change: {message}",
                    webhook.name
                ));
            }
            Err(e) => match webhook.fail_policy {
                FailPolicy::Fail => {
                    return Err(format!("admission webhook '{}' failed: {e}", webhook.name));
                }
                FailPolicy::Ignore => {
                    tracing::warn!(webhook = %webhook.name, error = %e, "Ignoring a failed admission webhook");
                    warnings.push(format!(
                        "admission webhook '{}' failed and was ignored: {e}",
                        webhook.name
                    ));
                }
            },
        }
    }
    Ok(warnings)
}

#[derive(Debug, PartialEq)]
enum Answer {
    Allowed,
    Denied(String),
}

fn parse_answer(status: hyper::StatusCode, body: &[u8]) -> Result<Answer, String> {
    if !status.is_success() {
        return Err(format!("answered {status}"));
    }
    #[derive(serde::Deserialize)]
    struct Body {
        allowed: bool,
        #[serde(default)]
        message: String,
    }
    let answer: Body = serde_json::from_slice(body).map_err(|e| format!("invalid answer: {e}"))?;
    Ok(if answer.allowed {
        Answer::Allowed
    } else {
        let mut message = answer.message;
        if message.is_empty() {
            message = "no reason given".into();
        }
        // Webhook text ends up in CLI output and logs: keep it short and printable.
        message.retain(|c| !c.is_control());
        message.truncate(message.floor_char_boundary(512));
        Answer::Denied(message)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves one canned HTTP response per connection, returning the
    /// requests it received.
    async fn serve(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut conn, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                // Read until the JSON body is complete.
                while !request.ends_with(b"}") {
                    let n = conn.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                }
                requests.push(String::from_utf8(request).unwrap());
                conn.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            }
            requests
        });
        (url, server)
    }

    #[tokio::test]
    async fn failed_deliveries_are_retried() {
        let (url, server) = serve(vec![("503 Service Unavailable", ""), ("200 OK", "")]).await;
        let delivery = tokio::spawn(deliver(
            WebhookClient::new(),
            Notification {
                url,
                body: r#"{"version":"4"}"#.into(),
                headers: vec![("x-test", "yes".into())],
            },
            Duration::from_millis(10),
            "test",
        ));
        let requests = server.await.unwrap();
        delivery.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /hook "));
        assert!(requests[1].contains("application/json"));
        assert!(requests[1].contains("x-test: yes"));
    }

    fn hook(name: &str, url: &str, fail_policy: FailPolicy) -> AdmissionWebhook {
        AdmissionWebhook {
            name: name.into(),
            url: url.into(),
            fail_policy,
            timeout_seconds: 5,
        }
    }

    #[tokio::test]
    async fn admission_webhooks_admit_reject_and_fail() {
        let client = WebhookClient::new();
        let review_body = serde_json::json!({"kind": "AdmissionReview"});

        let (url, server) = serve(vec![("200 OK", r#"{"allowed":true}"#)]).await;
        let warnings = review(&client, &[hook("a", &url, FailPolicy::Fail)], &review_body)
            .await
            .unwrap();
        assert!(warnings.is_empty());
        assert!(server.await.unwrap()[0].contains(r#""kind":"AdmissionReview""#));

        let (url, _server) = serve(vec![(
            "200 OK",
            r#"{"allowed":false,"message":"no friday deploys"}"#,
        )])
        .await;
        let err = review(
            &client,
            &[hook("a", &url, FailPolicy::Ignore)],
            &review_body,
        )
        .await
        .unwrap_err();
        assert!(err.contains("no friday deploys"), "{err}");

        // Unreachable: a port nothing listens on.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/hook", l.local_addr().unwrap())
        };
        let warnings = review(
            &client,
            &[hook("best-effort", &closed, FailPolicy::Ignore)],
            &review_body,
        )
        .await
        .unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            review(
                &client,
                &[hook("strict", &closed, FailPolicy::Fail)],
                &review_body
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn answers_must_be_explicit() {
        let ok = hyper::StatusCode::OK;
        assert_eq!(
            parse_answer(ok, br#"{"allowed":true}"#),
            Ok(Answer::Allowed)
        );
        assert!(parse_answer(ok, b"{}").is_err());
        assert!(parse_answer(ok, b"yes").is_err());
        assert!(
            parse_answer(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                br#"{"allowed":true}"#
            )
            .is_err()
        );
        assert_eq!(
            parse_answer(ok, b"{\"allowed\":false,\"message\":\"a\\u0007b\"}"),
            Ok(Answer::Denied("ab".into()))
        );
    }
}
