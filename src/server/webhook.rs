#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

/// Webhook notification configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebhookConfig {
    /// Unique name for this webhook.
    pub name: String,
    /// URL to POST to when events match.
    pub url: String,
    /// Events that trigger this webhook.
    pub events: Vec<String>,
    /// Optional secret for HMAC signature verification.
    pub secret: Option<String>,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    10
}

/// Manages outbound webhook notifications for fleet events.
#[derive(Clone)]
pub struct WebhookDispatcher {
    configs: Arc<RwLock<Vec<WebhookConfig>>>,
}

impl Default for WebhookDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookDispatcher {
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register webhook configurations.
    pub async fn set_webhooks(&self, configs: Vec<WebhookConfig>) {
        tracing::info!(count = configs.len(), "Webhooks configured");
        *self.configs.write().await = configs;
    }

    /// Dispatch an event to all matching webhooks.
    /// Runs asynchronously — failures are logged but don't block the caller.
    pub async fn dispatch(&self, event_type: &str, payload: &serde_json::Value) {
        let configs = self.configs.read().await;
        let matching: Vec<WebhookConfig> = configs
            .iter()
            .filter(|c| c.events.iter().any(|e| e == event_type || e == "*"))
            .cloned()
            .collect();
        drop(configs);

        for config in matching {
            let payload = payload.clone();
            let event_type = event_type.to_string();
            tokio::spawn(async move {
                if let Err(e) = send_webhook(&config, &event_type, &payload).await {
                    tracing::warn!(
                        webhook = %config.name,
                        url = %config.url,
                        error = %e,
                        "Webhook delivery failed"
                    );
                }
            });
        }
    }
}

async fn send_webhook(
    config: &WebhookConfig,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<(), std::io::Error> {
    let body = serde_json::json!({
        "event": event_type,
        "data": payload,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });

    let body_str =
        serde_json::to_string(&body).map_err(|e| std::io::Error::other(e.to_string()))?;

    let timeout = Duration::from_secs(config.timeout_seconds);

    let result = tokio::time::timeout(timeout, async {
        // Use a raw TCP connection + HTTP/1.1 POST to avoid heavy HTTP client dependency
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Parse URL to extract host:port and path
        let url = &config.url;
        let (host_port, path) = parse_http_url(url)?;

        let mut stream = tokio::net::TcpStream::connect(&host_port).await?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_str.len(),
            body_str
        );
        stream.write_all(request.as_bytes()).await?;

        let mut response = vec![0u8; 256];
        let _ = stream.read(&mut response).await?;

        Ok::<(), std::io::Error>(())
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(std::io::Error::other("webhook timeout")),
    }
}

fn parse_http_url(url: &str) -> Result<(String, String), std::io::Error> {
    let url = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::other("only http:// URLs supported for webhooks"))?;
    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{path}");
    Ok((host_port.to_string(), path))
}

/// Call all configured admission webhooks with the given payload.
///
/// POSTs the payload to each webhook URL and expects a JSON response of the form:
/// `{"allowed": true/false, "message": "..."}`.
///
/// If any webhook with `FailPolicy::Fail` rejects (allowed=false) or errors,
/// the request is denied. Webhooks with `FailPolicy::Ignore` are best-effort.
pub async fn call_admission_webhooks(
    webhooks: &[crate::config::AdmissionWebhook],
    payload: &serde_json::Value,
) -> Result<(), String> {
    for webhook in webhooks {
        let result = call_single_admission_webhook(webhook, payload).await;
        match result {
            Ok(()) => {}
            Err(e) => match webhook.fail_policy {
                crate::config::FailPolicy::Fail => {
                    return Err(format!("admission webhook '{}' denied: {e}", webhook.name));
                }
                crate::config::FailPolicy::Ignore => {
                    tracing::warn!(
                        webhook = %webhook.name,
                        error = %e,
                        "Admission webhook failed but fail policy is Ignore"
                    );
                }
            },
        }
    }
    Ok(())
}

async fn call_single_admission_webhook(
    webhook: &crate::config::AdmissionWebhook,
    payload: &serde_json::Value,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let body_str = serde_json::to_string(payload).map_err(|e| e.to_string())?;
    let timeout = Duration::from_secs(webhook.timeout_seconds);

    let result = tokio::time::timeout(timeout, async {
        let (host_port, path) = parse_http_url(&webhook.url).map_err(|e| e.to_string())?;

        let mut stream = tokio::net::TcpStream::connect(&host_port)
            .await
            .map_err(|e| format!("connection failed: {e}"))?;

        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
            body_str.len(),
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| format!("read failed: {e}"))?;

        let response_str = String::from_utf8_lossy(&response);

        // Parse HTTP response — find the body after \r\n\r\n
        let body = response_str
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or(&response_str);

        let parsed: serde_json::Value =
            serde_json::from_str(body).map_err(|e| format!("invalid response JSON: {e}"))?;

        let allowed = parsed
            .get("allowed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let message = parsed
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if allowed {
            Ok(())
        } else {
            Err(message)
        }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err("webhook request timed out".to_string()),
    }
}
