#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::proto::{HealthCheckSpec, HealthStatus, ServiceHealth};

/// Tracks health state for all local services.
#[derive(Clone)]
pub struct HealthChecker {
    results: Arc<RwLock<HashMap<String, HealthResult>>>,
}

#[derive(Debug, Clone)]
struct HealthResult {
    status: HealthStatus,
    message: String,
    consecutive_success: u32,
    consecutive_failure: u32,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start health checking for a service. Spawns a background task.
    pub fn start_checking(&self, service_name: String, instance_id: String, spec: HealthCheckSpec) {
        let results = self.results.clone();

        let interval = if spec.interval_seconds > 0 {
            Duration::from_secs(spec.interval_seconds as u64)
        } else {
            Duration::from_secs(10)
        };

        let timeout = if spec.timeout_seconds > 0 {
            Duration::from_secs(spec.timeout_seconds as u64)
        } else {
            Duration::from_secs(5)
        };

        let healthy_threshold = if spec.healthy_threshold > 0 {
            spec.healthy_threshold
        } else {
            3
        };

        let unhealthy_threshold = if spec.unhealthy_threshold > 0 {
            spec.unhealthy_threshold
        } else {
            3
        };

        // Initialize result
        {
            let results = results.clone();
            let key = service_name.clone();
            tokio::spawn(async move {
                results.write().await.insert(
                    key,
                    HealthResult {
                        status: HealthStatus::HealthUnknown,
                        message: "initializing".into(),
                        consecutive_success: 0,
                        consecutive_failure: 0,
                        healthy_threshold,
                        unhealthy_threshold,
                    },
                );
            });
        }

        let svc = service_name.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                let check_result = run_check(&spec, timeout).await;

                let mut results = results.write().await;
                if let Some(result) = results.get_mut(&svc) {
                    match check_result {
                        Ok(msg) => {
                            result.consecutive_success += 1;
                            result.consecutive_failure = 0;
                            result.message = msg;
                            if result.consecutive_success >= result.healthy_threshold {
                                result.status = HealthStatus::Healthy;
                            }
                        }
                        Err(msg) => {
                            result.consecutive_failure += 1;
                            result.consecutive_success = 0;
                            result.message = msg;
                            if result.consecutive_failure >= result.unhealthy_threshold {
                                result.status = HealthStatus::Unhealthy;
                            }
                        }
                    }

                    tracing::debug!(
                        service = %svc,
                        status = ?result.status,
                        message = %result.message,
                        "Health check"
                    );
                }
            }
        });

        tracing::info!(
            service = %service_name,
            instance = %instance_id,
            interval = ?interval,
            "Health checking started"
        );
    }

    /// Stop health checking for a service.
    pub async fn stop_checking(&self, service_name: &str) {
        self.results.write().await.remove(service_name);
    }

    /// Get current health reports for all services.
    pub async fn reports(&self, node_id: &str) -> Vec<ServiceHealth> {
        let results = self.results.read().await;
        results
            .iter()
            .map(|(name, result)| ServiceHealth {
                service_name: name.clone(),
                instance_id: format!("{}-{}", name, node_id),
                status: result.status as i32,
                message: result.message.clone(),
                checked_at: crate::agent::now_epoch(),
            })
            .collect()
    }
}

/// Execute a single health check probe.
async fn run_check(spec: &HealthCheckSpec, timeout: Duration) -> Result<String, String> {
    use crate::proto::health_check_spec::Probe;

    match &spec.probe {
        Some(Probe::Http(http)) => check_http(http.port as u16, &http.path, timeout).await,
        Some(Probe::Tcp(tcp)) => check_tcp(tcp.port as u16, timeout).await,
        Some(Probe::Exec(exec)) => check_exec(&exec.command, timeout).await,
        None => Err("no probe configured".into()),
    }
}

async fn check_http(port: u16, path: &str, timeout: Duration) -> Result<String, String> {
    let url = format!("http://127.0.0.1:{port}{path}");

    let result = tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .map_err(|e| e.to_string())?;

        // Simple HTTP/1.1 GET
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");

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

        let response_str = String::from_utf8_lossy(&response);
        if let Some(status_line) = response_str.lines().next() {
            if status_line.contains("200") || status_line.contains("204") {
                Ok(format!("{url} → {status_line}"))
            } else {
                Err(format!("{url} → {status_line}"))
            }
        } else {
            Err(format!("{url} → empty response"))
        }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(format!("{url} → timeout")),
    }
}

async fn check_tcp(port: u16, timeout: Duration) -> Result<String, String> {
    let addr = format!("127.0.0.1:{port}");
    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Ok(format!("tcp:{port} → connected")),
        Ok(Err(e)) => Err(format!("tcp:{port} → {e}")),
        Err(_) => Err(format!("tcp:{port} → timeout")),
    }
}

async fn check_exec(command: &[String], timeout: Duration) -> Result<String, String> {
    if command.is_empty() {
        return Err("empty command".into());
    }

    let result = tokio::time::timeout(timeout, async {
        let output = tokio::process::Command::new(&command[0])
            .args(&command[1..])
            .output()
            .await
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            Ok("exit 0".into())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("exit {} — {}", output.status, stderr.trim()))
        }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err("exec timeout".into()),
    }
}
