#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::proto::{HealthCheckSpec, HealthStatus, ServiceHealth};

/// Tracks health state for all local services.
/// Supports separate liveness (should we restart?), readiness (should we route?),
/// and startup (is it still initializing?) probes.
#[derive(Clone)]
pub struct HealthChecker {
    results: Arc<RwLock<HashMap<String, HealthResult>>>,
}

#[derive(Debug, Clone)]
struct HealthResult {
    /// Liveness status — failures trigger restart.
    liveness: HealthStatus,
    liveness_message: String,
    liveness_success: u32,
    liveness_failure: u32,

    /// Readiness status — failures remove from load balancing.
    readiness: HealthStatus,
    readiness_message: String,
    readiness_success: u32,
    readiness_failure: u32,

    /// Whether the startup probe has passed (suppresses liveness until true).
    startup_passed: bool,

    healthy_threshold: u32,
    unhealthy_threshold: u32,
}

/// Configuration for the three probe types.
pub struct ProbeConfig {
    /// Liveness probe spec (or the unified health check).
    pub liveness: Option<HealthCheckSpec>,
    /// Readiness probe spec (defaults to liveness if not set).
    pub readiness: Option<HealthCheckSpec>,
    /// Startup probe spec (optional).
    pub startup: Option<HealthCheckSpec>,
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start health checking for a service using the unified probe (backwards-compatible).
    pub fn start_checking(&self, service_name: String, instance_id: String, spec: HealthCheckSpec) {
        self.start_checking_probes(
            service_name,
            instance_id,
            ProbeConfig {
                liveness: Some(spec.clone()),
                readiness: Some(spec),
                startup: None,
            },
        );
    }

    /// Start health checking with separate liveness/readiness/startup probes.
    pub fn start_checking_probes(
        &self,
        service_name: String,
        instance_id: String,
        probes: ProbeConfig,
    ) {
        let results = self.results.clone();
        let has_startup = probes.startup.is_some();

        let healthy_threshold = probes
            .liveness
            .as_ref()
            .map(|s| {
                if s.healthy_threshold > 0 {
                    s.healthy_threshold
                } else {
                    3
                }
            })
            .unwrap_or(3);
        let unhealthy_threshold = probes
            .liveness
            .as_ref()
            .map(|s| {
                if s.unhealthy_threshold > 0 {
                    s.unhealthy_threshold
                } else {
                    3
                }
            })
            .unwrap_or(3);

        // Initialize result
        {
            let results = results.clone();
            let key = service_name.clone();
            tokio::spawn(async move {
                results.write().await.insert(
                    key,
                    HealthResult {
                        liveness: HealthStatus::HealthUnknown,
                        liveness_message: "initializing".into(),
                        liveness_success: 0,
                        liveness_failure: 0,
                        readiness: HealthStatus::HealthUnknown,
                        readiness_message: "initializing".into(),
                        readiness_success: 0,
                        readiness_failure: 0,
                        startup_passed: !has_startup,
                        healthy_threshold,
                        unhealthy_threshold,
                    },
                );
            });
        }

        // Startup probe (if configured)
        if let Some(startup_spec) = probes.startup {
            let results = results.clone();
            let svc = service_name.clone();
            let interval = probe_interval(&startup_spec);
            let timeout = probe_timeout(&startup_spec);

            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                loop {
                    tick.tick().await;
                    let check = run_check(&startup_spec, timeout).await;
                    let mut results = results.write().await;
                    if let Some(result) = results.get_mut(&svc) {
                        if check.is_ok() {
                            result.startup_passed = true;
                            tracing::info!(service = %svc, "Startup probe passed");
                            break;
                        }
                    } else {
                        break; // service removed
                    }
                }
            });
        }

        // Liveness probe
        if let Some(liveness_spec) = probes.liveness {
            let results = results.clone();
            let svc = service_name.clone();
            let interval = probe_interval(&liveness_spec);
            let timeout = probe_timeout(&liveness_spec);

            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                loop {
                    tick.tick().await;

                    // Skip liveness checks while startup probe hasn't passed
                    {
                        let r = results.read().await;
                        match r.get(&svc) {
                            Some(result) if !result.startup_passed => continue,
                            None => break,
                            _ => {}
                        }
                    }

                    let check = run_check(&liveness_spec, timeout).await;
                    let mut results = results.write().await;
                    if let Some(result) = results.get_mut(&svc) {
                        update_probe_status(
                            check,
                            &mut result.liveness,
                            &mut result.liveness_message,
                            &mut result.liveness_success,
                            &mut result.liveness_failure,
                            result.healthy_threshold,
                            result.unhealthy_threshold,
                        );
                        tracing::debug!(
                            service = %svc,
                            liveness = ?result.liveness,
                            message = %result.liveness_message,
                            "Liveness check"
                        );
                    } else {
                        break;
                    }
                }
            });
        }

        // Readiness probe
        if let Some(readiness_spec) = probes.readiness {
            let results = results.clone();
            let svc = service_name.clone();
            let interval = probe_interval(&readiness_spec);
            let timeout = probe_timeout(&readiness_spec);

            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                loop {
                    tick.tick().await;
                    let check = run_check(&readiness_spec, timeout).await;
                    let mut results = results.write().await;
                    if let Some(result) = results.get_mut(&svc) {
                        update_probe_status(
                            check,
                            &mut result.readiness,
                            &mut result.readiness_message,
                            &mut result.readiness_success,
                            &mut result.readiness_failure,
                            result.healthy_threshold,
                            result.unhealthy_threshold,
                        );
                        tracing::debug!(
                            service = %svc,
                            readiness = ?result.readiness,
                            message = %result.readiness_message,
                            "Readiness check"
                        );
                    } else {
                        break;
                    }
                }
            });
        }

        tracing::info!(
            service = %service_name,
            instance = %instance_id,
            has_startup = %has_startup,
            "Health checking started (liveness + readiness)"
        );
    }

    /// Stop health checking for a service.
    pub async fn stop_checking(&self, service_name: &str) {
        self.results.write().await.remove(service_name);
    }

    /// Get current health reports for all services.
    /// Reports both liveness (status field) and readiness (readiness field).
    pub async fn reports(&self, node_id: &str) -> Vec<ServiceHealth> {
        let results = self.results.read().await;
        results
            .iter()
            .map(|(name, result)| ServiceHealth {
                service_name: name.clone(),
                instance_id: format!("{}-{}", name, node_id),
                status: result.liveness as i32,
                message: result.liveness_message.clone(),
                checked_at: crate::agent::now_epoch(),
                readiness: result.readiness as i32,
            })
            .collect()
    }

    /// Check if a service is ready to receive traffic.
    pub async fn is_ready(&self, service_name: &str) -> bool {
        let results = self.results.read().await;
        results
            .get(service_name)
            .is_some_and(|r| r.readiness == HealthStatus::Healthy)
    }

    /// Check if a service is alive (not needing restart).
    pub async fn is_alive(&self, service_name: &str) -> bool {
        let results = self.results.read().await;
        results
            .get(service_name)
            .is_some_and(|r| r.liveness == HealthStatus::Healthy)
    }
}

fn probe_interval(spec: &HealthCheckSpec) -> Duration {
    if spec.interval_seconds > 0 {
        Duration::from_secs(spec.interval_seconds as u64)
    } else {
        Duration::from_secs(10)
    }
}

fn probe_timeout(spec: &HealthCheckSpec) -> Duration {
    if spec.timeout_seconds > 0 {
        Duration::from_secs(spec.timeout_seconds as u64)
    } else {
        Duration::from_secs(5)
    }
}

fn update_probe_status(
    check_result: Result<String, String>,
    status: &mut HealthStatus,
    message: &mut String,
    consecutive_success: &mut u32,
    consecutive_failure: &mut u32,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
) {
    match check_result {
        Ok(msg) => {
            *consecutive_success += 1;
            *consecutive_failure = 0;
            *message = msg;
            if *consecutive_success >= healthy_threshold {
                *status = HealthStatus::Healthy;
            }
        }
        Err(msg) => {
            *consecutive_failure += 1;
            *consecutive_success = 0;
            *message = msg;
            if *consecutive_failure >= unhealthy_threshold {
                *status = HealthStatus::Unhealthy;
            }
        }
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
