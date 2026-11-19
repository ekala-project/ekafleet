//! Liveness, readiness and startup probes of the services this agent runs.
//!
//! Each service gets one set of probe loops per probe configuration: a
//! desired state that repeats the configuration leaves them running, a
//! changed one replaces them, and a service that leaves the node stops them.
//! A liveness probe that turns unhealthy asks for a restart of the service.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::proto::{HealthCheckSpec, HealthStatus, ServiceHealth, ServiceSpec};

/// Tracks health state for all local services.
#[derive(Clone, Default)]
pub struct HealthChecker {
    results: Arc<RwLock<HashMap<String, HealthResult>>>,
    running: Arc<Mutex<HashMap<String, Running>>>,
    restarts: Option<mpsc::UnboundedSender<String>>,
}

struct Running {
    probes: ProbeConfig,
    cancel: CancellationToken,
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

    /// Whether the startup probe has passed (suppresses liveness and
    /// readiness until true).
    startup_passed: bool,
}

impl HealthResult {
    fn new(startup_passed: bool) -> Self {
        Self {
            liveness: HealthStatus::HealthUnknown,
            liveness_message: "initializing".into(),
            liveness_success: 0,
            liveness_failure: 0,
            readiness: HealthStatus::HealthUnknown,
            readiness_message: "initializing".into(),
            readiness_success: 0,
            readiness_failure: 0,
            startup_passed,
        }
    }
}

/// The probes of one service and the address they check.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeConfig {
    /// Address the service listens on: loopback, or its namespace IP.
    pub host: String,
    /// Liveness probe spec (or the unified health check).
    pub liveness: Option<HealthCheckSpec>,
    /// Readiness probe spec (defaults to liveness if not set).
    pub readiness: Option<HealthCheckSpec>,
    /// Startup probe spec (optional).
    pub startup: Option<HealthCheckSpec>,
}

impl ProbeConfig {
    /// The probes `spec` declares: separate probes take precedence over the
    /// unified health check, and readiness falls back to liveness. `None`
    /// when it declares none.
    pub fn for_service(spec: &ServiceSpec) -> Option<Self> {
        let liveness = spec
            .liveness_probe
            .clone()
            .or_else(|| spec.health_check.clone());
        let readiness = spec
            .readiness_probe
            .clone()
            .or_else(|| spec.health_check.clone())
            .or_else(|| liveness.clone());
        let startup = spec.startup_probe.clone();
        if liveness.is_none() && readiness.is_none() && startup.is_none() {
            return None;
        }
        let host = if !crate::agent::netns::is_default_namespace(&spec.namespace)
            && !spec.namespace_ip.is_empty()
        {
            spec.namespace_ip.clone()
        } else {
            "127.0.0.1".into()
        };
        Some(Self {
            host,
            liveness,
            readiness,
            startup,
        })
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Startup,
    Liveness,
    Readiness,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Send the name of each service whose liveness probe turns unhealthy
    /// to `restarts`.
    pub fn with_restarts(mut self, restarts: mpsc::UnboundedSender<String>) -> Self {
        self.restarts = Some(restarts);
        self
    }

    /// Probe `service` with `probes`, unless it already is.
    pub async fn ensure(&self, service: &str, probes: ProbeConfig) {
        let cancel = {
            let mut running = self.running.lock().unwrap();
            if running.get(service).is_some_and(|r| r.probes == probes) {
                return;
            }
            let cancel = CancellationToken::new();
            if let Some(old) = running.insert(
                service.to_string(),
                Running {
                    probes: probes.clone(),
                    cancel: cancel.clone(),
                },
            ) {
                old.cancel.cancel();
            }
            cancel
        };
        self.results.write().await.insert(
            service.to_string(),
            HealthResult::new(probes.startup.is_none()),
        );
        let has_startup = probes.startup.is_some();
        for (kind, spec) in [
            (Kind::Startup, probes.startup),
            (Kind::Liveness, probes.liveness),
            (Kind::Readiness, probes.readiness),
        ] {
            if let Some(spec) = spec {
                tokio::spawn(self.clone().probe_loop(
                    service.to_string(),
                    probes.host.clone(),
                    kind,
                    spec,
                    has_startup,
                    cancel.clone(),
                ));
            }
        }
        tracing::info!(service, has_startup, "Health checking started");
    }

    /// Stop probing every service `keep` rejects.
    pub async fn retain(&self, keep: impl Fn(&str) -> bool) {
        let stopped: Vec<String> = {
            let mut running = self.running.lock().unwrap();
            let stopped: Vec<String> = running.keys().filter(|s| !keep(s)).cloned().collect();
            for name in &stopped {
                if let Some(r) = running.remove(name) {
                    r.cancel.cancel();
                }
            }
            stopped
        };
        let mut results = self.results.write().await;
        results.retain(|name, _| keep(name));
        for name in stopped {
            tracing::info!(service = %name, "Health checking stopped");
        }
    }

    /// Stop health checking for a service.
    pub async fn stop_checking(&self, service_name: &str) {
        self.retain(|name| name != service_name).await;
    }

    async fn probe_loop(
        self,
        svc: String,
        host: String,
        kind: Kind,
        spec: HealthCheckSpec,
        has_startup: bool,
        cancel: CancellationToken,
    ) {
        let timeout = probe_timeout(&spec);
        let healthy_threshold = threshold(spec.healthy_threshold);
        let unhealthy_threshold = threshold(spec.unhealthy_threshold);
        let mut tick = tokio::time::interval(probe_interval(&spec));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tick.tick() => {}
            }
            // Startup runs until it passes (again after each restart); the
            // others wait for it.
            let started = match self.results.read().await.get(&svc) {
                Some(r) => r.startup_passed,
                None => return,
            };
            if started == (kind == Kind::Startup) {
                continue;
            }

            let check = tokio::select! {
                _ = cancel.cancelled() => return,
                check = run_check(&spec, &host, timeout) => check,
            };
            let mut results = self.results.write().await;
            // A replaced configuration may have reset the result meanwhile.
            if cancel.is_cancelled() {
                return;
            }
            let Some(result) = results.get_mut(&svc) else {
                return;
            };
            match kind {
                Kind::Startup => {
                    if check.is_ok() {
                        result.startup_passed = true;
                        tracing::info!(service = %svc, "Startup probe passed");
                    }
                }
                Kind::Readiness => {
                    update_probe_status(
                        check,
                        &mut result.readiness,
                        &mut result.readiness_message,
                        &mut result.readiness_success,
                        &mut result.readiness_failure,
                        healthy_threshold,
                        unhealthy_threshold,
                    );
                }
                Kind::Liveness => {
                    update_probe_status(
                        check,
                        &mut result.liveness,
                        &mut result.liveness_message,
                        &mut result.liveness_success,
                        &mut result.liveness_failure,
                        healthy_threshold,
                        unhealthy_threshold,
                    );
                    // Each run of `unhealthy_threshold` failures restarts it.
                    if result.liveness_failure == unhealthy_threshold
                        && let Some(restarts) = &self.restarts
                    {
                        tracing::warn!(
                            service = %svc,
                            message = %result.liveness_message,
                            "Liveness probe failed; restarting the service"
                        );
                        let _ = restarts.send(svc.clone());
                        // Start over: the startup probe guards the restart
                        // as it guarded the first start.
                        let message = std::mem::take(&mut result.liveness_message);
                        *result = HealthResult::new(!has_startup);
                        result.liveness = HealthStatus::Unhealthy;
                        result.liveness_message = format!("restarted: {message}");
                    }
                }
            }
        }
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

fn threshold(configured: u32) -> u32 {
    if configured > 0 { configured } else { 3 }
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
async fn run_check(
    spec: &HealthCheckSpec,
    host: &str,
    timeout: Duration,
) -> Result<String, String> {
    use crate::proto::health_check_spec::Probe;

    match &spec.probe {
        Some(Probe::Http(http)) => check_http(host, http.port as u16, &http.path, timeout).await,
        Some(Probe::Tcp(tcp)) => check_tcp(host, tcp.port as u16, timeout).await,
        Some(Probe::Exec(exec)) => check_exec(&exec.command, timeout).await,
        Some(Probe::Grpc(grpc)) => check_grpc(host, grpc.port as u16, &grpc.service, timeout).await,
        None => Err("no probe configured".into()),
    }
}

async fn check_http(
    host: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> Result<String, String> {
    let url = format!("http://{host}:{port}{path}");

    let result = tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string())?;

        // Simple HTTP/1.1 GET
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");

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
            // Accept any 2xx status code as healthy
            if status_line.contains(" 2") {
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

async fn check_tcp(host: &str, port: u16, timeout: Duration) -> Result<String, String> {
    match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => Ok(format!("tcp:{port} → connected")),
        Ok(Err(e)) => Err(format!("tcp:{port} → {e}")),
        Err(_) => Err(format!("tcp:{port} → timeout")),
    }
}

/// Check gRPC health by establishing an HTTP/2 connection via tonic.
/// This verifies that the service is accepting HTTP/2 connections (required
/// for gRPC), which is a stronger signal than a raw TCP connect.
async fn check_grpc(
    host: &str,
    port: u16,
    _service: &str,
    timeout: Duration,
) -> Result<String, String> {
    let endpoint = format!("http://{host}:{port}");
    let result = tokio::time::timeout(timeout, async {
        tonic::transport::Endpoint::from_shared(endpoint)
            .map_err(|e| format!("grpc:{port} → bad endpoint: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("grpc:{port} → connect failed: {e}"))?;
        Ok::<_, String>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(format!("grpc:{port} → h2 connected")),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(format!("grpc:{port} → timeout")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::health_check_spec::Probe;

    fn tcp(port: u16) -> HealthCheckSpec {
        HealthCheckSpec {
            probe: Some(Probe::Tcp(crate::proto::TcpProbe { port: port.into() })),
            interval_seconds: 1,
            timeout_seconds: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        }
    }

    /// A port nothing listens on.
    fn closed_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn probes(liveness: Option<HealthCheckSpec>, startup: Option<HealthCheckSpec>) -> ProbeConfig {
        ProbeConfig {
            host: "127.0.0.1".into(),
            readiness: liveness.clone(),
            liveness,
            startup,
        }
    }

    async fn wait_for(checker: &HealthChecker, f: impl Fn(&HealthResult) -> bool) {
        for _ in 0..100 {
            if checker.results.read().await.get("web").is_some_and(&f) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("condition never held: {:?}", checker.results.read().await);
    }

    #[test]
    fn separate_probes_take_precedence_and_namespaced_services_are_probed_on_their_ip() {
        let mut spec = ServiceSpec {
            name: "web".into(),
            health_check: Some(tcp(1)),
            ..Default::default()
        };
        let p = ProbeConfig::for_service(&spec).unwrap();
        assert_eq!((p.liveness, p.readiness), (Some(tcp(1)), Some(tcp(1))));
        assert_eq!(p.host, "127.0.0.1");

        spec.liveness_probe = Some(tcp(2));
        spec.startup_probe = Some(tcp(3));
        spec.health_check = None;
        spec.namespace = "tenant".into();
        spec.namespace_ip = "10.200.0.5".into();
        let p = ProbeConfig::for_service(&spec).unwrap();
        assert_eq!(p.liveness, Some(tcp(2)));
        assert_eq!(
            p.readiness,
            Some(tcp(2)),
            "readiness falls back to liveness"
        );
        assert_eq!(p.startup, Some(tcp(3)));
        assert_eq!(p.host, "10.200.0.5");

        spec.liveness_probe = None;
        spec.startup_probe = None;
        assert!(ProbeConfig::for_service(&spec).is_none());
    }

    #[tokio::test]
    async fn repeating_the_configuration_keeps_the_probes_and_their_results() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let checker = HealthChecker::new();
        checker.ensure("web", probes(Some(tcp(port)), None)).await;
        wait_for(&checker, |r| {
            r.liveness == HealthStatus::Healthy && r.readiness == HealthStatus::Healthy
        })
        .await;

        // The same configuration again (every desired state repeats it).
        checker.ensure("web", probes(Some(tcp(port)), None)).await;
        assert!(checker.is_ready("web").await);
        assert_eq!(checker.running.lock().unwrap().len(), 1);

        // A new configuration starts over.
        checker
            .ensure("web", probes(Some(tcp(closed_port())), None))
            .await;
        assert!(!checker.is_ready("web").await);

        checker.retain(|_| false).await;
        assert!(checker.reports("n1").await.is_empty());
        assert!(checker.running.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_liveness_restarts_the_service_unless_startup_has_not_passed() {
        let (tx, mut restarts) = mpsc::unbounded_channel();
        let checker = HealthChecker::new().with_restarts(tx);

        // Still starting: liveness waits, nothing restarts.
        checker
            .ensure(
                "web",
                probes(Some(tcp(closed_port())), Some(tcp(closed_port()))),
            )
            .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(1500), restarts.recv())
                .await
                .is_err()
        );
        assert_eq!(
            checker.results.read().await["web"].liveness,
            HealthStatus::HealthUnknown
        );

        // Without a startup probe, each failed run restarts it.
        checker
            .ensure("web", probes(Some(tcp(closed_port())), None))
            .await;
        for _ in 0..2 {
            let restarted = tokio::time::timeout(Duration::from_secs(5), restarts.recv())
                .await
                .expect("no restart")
                .unwrap();
            assert_eq!(restarted, "web");
        }
        wait_for(&checker, |r| r.liveness_message.starts_with("restarted")).await;

        // Stopped probes restart nothing.
        checker.stop_checking("web").await;
        while restarts.try_recv().is_ok() {}
        assert!(
            tokio::time::timeout(Duration::from_millis(1500), restarts.recv())
                .await
                .is_err()
        );
    }
}
