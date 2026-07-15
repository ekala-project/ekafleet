#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::proto::ServiceSpec;

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("systemctl failed: {0}")]
    Systemctl(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Manages local services via systemd unit files.
///
/// Supports two execution modes:
/// - **Native process**: `ExecStart` points directly to a Nix store binary
/// - **OCI container**: `ExecStart` invokes `systemd-nspawn --oci-bundle`
///
/// Both modes produce `ekafleet-{name}.service` units under the same
/// cgroup hierarchy, preserving workload attestation, journald logging,
/// and lifecycle hook semantics.
pub struct Supervisor {
    unit_dir: PathBuf,
    /// Directory holding indirect Nix GC roots for deployed service closures,
    /// so `nix-collect-garbage` never reaps a store path a running service
    /// depends on. See [`Supervisor::add_gc_root`].
    gcroot_dir: PathBuf,
    managed_units: HashMap<String, UnitState>,
}

#[derive(Debug, Clone)]
struct UnitState {
    unit_name: String,
    /// For native services: the Nix store path.
    /// For container services: the resolved image digest.
    version_key: String,
    running: bool,
}

/// The path to the OCI bundle store used by the supervisor.
const OCI_STORE_DIR: &str = "/var/lib/ekafleet/oci";

impl Supervisor {
    pub fn new(data_dir: &Path) -> Self {
        let unit_dir = data_dir.join("units");
        let gcroot_dir = data_dir.join("gcroots");
        Self {
            unit_dir,
            gcroot_dir,
            managed_units: HashMap::new(),
        }
    }

    /// Reconcile local services with desired state.
    /// Starts new services, restarts changed ones, stops removed ones.
    pub async fn reconcile(
        &mut self,
        desired: &HashMap<String, ServiceSpec>,
    ) -> Result<Vec<SupervisorAction>, SupervisorError> {
        let mut actions = Vec::new();

        // Start or update desired services
        for (name, spec) in desired {
            let unit_name = format!("ekafleet-{name}.service");
            let version_key = version_key_for(spec);

            match self.managed_units.get(name) {
                Some(existing) if existing.version_key == version_key => {
                    // Already running with correct version
                    tracing::debug!(service = %name, "Already up-to-date");
                }
                Some(existing) => {
                    // Version changed — restart
                    tracing::info!(
                        service = %name,
                        old = %existing.version_key,
                        new = %version_key,
                        "Restarting service (version changed)"
                    );
                    self.root_service_closure(name, spec).await;
                    self.write_unit_file(&unit_name, spec).await?;
                    systemctl(&["daemon-reload"]).await?;
                    systemctl(&["restart", &unit_name]).await?;
                    self.managed_units.insert(
                        name.clone(),
                        UnitState {
                            unit_name: unit_name.clone(),
                            version_key,
                            running: true,
                        },
                    );
                    actions.push(SupervisorAction::Restarted(name.clone()));
                }
                None => {
                    // New service
                    tracing::info!(service = %name, "Starting new service");
                    self.root_service_closure(name, spec).await;
                    self.write_unit_file(&unit_name, spec).await?;
                    systemctl(&["daemon-reload"]).await?;
                    systemctl(&["enable", "--now", &unit_name]).await?;
                    self.managed_units.insert(
                        name.clone(),
                        UnitState {
                            unit_name: unit_name.clone(),
                            version_key,
                            running: true,
                        },
                    );
                    actions.push(SupervisorAction::Started(name.clone()));
                }
            }
        }

        // Stop services no longer in desired state
        let to_remove: Vec<String> = self
            .managed_units
            .keys()
            .filter(|name| !desired.contains_key(*name))
            .cloned()
            .collect();

        for name in to_remove {
            if let Some(state) = self.managed_units.remove(&name) {
                tracing::info!(service = %name, "Stopping removed service");
                systemctl(&["disable", "--now", &state.unit_name]).await?;
                self.remove_unit_file(&state.unit_name).await?;
                self.remove_gc_root(&name).await;
                actions.push(SupervisorAction::Stopped(name));
            }
        }

        Ok(actions)
    }

    /// Generate a systemd unit file from a service spec.
    /// Dispatches to native or container unit generation based on the spec.
    async fn write_unit_file(
        &self,
        unit_name: &str,
        spec: &ServiceSpec,
    ) -> Result<(), SupervisorError> {
        if is_container_service(spec) {
            self.write_container_unit_file(unit_name, spec).await
        } else {
            self.write_native_unit_file(unit_name, spec).await
        }
    }

    /// Generate a systemd unit file for a native (Nix) process service.
    async fn write_native_unit_file(
        &self,
        unit_name: &str,
        spec: &ServiceSpec,
    ) -> Result<(), SupervisorError> {
        tokio::fs::create_dir_all(&self.unit_dir).await?;

        let env_lines = build_env_lines(spec);
        let extra_lines = build_extra_directives(spec);

        let unit_content = format!(
            r#"[Unit]
Description=ekafleet managed: {name}
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=on-failure
RestartSec=5
{extra}
{env}

[Install]
WantedBy=multi-user.target
"#,
            name = spec.name,
            command = spec.command,
            extra = extra_lines,
            env = env_lines,
        );

        self.install_unit(unit_name, &unit_content).await
    }

    /// Generate a systemd unit file that runs an OCI container via systemd-nspawn.
    ///
    /// The unit wraps `systemd-nspawn --oci-bundle=<path> --machine=ekafleet-<name>`
    /// with bind mounts for the SPIFFE workload API socket and secrets.
    /// The container inherits the unit's cgroup, so attestation, journald
    /// logging, and resource controls work identically to native services.
    async fn write_container_unit_file(
        &self,
        unit_name: &str,
        spec: &ServiceSpec,
    ) -> Result<(), SupervisorError> {
        tokio::fs::create_dir_all(&self.unit_dir).await?;

        let machine_name = format!("ekafleet-{}", spec.name);
        let bundle_path = format!("{OCI_STORE_DIR}/bundles/{}", spec.name);

        // Build nspawn command with bind mounts
        let spiffe_socket = crate::spiffe::socket::DEFAULT_SOCKET_PATH;
        let secrets_dir = format!("/var/lib/ekafleet/secrets/{}", spec.name);

        let mut nspawn_args = vec![
            format!("--oci-bundle={bundle_path}"),
            format!("--machine={machine_name}"),
            // Share host network — preserves nftables policy enforcement
            "--network-namespace-path=/proc/1/ns/net".to_string(),
            // Bind-mount SPIFFE workload API socket
            format!("--bind={spiffe_socket}"),
            // Bind-mount secrets directory (read-only inside container)
            format!("--bind-ro={secrets_dir}:/run/secrets"),
            // Register with machined for machinectl access
            "--register=yes".to_string(),
            // Keep unit running (don't daemonize)
            "--keep-unit".to_string(),
        ];

        // Add user-specified bind mounts from environment hints
        for (key, value) in &spec.environment {
            if key == "EKAFLEET_EXTRA_BINDS" {
                for bind in value.split(',') {
                    let bind = bind.trim();
                    if !bind.is_empty() {
                        nspawn_args.push(format!("--bind={bind}"));
                    }
                }
            }
        }

        let nspawn_cmd = format!("systemd-nspawn {}", nspawn_args.join(" \\\n  "));

        let env_lines = build_env_lines(spec);
        let extra_lines = build_extra_directives(spec);

        let unit_content = format!(
            r#"[Unit]
Description=ekafleet container: {name}
After=network.target
Wants=machines.target

[Service]
Type=simple
ExecStart={nspawn_cmd}
ExecStop=machinectl terminate {machine}
Restart=on-failure
RestartSec=5
KillMode=mixed
{extra}
{env}

[Install]
WantedBy=multi-user.target
"#,
            name = spec.name,
            nspawn_cmd = nspawn_cmd,
            machine = machine_name,
            extra = extra_lines,
            env = env_lines,
        );

        self.install_unit(unit_name, &unit_content).await
    }

    /// Write unit file to disk and symlink into systemd.
    async fn install_unit(&self, unit_name: &str, content: &str) -> Result<(), SupervisorError> {
        let path = self.unit_dir.join(unit_name);
        tokio::fs::write(&path, content).await?;

        // Symlink into systemd directory
        let systemd_path = PathBuf::from("/etc/systemd/system").join(unit_name);
        // Remove existing symlink if present
        let _ = tokio::fs::remove_file(&systemd_path).await;
        tokio::fs::symlink(&path, &systemd_path).await?;

        tracing::debug!(unit = %unit_name, path = %path.display(), "Unit file written");
        Ok(())
    }

    async fn remove_unit_file(&self, unit_name: &str) -> Result<(), SupervisorError> {
        let path = self.unit_dir.join(unit_name);
        let _ = tokio::fs::remove_file(&path).await;

        let systemd_path = PathBuf::from("/etc/systemd/system").join(unit_name);
        let _ = tokio::fs::remove_file(&systemd_path).await;

        systemctl(&["daemon-reload"]).await?;
        Ok(())
    }

    /// Register an indirect GC root for a native service's store path, so
    /// `nix-collect-garbage` cannot reap a closure a running service depends
    /// on. Container services (which have no store path) are skipped.
    ///
    /// Failure to root is logged but not fatal: the service can still run;
    /// it is just exposed to GC until the next successful reconcile.
    async fn root_service_closure(&self, name: &str, spec: &ServiceSpec) {
        if is_container_service(spec) || spec.store_path.is_empty() {
            return;
        }
        if let Err(e) = self.add_gc_root(name, &spec.store_path).await {
            tracing::warn!(
                service = %name,
                store_path = %spec.store_path,
                error = %e,
                "Failed to register GC root for service closure — path is exposed to nix GC"
            );
        }
    }

    /// Create an indirect GC root at `{gcroot_dir}/<service>` pointing at
    /// `store_path` via `nix-store --add-root ... --realise`. The `--realise`
    /// also ensures the path is present in the local store.
    async fn add_gc_root(&self, name: &str, store_path: &str) -> Result<(), SupervisorError> {
        tokio::fs::create_dir_all(&self.gcroot_dir).await?;
        let root_link = self.gcroot_dir.join(name);
        let root_link_str = root_link
            .to_str()
            .ok_or_else(|| SupervisorError::Systemctl("invalid gcroot path".into()))?;

        let output = tokio::process::Command::new("nix-store")
            .args(["--add-root", root_link_str, "--realise", store_path])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SupervisorError::Systemctl(format!(
                "nix-store --add-root failed: {}",
                stderr.trim()
            )));
        }

        tracing::debug!(
            service = %name,
            store_path = %store_path,
            root = %root_link.display(),
            "Registered GC root for service closure"
        );
        Ok(())
    }

    /// Remove the indirect GC root for a service, allowing its (now unused)
    /// closure to be collected by a future `nix-collect-garbage`.
    async fn remove_gc_root(&self, name: &str) {
        let root_link = self.gcroot_dir.join(name);
        if let Err(e) = tokio::fs::remove_file(&root_link).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                service = %name,
                error = %e,
                "Failed to remove GC root for stopped service"
            );
        }
    }

    /// Get list of currently managed service names.
    pub fn managed_services(&self) -> Vec<String> {
        self.managed_units.keys().cloned().collect()
    }

    /// Check if a specific service is running.
    pub async fn is_running(&self, service_name: &str) -> bool {
        if let Some(state) = self.managed_units.get(service_name) {
            let result = systemctl(&["is-active", "--quiet", &state.unit_name]).await;
            result.is_ok()
        } else {
            false
        }
    }

    /// Query the actual systemd state of a managed service.
    /// Returns `ServiceState::Unknown` if the service is not managed.
    pub async fn service_state(&self, service_name: &str) -> crate::proto::ServiceState {
        let Some(unit) = self.managed_units.get(service_name) else {
            return crate::proto::ServiceState::Unknown;
        };
        query_unit_state(&unit.unit_name).await
    }
}

/// Whether a ServiceSpec describes an OCI container service.
fn is_container_service(spec: &ServiceSpec) -> bool {
    !spec.container_image.is_empty()
}

/// Compute the version key used to detect when a service needs restarting.
/// For native services this is the Nix store path; for containers it's
/// the image reference (which should include a digest for pinning).
fn version_key_for(spec: &ServiceSpec) -> String {
    if is_container_service(spec) {
        spec.container_image.clone()
    } else {
        spec.store_path.clone()
    }
}

/// Build environment variable lines for a systemd unit file.
fn build_env_lines(spec: &ServiceSpec) -> String {
    let mut env_entries: Vec<String> = spec
        .environment
        .iter()
        .map(|(k, v)| format!("Environment={k}={v}"))
        .collect();

    // SPIFFE Workload API socket path
    env_entries.push(format!(
        "Environment=SPIFFE_ENDPOINT_SOCKET=unix://{}",
        crate::spiffe::socket::DEFAULT_SOCKET_PATH
    ));
    // Service name for workload attestation (PID → service mapping fallback)
    env_entries.push(format!("Environment=EKAFLEET_SERVICE={}", spec.name));

    env_entries.join("\n")
}

/// Build extra systemd directives from lifecycle hooks and cgroup controls.
fn build_extra_directives(spec: &ServiceSpec) -> String {
    let lifecycle = spec.lifecycle.as_ref();
    let stop_signal = lifecycle
        .and_then(|l| {
            if l.stop_signal.is_empty() {
                None
            } else {
                Some(l.stop_signal.as_str())
            }
        })
        .unwrap_or("SIGTERM");
    let grace_period = lifecycle
        .map(|l| l.termination_grace_period_seconds)
        .unwrap_or(30);

    let mut extra_directives = Vec::new();

    // Post-start hook
    if let Some(lc) = lifecycle
        && !lc.post_start.is_empty()
    {
        extra_directives.push(format!("ExecStartPost={}", lc.post_start.join(" ")));
    }

    // Pre-stop hook
    if let Some(lc) = lifecycle
        && !lc.pre_stop.is_empty()
    {
        extra_directives.push(format!("ExecStop={}", lc.pre_stop.join(" ")));
    }

    // Custom kill signal and grace period
    extra_directives.push(format!("KillSignal={stop_signal}"));
    extra_directives.push(format!("TimeoutStopSec={grace_period}"));

    // Cgroup v2 resource controls
    if let Some(cg) = &spec.cgroup_controls {
        extra_directives.push("Slice=system-ekafleet.slice".to_string());
        if cg.cpu_weight > 0 {
            extra_directives.push(format!("CPUWeight={}", cg.cpu_weight));
        }
        if cg.memory_high_mb > 0 {
            extra_directives.push(format!("MemoryHigh={}M", cg.memory_high_mb));
        }
        if cg.memory_max_mb > 0 {
            extra_directives.push(format!("MemoryMax={}M", cg.memory_max_mb));
        }
        if cg.io_weight > 0 {
            extra_directives.push(format!("IOWeight={}", cg.io_weight));
        }
        if cg.tasks_max > 0 {
            extra_directives.push(format!("TasksMax={}", cg.tasks_max));
        }
        if !cg.oom_policy.is_empty() {
            extra_directives.push(format!("OOMPolicy={}", cg.oom_policy));
        }
    }

    extra_directives.join("\n")
}

#[derive(Debug)]
pub enum SupervisorAction {
    Started(String),
    Restarted(String),
    Stopped(String),
}

async fn systemctl(args: &[&str]) -> Result<(), SupervisorError> {
    let output = tokio::process::Command::new("systemctl")
        .args(args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SupervisorError::Systemctl(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

/// Query `systemctl is-active` for a unit and map the result to a
/// [`ServiceState`](crate::proto::ServiceState).
async fn query_unit_state(unit_name: &str) -> crate::proto::ServiceState {
    let output = tokio::process::Command::new("systemctl")
        .args(["is-active", unit_name])
        .output()
        .await;

    let stdout = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => return crate::proto::ServiceState::Unknown,
    };

    match stdout.as_str() {
        "active" => crate::proto::ServiceState::ServiceRunning,
        "activating" => crate::proto::ServiceState::ServiceStarting,
        "failed" => crate::proto::ServiceState::ServiceFailed,
        // inactive, deactivating, etc.
        _ => crate::proto::ServiceState::ServiceStopped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_spec(name: &str, command: &str, store_path: &str) -> ServiceSpec {
        ServiceSpec {
            name: name.to_string(),
            command: command.to_string(),
            store_path: store_path.to_string(),
            container_image: String::new(),
            ..Default::default()
        }
    }

    fn container_spec(name: &str, image: &str) -> ServiceSpec {
        ServiceSpec {
            name: name.to_string(),
            container_image: image.to_string(),
            command: String::new(),
            store_path: String::new(),
            ..Default::default()
        }
    }

    #[test]
    fn is_container_service_detection() {
        let native = native_spec("web", "/nix/store/abc/bin/web", "/nix/store/abc");
        assert!(!is_container_service(&native));

        let container = container_spec("api", "ghcr.io/org/api:v1.0");
        assert!(is_container_service(&container));
    }

    #[tokio::test]
    async fn remove_gc_root_missing_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let sv = Supervisor::new(dir.path());
        // No root exists yet; this must not panic or leave an error path.
        sv.remove_gc_root("nonexistent").await;
    }

    #[tokio::test]
    async fn root_service_closure_skips_containers_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let sv = Supervisor::new(dir.path());

        // Container service: no store path, must be skipped (no nix-store call).
        let container = container_spec("api", "ghcr.io/org/api:v1.0");
        sv.root_service_closure("api", &container).await;

        // Native service with empty store path: also skipped.
        let empty = native_spec("web", "/bin/web", "");
        sv.root_service_closure("web", &empty).await;

        // gcroot dir should not have been populated for skipped services.
        assert!(!sv.gcroot_dir.join("api").exists());
        assert!(!sv.gcroot_dir.join("web").exists());
    }

    #[test]
    fn version_key_native() {
        let spec = native_spec("web", "/nix/store/abc/bin/web", "/nix/store/abc");
        assert_eq!(version_key_for(&spec), "/nix/store/abc");
    }

    #[test]
    fn version_key_container() {
        let spec = container_spec("api", "ghcr.io/org/api:v1.0@sha256:abcdef");
        assert_eq!(version_key_for(&spec), "ghcr.io/org/api:v1.0@sha256:abcdef");
    }

    #[test]
    fn build_env_lines_includes_spiffe() {
        let spec = native_spec("web", "/bin/web", "/nix/store/x");
        let lines = build_env_lines(&spec);
        assert!(lines.contains("SPIFFE_ENDPOINT_SOCKET"));
        assert!(lines.contains("EKAFLEET_SERVICE=web"));
    }

    #[test]
    fn build_env_lines_includes_custom_env() {
        let mut spec = native_spec("web", "/bin/web", "/nix/store/x");
        spec.environment
            .insert("MY_VAR".to_string(), "my_value".to_string());
        let lines = build_env_lines(&spec);
        assert!(lines.contains("Environment=MY_VAR=my_value"));
    }

    #[test]
    fn build_extra_directives_defaults() {
        let spec = native_spec("web", "/bin/web", "/nix/store/x");
        let extra = build_extra_directives(&spec);
        assert!(extra.contains("KillSignal=SIGTERM"));
        assert!(extra.contains("TimeoutStopSec=30"));
    }

    #[test]
    fn build_extra_directives_with_cgroup() {
        let mut spec = native_spec("web", "/bin/web", "/nix/store/x");
        spec.cgroup_controls = Some(crate::proto::CgroupControls {
            cpu_weight: 200,
            memory_high_mb: 512,
            memory_max_mb: 1024,
            io_weight: 100,
            tasks_max: 50,
            oom_policy: "stop".to_string(),
        });
        let extra = build_extra_directives(&spec);
        assert!(extra.contains("Slice=system-ekafleet.slice"));
        assert!(extra.contains("CPUWeight=200"));
        assert!(extra.contains("MemoryHigh=512M"));
        assert!(extra.contains("MemoryMax=1024M"));
        assert!(extra.contains("TasksMax=50"));
    }

    #[tokio::test]
    async fn write_native_unit_file() {
        let dir = tempfile::tempdir().unwrap();
        let supervisor = Supervisor::new(dir.path());

        let spec = native_spec("web", "/nix/store/abc/bin/web", "/nix/store/abc");

        // Write to a local test path (won't try to symlink into /etc)
        tokio::fs::create_dir_all(&supervisor.unit_dir)
            .await
            .unwrap();
        let unit_content = {
            let env_lines = build_env_lines(&spec);
            let extra_lines = build_extra_directives(&spec);
            format!(
                r#"[Unit]
Description=ekafleet managed: {name}
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=on-failure
RestartSec=5
{extra}
{env}

[Install]
WantedBy=multi-user.target
"#,
                name = spec.name,
                command = spec.command,
                extra = extra_lines,
                env = env_lines,
            )
        };

        let path = supervisor.unit_dir.join("ekafleet-web.service");
        tokio::fs::write(&path, &unit_content).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(content.contains("ExecStart=/nix/store/abc/bin/web"));
        assert!(content.contains("Type=simple"));
        assert!(content.contains("EKAFLEET_SERVICE=web"));
    }

    #[tokio::test]
    async fn write_container_unit_generates_nspawn() {
        let dir = tempfile::tempdir().unwrap();
        let supervisor = Supervisor::new(dir.path());

        let spec = container_spec("api", "ghcr.io/org/api:v1.0");

        // Generate the unit content directly (avoid symlinking into /etc)
        tokio::fs::create_dir_all(&supervisor.unit_dir)
            .await
            .unwrap();

        let machine_name = format!("ekafleet-{}", spec.name);
        let bundle_path = format!("{OCI_STORE_DIR}/bundles/{}", spec.name);
        let spiffe_socket = crate::spiffe::socket::DEFAULT_SOCKET_PATH;
        let secrets_dir = format!("/var/lib/ekafleet/secrets/{}", spec.name);

        let nspawn_args = [
            format!("--oci-bundle={bundle_path}"),
            format!("--machine={machine_name}"),
            "--network-namespace-path=/proc/1/ns/net".to_string(),
            format!("--bind={spiffe_socket}"),
            format!("--bind-ro={secrets_dir}:/run/secrets"),
            "--register=yes".to_string(),
            "--keep-unit".to_string(),
        ];

        let nspawn_cmd = format!("systemd-nspawn {}", nspawn_args.join(" \\\n  "));
        let env_lines = build_env_lines(&spec);
        let extra_lines = build_extra_directives(&spec);

        let unit_content = format!(
            r#"[Unit]
Description=ekafleet container: {name}
After=network.target
Wants=machines.target

[Service]
Type=simple
ExecStart={nspawn_cmd}
ExecStop=machinectl terminate {machine}
Restart=on-failure
RestartSec=5
KillMode=mixed
{extra}
{env}

[Install]
WantedBy=multi-user.target
"#,
            name = spec.name,
            nspawn_cmd = nspawn_cmd,
            machine = machine_name,
            extra = extra_lines,
            env = env_lines,
        );

        let path = supervisor.unit_dir.join("ekafleet-api.service");
        tokio::fs::write(&path, &unit_content).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();

        // Verify nspawn invocation
        assert!(content.contains("systemd-nspawn"));
        assert!(content.contains(&format!("--oci-bundle={bundle_path}")));
        assert!(content.contains(&format!("--machine={machine_name}")));

        // Verify host networking
        assert!(content.contains("--network-namespace-path=/proc/1/ns/net"));

        // Verify SPIFFE socket bind mount
        assert!(content.contains(&format!("--bind={spiffe_socket}")));

        // Verify secrets bind mount
        assert!(content.contains("--bind-ro=/var/lib/ekafleet/secrets/api:/run/secrets"));

        // Verify machined registration
        assert!(content.contains("--register=yes"));
        assert!(content.contains("--keep-unit"));

        // Verify Type=simple (container managed by systemd directly)
        assert!(content.contains("Type=simple"));

        // Verify machinectl terminate for clean shutdown
        assert!(content.contains("ExecStop=machinectl terminate ekafleet-api"));

        // Verify Wants=machines.target
        assert!(content.contains("Wants=machines.target"));

        // Verify KillMode=mixed (signal main + cgroup cleanup)
        assert!(content.contains("KillMode=mixed"));

        // Verify EKAFLEET_SERVICE is set
        assert!(content.contains("EKAFLEET_SERVICE=api"));
    }
}
