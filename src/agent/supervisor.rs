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
pub struct Supervisor {
    unit_dir: PathBuf,
    managed_units: HashMap<String, UnitState>,
}

#[derive(Debug, Clone)]
struct UnitState {
    unit_name: String,
    store_path: String,
    running: bool,
}

impl Supervisor {
    pub fn new(data_dir: &Path) -> Self {
        let unit_dir = data_dir.join("units");
        Self {
            unit_dir,
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

            match self.managed_units.get(name) {
                Some(existing) if existing.store_path == spec.store_path => {
                    // Already running with correct version
                    tracing::debug!(service = %name, "Already up-to-date");
                }
                Some(existing) => {
                    // Version changed — restart
                    tracing::info!(
                        service = %name,
                        old = %existing.store_path,
                        new = %spec.store_path,
                        "Restarting service (version changed)"
                    );
                    self.write_unit_file(&unit_name, spec).await?;
                    systemctl(&["daemon-reload"]).await?;
                    systemctl(&["restart", &unit_name]).await?;
                    self.managed_units.insert(
                        name.clone(),
                        UnitState {
                            unit_name: unit_name.clone(),
                            store_path: spec.store_path.clone(),
                            running: true,
                        },
                    );
                    actions.push(SupervisorAction::Restarted(name.clone()));
                }
                None => {
                    // New service
                    tracing::info!(service = %name, "Starting new service");
                    self.write_unit_file(&unit_name, spec).await?;
                    systemctl(&["daemon-reload"]).await?;
                    systemctl(&["enable", "--now", &unit_name]).await?;
                    self.managed_units.insert(
                        name.clone(),
                        UnitState {
                            unit_name: unit_name.clone(),
                            store_path: spec.store_path.clone(),
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
                actions.push(SupervisorAction::Stopped(name));
            }
        }

        Ok(actions)
    }

    /// Generate a systemd unit file from a service spec.
    async fn write_unit_file(
        &self,
        unit_name: &str,
        spec: &ServiceSpec,
    ) -> Result<(), SupervisorError> {
        tokio::fs::create_dir_all(&self.unit_dir).await?;

        let mut env_entries: Vec<String> = spec
            .environment
            .iter()
            .map(|(k, v)| format!("Environment={k}={v}"))
            .collect();

        // SPIFFE Workload API socket path for go-spiffe / rust-spiffe libraries
        env_entries.push(format!(
            "Environment=SPIFFE_ENDPOINT_SOCKET=unix://{}",
            crate::spiffe::socket::DEFAULT_SOCKET_PATH
        ));
        // Service name for workload attestation (PID → service mapping fallback)
        env_entries.push(format!("Environment=EKAFLEET_SERVICE={}", spec.name));

        let env_lines = env_entries.join("\n");

        let unit_content = format!(
            r#"[Unit]
Description=ekafleet managed: {name}
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=on-failure
RestartSec=5
{env}

[Install]
WantedBy=multi-user.target
"#,
            name = spec.name,
            command = spec.command,
            env = env_lines,
        );

        let path = self.unit_dir.join(unit_name);
        tokio::fs::write(&path, unit_content).await?;

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
