use std::time::Duration;

/// Execute a command in the context of a running service.
///
/// For native (Nix) services, uses `systemd-run` to inherit the service's
/// cgroup, environment, and namespaces.
///
/// For OCI container services, uses `machinectl shell` to execute inside
/// the container's namespace via systemd-machined.
pub async fn exec_in_service(
    service_name: &str,
    command: &[String],
    timeout: Duration,
) -> Result<ExecResult, std::io::Error> {
    if command.is_empty() {
        return Err(std::io::Error::other("empty command"));
    }

    let machine_name = format!("ekafleet-{service_name}");

    // Check if this service is running as a container by probing machined
    let is_container = is_machine_running(&machine_name).await;

    let result = tokio::time::timeout(timeout, async {
        if is_container {
            exec_in_container(&machine_name, service_name, command).await
        } else {
            exec_in_native(service_name, command).await
        }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(std::io::Error::other("exec timeout")),
    }
}

/// Execute a command in a native (Nix process) service's context.
async fn exec_in_native(
    service_name: &str,
    command: &[String],
) -> Result<ExecResult, std::io::Error> {
    let unit = format!("ekafleet-{service_name}.service");

    let mut args = vec![
        "--scope".to_string(),
        "--slice=system-ekafleet.slice".to_string(),
        "--property=Type=oneshot".to_string(),
        "--quiet".to_string(),
        "--".to_string(),
    ];
    args.extend(command.iter().cloned());

    let output = tokio::process::Command::new("systemd-run")
        .args(&args)
        .env("EKAFLEET_SERVICE", service_name)
        .env("EKAFLEET_UNIT", &unit)
        .output()
        .await?;

    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Execute a command inside a container via `machinectl shell`.
async fn exec_in_container(
    machine_name: &str,
    service_name: &str,
    command: &[String],
) -> Result<ExecResult, std::io::Error> {
    // machinectl shell <machine> <command...>
    let mut args = vec![
        "shell".to_string(),
        machine_name.to_string(),
        "--".to_string(),
    ];
    args.extend(command.iter().cloned());

    let output = tokio::process::Command::new("machinectl")
        .args(&args)
        .env("EKAFLEET_SERVICE", service_name)
        .output()
        .await?;

    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Check if a machine (container) is registered with systemd-machined.
async fn is_machine_running(machine_name: &str) -> bool {
    let output = tokio::process::Command::new("machinectl")
        .args(["status", machine_name, "--no-pager"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    matches!(output, Ok(status) if status.success())
}

/// Result of a remote exec command.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}
