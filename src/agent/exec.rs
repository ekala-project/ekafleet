use std::time::Duration;

/// Execute a command in the context of a running service's systemd unit.
/// Uses `systemd-run` to inherit the service's cgroup, environment, and namespaces.
pub async fn exec_in_service(
    service_name: &str,
    command: &[String],
    timeout: Duration,
) -> Result<ExecResult, std::io::Error> {
    if command.is_empty() {
        return Err(std::io::Error::other("empty command"));
    }

    let unit = format!("ekafleet-{service_name}.service");

    // Use systemd-run --scope to execute in the same slice as the service
    let mut args = vec![
        "--scope".to_string(),
        "--slice=system-ekafleet.slice".to_string(),
        "--property=Type=oneshot".to_string(),
        "--quiet".to_string(),
        "--".to_string(),
    ];
    args.extend(command.iter().cloned());

    let result = tokio::time::timeout(timeout, async {
        let output = tokio::process::Command::new("systemd-run")
            .args(&args)
            .env("EKAFLEET_SERVICE", service_name)
            .env("EKAFLEET_UNIT", &unit)
            .output()
            .await?;

        Ok::<_, std::io::Error>(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(std::io::Error::other("exec timeout")),
    }
}

/// Result of a remote exec command.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}
