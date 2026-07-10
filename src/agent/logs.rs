use tokio::process::Command;

/// Stream logs from a service's systemd journal in real-time.
/// Returns a child process whose stdout produces journal lines.
pub async fn stream_journal(
    service_name: &str,
    lines: u32,
    follow: bool,
) -> Result<tokio::process::Child, std::io::Error> {
    let unit = format!("ekafleet-{service_name}.service");

    let mut args = vec![
        "--unit".to_string(),
        unit,
        "--output".to_string(),
        "short-iso".to_string(),
        format!("--lines={lines}"),
    ];

    if follow {
        args.push("--follow".to_string());
    }

    let child = Command::new("journalctl")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    Ok(child)
}

/// Read recent log lines from a service (non-streaming).
pub async fn read_logs(service_name: &str, lines: u32) -> Result<String, std::io::Error> {
    let unit = format!("ekafleet-{service_name}.service");

    let output = Command::new("journalctl")
        .args([
            "--unit",
            &unit,
            "--output",
            "short-iso",
            &format!("--lines={lines}"),
            "--no-pager",
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "journalctl failed: {}",
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
