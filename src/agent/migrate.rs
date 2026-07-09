#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Migrate volume data from a source machine to a destination machine
/// using rsync over SSH. Used when a stateful service is rescheduled.
pub async fn migrate_volume(
    source_host: &str,
    source_path: &Path,
    dest_path: &Path,
) -> Result<MigrateResult, std::io::Error> {
    tokio::fs::create_dir_all(dest_path).await?;

    let source = format!("{}:{}/", source_host, source_path.display());
    let dest = format!("{}/", dest_path.display());

    tracing::info!(
        source_host = %source_host,
        source_path = %source_path.display(),
        dest_path = %dest_path.display(),
        "Starting volume data migration"
    );

    let output = tokio::process::Command::new("rsync")
        .args(["-avz", "--delete", "--timeout=300", &source, &dest])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        tracing::error!(
            stderr = %stderr.trim(),
            "Volume migration failed"
        );
        return Err(std::io::Error::other(format!(
            "rsync failed: {}",
            stderr.trim()
        )));
    }

    // Parse bytes transferred from rsync output
    let bytes = parse_rsync_bytes(&stdout);

    tracing::info!(bytes_transferred = bytes, "Volume data migration completed");

    Ok(MigrateResult {
        bytes_transferred: bytes,
        source_path: source_path.to_path_buf(),
        dest_path: dest_path.to_path_buf(),
    })
}

#[derive(Debug, Clone)]
pub struct MigrateResult {
    pub bytes_transferred: u64,
    pub source_path: PathBuf,
    pub dest_path: PathBuf,
}

fn parse_rsync_bytes(output: &str) -> u64 {
    // Look for "total size is X" line
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("total size is ")
            && let Some(num_str) = rest.split_whitespace().next()
        {
            let cleaned: String = num_str.chars().filter(|c| c.is_ascii_digit()).collect();
            return cleaned.parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rsync_output() {
        let output = "sent 1,234 bytes  received 567 bytes  1,801.00 bytes/sec\ntotal size is 45,678  speedup is 25.36\n";
        assert_eq!(parse_rsync_bytes(output), 45678);
    }
}
