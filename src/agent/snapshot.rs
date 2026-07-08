#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Create a point-in-time snapshot of a persistent volume by copying
/// the volume directory to a timestamped snapshot location.
pub async fn create_snapshot(
    volume_path: &Path,
    snapshot_dir: &Path,
    service_name: &str,
    volume_name: &str,
) -> Result<PathBuf, std::io::Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let snapshot_name = format!("{service_name}-{volume_name}-{timestamp}");
    let snapshot_path = snapshot_dir.join(&snapshot_name);

    tokio::fs::create_dir_all(&snapshot_path).await?;

    // Use cp -a for a faithful copy preserving permissions and symlinks
    let output = tokio::process::Command::new("cp")
        .args(["-a", "--reflink=auto"])
        .arg(format!("{}/.", volume_path.display()))
        .arg(snapshot_path.display().to_string())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "snapshot cp failed: {}",
            stderr.trim()
        )));
    }

    tracing::info!(
        service = %service_name,
        volume = %volume_name,
        snapshot = %snapshot_name,
        "Volume snapshot created"
    );

    Ok(snapshot_path)
}

/// Restore a volume from a snapshot.
pub async fn restore_snapshot(
    snapshot_path: &Path,
    volume_path: &Path,
) -> Result<(), std::io::Error> {
    // Clear the target directory
    if volume_path.exists() {
        tokio::fs::remove_dir_all(volume_path).await?;
    }
    tokio::fs::create_dir_all(volume_path).await?;

    let output = tokio::process::Command::new("cp")
        .args(["-a", "--reflink=auto"])
        .arg(format!("{}/.", snapshot_path.display()))
        .arg(volume_path.display().to_string())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "restore cp failed: {}",
            stderr.trim()
        )));
    }

    tracing::info!(
        snapshot = %snapshot_path.display(),
        volume = %volume_path.display(),
        "Volume restored from snapshot"
    );

    Ok(())
}

/// List available snapshots for a service/volume.
pub async fn list_snapshots(
    snapshot_dir: &Path,
    service_name: &str,
    volume_name: &str,
) -> Result<Vec<PathBuf>, std::io::Error> {
    let prefix = format!("{service_name}-{volume_name}-");
    let mut snapshots = Vec::new();

    if !snapshot_dir.exists() {
        return Ok(snapshots);
    }

    let mut entries = tokio::fs::read_dir(snapshot_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&prefix) && entry.file_type().await?.is_dir() {
            snapshots.push(entry.path());
        }
    }

    snapshots.sort();
    Ok(snapshots)
}
