//! Filesystem helpers shared across subsystems.

use std::path::Path;

use tokio::io::AsyncWriteExt;

/// Replace `path` atomically with `contents`.
///
/// The data is written to a sibling temporary file that is *created* with
/// `mode` (so key material is never briefly readable under the process
/// umask's default mode), fsynced, then renamed over `path`. Readers see
/// either the old or the new file, never a partial write, and replacing a
/// read-only (e.g. 0400) file works without first relaxing its mode.
pub async fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    match tokio::fs::remove_file(&tmp).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = opts.open(&tmp).await?;
    file.write_all(contents).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&tmp, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn creates_with_mode_and_replaces_read_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        write_atomic(&path, b"one", 0o400).await.unwrap();
        write_atomic(&path, b"two", 0o400).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(!dir.path().join("key.pem.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400);
        }
    }
}
