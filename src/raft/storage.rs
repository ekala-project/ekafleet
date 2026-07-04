use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Persistent storage for Raft log entries and snapshots.
/// Uses simple file-based storage. Production would use openraft
/// with a proper storage backend.
pub struct RaftStorage {
    data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub command: super::state::Command,
}

impl RaftStorage {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.join("raft"),
        }
    }

    /// Initialize storage directory.
    pub async fn initialize(&self) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        tokio::fs::create_dir_all(self.data_dir.join("log")).await?;
        tokio::fs::create_dir_all(self.data_dir.join("snapshots")).await?;
        tracing::info!(dir = %self.data_dir.display(), "Raft storage initialized");
        Ok(())
    }

    /// Append a log entry.
    pub async fn append_log(&self, entry: &LogEntry) -> Result<(), std::io::Error> {
        let path = self
            .data_dir
            .join("log")
            .join(format!("{:020}.json", entry.index));
        let data = serde_json::to_vec(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(path, data).await
    }

    /// Read log entries from a given index.
    pub async fn read_log_from(&self, from_index: u64) -> Result<Vec<LogEntry>, std::io::Error> {
        let log_dir = self.data_dir.join("log");
        let mut entries = Vec::new();

        let mut dir = tokio::fs::read_dir(&log_dir).await?;
        let mut files = Vec::new();
        while let Some(entry) = dir.next_entry().await? {
            files.push(entry.path());
        }
        files.sort();

        for path in files {
            let data = tokio::fs::read(&path).await?;
            let entry: LogEntry = serde_json::from_slice(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            if entry.index >= from_index {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Save a snapshot.
    pub async fn save_snapshot(&self, index: u64, data: &[u8]) -> Result<(), std::io::Error> {
        let path = self
            .data_dir
            .join("snapshots")
            .join(format!("{:020}.snap", index));
        tokio::fs::write(path, data).await?;

        tracing::info!(index, size = data.len(), "Snapshot saved");
        Ok(())
    }

    /// Load the latest snapshot.
    pub async fn load_latest_snapshot(&self) -> Result<Option<(u64, Vec<u8>)>, std::io::Error> {
        let snap_dir = self.data_dir.join("snapshots");
        if !snap_dir.exists() {
            return Ok(None);
        }

        let mut dir = tokio::fs::read_dir(&snap_dir).await?;
        let mut latest: Option<PathBuf> = None;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "snap") {
                latest = Some(path);
            }
        }

        match latest {
            Some(path) => {
                let data = tokio::fs::read(&path).await?;
                let index = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                Ok(Some((index, data)))
            }
            None => Ok(None),
        }
    }

    /// Compact log entries up to (and including) the given index.
    pub async fn compact_log(&self, up_to: u64) -> Result<usize, std::io::Error> {
        let log_dir = self.data_dir.join("log");
        let mut dir = tokio::fs::read_dir(&log_dir).await?;
        let mut removed = 0;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            let index: u64 = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::MAX);

            if index <= up_to {
                tokio::fs::remove_file(path).await?;
                removed += 1;
            }
        }

        tracing::info!(up_to, removed, "Log compacted");
        Ok(removed)
    }
}
