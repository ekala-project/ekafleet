use std::path::{Path, PathBuf};
use std::sync::Arc;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

const NONCE_LEN: usize = 12; // AES-256-GCM nonce size

/// Persistent storage for Raft log entries and snapshots.
/// All data is encrypted at rest with AES-256-GCM.
pub struct RaftStorage {
    data_dir: PathBuf,
    key: Arc<LessSafeKey>,
    rng: Arc<SystemRandom>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub command: super::state::Command,
}

impl RaftStorage {
    pub fn new(data_dir: &Path, encryption_key: &[u8; 32]) -> Self {
        let unbound =
            UnboundKey::new(&AES_256_GCM, encryption_key).expect("valid 256-bit key required");
        let key = LessSafeKey::new(unbound);

        Self {
            data_dir: data_dir.join("raft"),
            key: Arc::new(key),
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Encrypt data using AES-256-GCM. Returns nonce || ciphertext || tag.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| std::io::Error::other("RNG failure"))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| std::io::Error::other("encryption failed"))?;

        let mut sealed = Vec::with_capacity(NONCE_LEN + in_out.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&in_out);
        Ok(sealed)
    }

    /// Decrypt sealed data (nonce || ciphertext || tag).
    fn decrypt(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        if sealed.len() < NONCE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed data too short",
            ));
        }

        let (nonce_bytes, ciphertext_and_tag) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid nonce"))?;

        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "decryption failed")
            })?;

        Ok(plaintext.to_vec())
    }

    /// Initialize storage directory.
    pub async fn initialize(&self) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        tokio::fs::create_dir_all(self.data_dir.join("log")).await?;
        tokio::fs::create_dir_all(self.data_dir.join("snapshots")).await?;

        // Set restrictive permissions on the data directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            tokio::fs::set_permissions(&self.data_dir, perms).await?;
        }

        tracing::info!(dir = %self.data_dir.display(), "Raft storage initialized (encrypted)");
        Ok(())
    }

    /// Append a log entry (encrypted at rest).
    pub async fn append_log(&self, entry: &LogEntry) -> Result<(), std::io::Error> {
        let path = self
            .data_dir
            .join("log")
            .join(format!("{:020}.log", entry.index));
        let json = serde_json::to_vec(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let sealed = self.encrypt(&json)?;
        tokio::fs::write(path, sealed).await
    }

    /// Read log entries from a given index (decrypted).
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
            let sealed = tokio::fs::read(&path).await?;
            let json = self.decrypt(&sealed)?;
            let entry: LogEntry = serde_json::from_slice(&json)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            if entry.index >= from_index {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Save a snapshot (encrypted at rest).
    pub async fn save_snapshot(&self, index: u64, data: &[u8]) -> Result<(), std::io::Error> {
        let path = self
            .data_dir
            .join("snapshots")
            .join(format!("{:020}.snap", index));
        let sealed = self.encrypt(data)?;
        let sealed_size = sealed.len();
        tokio::fs::write(path, sealed).await?;

        tracing::info!(index, sealed_size, "Snapshot saved (encrypted)");
        Ok(())
    }

    /// Load the latest snapshot (decrypted).
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
                let sealed = tokio::fs::read(&path).await?;
                let data = self.decrypt(&sealed)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xCD; 32]
    }

    async fn test_storage() -> (RaftStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = RaftStorage::new(dir.path(), &test_key());
        storage.initialize().await.unwrap();
        (storage, dir)
    }

    fn test_entry(index: u64) -> LogEntry {
        LogEntry {
            index,
            term: 1,
            command: super::super::state::Command::PutSecret {
                service_name: "test-svc".into(),
                secret_name: "password".into(),
                encrypted_value: b"encrypted-data".to_vec(),
            },
        }
    }

    #[tokio::test]
    async fn log_roundtrip_encrypted() {
        let (storage, _dir) = test_storage().await;

        let entry = test_entry(1);
        storage.append_log(&entry).await.unwrap();

        let entries = storage.read_log_from(0).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].index, 1);
        assert_eq!(entries[0].term, 1);
    }

    #[tokio::test]
    async fn log_files_are_not_plaintext() {
        let (storage, dir) = test_storage().await;

        let entry = test_entry(1);
        storage.append_log(&entry).await.unwrap();

        // Read the raw file bytes
        let log_file = dir
            .path()
            .join("raft")
            .join("log")
            .join("00000000000000000001.log");
        let raw = tokio::fs::read(&log_file).await.unwrap();

        // Raw file must NOT contain plaintext JSON
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(
            !raw_str.contains("test-svc"),
            "log file must not contain plaintext service name"
        );
        assert!(
            !raw_str.contains("password"),
            "log file must not contain plaintext secret name"
        );
    }

    #[tokio::test]
    async fn wrong_key_cannot_read_log() {
        let dir = tempfile::tempdir().unwrap();

        // Write with key A
        let storage_a = RaftStorage::new(dir.path(), &[0xAA; 32]);
        storage_a.initialize().await.unwrap();
        storage_a.append_log(&test_entry(1)).await.unwrap();

        // Try to read with key B
        let storage_b = RaftStorage::new(dir.path(), &[0xBB; 32]);
        let result = storage_b.read_log_from(0).await;

        assert!(result.is_err(), "reading with wrong key must fail");
    }

    #[tokio::test]
    async fn snapshot_roundtrip_encrypted() {
        let (storage, _dir) = test_storage().await;

        let data = b"snapshot-state-data-with-secrets";
        storage.save_snapshot(42, data).await.unwrap();

        let loaded = storage.load_latest_snapshot().await.unwrap();
        assert!(loaded.is_some());

        let (index, decrypted) = loaded.unwrap();
        assert_eq!(index, 42);
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn snapshot_files_are_not_plaintext() {
        let (storage, dir) = test_storage().await;

        storage
            .save_snapshot(1, b"contains-secret-data")
            .await
            .unwrap();

        let snap_file = dir
            .path()
            .join("raft")
            .join("snapshots")
            .join("00000000000000000001.snap");
        let raw = tokio::fs::read(&snap_file).await.unwrap();

        let raw_str = String::from_utf8_lossy(&raw);
        assert!(
            !raw_str.contains("contains-secret-data"),
            "snapshot must not contain plaintext"
        );
    }

    #[tokio::test]
    async fn compact_removes_old_entries() {
        let (storage, _dir) = test_storage().await;

        for i in 1..=5 {
            storage.append_log(&test_entry(i)).await.unwrap();
        }

        let removed = storage.compact_log(3).await.unwrap();
        assert_eq!(removed, 3);

        let remaining = storage.read_log_from(0).await.unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].index, 4);
        assert_eq!(remaining[1].index, 5);
    }

    #[tokio::test]
    async fn read_log_from_filters_by_index() {
        let (storage, _dir) = test_storage().await;

        for i in 1..=5 {
            storage.append_log(&test_entry(i)).await.unwrap();
        }

        let entries = storage.read_log_from(3).await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].index, 3);
    }

    #[tokio::test]
    async fn no_snapshot_returns_none() {
        let (storage, _dir) = test_storage().await;
        let result = storage.load_latest_snapshot().await.unwrap();
        assert!(result.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn data_dir_has_restrictive_permissions() {
        let (_, dir) = test_storage().await;
        use std::os::unix::fs::PermissionsExt;

        let raft_dir = dir.path().join("raft");
        let perms = std::fs::metadata(&raft_dir).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o700,
            "raft data dir must be owner-only"
        );
    }
}
