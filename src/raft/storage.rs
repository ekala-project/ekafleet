use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use super::RaftError;

const NONCE_LEN: usize = 12; // AES-256-GCM nonce size
const LOG_EXT: &str = "log";
const SNAPSHOT_EXT: &str = "snap";

/// Persistent storage for Raft log entries and snapshots.
///
/// Every file is encrypted at rest with AES-256-GCM under the dedicated
/// Raft storage key, with its kind and index bound as additional
/// authenticated data so entries cannot be swapped or renamed. Files are
/// replaced atomically with mode 0600, so a crash never leaves a torn file.
pub struct RaftStorage {
    data_dir: PathBuf,
    key: Arc<LessSafeKey>,
    /// Key that encrypted storage written before the dedicated Raft key
    /// existed (the fleet key, with index-less AAD). Read-only fallback used
    /// to migrate such files; see [`RaftStorage::used_legacy_key`].
    legacy_key: Option<Arc<LessSafeKey>>,
    legacy_reads: AtomicBool,
    rng: Arc<SystemRandom>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub command: super::state::Command,
}

fn aead_key(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("valid 256-bit key required"))
}

fn aad(kind: &str, index: u64) -> Vec<u8> {
    format!("{kind}\0{index}").into_bytes()
}

/// Index encoded in a `<20-digit index>.<ext>` file name.
fn file_index(path: &Path, ext: &str) -> Option<u64> {
    if path.extension().is_none_or(|e| e != ext) {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}

impl RaftStorage {
    pub fn new(data_dir: &Path, encryption_key: &[u8; 32]) -> Self {
        Self {
            data_dir: data_dir.join("raft"),
            key: Arc::new(aead_key(encryption_key)),
            legacy_key: None,
            legacy_reads: AtomicBool::new(false),
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Also accept files written under `legacy_key` (read-only).
    pub fn with_legacy_key(mut self, legacy_key: &[u8; 32]) -> Self {
        self.legacy_key = Some(Arc::new(aead_key(legacy_key)));
        self
    }

    /// Whether any read so far needed the legacy key. The caller then
    /// rewrites the state under the current key ([`Self::rewrite`]).
    pub fn used_legacy_key(&self) -> bool {
        self.legacy_reads.load(Ordering::Relaxed)
    }

    /// Whether anything has been persisted yet.
    pub async fn is_empty(&self) -> Result<bool, RaftError> {
        for dir in ["log", "snapshots"] {
            match tokio::fs::read_dir(self.data_dir.join(dir)).await {
                Ok(mut entries) => {
                    if entries.next_entry().await?.is_some() {
                        return Ok(false);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }

    /// Encrypt data using AES-256-GCM with additional authenticated data.
    /// Returns nonce || ciphertext || tag.
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RaftError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| RaftError::Crypto("RNG failure"))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| RaftError::Crypto("encryption failed"))?;

        let mut sealed = Vec::with_capacity(NONCE_LEN + in_out.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&in_out);
        Ok(sealed)
    }

    fn open(key: &LessSafeKey, sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return None;
        }
        let (nonce_bytes, ciphertext_and_tag) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).ok()?;
        let mut in_out = ciphertext_and_tag.to_vec();
        key.open_in_place(nonce, Aad::from(aad), &mut in_out)
            .ok()
            .map(|p| p.to_vec())
    }

    /// Decrypt the file at `path` (nonce || ciphertext || tag), falling back
    /// to the legacy key and AAD.
    async fn read_sealed(&self, path: &Path, kind: &str, index: u64) -> Result<Vec<u8>, RaftError> {
        let sealed = tokio::fs::read(path).await?;
        if let Some(plain) = Self::open(&self.key, &sealed, &aad(kind, index)) {
            return Ok(plain);
        }
        if let Some(legacy) = &self.legacy_key
            && let Some(plain) = Self::open(legacy, &sealed, kind.as_bytes())
        {
            self.legacy_reads.store(true, Ordering::Relaxed);
            return Ok(plain);
        }
        Err(RaftError::Corrupt {
            path: path.to_path_buf(),
            reason: "cannot be decrypted with the Raft storage key".into(),
        })
    }

    async fn write_sealed(
        &self,
        path: &Path,
        kind: &str,
        index: u64,
        data: &[u8],
    ) -> Result<(), RaftError> {
        let sealed = self.encrypt(data, &aad(kind, index))?;
        crate::fsutil::write_atomic(path, &sealed, 0o600).await?;
        Ok(())
    }

    /// Sorted `(index, path)` of the files with `ext` in `dir`.
    async fn indexed_files(&self, dir: &str, ext: &str) -> Result<Vec<(u64, PathBuf)>, RaftError> {
        let mut files = Vec::new();
        let mut entries = match tokio::fs::read_dir(self.data_dir.join(dir)).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(files),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(index) = file_index(&path, ext) {
                files.push((index, path));
            }
        }
        files.sort();
        Ok(files)
    }

    /// Initialize storage directory.
    pub async fn initialize(&self) -> Result<(), RaftError> {
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

    fn log_path(&self, index: u64) -> PathBuf {
        self.data_dir
            .join("log")
            .join(format!("{index:020}.{LOG_EXT}"))
    }

    fn snapshot_path(&self, index: u64) -> PathBuf {
        self.data_dir
            .join("snapshots")
            .join(format!("{index:020}.{SNAPSHOT_EXT}"))
    }

    /// Append a log entry (encrypted at rest, durable on return).
    pub async fn append_log(&self, entry: &LogEntry) -> Result<(), RaftError> {
        let json = serde_json::to_vec(entry)?;
        self.write_sealed(&self.log_path(entry.index), "raft-log", entry.index, &json)
            .await
    }

    /// Read log entries from a given index (decrypted), in index order.
    pub async fn read_log_from(&self, from_index: u64) -> Result<Vec<LogEntry>, RaftError> {
        let mut entries = Vec::new();
        for (index, path) in self.indexed_files("log", LOG_EXT).await? {
            if index < from_index {
                continue;
            }
            let json = self.read_sealed(&path, "raft-log", index).await?;
            let entry: LogEntry =
                serde_json::from_slice(&json).map_err(|e| RaftError::Corrupt {
                    path: path.clone(),
                    reason: e.to_string(),
                })?;
            if entry.index != index {
                return Err(RaftError::Corrupt {
                    path,
                    reason: format!("holds entry {}", entry.index),
                });
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Save a snapshot (encrypted at rest), then drop every other snapshot.
    pub async fn save_snapshot(&self, index: u64, data: &[u8]) -> Result<(), RaftError> {
        self.write_sealed(&self.snapshot_path(index), "raft-snapshot", index, data)
            .await?;
        for (other, path) in self.indexed_files("snapshots", SNAPSHOT_EXT).await? {
            if other != index {
                tokio::fs::remove_file(path).await?;
            }
        }
        tracing::info!(index, size = data.len(), "Snapshot saved (encrypted)");
        Ok(())
    }

    /// Load the snapshot with the highest index (decrypted).
    pub async fn load_latest_snapshot(&self) -> Result<Option<(u64, Vec<u8>)>, RaftError> {
        let Some((index, path)) = self.indexed_files("snapshots", SNAPSHOT_EXT).await?.pop() else {
            return Ok(None);
        };
        let data = self.read_sealed(&path, "raft-snapshot", index).await?;
        Ok(Some((index, data)))
    }

    /// Compact log entries up to (and including) the given index.
    pub async fn compact_log(&self, up_to: u64) -> Result<usize, RaftError> {
        let mut removed = 0;
        for (index, path) in self.indexed_files("log", LOG_EXT).await? {
            if index <= up_to {
                tokio::fs::remove_file(path).await?;
                removed += 1;
            }
        }
        tracing::info!(up_to, removed, "Log compacted");
        Ok(removed)
    }

    /// Write `entry` in the pre-raft-key format (this storage's key standing
    /// in for the fleet key, index-less AAD), for migration tests.
    #[cfg(test)]
    pub(crate) async fn append_log_legacy_format(&self, entry: &LogEntry) -> Result<(), RaftError> {
        let sealed = self.encrypt(&serde_json::to_vec(entry)?, b"raft-log")?;
        tokio::fs::write(self.log_path(entry.index), sealed).await?;
        Ok(())
    }

    /// Replace everything on disk with a single snapshot of `data` at
    /// `index`. Used to re-encrypt legacy storage and to install a restored
    /// snapshot. Every intermediate state stays readable: the new snapshot
    /// lands before the log it subsumes is removed.
    pub async fn rewrite(&self, index: u64, data: &[u8]) -> Result<(), RaftError> {
        self.save_snapshot(index, data).await?;
        self.compact_log(u64::MAX).await?;
        Ok(())
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

    #[tokio::test]
    async fn latest_snapshot_is_the_highest_index_and_others_are_pruned() {
        let (storage, dir) = test_storage().await;
        // Simulate a stale, higher-sorting leftover next to newer ones.
        for index in [9, 100, 42] {
            storage
                .write_sealed(
                    &storage.snapshot_path(index),
                    "raft-snapshot",
                    index,
                    format!("state-{index}").as_bytes(),
                )
                .await
                .unwrap();
        }
        let (index, data) = storage.load_latest_snapshot().await.unwrap().unwrap();
        assert_eq!((index, data.as_slice()), (100, b"state-100".as_slice()));

        storage.save_snapshot(101, b"state-101").await.unwrap();
        let snaps = std::fs::read_dir(dir.path().join("raft/snapshots"))
            .unwrap()
            .count();
        assert_eq!(snaps, 1, "older snapshots are pruned");
    }

    #[tokio::test]
    async fn entries_are_bound_to_their_index() {
        let (storage, dir) = test_storage().await;
        storage.append_log(&test_entry(1)).await.unwrap();
        storage.append_log(&test_entry(2)).await.unwrap();
        let log = dir.path().join("raft/log");
        // Replace entry 2 with a copy of entry 1 (a replay on disk).
        std::fs::copy(
            log.join("00000000000000000001.log"),
            log.join("00000000000000000002.log"),
        )
        .unwrap();
        let err = storage.read_log_from(0).await.unwrap_err();
        assert!(matches!(err, RaftError::Corrupt { .. }), "{err}");
    }

    #[tokio::test]
    async fn temp_files_are_ignored() {
        let (storage, dir) = test_storage().await;
        storage.append_log(&test_entry(1)).await.unwrap();
        std::fs::write(
            dir.path().join("raft/log/00000000000000000002.log.tmp"),
            b"torn",
        )
        .unwrap();
        assert_eq!(storage.read_log_from(0).await.unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (storage, dir) = test_storage().await;
        storage.append_log(&test_entry(1)).await.unwrap();
        storage.save_snapshot(1, b"s").await.unwrap();
        for file in [
            "raft/log/00000000000000000001.log",
            "raft/snapshots/00000000000000000001.snap",
        ] {
            let mode = std::fs::metadata(dir.path().join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{file}");
        }
    }

    #[tokio::test]
    async fn legacy_key_files_are_read_and_flagged() {
        let dir = tempfile::tempdir().unwrap();
        // Write the pre-raft-key format: fleet key, index-less AAD.
        let legacy = [0xAA; 32];
        let old = RaftStorage::new(dir.path(), &legacy);
        old.initialize().await.unwrap();
        let json = serde_json::to_vec(&test_entry(1)).unwrap();
        let mut sealed = {
            let key = aead_key(&legacy);
            let mut buf = json.clone();
            let nonce = [7u8; NONCE_LEN];
            key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(b"raft-log"),
                &mut buf,
            )
            .unwrap();
            let mut out = nonce.to_vec();
            out.append(&mut buf);
            out
        };
        std::fs::write(old.log_path(1), &sealed).unwrap();

        let without = RaftStorage::new(dir.path(), &[0xBB; 32]);
        assert!(without.read_log_from(0).await.is_err());

        let with = RaftStorage::new(dir.path(), &[0xBB; 32]).with_legacy_key(&legacy);
        assert!(!with.used_legacy_key());
        assert_eq!(with.read_log_from(0).await.unwrap().len(), 1);
        assert!(with.used_legacy_key());

        // Tampering is still detected under the legacy key.
        *sealed.last_mut().unwrap() ^= 1;
        std::fs::write(old.log_path(1), &sealed).unwrap();
        assert!(with.read_log_from(0).await.is_err());
    }
}
