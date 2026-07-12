//! Content-addressable OCI blob store on the local filesystem.
//!
//! Stores blobs (layers, configs, manifests) by digest under:
//!   `<root>/blobs/sha256/<hex>`
//!
//! Stores unpacked OCI bundles under:
//!   `<root>/bundles/<service_name>/rootfs/`

use std::path::{Path, PathBuf};

use super::digest::Digest;

/// Filesystem layout for the OCI image store.
pub struct ImageStore {
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("blob not found: {0}")]
    NotFound(Digest),
}

impl ImageStore {
    /// Create a new store rooted at the given directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Ensure the store directories exist.
    pub async fn init(&self) -> Result<(), StoreError> {
        tokio::fs::create_dir_all(self.blobs_dir()).await?;
        tokio::fs::create_dir_all(self.bundles_dir()).await?;
        tokio::fs::create_dir_all(self.manifests_dir()).await?;
        Ok(())
    }

    // -- Blob operations --

    /// Path where a blob with the given digest is stored.
    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.blobs_dir().join(digest.hex())
    }

    /// Check whether a blob exists locally.
    pub async fn has_blob(&self, digest: &Digest) -> bool {
        self.blob_path(digest).exists()
    }

    /// Write a blob to the store. The caller is responsible for
    /// verifying the digest before calling this.
    pub async fn put_blob(&self, digest: &Digest, data: &[u8]) -> Result<(), StoreError> {
        let path = self.blob_path(digest);
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;
        tokio::fs::write(&path, data).await?;
        tracing::debug!(digest = %digest, size = data.len(), "Stored blob");
        Ok(())
    }

    /// Read a blob from the store.
    pub async fn get_blob(&self, digest: &Digest) -> Result<Vec<u8>, StoreError> {
        let path = self.blob_path(digest);
        if !path.exists() {
            return Err(StoreError::NotFound(digest.clone()));
        }
        Ok(tokio::fs::read(&path).await?)
    }

    /// Remove a blob from the store.
    pub async fn remove_blob(&self, digest: &Digest) -> Result<(), StoreError> {
        let path = self.blob_path(digest);
        if path.exists() {
            tokio::fs::remove_file(&path).await?;
        }
        Ok(())
    }

    // -- Manifest operations --

    /// Store a manifest (keyed by a stable identifier, not necessarily its digest).
    pub async fn put_manifest(&self, key: &str, data: &[u8]) -> Result<(), StoreError> {
        let path = self.manifests_dir().join(key);
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    /// Read a stored manifest.
    pub async fn get_manifest(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.manifests_dir().join(key);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(tokio::fs::read(&path).await?))
    }

    // -- Bundle operations --

    /// Root path for a service's unpacked bundle.
    pub fn bundle_path(&self, service_name: &str) -> PathBuf {
        self.bundles_dir().join(service_name)
    }

    /// Rootfs path for a service's unpacked bundle.
    pub fn rootfs_path(&self, service_name: &str) -> PathBuf {
        self.bundle_path(service_name).join("rootfs")
    }

    /// Check whether a bundle exists for a service.
    pub async fn has_bundle(&self, service_name: &str) -> bool {
        self.rootfs_path(service_name).exists()
    }

    /// Remove a service's unpacked bundle.
    pub async fn remove_bundle(&self, service_name: &str) -> Result<(), StoreError> {
        let path = self.bundle_path(service_name);
        if path.exists() {
            tokio::fs::remove_dir_all(&path).await?;
        }
        Ok(())
    }

    // -- Listing --

    /// List all blob digests in the store.
    pub async fn list_blobs(&self) -> Result<Vec<Digest>, StoreError> {
        let dir = self.blobs_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut digests = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let hex = name.to_string_lossy();
            if let Ok(digest) = format!("sha256:{hex}").parse() {
                digests.push(digest);
            }
        }
        Ok(digests)
    }

    /// List all service bundles.
    pub async fn list_bundles(&self) -> Result<Vec<String>, StoreError> {
        let dir = self.bundles_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut names = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        Ok(names)
    }

    // -- Internal paths --

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs").join("sha256")
    }

    fn manifests_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }

    fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }
}

impl ImageStore {
    /// Return the store root for use in cleanup/GC operations.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blob_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let data = b"hello world";
        let digest = Digest::from_bytes(data);

        assert!(!store.has_blob(&digest).await);
        store.put_blob(&digest, data).await.unwrap();
        assert!(store.has_blob(&digest).await);

        let read_back = store.get_blob(&digest).await.unwrap();
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn blob_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let digest = Digest::from_bytes(b"missing");
        assert!(store.get_blob(&digest).await.is_err());
    }

    #[tokio::test]
    async fn manifest_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let key = "test-manifest";
        let data = b"{\"schemaVersion\": 2}";

        assert!(store.get_manifest(key).await.unwrap().is_none());
        store.put_manifest(key, data).await.unwrap();
        assert_eq!(store.get_manifest(key).await.unwrap().unwrap(), data);
    }

    #[tokio::test]
    async fn list_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let d1 = Digest::from_bytes(b"one");
        let d2 = Digest::from_bytes(b"two");
        store.put_blob(&d1, b"one").await.unwrap();
        store.put_blob(&d2, b"two").await.unwrap();

        let blobs = store.list_blobs().await.unwrap();
        assert_eq!(blobs.len(), 2);
        assert!(blobs.contains(&d1));
        assert!(blobs.contains(&d2));
    }

    #[tokio::test]
    async fn remove_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let digest = Digest::from_bytes(b"removeme");
        store.put_blob(&digest, b"removeme").await.unwrap();
        assert!(store.has_blob(&digest).await);

        store.remove_blob(&digest).await.unwrap();
        assert!(!store.has_blob(&digest).await);
    }

    #[tokio::test]
    async fn bundle_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let svc = "test-svc";
        assert!(!store.has_bundle(svc).await);

        // Create a fake bundle
        let rootfs = store.rootfs_path(svc);
        tokio::fs::create_dir_all(&rootfs).await.unwrap();
        tokio::fs::write(rootfs.join("hello"), b"world")
            .await
            .unwrap();
        assert!(store.has_bundle(svc).await);

        store.remove_bundle(svc).await.unwrap();
        assert!(!store.has_bundle(svc).await);
    }
}
