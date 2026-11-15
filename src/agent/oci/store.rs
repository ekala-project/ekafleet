//! Content-addressable OCI blob store on the local filesystem.
//!
//! Layout under the store root:
//!   `blobs/sha256/<hex>`            layers and configs, by digest
//!   `manifests/<hex>`               the image manifest run for a pinned digest
//!   `bundles/<service>/<hex>/`      an unpacked bundle: `rootfs/`,
//!                                   `image-config.json`, `config.json`
//!
//! A bundle directory appears only once complete: it is assembled under a
//! hidden staging name and renamed into place.

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

/// The image config copied into every complete bundle.
pub const IMAGE_CONFIG_FILE: &str = "image-config.json";

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

    /// Return the store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // -- Blob operations --

    /// Path where a blob with the given digest is stored.
    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.blobs_dir().join(digest.hex())
    }

    /// Check whether a blob exists locally.
    pub async fn has_blob(&self, digest: &Digest) -> bool {
        tokio::fs::try_exists(self.blob_path(digest))
            .await
            .unwrap_or(false)
    }

    /// Write a blob to the store. The caller is responsible for
    /// verifying the digest before calling this.
    pub async fn put_blob(&self, digest: &Digest, data: &[u8]) -> Result<(), StoreError> {
        let path = self.blob_path(digest);
        write_atomic(&path, data).await?;
        tracing::debug!(digest = %digest, size = data.len(), "Stored blob");
        Ok(())
    }

    /// Read a blob from the store.
    pub async fn get_blob(&self, digest: &Digest) -> Result<Vec<u8>, StoreError> {
        match tokio::fs::read(self.blob_path(digest)).await {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StoreError::NotFound(digest.clone()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a blob from the store.
    pub async fn remove_blob(&self, digest: &Digest) -> Result<(), StoreError> {
        remove_file(&self.blob_path(digest)).await
    }

    /// List all blob digests in the store.
    pub async fn list_blobs(&self) -> Result<Vec<Digest>, StoreError> {
        Ok(list_names(&self.blobs_dir())
            .await?
            .into_iter()
            .filter_map(|hex| format!("sha256:{hex}").parse().ok())
            .collect())
    }

    // -- Manifest operations --

    /// Store the image manifest run for a pinned digest (by its hex).
    pub async fn put_manifest(&self, key: &str, data: &[u8]) -> Result<(), StoreError> {
        write_atomic(&self.manifests_dir().join(key), data).await?;
        Ok(())
    }

    /// Read a stored manifest.
    pub async fn get_manifest(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        match tokio::fs::read(self.manifests_dir().join(key)).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a stored manifest.
    pub async fn remove_manifest(&self, key: &str) -> Result<(), StoreError> {
        remove_file(&self.manifests_dir().join(key)).await
    }

    /// List the keys of all stored manifests.
    pub async fn list_manifests(&self) -> Result<Vec<String>, StoreError> {
        list_names(&self.manifests_dir()).await
    }

    // -- Bundle operations --

    /// A service's bundle for a pinned image digest (by its hex).
    pub fn bundle_path(&self, service: &str, hex: &str) -> PathBuf {
        self.bundles_dir().join(service).join(hex)
    }

    /// Rootfs of a service's bundle.
    pub fn rootfs_path(&self, service: &str, hex: &str) -> PathBuf {
        self.bundle_path(service, hex).join("rootfs")
    }

    /// Where a bundle is assembled before being renamed into place.
    pub fn staging_path(&self, service: &str, hex: &str) -> PathBuf {
        self.bundles_dir()
            .join(service)
            .join(format!(".{hex}.partial"))
    }

    /// Whether a complete bundle exists.
    pub async fn has_bundle(&self, service: &str, hex: &str) -> bool {
        tokio::fs::try_exists(self.bundle_path(service, hex).join(IMAGE_CONFIG_FILE))
            .await
            .unwrap_or(false)
    }

    /// Remove one bundle (or a leftover staging directory).
    pub async fn remove_bundle(&self, service: &str, hex: &str) -> Result<(), StoreError> {
        remove_dir(&self.bundle_path(service, hex)).await
    }

    /// Every bundle directory as `(service, name)`; names of incomplete
    /// bundles are their staging names.
    pub async fn list_bundles(&self) -> Result<Vec<(String, String)>, StoreError> {
        let mut out = Vec::new();
        for service in list_names(&self.bundles_dir()).await? {
            for name in list_names(&self.bundles_dir().join(&service)).await? {
                out.push((service.clone(), name));
            }
        }
        Ok(out)
    }

    /// Remove a service's directory once it holds no bundles.
    pub async fn remove_service_dir_if_empty(&self, service: &str) {
        let _ = tokio::fs::remove_dir(self.bundles_dir().join(service)).await;
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

/// Write a file via a temporary sibling, so readers never see a partial one.
async fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    tokio::fs::write(&tmp, data).await?;
    tokio::fs::rename(&tmp, path).await
}

async fn remove_file(path: &Path) -> Result<(), StoreError> {
    match tokio::fs::remove_file(path).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

async fn remove_dir(path: &Path) -> Result<(), StoreError> {
    match tokio::fs::remove_dir_all(path).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Names of the entries of a directory (none if it does not exist),
/// skipping temporary files.
async fn list_names(dir: &Path) -> Result<Vec<String>, StoreError> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".tmp") {
            names.push(name);
        }
    }
    Ok(names)
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

        let (svc, hex) = ("test-svc", "ab".repeat(32));
        assert!(!store.has_bundle(svc, &hex).await);

        // A bundle is complete once its image config is in place.
        let rootfs = store.rootfs_path(svc, &hex);
        tokio::fs::create_dir_all(&rootfs).await.unwrap();
        assert!(!store.has_bundle(svc, &hex).await);
        tokio::fs::write(store.bundle_path(svc, &hex).join(IMAGE_CONFIG_FILE), b"{}")
            .await
            .unwrap();
        assert!(store.has_bundle(svc, &hex).await);
        assert_eq!(
            store.list_bundles().await.unwrap(),
            vec![(svc.to_string(), hex.clone())]
        );

        store.remove_bundle(svc, &hex).await.unwrap();
        assert!(!store.has_bundle(svc, &hex).await);
        store.remove_service_dir_if_empty(svc).await;
        assert!(store.list_bundles().await.unwrap().is_empty());
    }
}
