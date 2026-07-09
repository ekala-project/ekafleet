#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

/// Trait for pluggable storage backends (CSI-style driver interface).
pub trait StorageDriver: Send + Sync {
    /// Create a new volume with the given name and size.
    fn create_volume(
        &self,
        name: &str,
        size_mb: u64,
    ) -> impl std::future::Future<Output = Result<String, std::io::Error>> + Send;

    /// Delete an existing volume by ID.
    fn delete_volume(
        &self,
        volume_id: &str,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + Send;

    /// Attach a volume to a node, returning the mount path.
    fn attach_volume(
        &self,
        volume_id: &str,
        node: &str,
    ) -> impl std::future::Future<Output = Result<String, std::io::Error>> + Send;

    /// Detach a volume from a node.
    fn detach_volume(
        &self,
        volume_id: &str,
        node: &str,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + Send;
}

/// Local storage driver that creates directories on the local filesystem.
pub struct LocalStorageDriver {
    base_dir: PathBuf,
}

impl LocalStorageDriver {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }
}

impl StorageDriver for LocalStorageDriver {
    async fn create_volume(&self, name: &str, _size_mb: u64) -> Result<String, std::io::Error> {
        let vol_path = self.base_dir.join(name);
        tokio::fs::create_dir_all(&vol_path).await?;
        Ok(vol_path.display().to_string())
    }

    async fn delete_volume(&self, volume_id: &str) -> Result<(), std::io::Error> {
        let path = PathBuf::from(volume_id);
        if path.exists() {
            tokio::fs::remove_dir_all(&path).await?;
        }
        Ok(())
    }

    async fn attach_volume(&self, volume_id: &str, _node: &str) -> Result<String, std::io::Error> {
        // Local volumes are already on-node; just return the path.
        Ok(volume_id.to_string())
    }

    async fn detach_volume(&self, _volume_id: &str, _node: &str) -> Result<(), std::io::Error> {
        // Local volumes don't need explicit detach.
        Ok(())
    }
}

/// NFS storage driver that mounts NFS shares.
pub struct NfsStorageDriver {
    /// NFS server address (e.g., "10.0.0.1:/exports").
    server: String,
    mount_base: PathBuf,
}

impl NfsStorageDriver {
    pub fn new(server: String, mount_base: PathBuf) -> Self {
        Self { server, mount_base }
    }
}

impl StorageDriver for NfsStorageDriver {
    async fn create_volume(&self, name: &str, _size_mb: u64) -> Result<String, std::io::Error> {
        // NFS volumes are directories on the NFS export. Create the mount point.
        let mount_point = self.mount_base.join(name);
        tokio::fs::create_dir_all(&mount_point).await?;
        Ok(mount_point.display().to_string())
    }

    async fn delete_volume(&self, volume_id: &str) -> Result<(), std::io::Error> {
        // Unmount first, then remove mount point.
        let output = tokio::process::Command::new("umount")
            .arg(volume_id)
            .output()
            .await?;
        if !output.status.success() {
            tracing::warn!(
                volume_id,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "umount failed (may already be unmounted)"
            );
        }
        let path = PathBuf::from(volume_id);
        if path.exists() {
            tokio::fs::remove_dir_all(&path).await?;
        }
        Ok(())
    }

    async fn attach_volume(&self, volume_id: &str, _node: &str) -> Result<String, std::io::Error> {
        let nfs_source = format!("{}/{}", self.server, volume_id);
        let mount_point = PathBuf::from(volume_id);
        tokio::fs::create_dir_all(&mount_point).await?;

        let output = tokio::process::Command::new("mount")
            .args(["-t", "nfs"])
            .arg(&nfs_source)
            .arg(&mount_point)
            .output()
            .await?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "NFS mount failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(mount_point.display().to_string())
    }

    async fn detach_volume(&self, volume_id: &str, _node: &str) -> Result<(), std::io::Error> {
        let output = tokio::process::Command::new("umount")
            .arg(volume_id)
            .output()
            .await?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "NFS umount failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }
}

/// Manages persistent volumes for stateful services.
/// Handles creation, mounting, cleanup, and tracking of volume state.
#[derive(Clone)]
pub struct VolumeManager {
    base_dir: PathBuf,
    volumes: Arc<RwLock<HashMap<String, VolumeState>>>,
}

/// State of a provisioned volume.
#[derive(Debug, Clone)]
struct VolumeState {
    service_name: String,
    volume_name: String,
    mount_path: PathBuf,
    storage_class: String,
    size_mb: u64,
    created: bool,
}

impl VolumeManager {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            base_dir: data_dir.join("volumes"),
            volumes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Provision a volume for a service. Creates the directory and tracks state.
    /// Returns the host path where the volume data is stored.
    /// Checks if the volume already exists on disk before creating, and logs
    /// whether this is a new provision or a re-attach.
    pub async fn provision(
        &self,
        service_name: &str,
        volume_name: &str,
        mount_path: &str,
        storage_class: &str,
        size_mb: u64,
    ) -> Result<PathBuf, std::io::Error> {
        let key = volume_key(service_name, volume_name);
        let host_path = self.base_dir.join(service_name).join(volume_name);

        // Check if the volume already exists on disk
        let already_exists = host_path.exists();

        if already_exists {
            tracing::info!(
                service = %service_name,
                volume = %volume_name,
                path = %host_path.display(),
                "Re-attaching existing volume"
            );
        } else {
            // Create the volume directory using the appropriate storage driver
            match storage_class {
                "nfs" => {
                    // For NFS, we still create the local mount point
                    tokio::fs::create_dir_all(&host_path).await?;
                }
                _ => {
                    // Default to local storage
                    tokio::fs::create_dir_all(&host_path).await?;
                }
            }
            tracing::info!(
                service = %service_name,
                volume = %volume_name,
                path = %host_path.display(),
                size_mb,
                storage_class,
                "New volume provisioned"
            );
        }

        let mut volumes = self.volumes.write().await;
        volumes.insert(
            key,
            VolumeState {
                service_name: service_name.to_string(),
                volume_name: volume_name.to_string(),
                mount_path: PathBuf::from(mount_path),
                storage_class: storage_class.to_string(),
                size_mb,
                created: true,
            },
        );

        Ok(host_path)
    }

    /// Get the host path for an existing volume.
    pub async fn get_host_path(&self, service_name: &str, volume_name: &str) -> Option<PathBuf> {
        let key = volume_key(service_name, volume_name);
        let volumes = self.volumes.read().await;
        if volumes.contains_key(&key) {
            Some(self.base_dir.join(service_name).join(volume_name))
        } else {
            None
        }
    }

    /// Release a volume (mark as unattached). Does NOT delete data
    /// if reclaim_retain is true.
    pub async fn release(
        &self,
        service_name: &str,
        volume_name: &str,
        delete_data: bool,
    ) -> Result<(), std::io::Error> {
        let key = volume_key(service_name, volume_name);
        let mut volumes = self.volumes.write().await;
        volumes.remove(&key);

        if delete_data {
            let host_path = self.base_dir.join(service_name).join(volume_name);
            if host_path.exists() {
                tokio::fs::remove_dir_all(&host_path).await?;
                tracing::info!(
                    service = %service_name,
                    volume = %volume_name,
                    "Volume data deleted"
                );
            }
        } else {
            tracing::info!(
                service = %service_name,
                volume = %volume_name,
                "Volume released (data retained)"
            );
        }

        Ok(())
    }

    /// List all volumes for a service.
    pub async fn list_volumes(&self, service_name: &str) -> Vec<VolumeInfo> {
        let volumes = self.volumes.read().await;
        volumes
            .values()
            .filter(|v| v.service_name == service_name)
            .map(|v| VolumeInfo {
                name: v.volume_name.clone(),
                mount_path: v.mount_path.display().to_string(),
                host_path: self
                    .base_dir
                    .join(&v.service_name)
                    .join(&v.volume_name)
                    .display()
                    .to_string(),
                storage_class: v.storage_class.clone(),
                size_mb: v.size_mb,
            })
            .collect()
    }

    /// Scan the base directory for existing volumes and re-register them.
    /// Called on agent startup to recover volume state.
    pub async fn recover_volumes(&self) -> Result<usize, std::io::Error> {
        let mut count = 0;

        if !self.base_dir.exists() {
            return Ok(0);
        }

        let mut services = tokio::fs::read_dir(&self.base_dir).await?;
        while let Some(service_entry) = services.next_entry().await? {
            if !service_entry.file_type().await?.is_dir() {
                continue;
            }
            let service_name = service_entry.file_name().to_string_lossy().to_string();

            let mut vols = tokio::fs::read_dir(service_entry.path()).await?;
            while let Some(vol_entry) = vols.next_entry().await? {
                if !vol_entry.file_type().await?.is_dir() {
                    continue;
                }
                let volume_name = vol_entry.file_name().to_string_lossy().to_string();
                let key = volume_key(&service_name, &volume_name);

                let mut volumes = self.volumes.write().await;
                volumes.insert(
                    key,
                    VolumeState {
                        service_name: service_name.clone(),
                        volume_name: volume_name.clone(),
                        mount_path: PathBuf::from("/var/lib/ekafleet/data")
                            .join(&service_name)
                            .join(&volume_name),
                        storage_class: "local".to_string(),
                        size_mb: 0,
                        created: true,
                    },
                );
                count += 1;

                tracing::debug!(
                    service = %service_name,
                    volume = %volume_name,
                    "Volume recovered from disk"
                );
            }
        }

        if count > 0 {
            tracing::info!(count, "Recovered existing volumes");
        }
        Ok(count)
    }
}

/// Volume information exposed to callers.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub name: String,
    pub mount_path: String,
    pub host_path: String,
    pub storage_class: String,
    pub size_mb: u64,
}

fn volume_key(service_name: &str, volume_name: &str) -> String {
    format!("{service_name}/{volume_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provision_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = VolumeManager::new(tmp.path());

        let path = mgr
            .provision("postgres", "data", "/var/lib/postgresql", "local", 10240)
            .await
            .unwrap();
        assert!(path.exists());

        let vols = mgr.list_volumes("postgres").await;
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].name, "data");
        assert_eq!(vols[0].size_mb, 10240);
    }

    #[tokio::test]
    async fn release_with_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = VolumeManager::new(tmp.path());

        let path = mgr
            .provision("svc", "vol", "/data", "local", 100)
            .await
            .unwrap();
        assert!(path.exists());

        mgr.release("svc", "vol", true).await.unwrap();
        assert!(!path.exists());
        assert!(mgr.list_volumes("svc").await.is_empty());
    }

    #[tokio::test]
    async fn release_retain_data() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = VolumeManager::new(tmp.path());

        let path = mgr
            .provision("svc", "vol", "/data", "local", 100)
            .await
            .unwrap();
        mgr.release("svc", "vol", false).await.unwrap();

        // Data directory still exists after retain-release
        assert!(path.exists());
        // But volume is no longer tracked
        assert!(mgr.list_volumes("svc").await.is_empty());
    }

    #[tokio::test]
    async fn recover_volumes() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = VolumeManager::new(tmp.path());

        // Manually create volume directories to simulate pre-existing data
        let vol_path = tmp.path().join("volumes").join("db").join("pgdata");
        tokio::fs::create_dir_all(&vol_path).await.unwrap();

        let count = mgr.recover_volumes().await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(mgr.list_volumes("db").await.len(), 1);
    }
}
