//! Persistent volumes of stateful services.
//!
//! A volume is a directory, one per (service, volume) on a node, at
//! `<data dir>/volumes/<service>/<volume>`; the service's unit bind-mounts
//! it at the volume's mount path. Only the `local` storage class exists and
//! a volume's size is advisory (the scheduler counts it against the node's
//! disk capacity).
//!
//! When a service is no longer assigned here its volumes are kept, unless
//! the volume was declared without `reclaimRetain`: such volumes carry a
//! `.<volume>.reclaim` marker next to them and are deleted, snapshots
//! included. Volume names cannot start with a dot, so markers and staging
//! directories never collide with a volume.
//!
//! A service can be *held*: stopped and kept from starting while its
//! volumes are exported to another node or a snapshot is restored.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::proto::{ServiceSpec, VolumeSnapshotInfo};

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("{0}")]
    InvalidName(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Copy(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The directory holding a node's volumes.
pub fn volumes_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("volumes")
}

/// The host directory of one volume.
pub fn volume_path(data_dir: &Path, service: &str, volume: &str) -> PathBuf {
    volumes_dir(data_dir).join(service).join(volume)
}

/// A one-time permission for `peer` to pull a service's volumes.
struct ExportGrant {
    peer: String,
    expires: Instant,
}

pub struct VolumeManager {
    base: PathBuf,
    snapshots: PathBuf,
    /// CA bundle that peers' node SVIDs chain to (volume transfers).
    ca_pem: Option<String>,
    holds: Mutex<HashMap<String, Instant>>,
    /// Services whose volumes just arrived from another node and must not
    /// be reclaimed before their assignment here does.
    protected: Mutex<HashMap<String, Instant>>,
    grants: Mutex<HashMap<String, ExportGrant>>,
    holds_changed: tokio::sync::Notify,
}

impl VolumeManager {
    pub fn new(data_dir: &Path, ca_pem: Option<String>) -> Self {
        Self {
            base: volumes_dir(data_dir),
            snapshots: data_dir.join("volume-snapshots"),
            ca_pem,
            holds: Mutex::new(HashMap::new()),
            protected: Mutex::new(HashMap::new()),
            grants: Mutex::new(HashMap::new()),
            holds_changed: tokio::sync::Notify::new(),
        }
    }

    pub fn ca_pem(&self) -> Option<&str> {
        self.ca_pem.as_deref()
    }

    /// The directory holding all of a service's volumes.
    pub fn service_dir(&self, service: &str) -> PathBuf {
        self.base.join(service)
    }

    fn volume_dir(&self, service: &str, volume: &str) -> Result<PathBuf, VolumeError> {
        validate(service, volume)?;
        Ok(self.base.join(service).join(volume))
    }

    fn reclaim_marker(&self, service: &str, volume: &str) -> PathBuf {
        self.base.join(service).join(format!(".{volume}.reclaim"))
    }

    /// Create the volumes of `specs` that do not exist yet and record which
    /// ones are deleted once unassigned.
    pub async fn provision<'a>(
        &self,
        specs: impl IntoIterator<Item = &'a ServiceSpec>,
    ) -> Result<(), VolumeError> {
        for spec in specs {
            for volume in &spec.volumes {
                let dir = self.volume_dir(&spec.name, &volume.name)?;
                if !dir.is_dir() {
                    create_private_dir(&self.base).await?;
                    create_private_dir(&self.service_dir(&spec.name)).await?;
                    tokio::fs::create_dir(&dir).await?;
                    tracing::info!(
                        service = %spec.name,
                        volume = %volume.name,
                        path = %dir.display(),
                        size_mb = volume.size_mb,
                        "Volume provisioned"
                    );
                }
                let marker = self.reclaim_marker(&spec.name, &volume.name);
                if volume.reclaim_retain {
                    remove_if_exists(&marker).await?;
                } else if !marker.exists() {
                    tokio::fs::write(&marker, b"").await?;
                }
            }
        }
        Ok(())
    }

    /// Delete the volumes marked for reclaim that no service in `specs`
    /// declares any more (other than held services'), with their snapshots.
    /// Everything else is kept.
    pub async fn reclaim<'a>(
        &self,
        specs: impl IntoIterator<Item = &'a ServiceSpec>,
    ) -> Result<(), VolumeError> {
        let declared: HashSet<(&str, &str)> = specs
            .into_iter()
            .flat_map(|s| s.volumes.iter().map(|v| (s.name.as_str(), v.name.as_str())))
            .collect();
        let mut services = match tokio::fs::read_dir(&self.base).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        while let Some(service_entry) = services.next_entry().await? {
            let service = service_entry.file_name().to_string_lossy().into_owned();
            if service.starts_with('.') || self.is_held(&service) || self.is_protected(&service) {
                continue;
            }
            let mut files = tokio::fs::read_dir(service_entry.path()).await?;
            while let Some(file) = files.next_entry().await? {
                let name = file.file_name().to_string_lossy().into_owned();
                let Some(volume) = name
                    .strip_prefix('.')
                    .and_then(|n| n.strip_suffix(".reclaim"))
                else {
                    continue;
                };
                if declared.contains(&(service.as_str(), volume)) {
                    continue;
                }
                remove_dir_if_exists(&service_entry.path().join(volume)).await?;
                remove_dir_if_exists(&self.snapshots.join(&service).join(volume)).await?;
                remove_if_exists(&file.path()).await?;
                tracing::info!(service = %service, volume = %volume, "Volume deleted (not retained)");
            }
            // Drop the service's directory once nothing is left in it.
            let _ = tokio::fs::remove_dir(service_entry.path()).await;
        }
        Ok(())
    }

    /// Keep `service` stopped for `ttl`.
    pub fn hold(&self, service: &str, ttl: Duration) {
        self.holds
            .lock()
            .expect("holds lock")
            .insert(service.to_string(), Instant::now() + ttl);
        self.holds_changed.notify_one();
    }

    /// Let `service` start again.
    pub fn release(&self, service: &str) {
        self.holds.lock().expect("holds lock").remove(service);
        self.holds_changed.notify_one();
    }

    /// Drop the holds of services no longer assigned here: they stay
    /// stopped regardless, and a hold would keep their volumes from being
    /// reclaimed (e.g. on the source of a finished migration).
    pub fn release_unassigned<'a>(&self, assigned: impl IntoIterator<Item = &'a str>) {
        let assigned: std::collections::HashSet<&str> = assigned.into_iter().collect();
        self.holds
            .lock()
            .expect("holds lock")
            .retain(|service, _| assigned.contains(service.as_str()));
    }

    pub fn is_held(&self, service: &str) -> bool {
        let mut holds = self.holds.lock().expect("holds lock");
        match holds.get(service) {
            Some(expires) if *expires > Instant::now() => true,
            Some(_) => {
                holds.remove(service);
                false
            }
            None => false,
        }
    }

    /// Wait until a hold expires or holds change, so services whose hold
    /// ended can be started again (waking early is harmless).
    pub async fn hold_ended(&self) {
        let next = self
            .holds
            .lock()
            .expect("holds lock")
            .values()
            .min()
            .copied();
        match next {
            Some(at) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(at.into()) => {}
                    _ = self.holds_changed.notified() => {}
                }
            }
            None => self.holds_changed.notified().await,
        }
    }

    /// Keep `service`'s volumes from being reclaimed for `ttl`.
    pub fn protect(&self, service: &str, ttl: Duration) {
        self.protected
            .lock()
            .expect("protected lock")
            .insert(service.to_string(), Instant::now() + ttl);
    }

    fn is_protected(&self, service: &str) -> bool {
        let mut protected = self.protected.lock().expect("protected lock");
        protected.retain(|_, until| *until > Instant::now());
        protected.contains_key(service)
    }

    /// Allow `peer` (a SPIFFE ID) one pull of `service`'s volumes within `ttl`.
    pub fn grant_export(&self, service: &str, peer: &str, ttl: Duration) {
        self.grants.lock().expect("grants lock").insert(
            service.to_string(),
            ExportGrant {
                peer: peer.to_string(),
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Consume the export grant of `service` if `peer` holds it.
    pub fn take_export(&self, service: &str, peer: &str) -> bool {
        let mut grants = self.grants.lock().expect("grants lock");
        let granted = grants
            .get(service)
            .is_some_and(|g| g.peer == peer && g.expires > Instant::now());
        if granted {
            grants.remove(service);
        }
        granted
    }

    /// Where an incoming copy of a service's volumes is unpacked.
    pub fn incoming_dir(&self, service: &str) -> PathBuf {
        self.base.join(format!(".incoming-{service}"))
    }

    /// Replace a service's volumes with the copy in [`Self::incoming_dir`].
    pub async fn install_incoming(&self, service: &str) -> Result<(), VolumeError> {
        validate_service(service)?;
        let incoming = self.incoming_dir(service);
        let current = self.service_dir(service);
        let old = self.base.join(format!(".old-{service}"));
        remove_dir_if_exists(&old).await?;
        if current.exists() {
            tokio::fs::rename(&current, &old).await?;
        }
        tokio::fs::rename(&incoming, &current).await?;
        set_private(&current).await?;
        remove_dir_if_exists(&old).await?;
        Ok(())
    }

    fn snapshot_dir(&self, service: &str, volume: &str) -> Result<PathBuf, VolumeError> {
        validate(service, volume)?;
        Ok(self.snapshots.join(service).join(volume))
    }

    /// Copy a volume (reflinked where the filesystem allows) into a new
    /// snapshot. A running service keeps writing meanwhile, so the copy is
    /// only as consistent as the service's on-disk state.
    pub async fn create_snapshot(
        &self,
        service: &str,
        volume: &str,
    ) -> Result<VolumeSnapshotInfo, VolumeError> {
        let source = self.volume_dir(service, volume)?;
        if !source.is_dir() {
            return Err(VolumeError::NotFound(format!(
                "volume {service}/{volume} does not exist on this node"
            )));
        }
        let dir = self.snapshot_dir(service, volume)?;
        create_private_dir(&self.snapshots).await?;
        create_private_dir(&self.snapshots.join(service)).await?;
        create_private_dir(&dir).await?;
        let stamp = snapshot_stamp(SystemTime::now());
        let mut id = stamp.clone();
        let mut n = 1;
        while dir.join(&id).exists() || dir.join(format!(".{id}.partial")).exists() {
            n += 1;
            id = format!("{stamp}-{n}");
        }
        // Copied under a temporary name, so a failed copy is never listed.
        let partial = dir.join(format!(".{id}.partial"));
        copy_tree(&source, &partial).await?;
        tokio::fs::rename(&partial, dir.join(&id)).await?;
        tracing::info!(service, volume, snapshot = %id, "Volume snapshot created");
        self.snapshot_info(service, volume, &id).await
    }

    async fn snapshot_info(
        &self,
        service: &str,
        volume: &str,
        id: &str,
    ) -> Result<VolumeSnapshotInfo, VolumeError> {
        let path = self.snapshot_dir(service, volume)?.join(id);
        let meta = tokio::fs::metadata(&path).await?;
        let created_at = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let size_bytes = tokio::task::spawn_blocking(move || tree_size(&path))
            .await
            .map_err(std::io::Error::other)??;
        Ok(VolumeSnapshotInfo {
            node: String::new(),
            service_name: service.to_string(),
            volume_name: volume.to_string(),
            snapshot_id: id.to_string(),
            created_at,
            size_bytes,
        })
    }

    /// The snapshots of one volume, or of all of a service's volumes when
    /// `volume` is empty, oldest first.
    pub async fn list_snapshots(
        &self,
        service: &str,
        volume: &str,
    ) -> Result<Vec<VolumeSnapshotInfo>, VolumeError> {
        validate_service(service)?;
        let volumes = if volume.is_empty() {
            list_names(&self.snapshots.join(service)).await?
        } else {
            vec![volume.to_string()]
        };
        let mut out = Vec::new();
        for volume in volumes {
            for id in list_names(&self.snapshot_dir(service, &volume)?).await? {
                out.push(self.snapshot_info(service, &volume, &id).await?);
            }
        }
        out.sort_by(|a, b| {
            (a.volume_name.as_str(), a.created_at, a.snapshot_id.as_str()).cmp(&(
                b.volume_name.as_str(),
                b.created_at,
                b.snapshot_id.as_str(),
            ))
        });
        Ok(out)
    }

    fn existing_snapshot(
        &self,
        service: &str,
        volume: &str,
        id: &str,
    ) -> Result<PathBuf, VolumeError> {
        crate::secrets::validate_name("snapshot", id).map_err(VolumeError::InvalidName)?;
        let path = self.snapshot_dir(service, volume)?.join(id);
        if !path.is_dir() {
            return Err(VolumeError::NotFound(format!(
                "no snapshot {id} of {service}/{volume} on this node"
            )));
        }
        Ok(path)
    }

    /// Replace a volume's contents with a snapshot. The caller holds (stops)
    /// the service around this.
    pub async fn restore_snapshot(
        &self,
        service: &str,
        volume: &str,
        id: &str,
    ) -> Result<VolumeSnapshotInfo, VolumeError> {
        let snapshot = self.existing_snapshot(service, volume, id)?;
        let target = self.volume_dir(service, volume)?;
        let service_dir = self.service_dir(service);
        create_private_dir(&self.base).await?;
        create_private_dir(&service_dir).await?;
        let staged = service_dir.join(format!(".{volume}.restoring"));
        let old = service_dir.join(format!(".{volume}.old"));
        remove_dir_if_exists(&staged).await?;
        remove_dir_if_exists(&old).await?;
        copy_tree(&snapshot, &staged).await?;
        if target.exists() {
            tokio::fs::rename(&target, &old).await?;
        }
        tokio::fs::rename(&staged, &target).await?;
        remove_dir_if_exists(&old).await?;
        tracing::info!(service, volume, snapshot = %id, "Volume restored from snapshot");
        self.snapshot_info(service, volume, id).await
    }

    pub async fn delete_snapshot(
        &self,
        service: &str,
        volume: &str,
        id: &str,
    ) -> Result<VolumeSnapshotInfo, VolumeError> {
        let path = self.existing_snapshot(service, volume, id)?;
        let info = self.snapshot_info(service, volume, id).await?;
        tokio::fs::remove_dir_all(&path).await?;
        tracing::info!(service, volume, snapshot = %id, "Volume snapshot deleted");
        Ok(info)
    }
}

fn validate_service(service: &str) -> Result<(), VolumeError> {
    crate::secrets::validate_name("service", service).map_err(VolumeError::InvalidName)
}

fn validate(service: &str, volume: &str) -> Result<(), VolumeError> {
    validate_service(service)?;
    crate::secrets::validate_name("volume", volume).map_err(VolumeError::InvalidName)
}

/// `YYYYMMDDTHHMMSSZ` (UTC).
fn snapshot_stamp(at: SystemTime) -> String {
    let secs = at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let t = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Names in `dir` not starting with a dot (missing directory: none), sorted.
async fn list_names(dir: &Path) -> Result<Vec<String>, VolumeError> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with('.') && entry.file_type().await?.is_dir() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// `cp -a` `source`'s contents into the new directory `dest`, sharing
/// extents where the filesystem supports reflinks.
async fn copy_tree(source: &Path, dest: &Path) -> Result<(), VolumeError> {
    tokio::fs::create_dir(dest).await?;
    let output = tokio::process::Command::new("cp")
        .args(["-a", "--reflink=auto", "--"])
        .arg(source.join("."))
        .arg(dest)
        .output()
        .await?;
    if !output.status.success() {
        let _ = tokio::fs::remove_dir_all(dest).await;
        return Err(VolumeError::Copy(format!(
            "cp failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Bytes in regular files under `path` (symlinks not followed).
fn tree_size(path: &Path) -> std::io::Result<u64> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Ok(if meta.is_file() { meta.len() } else { 0 });
    }
    let mut total = 0;
    for entry in std::fs::read_dir(path)? {
        total += tree_size(&entry?.path())?;
    }
    Ok(total)
}

async fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    match tokio::fs::create_dir(dir).await {
        Ok(()) => set_private(dir).await,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::create_dir(dir).await?;
            set_private(dir).await
        }
        Err(e) => Err(e),
    }
}

async fn set_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await
}

async fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

async fn remove_dir_if_exists(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::VolumeMount;

    fn spec(name: &str, volumes: &[(&str, bool)]) -> ServiceSpec {
        ServiceSpec {
            name: name.to_string(),
            volumes: volumes
                .iter()
                .map(|(v, retain)| VolumeMount {
                    name: v.to_string(),
                    mount_path: format!("/var/lib/{v}"),
                    size_mb: 10,
                    storage_class: "local".into(),
                    access_mode: "ReadWriteOnce".into(),
                    reclaim_retain: *retain,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn volumes_are_kept_unless_declared_without_retain() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = VolumeManager::new(tmp.path(), None);
        let db = spec("db", &[("data", true), ("scratch", false)]);
        mgr.provision([&db]).await.unwrap();
        let data = volume_path(tmp.path(), "db", "data");
        let scratch = volume_path(tmp.path(), "db", "scratch");
        std::fs::write(data.join("table"), "rows").unwrap();
        assert!(scratch.is_dir());
        mgr.create_snapshot("db", "scratch").await.unwrap();

        // Provisioning again keeps the data.
        mgr.provision([&db]).await.unwrap();
        assert_eq!(std::fs::read_to_string(data.join("table")).unwrap(), "rows");
        mgr.reclaim([&db]).await.unwrap();
        assert!(scratch.is_dir());

        // Held services are left alone, even when unassigned.
        mgr.hold("db", Duration::from_secs(60));
        mgr.reclaim([]).await.unwrap();
        assert!(scratch.is_dir());
        mgr.release("db");
        // So are services whose volumes just arrived.
        mgr.protect("db", Duration::from_secs(60));
        mgr.reclaim([]).await.unwrap();
        assert!(scratch.is_dir());
        mgr.protect("db", Duration::ZERO);

        mgr.reclaim([]).await.unwrap();
        assert!(!scratch.exists());
        assert!(
            mgr.list_snapshots("db", "scratch")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(std::fs::read_to_string(data.join("table")).unwrap(), "rows");

        // A retained volume comes back with its data.
        mgr.provision([&db]).await.unwrap();
        assert_eq!(std::fs::read_to_string(data.join("table")).unwrap(), "rows");

        assert!(matches!(
            mgr.provision([&spec("db", &[("../x", true)])]).await,
            Err(VolumeError::InvalidName(_))
        ));
    }

    #[tokio::test]
    async fn snapshots_restore_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = VolumeManager::new(tmp.path(), None);
        mgr.provision([&spec("db", &[("data", true)])])
            .await
            .unwrap();
        let data = volume_path(tmp.path(), "db", "data");
        std::fs::write(data.join("f"), "one").unwrap();

        let first = mgr.create_snapshot("db", "data").await.unwrap();
        assert_eq!(first.size_bytes, 3);
        let second = mgr.create_snapshot("db", "data").await.unwrap();
        assert_ne!(first.snapshot_id, second.snapshot_id);
        let listed = mgr.list_snapshots("db", "").await.unwrap();
        assert_eq!(listed.len(), 2);

        std::fs::write(data.join("f"), "two").unwrap();
        std::fs::write(data.join("new"), "x").unwrap();
        mgr.restore_snapshot("db", "data", &first.snapshot_id)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(data.join("f")).unwrap(), "one");
        assert!(!data.join("new").exists());

        mgr.delete_snapshot("db", "data", &first.snapshot_id)
            .await
            .unwrap();
        assert_eq!(mgr.list_snapshots("db", "data").await.unwrap().len(), 1);
        assert!(matches!(
            mgr.restore_snapshot("db", "data", &first.snapshot_id).await,
            Err(VolumeError::NotFound(_))
        ));
        assert!(matches!(
            mgr.restore_snapshot("db", "data", "../../etc").await,
            Err(VolumeError::InvalidName(_))
        ));
        assert!(matches!(
            mgr.create_snapshot("db", "missing").await,
            Err(VolumeError::NotFound(_))
        ));
    }

    #[test]
    fn holds_of_unassigned_services_are_dropped() {
        let mgr = VolumeManager::new(Path::new("/nonexistent"), None);
        mgr.hold("db", Duration::from_secs(60));
        mgr.hold("web", Duration::from_secs(60));
        mgr.release_unassigned(["web"]);
        assert!(!mgr.is_held("db"));
        assert!(mgr.is_held("web"));
    }

    #[tokio::test]
    async fn holds_expire_and_grants_are_single_use() {
        let mgr = VolumeManager::new(Path::new("/nonexistent"), None);
        mgr.hold("db", Duration::from_millis(50));
        assert!(mgr.is_held("db"));
        // The first wakeup may be the hold's own notification; the expiry
        // follows.
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(5), mgr.hold_ended())
                .await
                .unwrap();
        }
        assert!(!mgr.is_held("db"));

        mgr.hold("db", Duration::from_secs(60));
        // Consume the wakeup of the hold itself.
        tokio::time::timeout(Duration::from_secs(5), mgr.hold_ended())
            .await
            .unwrap();
        let ended = mgr.hold_ended();
        tokio::pin!(ended);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut ended)
                .await
                .is_err()
        );
        mgr.release("db");
        tokio::time::timeout(Duration::from_secs(5), ended)
            .await
            .unwrap();
        assert!(!mgr.is_held("db"));

        mgr.grant_export("db", "spiffe://t/agent/b", Duration::from_secs(60));
        assert!(!mgr.take_export("db", "spiffe://t/agent/c"));
        assert!(!mgr.take_export("web", "spiffe://t/agent/b"));
        assert!(mgr.take_export("db", "spiffe://t/agent/b"));
        assert!(!mgr.take_export("db", "spiffe://t/agent/b"));
        mgr.grant_export("db", "spiffe://t/agent/b", Duration::ZERO);
        assert!(!mgr.take_export("db", "spiffe://t/agent/b"));
    }

    #[test]
    fn snapshot_ids_are_utc_stamps() {
        let at = UNIX_EPOCH + Duration::from_secs(1_731_612_236);
        assert_eq!(snapshot_stamp(at), "20241114T192356Z");
    }
}
