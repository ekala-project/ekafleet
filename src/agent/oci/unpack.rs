//! OCI image layer unpacking.
//!
//! Extracts tar+gzip layers into a rootfs directory, handling OCI
//! whiteout files (`.wh.` prefix) for layer deletions.

use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive;

use super::digest::Digest;
use super::manifest::ImageManifest;
use super::store::ImageStore;

#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("blob not found in store: {0}")]
    BlobNotFound(Digest),
    #[error("tar extraction failed: {0}")]
    Tar(String),
}

/// Unpack an image's layers into a rootfs directory for the given service.
///
/// Layers are applied in order (bottom-up), handling whiteout files
/// to remove entries from lower layers.
pub async fn unpack_image(
    store: &ImageStore,
    service_name: &str,
    manifest: &ImageManifest,
) -> Result<PathBuf, UnpackError> {
    let rootfs = store.rootfs_path(service_name);

    // Clean up any previous rootfs
    if rootfs.exists() {
        tokio::fs::remove_dir_all(&rootfs).await?;
    }
    tokio::fs::create_dir_all(&rootfs).await?;

    // Apply layers in order
    for (i, layer) in manifest.layers.iter().enumerate() {
        let blob = store
            .get_blob(&layer.digest)
            .await
            .map_err(|_| UnpackError::BlobNotFound(layer.digest.clone()))?;

        tracing::debug!(
            layer = i,
            digest = %layer.digest,
            size = blob.len(),
            "Unpacking layer"
        );

        // Layer unpacking is CPU-bound; run on blocking thread pool
        let rootfs_clone = rootfs.clone();
        tokio::task::spawn_blocking(move || unpack_layer(&blob, &rootfs_clone))
            .await
            .map_err(|e| UnpackError::Tar(format!("task join error: {e}")))??;
    }

    tracing::info!(
        service = service_name,
        layers = manifest.layers.len(),
        "Image unpacked"
    );

    Ok(rootfs)
}

/// Unpack a single gzipped tar layer into the rootfs, handling whiteouts.
fn unpack_layer(data: &[u8], rootfs: &Path) -> Result<(), UnpackError> {
    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    // Do not unpack outside rootfs
    archive.set_overwrite(true);

    for entry_result in archive
        .entries()
        .map_err(|e| UnpackError::Tar(e.to_string()))?
    {
        let mut entry = entry_result.map_err(|e| UnpackError::Tar(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| UnpackError::Tar(e.to_string()))?
            .into_owned();

        // Skip entries that would escape the rootfs
        if path.has_root()
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            tracing::warn!(path = %path.display(), "Skipping path traversal attempt");
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Handle OCI whiteout files
        if file_name == ".wh..wh..opq" {
            // Opaque whiteout: delete all existing contents of the parent directory
            let parent = rootfs.join(path.parent().unwrap_or(Path::new("")));
            if parent.exists() {
                remove_dir_contents(&parent)?;
            }
            continue;
        }

        if let Some(target) = file_name.strip_prefix(".wh.") {
            // Regular whiteout: delete the named entry
            let target_path = rootfs
                .join(path.parent().unwrap_or(Path::new("")))
                .join(target);
            if target_path.is_dir() {
                std::fs::remove_dir_all(&target_path)
                    .map_err(|e| UnpackError::Tar(format!("whiteout removal failed: {e}")))?;
            } else if target_path.exists() {
                std::fs::remove_file(&target_path)
                    .map_err(|e| UnpackError::Tar(format!("whiteout removal failed: {e}")))?;
            }
            continue;
        }

        // Normal entry: unpack into rootfs
        entry
            .unpack_in(rootfs)
            .map_err(|e| UnpackError::Tar(format!("unpack entry {}: {e}", path.display())))?;
    }

    Ok(())
}

/// Remove all contents of a directory without removing the directory itself.
fn remove_dir_contents(dir: &Path) -> Result<(), UnpackError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a gzipped tar archive from a list of (path, content) entries.
    fn make_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut ar = tar::Builder::new(&mut encoder);
            for (path, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                ar.append(&header, &data[..]).unwrap();
            }
            ar.finish().unwrap();
        }
        encoder.finish().unwrap()
    }

    fn make_tar_gz_with_dirs(entries: &[TarEntry<'_>]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut ar = tar::Builder::new(&mut encoder);
            for entry in entries {
                match entry {
                    TarEntry::File(path, data) => {
                        let mut header = tar::Header::new_gnu();
                        header.set_path(path).unwrap();
                        header.set_size(data.len() as u64);
                        header.set_mode(0o644);
                        header.set_entry_type(tar::EntryType::Regular);
                        header.set_cksum();
                        ar.append(&header, &data[..]).unwrap();
                    }
                    TarEntry::Dir(path) => {
                        let mut header = tar::Header::new_gnu();
                        header.set_path(*path).unwrap();
                        header.set_size(0);
                        header.set_mode(0o755);
                        header.set_entry_type(tar::EntryType::Directory);
                        header.set_cksum();
                        ar.append(&header, &[][..]).unwrap();
                    }
                    TarEntry::Whiteout(path) => {
                        let mut header = tar::Header::new_gnu();
                        header.set_path(*path).unwrap();
                        header.set_size(0);
                        header.set_mode(0o644);
                        header.set_entry_type(tar::EntryType::Regular);
                        header.set_cksum();
                        ar.append(&header, &[][..]).unwrap();
                    }
                }
            }
            ar.finish().unwrap();
        }
        encoder.finish().unwrap()
    }

    enum TarEntry<'a> {
        File(&'a str, &'a [u8]),
        Dir(&'a str),
        Whiteout(&'a str),
    }

    #[tokio::test]
    async fn unpack_single_layer() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let layer_data = make_tar_gz(&[("hello.txt", b"world"), ("subdir/nested.txt", b"data")]);
        let digest = Digest::from_bytes(&layer_data);
        store.put_blob(&digest, &layer_data).await.unwrap();

        let manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: Digest::from_bytes(b"config"),
                size: 0,
                platform: None,
            },
            layers: vec![super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
                digest,
                size: layer_data.len() as u64,
                platform: None,
            }],
        };

        let rootfs = unpack_image(&store, "test-svc", &manifest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "world"
        );
        assert_eq!(
            std::fs::read_to_string(rootfs.join("subdir/nested.txt")).unwrap(),
            "data"
        );
    }

    #[tokio::test]
    async fn whiteout_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        // Layer 1: create files
        let layer1 = make_tar_gz(&[("keep.txt", b"keep"), ("remove.txt", b"gone")]);
        let d1 = Digest::from_bytes(&layer1);
        store.put_blob(&d1, &layer1).await.unwrap();

        // Layer 2: whiteout remove.txt
        let layer2 = make_tar_gz_with_dirs(&[TarEntry::Whiteout(".wh.remove.txt")]);
        let d2 = Digest::from_bytes(&layer2);
        store.put_blob(&d2, &layer2).await.unwrap();

        let desc = |d: Digest, size: u64| super::super::manifest::Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: d,
            size,
            platform: None,
        };

        let manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: Digest::from_bytes(b"config"),
                size: 0,
                platform: None,
            },
            layers: vec![desc(d1, layer1.len() as u64), desc(d2, layer2.len() as u64)],
        };

        let rootfs = unpack_image(&store, "test-svc", &manifest).await.unwrap();
        assert!(rootfs.join("keep.txt").exists());
        assert!(!rootfs.join("remove.txt").exists());
    }

    #[tokio::test]
    async fn opaque_whiteout() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        // Layer 1: create a directory with files
        let layer1 = make_tar_gz_with_dirs(&[
            TarEntry::Dir("mydir/"),
            TarEntry::File("mydir/old.txt", b"old"),
        ]);
        let d1 = Digest::from_bytes(&layer1);
        store.put_blob(&d1, &layer1).await.unwrap();

        // Layer 2: opaque whiteout on mydir, then add new file
        let layer2 = make_tar_gz_with_dirs(&[
            TarEntry::Dir("mydir/"),
            TarEntry::Whiteout("mydir/.wh..wh..opq"),
            TarEntry::File("mydir/new.txt", b"new"),
        ]);
        let d2 = Digest::from_bytes(&layer2);
        store.put_blob(&d2, &layer2).await.unwrap();

        let desc = |d: Digest, size: u64| super::super::manifest::Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: d,
            size,
            platform: None,
        };

        let manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: Digest::from_bytes(b"config"),
                size: 0,
                platform: None,
            },
            layers: vec![desc(d1, layer1.len() as u64), desc(d2, layer2.len() as u64)],
        };

        let rootfs = unpack_image(&store, "test-svc", &manifest).await.unwrap();
        assert!(!rootfs.join("mydir/old.txt").exists());
        assert!(rootfs.join("mydir/new.txt").exists());
    }
}
