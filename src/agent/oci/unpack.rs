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

/// Unpack an image's layers, in order (bottom-up), into `rootfs`, which must
/// not exist yet; whiteout files remove entries from lower layers.
pub async fn unpack_image(
    store: &ImageStore,
    manifest: &ImageManifest,
    rootfs: &Path,
) -> Result<(), UnpackError> {
    tokio::fs::create_dir_all(rootfs).await?;
    // Image files keep their owners when unpacked by root (as the agent
    // runs); an unprivileged unpack (tests) cannot chown.
    let as_root = {
        use std::os::unix::fs::MetadataExt;
        tokio::fs::metadata(rootfs).await?.uid() == 0
    };

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
        let rootfs = rootfs.to_path_buf();
        tokio::task::spawn_blocking(move || unpack_layer(&blob, &rootfs, as_root))
            .await
            .map_err(|e| UnpackError::Tar(format!("task join error: {e}")))??;
    }

    tracing::debug!(
        rootfs = %rootfs.display(),
        layers = manifest.layers.len(),
        "Image unpacked"
    );
    Ok(())
}

/// Unpack a single (optionally gzipped) tar layer into the rootfs, handling
/// whiteouts.
///
/// The layer is untrusted: entries may not escape the rootfs, whiteouts are
/// only applied through real directories (an earlier layer may have planted
/// a symlink to a host path), and device nodes are not created.
fn unpack_layer(data: &[u8], rootfs: &Path, as_root: bool) -> Result<(), UnpackError> {
    if data.starts_with(&[0x1f, 0x8b]) {
        unpack_entries(Archive::new(GzDecoder::new(data)), rootfs, as_root)
    } else {
        unpack_entries(Archive::new(data), rootfs, as_root)
    }
}

fn unpack_entries<R: std::io::Read>(
    mut archive: Archive<R>,
    rootfs: &Path,
    as_root: bool,
) -> Result<(), UnpackError> {
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(as_root);
    archive.set_preserve_mtime(true);
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

        if matches!(
            entry.header().entry_type(),
            tar::EntryType::Char | tar::EntryType::Block
        ) {
            tracing::warn!(path = %path.display(), "Skipping device node in image layer");
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Handle OCI whiteout files
        if file_name == ".wh..wh..opq" {
            // Opaque whiteout: delete all existing contents of the parent directory
            match real_parent(rootfs, &path) {
                Some(dir) => remove_dir_contents(&dir)?,
                None => {
                    tracing::debug!(path = %path.display(), "Opaque whiteout of a missing or non-directory path")
                }
            }
            continue;
        }

        if let Some(target) = file_name.strip_prefix(".wh.") {
            // Regular whiteout: delete the named entry
            if target.is_empty() || target == "." || target == ".." {
                continue;
            }
            let Some(dir) = real_parent(rootfs, &path) else {
                tracing::debug!(path = %path.display(), "Whiteout under a missing or non-directory path");
                continue;
            };
            remove_entry(&dir.join(target))
                .map_err(|e| UnpackError::Tar(format!("whiteout removal failed: {e}")))?;
            continue;
        }

        // Normal entry: unpack_in refuses entries whose parent resolves
        // outside the rootfs, and replaces (rather than follows) an existing
        // final component.
        entry
            .unpack_in(rootfs)
            .map_err(|e| UnpackError::Tar(format!("unpack entry {}: {e}", path.display())))?;
    }

    Ok(())
}

/// The directory containing `rel` inside `rootfs`, provided every component
/// of it is a real directory (never a symlink).
fn real_parent(rootfs: &Path, rel: &Path) -> Option<PathBuf> {
    let mut dir = rootfs.to_path_buf();
    for component in rel.parent()?.components() {
        match component {
            std::path::Component::Normal(name) => dir.push(name),
            std::path::Component::CurDir => continue,
            _ => return None,
        }
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {}
            _ => return None,
        }
    }
    Some(dir)
}

/// Remove a file, symlink (not its target) or directory tree.
fn remove_entry(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Remove all contents of a directory without removing the directory itself.
fn remove_dir_contents(dir: &Path) -> Result<(), UnpackError> {
    for entry in std::fs::read_dir(dir)? {
        remove_entry(&entry?.path())?;
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
                annotations: None,
            },
            layers: vec![super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
                digest,
                size: layer_data.len() as u64,
                platform: None,
                annotations: None,
            }],
        };

        let rootfs = dir.path().join("rootfs");
        unpack_image(&store, &manifest, &rootfs).await.unwrap();
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
            annotations: None,
        };

        let manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: Digest::from_bytes(b"config"),
                size: 0,
                platform: None,
                annotations: None,
            },
            layers: vec![desc(d1, layer1.len() as u64), desc(d2, layer2.len() as u64)],
        };

        let rootfs = dir.path().join("rootfs");
        unpack_image(&store, &manifest, &rootfs).await.unwrap();
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
            annotations: None,
        };

        let manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: Digest::from_bytes(b"config"),
                size: 0,
                platform: None,
                annotations: None,
            },
            layers: vec![desc(d1, layer1.len() as u64), desc(d2, layer2.len() as u64)],
        };

        let rootfs = dir.path().join("rootfs");
        unpack_image(&store, &manifest, &rootfs).await.unwrap();
        assert!(!rootfs.join("mydir/old.txt").exists());
        assert!(rootfs.join("mydir/new.txt").exists());
    }

    fn manifest_for(store_layers: &[(Digest, u64)]) -> ImageManifest {
        ImageManifest {
            schema_version: 2,
            media_type: None,
            config: super::super::manifest::Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: Digest::from_bytes(b"config"),
                size: 0,
                platform: None,
                annotations: None,
            },
            layers: store_layers
                .iter()
                .map(|(digest, size)| super::super::manifest::Descriptor {
                    media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
                    digest: digest.clone(),
                    size: *size,
                    platform: None,
                    annotations: None,
                })
                .collect(),
        }
    }

    /// An uncompressed layer holding one symlink.
    fn symlink_layer(path: &str, target: &Path) -> Vec<u8> {
        let mut ar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        ar.append_link(&mut header, path, target).unwrap();
        ar.into_inner().unwrap()
    }

    #[tokio::test]
    async fn whiteouts_never_follow_symlinks_out_of_the_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir(&host).unwrap();
        std::fs::write(host.join("victim"), b"precious").unwrap();
        std::fs::write(host.join("other"), b"precious").unwrap();

        // Layer 1 plants a symlink to the host directory; layer 2 whites
        // out entries through it, both singly and opaquely.
        let layer1 = symlink_layer("evil", &host);
        let layer2 = make_tar_gz_with_dirs(&[
            TarEntry::Whiteout("evil/.wh.victim"),
            TarEntry::Whiteout("evil/.wh..wh..opq"),
        ]);
        let (d1, d2) = (Digest::from_bytes(&layer1), Digest::from_bytes(&layer2));
        store.put_blob(&d1, &layer1).await.unwrap();
        store.put_blob(&d2, &layer2).await.unwrap();
        let manifest = manifest_for(&[(d1, layer1.len() as u64), (d2, layer2.len() as u64)]);

        let rootfs = dir.path().join("rootfs");
        unpack_image(&store, &manifest, &rootfs).await.unwrap();
        assert!(host.join("victim").exists());
        assert!(host.join("other").exists());
        // The symlink itself is image content and stays.
        assert!(
            std::fs::symlink_metadata(rootfs.join("evil"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[tokio::test]
    async fn uncompressed_layers_unpack_and_whiteouts_remove_symlinks_themselves() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir(&host).unwrap();

        let layer1 = symlink_layer("link", &host);
        let layer2 = make_tar_gz_with_dirs(&[TarEntry::Whiteout(".wh.link")]);
        let (d1, d2) = (Digest::from_bytes(&layer1), Digest::from_bytes(&layer2));
        store.put_blob(&d1, &layer1).await.unwrap();
        store.put_blob(&d2, &layer2).await.unwrap();
        let manifest = manifest_for(&[(d1, layer1.len() as u64), (d2, layer2.len() as u64)]);

        let rootfs = dir.path().join("rootfs");
        unpack_image(&store, &manifest, &rootfs).await.unwrap();
        assert!(std::fs::symlink_metadata(rootfs.join("link")).is_err());
        assert!(host.exists());
    }
}
