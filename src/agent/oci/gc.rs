//! Garbage collection for the OCI image store.
//!
//! Keeps the bundles in use (per service and pinned digest), the manifests
//! of those digests and the blobs they reference; removes everything else,
//! including leftover staging directories.

use std::collections::HashSet;

use super::digest::Digest;
use super::manifest::ImageManifest;
use super::store::{ImageStore, StoreError};

/// Result of a garbage collection run.
#[derive(Debug, Default)]
pub struct GcResult {
    /// Number of blobs removed.
    pub blobs_removed: usize,
    /// Number of bundles removed.
    pub bundles_removed: usize,
    /// Total bytes freed by removed blobs.
    pub bytes_freed: u64,
}

/// Remove every bundle not in `keep` (as `(service, digest hex)`), and the
/// manifests and blobs no kept bundle needs.
///
/// Must not run while a pull is writing to the store.
pub async fn collect(
    store: &ImageStore,
    keep: &HashSet<(String, String)>,
) -> Result<GcResult, StoreError> {
    let mut result = GcResult::default();

    let mut services = HashSet::new();
    for (service, name) in store.list_bundles().await? {
        if !keep.contains(&(service.clone(), name.clone())) {
            store.remove_bundle(&service, &name).await?;
            result.bundles_removed += 1;
            tracing::debug!(service, bundle = name, "Removed unused bundle");
        }
        services.insert(service);
    }
    for service in services {
        store.remove_service_dir_if_empty(&service).await;
    }

    let kept_digests: HashSet<&str> = keep.iter().map(|(_, hex)| hex.as_str()).collect();
    let mut referenced: HashSet<Digest> = HashSet::new();
    for key in store.list_manifests().await? {
        if !kept_digests.contains(key.as_str()) {
            store.remove_manifest(&key).await?;
            continue;
        }
        let Some(raw) = store.get_manifest(&key).await? else {
            continue;
        };
        match serde_json::from_slice::<ImageManifest>(&raw) {
            Ok(manifest) => {
                referenced.insert(manifest.config.digest.clone());
                referenced.extend(manifest.layers.into_iter().map(|l| l.digest));
            }
            // Re-fetched on the next pull of this digest.
            Err(_) => store.remove_manifest(&key).await?,
        }
    }

    for digest in store.list_blobs().await? {
        if referenced.contains(&digest) {
            continue;
        }
        if let Ok(meta) = tokio::fs::metadata(store.blob_path(&digest)).await {
            result.bytes_freed += meta.len();
        }
        store.remove_blob(&digest).await?;
        result.blobs_removed += 1;
    }

    if result.blobs_removed > 0 || result.bundles_removed > 0 {
        tracing::info!(
            blobs = result.blobs_removed,
            bundles = result.bundles_removed,
            bytes_freed = result.bytes_freed,
            "Image garbage collection complete"
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::oci::manifest::Descriptor;
    use crate::agent::oci::store::IMAGE_CONFIG_FILE;

    fn descriptor(data: &[u8]) -> Descriptor {
        Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: Digest::from_bytes(data),
            size: data.len() as u64,
            platform: None,
            annotations: None,
        }
    }

    /// Store an image (manifest, config and one layer per entry) and a
    /// complete bundle of it for `service`; returns the digest hex.
    async fn add_image(store: &ImageStore, service: &str, layers: &[&[u8]]) -> String {
        let config = format!("config of {service}");
        store
            .put_blob(&Digest::from_bytes(config.as_bytes()), config.as_bytes())
            .await
            .unwrap();
        for layer in layers {
            store
                .put_blob(&Digest::from_bytes(layer), layer)
                .await
                .unwrap();
        }
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: descriptor(config.as_bytes()),
            layers: layers.iter().map(|l| descriptor(l)).collect(),
        };
        let raw = serde_json::to_vec(&manifest).unwrap();
        let hex = Digest::from_bytes(&raw).hex().to_string();
        store.put_manifest(&hex, &raw).await.unwrap();
        let bundle = store.bundle_path(service, &hex);
        tokio::fs::create_dir_all(bundle.join("rootfs"))
            .await
            .unwrap();
        tokio::fs::write(bundle.join(IMAGE_CONFIG_FILE), b"{}")
            .await
            .unwrap();
        hex
    }

    #[tokio::test]
    async fn unused_bundles_and_their_exclusive_blobs_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let current = add_image(&store, "web", &[b"base", b"app v2"]).await;
        let old = add_image(&store, "web", &[b"base", b"app v1"]).await;
        let gone = add_image(&store, "removed", &[b"other"]).await;
        tokio::fs::create_dir_all(store.staging_path("web", "abandoned"))
            .await
            .unwrap();

        let keep = HashSet::from([("web".to_string(), current.clone())]);
        let result = collect(&store, &keep).await.unwrap();

        assert!(store.has_bundle("web", &current).await);
        assert!(!store.has_bundle("web", &old).await);
        assert!(!store.has_bundle("removed", &gone).await);
        assert_eq!(result.bundles_removed, 3);
        assert_eq!(
            store.list_bundles().await.unwrap(),
            vec![("web".to_string(), current.clone())]
        );
        assert_eq!(store.list_manifests().await.unwrap(), vec![current]);

        // The shared base layer and config stay; v1 and the removed image's
        // blobs go.
        assert!(store.has_blob(&Digest::from_bytes(b"base")).await);
        assert!(store.has_blob(&Digest::from_bytes(b"app v2")).await);
        assert!(!store.has_blob(&Digest::from_bytes(b"app v1")).await);
        assert!(!store.has_blob(&Digest::from_bytes(b"other")).await);
        assert_eq!(result.blobs_removed, 3);
    }

    #[tokio::test]
    async fn the_same_digest_is_kept_per_service() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();
        let hex = add_image(&store, "a", &[b"layer"]).await;
        let bundle_b = store.bundle_path("b", &hex);
        tokio::fs::create_dir_all(&bundle_b).await.unwrap();
        tokio::fs::write(bundle_b.join(IMAGE_CONFIG_FILE), b"{}")
            .await
            .unwrap();

        let keep = HashSet::from([("b".to_string(), hex.clone())]);
        collect(&store, &keep).await.unwrap();
        assert!(!store.has_bundle("a", &hex).await);
        assert!(store.has_bundle("b", &hex).await);
        assert!(store.has_blob(&Digest::from_bytes(b"layer")).await);
    }

    #[tokio::test]
    async fn empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();
        let result = collect(&store, &HashSet::new()).await.unwrap();
        assert_eq!(result.blobs_removed, 0);
        assert_eq!(result.bundles_removed, 0);
    }
}
