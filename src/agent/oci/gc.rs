//! Garbage collection for the OCI image store.
//!
//! Removes blobs that are not referenced by any active service's manifest
//! and removes bundles for services that are no longer desired.

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
    /// Total bytes freed (approximate, from blob sizes).
    pub bytes_freed: u64,
}

/// Run garbage collection on the image store.
///
/// `active_services` is the set of service names that are currently desired.
/// `active_manifests` maps service names to their resolved manifest (used to
/// determine which blobs are still referenced).
/// `retained_manifests` are historical manifests kept for rollback — their
/// referenced blobs are also preserved.
///
/// Blobs not referenced by any active or retained manifest are deleted.
/// Bundles for services not in `active_services` are removed.
pub async fn collect(
    store: &ImageStore,
    active_services: &HashSet<String>,
    active_manifests: &[(String, ImageManifest)],
    retained_manifests: &[ImageManifest],
) -> Result<GcResult, StoreError> {
    let mut result = GcResult::default();

    // Build set of all referenced digests (active + retained for rollback)
    let mut referenced: HashSet<Digest> = HashSet::new();
    for (_, manifest) in active_manifests {
        referenced.insert(manifest.config.digest.clone());
        for layer in &manifest.layers {
            referenced.insert(layer.digest.clone());
        }
    }
    for manifest in retained_manifests {
        referenced.insert(manifest.config.digest.clone());
        for layer in &manifest.layers {
            referenced.insert(layer.digest.clone());
        }
    }

    // Remove unreferenced blobs
    let all_blobs = store.list_blobs().await?;
    for digest in &all_blobs {
        if !referenced.contains(digest) {
            // Get size before removing
            if let Ok(data) = store.get_blob(digest).await {
                result.bytes_freed += data.len() as u64;
            }
            store.remove_blob(digest).await?;
            result.blobs_removed += 1;
            tracing::debug!(digest = %digest, "Removed unreferenced blob");
        }
    }

    // Remove bundles and history for inactive services
    let all_bundles = store.list_bundles().await?;
    for name in &all_bundles {
        if !active_services.contains(name) {
            store.remove_bundle(name).await?;
            store.remove_history(name).await?;
            result.bundles_removed += 1;
            tracing::debug!(service = name, "Removed inactive bundle");
        }
    }

    if result.blobs_removed > 0 || result.bundles_removed > 0 {
        tracing::info!(
            blobs = result.blobs_removed,
            bundles = result.bundles_removed,
            bytes_freed = result.bytes_freed,
            "Garbage collection complete"
        );
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::oci::manifest::Descriptor;

    fn make_descriptor(data: &[u8]) -> Descriptor {
        Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: Digest::from_bytes(data),
            size: data.len() as u64,
            platform: None,
        }
    }

    #[tokio::test]
    async fn gc_removes_unreferenced_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        // Store some blobs
        let active_data = b"active layer";
        let orphan_data = b"orphan layer";
        let config_data = b"config";

        let active_digest = Digest::from_bytes(active_data);
        let orphan_digest = Digest::from_bytes(orphan_data);
        let config_digest = Digest::from_bytes(config_data);

        store.put_blob(&active_digest, active_data).await.unwrap();
        store.put_blob(&orphan_digest, orphan_data).await.unwrap();
        store.put_blob(&config_digest, config_data).await.unwrap();

        // Only the active layer and config are referenced
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: config_digest.clone(),
                size: config_data.len() as u64,
                platform: None,
            },
            layers: vec![make_descriptor(active_data)],
        };

        let active_services: HashSet<String> = ["test-svc".to_string()].into();
        let result = collect(
            &store,
            &active_services,
            &[("test-svc".to_string(), manifest)],
            &[],
        )
        .await
        .unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert!(store.has_blob(&active_digest).await);
        assert!(store.has_blob(&config_digest).await);
        assert!(!store.has_blob(&orphan_digest).await);
    }

    #[tokio::test]
    async fn gc_removes_inactive_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        // Create bundles
        let active_rootfs = store.rootfs_path("active-svc");
        let inactive_rootfs = store.rootfs_path("inactive-svc");
        tokio::fs::create_dir_all(&active_rootfs).await.unwrap();
        tokio::fs::create_dir_all(&inactive_rootfs).await.unwrap();

        let active_services: HashSet<String> = ["active-svc".to_string()].into();
        let result = collect(&store, &active_services, &[], &[]).await.unwrap();

        assert_eq!(result.bundles_removed, 1);
        assert!(store.has_bundle("active-svc").await);
        assert!(!store.has_bundle("inactive-svc").await);
    }

    #[tokio::test]
    async fn gc_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let result = collect(&store, &HashSet::new(), &[], &[]).await.unwrap();
        assert_eq!(result.blobs_removed, 0);
        assert_eq!(result.bundles_removed, 0);
    }

    #[tokio::test]
    async fn gc_retains_blobs_from_retained_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        // Store blobs for current and previous image versions
        let current_layer = b"current layer";
        let previous_layer = b"previous layer";
        let config_data = b"config";
        let prev_config_data = b"prev config";

        let current_digest = Digest::from_bytes(current_layer);
        let previous_digest = Digest::from_bytes(previous_layer);
        let config_digest = Digest::from_bytes(config_data);
        let prev_config_digest = Digest::from_bytes(prev_config_data);

        store
            .put_blob(&current_digest, current_layer)
            .await
            .unwrap();
        store
            .put_blob(&previous_digest, previous_layer)
            .await
            .unwrap();
        store.put_blob(&config_digest, config_data).await.unwrap();
        store
            .put_blob(&prev_config_digest, prev_config_data)
            .await
            .unwrap();

        // Current manifest references current blobs
        let active_manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: make_descriptor(config_data),
            layers: vec![make_descriptor(current_layer)],
        };

        // Previous manifest references previous blobs (retained for rollback)
        let retained_manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: make_descriptor(prev_config_data),
            layers: vec![make_descriptor(previous_layer)],
        };

        let active_services: HashSet<String> = ["test-svc".to_string()].into();
        let result = collect(
            &store,
            &active_services,
            &[("test-svc".to_string(), active_manifest)],
            &[retained_manifest],
        )
        .await
        .unwrap();

        // No blobs should be removed — all are referenced
        assert_eq!(result.blobs_removed, 0);
        assert!(store.has_blob(&current_digest).await);
        assert!(store.has_blob(&previous_digest).await);
        assert!(store.has_blob(&config_digest).await);
        assert!(store.has_blob(&prev_config_digest).await);
    }

    #[tokio::test]
    async fn gc_without_retention_removes_previous() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().join("oci"));
        store.init().await.unwrap();

        let current_layer = b"current";
        let orphan_layer = b"orphan";
        let config_data = b"cfg";

        let current_digest = Digest::from_bytes(current_layer);
        let orphan_digest = Digest::from_bytes(orphan_layer);
        let config_digest = Digest::from_bytes(config_data);

        store
            .put_blob(&current_digest, current_layer)
            .await
            .unwrap();
        store.put_blob(&orphan_digest, orphan_layer).await.unwrap();
        store.put_blob(&config_digest, config_data).await.unwrap();

        let active_manifest = ImageManifest {
            schema_version: 2,
            media_type: None,
            config: make_descriptor(config_data),
            layers: vec![make_descriptor(current_layer)],
        };

        let active_services: HashSet<String> = ["test-svc".to_string()].into();
        // Empty retained_manifests — no rollback retention
        let result = collect(
            &store,
            &active_services,
            &[("test-svc".to_string(), active_manifest)],
            &[],
        )
        .await
        .unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert!(store.has_blob(&current_digest).await);
        assert!(!store.has_blob(&orphan_digest).await);
    }
}
