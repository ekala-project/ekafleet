//! Image pull policies and caching logic.
//!
//! Controls when images are fetched from the registry vs served from
//! the local store.

use serde::{Deserialize, Serialize};

use super::digest::Digest;
use super::manifest::{ImageManifest, ManifestKind, Platform};
use super::reference::ImageReference;
use super::registry::{RegistryClient, RegistryError};
use super::signature::{self, SignaturePolicy};
use super::store::{ImageStore, StoreError};
use super::unpack;

/// Controls when images are pulled from the registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PullPolicy {
    /// Always check the registry for a newer image.
    #[default]
    Always,
    /// Only pull if the image is not present locally.
    IfNotPresent,
    /// Never pull from the registry; fail if not present locally.
    Never,
}

/// Result of a pull operation.
#[derive(Debug)]
pub struct PullResult {
    /// The resolved manifest digest.
    pub digest: Digest,
    /// Path to the unpacked rootfs.
    pub rootfs: std::path::PathBuf,
    /// Whether the image was freshly pulled (true) or served from cache (false).
    pub pulled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PullError {
    #[error("registry error: {0}")]
    Registry(#[from] RegistryError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("unpack error: {0}")]
    Unpack(#[from] unpack::UnpackError),
    #[error("signature error: {0}")]
    Signature(#[from] signature::SignatureError),
    #[error("no matching platform in image index")]
    NoPlatformMatch,
    #[error("image not found locally and pull policy is Never")]
    NotFoundLocally,
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
}

/// Pull an image for a service according to the given policy.
///
/// This is the main entry point for the image management pipeline:
///   1. Check local cache based on policy
///   2. Fetch manifest (resolving multi-platform indexes)
///   3. Verify cosign signature (if `signature_policy` is set)
///   4. Download missing layers
///   5. Unpack into a rootfs bundle
pub async fn pull_image(
    client: &RegistryClient,
    store: &ImageStore,
    image: &ImageReference,
    service_name: &str,
    policy: &PullPolicy,
    signature_policy: Option<&SignaturePolicy>,
) -> Result<PullResult, PullError> {
    let manifest_key = manifest_cache_key(image);

    match policy {
        PullPolicy::Never => {
            // Must be present locally
            let cached = store.get_manifest(&manifest_key).await?;
            let raw = cached.ok_or(PullError::NotFoundLocally)?;
            let manifest = parse_single_manifest(&raw)?;
            let digest = Digest::from_bytes(&raw);

            // Ensure bundle exists
            if !store.has_bundle(service_name).await {
                unpack::unpack_image(store, service_name, &manifest).await?;
            }

            Ok(PullResult {
                digest,
                rootfs: store.rootfs_path(service_name),
                pulled: false,
            })
        }

        PullPolicy::IfNotPresent => {
            // Check if we have a cached manifest and bundle
            if let Some(raw) = store.get_manifest(&manifest_key).await? {
                if store.has_bundle(service_name).await {
                    let digest = Digest::from_bytes(&raw);
                    return Ok(PullResult {
                        digest,
                        rootfs: store.rootfs_path(service_name),
                        pulled: false,
                    });
                }
            }

            // Not present — pull
            do_pull(
                client,
                store,
                image,
                service_name,
                &manifest_key,
                signature_policy,
            )
            .await
        }

        PullPolicy::Always => {
            // Check if remote digest matches local
            if let Some(raw) = store.get_manifest(&manifest_key).await? {
                let local_digest = Digest::from_bytes(&raw);
                if let Ok(Some(remote_digest)) = client.head_manifest(image).await {
                    if local_digest == remote_digest && store.has_bundle(service_name).await {
                        tracing::debug!(
                            image = %image,
                            digest = %local_digest,
                            "Image up-to-date"
                        );
                        return Ok(PullResult {
                            digest: local_digest,
                            rootfs: store.rootfs_path(service_name),
                            pulled: false,
                        });
                    }
                }
            }

            do_pull(
                client,
                store,
                image,
                service_name,
                &manifest_key,
                signature_policy,
            )
            .await
        }
    }
}

/// Perform the actual pull: fetch manifest, verify signature, download layers, unpack.
async fn do_pull(
    client: &RegistryClient,
    store: &ImageStore,
    image: &ImageReference,
    service_name: &str,
    manifest_key: &str,
    signature_policy: Option<&SignaturePolicy>,
) -> Result<PullResult, PullError> {
    tracing::info!(image = %image, service = service_name, "Pulling image");

    // Fetch manifest (may be an index or a single manifest)
    let resp = client.fetch_manifest(image).await?;
    let (manifest, manifest_raw, manifest_digest) = match resp.kind {
        ManifestKind::Manifest(m) => (m, resp.raw, resp.digest),
        ManifestKind::Index(idx) => {
            // Resolve platform-specific manifest
            let target = Platform::current();
            let desc = idx
                .select_platform(&target)
                .ok_or(PullError::NoPlatformMatch)?;

            // Fetch the platform-specific manifest
            let mut platform_ref = image.clone();
            platform_ref.digest = Some(desc.digest.clone());
            platform_ref.tag = None;

            let platform_resp = client.fetch_manifest(&platform_ref).await?;
            match platform_resp.kind {
                ManifestKind::Manifest(m) => (m, platform_resp.raw, platform_resp.digest),
                ManifestKind::Index(_) => {
                    return Err(PullError::ManifestParse(
                        "nested image index not supported".into(),
                    ));
                }
            }
        }
    };

    // Verify cosign signature before downloading layers
    if let Some(sig_policy) = signature_policy {
        tracing::info!(
            image = %image,
            digest = %manifest_digest,
            "Verifying image signature"
        );
        signature::verify_image_signature(client, image, &manifest_digest, sig_policy).await?;
    }

    // Cache the manifest
    store.put_manifest(manifest_key, &manifest_raw).await?;

    // Download missing layers
    for (i, layer) in manifest.layers.iter().enumerate() {
        if store.has_blob(&layer.digest).await {
            tracing::debug!(layer = i, digest = %layer.digest, "Layer already cached");
            continue;
        }

        tracing::info!(
            layer = i,
            digest = %layer.digest,
            size = layer.size,
            "Downloading layer"
        );
        let blob = client.fetch_blob(image, &layer.digest).await?;
        store.put_blob(&blob.digest, &blob.data).await?;
    }

    // Download config blob
    if !store.has_blob(&manifest.config.digest).await {
        let config_blob = client.fetch_blob(image, &manifest.config.digest).await?;
        store
            .put_blob(&config_blob.digest, &config_blob.data)
            .await?;
    }

    // Unpack layers into rootfs
    unpack::unpack_image(store, service_name, &manifest).await?;

    tracing::info!(
        image = %image,
        service = service_name,
        digest = %manifest_digest,
        layers = manifest.layers.len(),
        "Image pulled and unpacked"
    );

    Ok(PullResult {
        digest: manifest_digest,
        rootfs: store.rootfs_path(service_name),
        pulled: true,
    })
}

/// Generate a stable cache key for a manifest based on the image reference.
fn manifest_cache_key(image: &ImageReference) -> String {
    // Use digest if pinned, otherwise registry/repo:tag
    if let Some(d) = &image.digest {
        d.hex().to_string()
    } else {
        let tag = image.tag.as_deref().unwrap_or("latest");
        // Sanitize for filesystem: replace / with _
        format!("{}_{}__{tag}", image.registry, image.repository)
            .replace('/', "_")
            .replace(':', "_")
    }
}

/// Parse raw manifest bytes as a single-platform manifest.
fn parse_single_manifest(data: &[u8]) -> Result<ImageManifest, PullError> {
    serde_json::from_slice(data).map_err(|e| PullError::ManifestParse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_key_with_digest() {
        let image: ImageReference = format!("ghcr.io/org/app@sha256:{}", "a".repeat(64))
            .parse()
            .unwrap();
        let key = manifest_cache_key(&image);
        assert_eq!(key, "a".repeat(64));
    }

    #[test]
    fn manifest_key_with_tag() {
        let image: ImageReference = "ghcr.io/org/app:v1.0".parse().unwrap();
        let key = manifest_cache_key(&image);
        assert_eq!(key, "ghcr.io_org_app__v1.0");
    }

    #[test]
    fn manifest_key_default_tag() {
        let image: ImageReference = "ghcr.io/org/app".parse().unwrap();
        let key = manifest_cache_key(&image);
        assert_eq!(key, "ghcr.io_org_app__latest");
    }

    #[test]
    fn pull_policy_default() {
        assert_eq!(PullPolicy::default(), PullPolicy::Always);
    }

    #[test]
    fn pull_policy_serde() {
        let json = serde_json::to_string(&PullPolicy::IfNotPresent).unwrap();
        let parsed: PullPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PullPolicy::IfNotPresent);
    }
}
