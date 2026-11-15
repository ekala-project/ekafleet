//! Pulling a pinned image into a service bundle.
//!
//! The server pins every image to a digest at apply time, so a pull never
//! asks the registry what a tag means: it verifies the signature on the
//! pinned digest, fetches that exact manifest (selecting this platform from
//! an index), the config and layers (all digest-checked), and unpacks them
//! into a staging directory that is renamed into place when complete.

use std::path::PathBuf;

use super::digest::Digest;
use super::manifest::{ImageConfig, ImageManifest, ManifestKind, Platform};
use super::reference::ImageReference;
use super::registry::{RegistryClient, RegistryError};
use super::signature::{self, SignaturePolicy};
use super::store::{IMAGE_CONFIG_FILE, ImageStore, StoreError};
use super::unpack;

/// How a fleet signature policy applies to a pull.
#[derive(Debug, Clone, Copy)]
pub struct Verification<'a> {
    pub policy: &'a SignaturePolicy,
    /// When false, a failed verification is logged and the pull proceeds.
    pub enforce: bool,
}

/// A bundle ready to run.
#[derive(Debug)]
pub struct PulledImage {
    /// The bundle directory (holding `rootfs/`).
    pub bundle: PathBuf,
    /// The image configuration (entrypoint, env, user, ...).
    pub config: ImageConfig,
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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("image {0} is not pinned to a digest")]
    NotPinned(String),
    #[error("no matching platform in image index")]
    NoPlatformMatch,
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
}

/// Pull `image` (which must carry a digest) into `service`'s bundle for that
/// digest, unless the bundle already exists.
pub async fn pull_pinned(
    client: &RegistryClient,
    store: &ImageStore,
    image: &ImageReference,
    service: &str,
    verification: Option<Verification<'_>>,
) -> Result<PulledImage, PullError> {
    let digest = image
        .digest
        .clone()
        .ok_or_else(|| PullError::NotPinned(image.to_string()))?;
    let hex = digest.hex().to_string();
    if store.has_bundle(service, &hex).await {
        return read_bundle(store, service, &hex).await;
    }

    // The signature covers the pinned (top-level) digest; check it before
    // downloading anything else.
    if let Some(v) = verification {
        match signature::verify_image_signature(client, image, &digest, v.policy).await {
            Ok(()) => {}
            Err(e) if !v.enforce => tracing::warn!(
                image = %image,
                service,
                error = %e,
                "Image signature not verified; the signature policy is advisory"
            ),
            Err(e) => return Err(e.into()),
        }
    }

    tracing::info!(image = %image, service, "Pulling image");
    let manifest = match store.get_manifest(&hex).await? {
        Some(raw) => parse_manifest(&raw)?,
        None => {
            let raw = fetch_platform_manifest(client, image).await?;
            let manifest = parse_manifest(&raw)?;
            store.put_manifest(&hex, &raw).await?;
            manifest
        }
    };

    for blob in manifest.layers.iter().chain([&manifest.config]) {
        if store.has_blob(&blob.digest).await {
            continue;
        }
        tracing::debug!(digest = %blob.digest, size = blob.size, "Downloading blob");
        let fetched = client.fetch_blob(image, &blob.digest).await?;
        store.put_blob(&fetched.digest, &fetched.data).await?;
    }
    let config_raw = store.get_blob(&manifest.config.digest).await?;
    let config = parse_config(&config_raw)?;

    let staging = store.staging_path(service, &hex);
    let _ = tokio::fs::remove_dir_all(&staging).await;
    let rootfs = staging.join("rootfs");
    unpack::unpack_image(store, &manifest, &rootfs).await?;
    // systemd-nspawn wants a /usr in the tree it boots into.
    if tokio::fs::symlink_metadata(rootfs.join("usr"))
        .await
        .is_err()
    {
        tokio::fs::create_dir(rootfs.join("usr")).await?;
    }
    tokio::fs::write(staging.join(IMAGE_CONFIG_FILE), &config_raw).await?;
    let bundle = store.bundle_path(service, &hex);
    let _ = tokio::fs::remove_dir_all(&bundle).await;
    tokio::fs::rename(&staging, &bundle).await?;

    tracing::info!(
        image = %image,
        service,
        layers = manifest.layers.len(),
        "Image pulled and unpacked"
    );
    Ok(PulledImage { bundle, config })
}

/// A complete bundle's image config.
pub async fn read_bundle(
    store: &ImageStore,
    service: &str,
    hex: &str,
) -> Result<PulledImage, PullError> {
    let bundle = store.bundle_path(service, hex);
    let raw = tokio::fs::read(bundle.join(IMAGE_CONFIG_FILE)).await?;
    Ok(PulledImage {
        bundle,
        config: parse_config(&raw)?,
    })
}

/// The image manifest to run for `image`: the manifest itself, or this
/// platform's entry of an index (fetched by its digest).
async fn fetch_platform_manifest(
    client: &RegistryClient,
    image: &ImageReference,
) -> Result<Vec<u8>, PullError> {
    let resp = client.fetch_manifest(image).await?;
    let ManifestKind::Index(index) = resp.kind else {
        return Ok(resp.raw);
    };
    let entry = index
        .select_platform(&Platform::current())
        .ok_or(PullError::NoPlatformMatch)?;
    let platform_ref = by_digest(image, &entry.digest);
    let resp = client.fetch_manifest(&platform_ref).await?;
    match resp.kind {
        ManifestKind::Manifest(_) => Ok(resp.raw),
        ManifestKind::Index(_) => Err(PullError::ManifestParse(
            "nested image index not supported".into(),
        )),
    }
}

/// `image` in the same repository, referenced by `digest` alone.
fn by_digest(image: &ImageReference, digest: &Digest) -> ImageReference {
    ImageReference {
        registry: image.registry.clone(),
        repository: image.repository.clone(),
        tag: None,
        digest: Some(digest.clone()),
    }
}

fn parse_manifest(data: &[u8]) -> Result<ImageManifest, PullError> {
    serde_json::from_slice(data).map_err(|e| PullError::ManifestParse(e.to_string()))
}

fn parse_config(data: &[u8]) -> Result<ImageConfig, PullError> {
    serde_json::from_slice(data).map_err(|e| PullError::ManifestParse(format!("image config: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unpinned_images_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path());
        store.init().await.unwrap();
        let client = RegistryClient::new(super::super::auth::Credentials::Anonymous);
        let image: ImageReference = "registry.invalid/app:v1".parse().unwrap();
        let err = pull_pinned(&client, &store, &image, "svc", None)
            .await
            .unwrap_err();
        assert!(matches!(err, PullError::NotPinned(_)), "{err}");
    }

    #[tokio::test]
    async fn existing_bundles_are_used_without_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path());
        store.init().await.unwrap();
        let hex = "cd".repeat(32);
        let bundle = store.bundle_path("svc", &hex);
        tokio::fs::create_dir_all(bundle.join("rootfs"))
            .await
            .unwrap();
        tokio::fs::write(
            bundle.join(IMAGE_CONFIG_FILE),
            br#"{"config":{"Entrypoint":["/bin/app"]}}"#,
        )
        .await
        .unwrap();

        let client = RegistryClient::new(super::super::auth::Credentials::Anonymous);
        let image: ImageReference = format!("registry.invalid/app@sha256:{hex}")
            .parse()
            .unwrap();
        let pulled = pull_pinned(&client, &store, &image, "svc", None)
            .await
            .unwrap();
        assert_eq!(pulled.bundle, bundle);
        assert_eq!(
            pulled.config.config.unwrap().entrypoint.unwrap(),
            vec!["/bin/app".to_string()]
        );
    }

    #[test]
    fn platform_manifests_are_fetched_by_digest_in_the_same_repository() {
        let image: ImageReference = "ghcr.io/org/app:v1".parse().unwrap();
        let digest = Digest::from_bytes(b"platform");
        let r = by_digest(&image, &digest);
        assert_eq!(r.to_string(), format!("ghcr.io/org/app@{digest}"));
    }
}
