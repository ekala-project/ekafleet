//! OCI image management for ekafleet agents.
//!
//! Provides a native OCI registry client, content-addressable image store,
//! and layer unpacking for systemd-nspawn execution.
//!
//! # Architecture
//!
//! ```text
//! ImageReference (parsed image string)
//!   → RegistryClient (fetch manifest + blobs with auth)
//!     → ImageStore (content-addressed local cache)
//!       → unpack (extract layers into rootfs)
//!         → bundle (generate config.json for nspawn)
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use ekafleet::agent::oci::{ImageManager, pull::PullPolicy};
//!
//! let mgr = ImageManager::new("/var/lib/ekafleet/oci", credentials);
//! let result = mgr.pull("ghcr.io/org/app:v1.0", "my-service", &PullPolicy::IfNotPresent, None).await?;
//! // result.rootfs is the unpacked image ready for nspawn
//! ```

pub mod auth;
pub mod bundle;
pub mod digest;
pub mod gc;
pub mod manifest;
pub mod pull;
pub mod reference;
pub mod registry;
pub mod signature;
pub mod store;
pub mod unpack;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use auth::Credentials;
use digest::Digest;
use manifest::ImageManifest;
use pull::{PullError, PullPolicy, PullResult};
use reference::ImageReference;
use registry::RegistryClient;
use signature::{SignatureError, SignaturePolicy};
use store::ImageStore;

/// A fleet-wide image signature policy applied to every image pulled by this
/// manager, independent of any per-service configuration.
pub struct FleetSignaturePolicy {
    /// The trusted signing key used to verify every image.
    pub policy: SignaturePolicy,
    /// When true, an image without a valid signature is rejected. When false,
    /// verification failures are logged but the pull proceeds.
    pub enforce: bool,
}

/// High-level OCI image manager combining registry, store, and unpacking.
pub struct ImageManager {
    client: RegistryClient,
    store: ImageStore,
    /// Optional fleet-wide signature policy applied to every pull.
    fleet_signature_policy: Option<FleetSignaturePolicy>,
}

/// Result of resolving an image's config.
pub struct ResolvedImage {
    /// Pull result with digest and rootfs path.
    pub pull: PullResult,
    /// Parsed image configuration (entrypoint, env, etc.).
    pub config: manifest::ImageConfig,
}

impl ImageManager {
    /// Create a new image manager.
    ///
    /// `store_path` is the root directory for the OCI store
    /// (e.g. `/var/lib/ekafleet/oci`).
    pub fn new(store_path: impl Into<PathBuf>, credentials: Credentials) -> Self {
        Self {
            client: RegistryClient::new(credentials),
            store: ImageStore::new(store_path),
            fleet_signature_policy: None,
        }
    }

    /// Apply a fleet-wide signature policy that verifies every image this
    /// manager pulls, unless a per-call policy is provided to [`Self::pull`].
    pub fn with_fleet_signature_policy(mut self, policy: FleetSignaturePolicy) -> Self {
        self.fleet_signature_policy = Some(policy);
        self
    }

    /// Initialize the store directories.
    pub async fn init(&self) -> Result<(), store::StoreError> {
        self.store.init().await
    }

    /// Pull an image and return the rootfs path and image config.
    ///
    /// If `signature_policy` is `Some`, the image's cosign signature is verified
    /// against the provided public key before downloading layers. Otherwise, if
    /// this manager has a fleet-wide signature policy, that policy is applied to
    /// every image: an enforcing policy rejects unsigned images, while a
    /// non-enforcing (advisory) policy logs verification failures but proceeds.
    pub async fn pull(
        &self,
        image: &str,
        service_name: &str,
        policy: &PullPolicy,
        signature_policy: Option<&SignaturePolicy>,
    ) -> Result<ResolvedImage, ImageManagerError> {
        let image_ref: ImageReference = image.parse()?;

        // A per-call policy takes precedence; otherwise fall back to the
        // fleet-wide policy (if any).
        let effective_policy =
            signature_policy.or(self.fleet_signature_policy.as_ref().map(|f| &f.policy));

        // A fleet policy that isn't being enforced (and has no per-call override)
        // is advisory: attempt verification for observability, but do not block
        // the pull on failure.
        let advisory_only = signature_policy.is_none()
            && self
                .fleet_signature_policy
                .as_ref()
                .is_some_and(|f| !f.enforce);

        let result = match pull::pull_image(
            &self.client,
            &self.store,
            &image_ref,
            service_name,
            policy,
            effective_policy,
        )
        .await
        {
            Ok(r) => r,
            Err(PullError::Signature(e)) if advisory_only => {
                tracing::warn!(
                    image = %image_ref,
                    service = service_name,
                    error = %e,
                    "Advisory signature policy: verification failed but pull is not enforced"
                );
                // Retry without signature verification since the policy is advisory.
                pull::pull_image(
                    &self.client,
                    &self.store,
                    &image_ref,
                    service_name,
                    policy,
                    None,
                )
                .await?
            }
            Err(e) => return Err(e.into()),
        };

        // Read the image config to get entrypoint/env/etc.
        let config = self.read_image_config(&image_ref, service_name).await?;

        Ok(ResolvedImage {
            pull: result,
            config,
        })
    }

    /// Check if an image is available locally for a service.
    pub async fn is_cached(&self, service_name: &str) -> bool {
        self.store.has_bundle(service_name).await
    }

    /// Run garbage collection, keeping only images for the given active services.
    ///
    /// `retain_generations` controls how many previous image versions per
    /// service are kept for rollback (default 1). Set to 0 to disable
    /// retention.
    pub async fn gc(
        &self,
        active_services: &HashSet<String>,
        active_manifests: &[(String, ImageManifest)],
        retain_generations: usize,
    ) -> Result<gc::GcResult, store::StoreError> {
        // Collect retained manifests from history
        let mut retained = Vec::new();
        for svc in active_services {
            let history = self.store.list_history(svc).await?;
            for (_, raw) in history.iter().take(retain_generations) {
                if let Ok(m) = serde_json::from_slice(raw) {
                    retained.push(m);
                }
            }
            // Prune excess history entries
            self.store.prune_history(svc, retain_generations).await?;
        }

        gc::collect(&self.store, active_services, active_manifests, &retained).await
    }

    /// Generate an OCI bundle config.json for systemd-nspawn.
    pub async fn write_bundle_config(
        &self,
        service_name: &str,
        image_config: &manifest::ImageConfig,
        extra_env: &HashMap<String, String>,
        extra_mounts: &[bundle::BindMount],
    ) -> Result<(), bundle::BundleError> {
        let bundle_dir = self.store.bundle_path(service_name);
        bundle::write_bundle_config(&bundle_dir, image_config, extra_env, extra_mounts).await
    }

    /// Get the rootfs path for a service's bundle.
    pub fn rootfs_path(&self, service_name: &str) -> PathBuf {
        self.store.rootfs_path(service_name)
    }

    /// Get the bundle path for a service.
    pub fn bundle_path(&self, service_name: &str) -> PathBuf {
        self.store.bundle_path(service_name)
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &ImageStore {
        &self.store
    }

    /// Read the image config blob for a pulled image.
    async fn read_image_config(
        &self,
        image: &ImageReference,
        service_name: &str,
    ) -> Result<manifest::ImageConfig, ImageManagerError> {
        // Read the cached manifest to find the config digest
        let manifest_key = pull_manifest_key(image);
        let raw = self
            .store
            .get_manifest(&manifest_key)
            .await?
            .ok_or(ImageManagerError::Pull(PullError::NotFoundLocally))?;

        let manifest: ImageManifest = serde_json::from_slice(&raw)
            .map_err(|e| ImageManagerError::Pull(PullError::ManifestParse(e.to_string())))?;

        let config_blob = self
            .store
            .get_blob(&manifest.config.digest)
            .await
            .map_err(|_| ImageManagerError::ConfigNotFound {
                service: service_name.to_string(),
                digest: manifest.config.digest.clone(),
            })?;

        let config: manifest::ImageConfig = serde_json::from_slice(&config_blob)
            .map_err(|e| ImageManagerError::Pull(PullError::ManifestParse(e.to_string())))?;

        Ok(config)
    }
}

/// Reproduce the manifest cache key logic from pull.rs.
fn pull_manifest_key(image: &ImageReference) -> String {
    if let Some(d) = &image.digest {
        d.hex().to_string()
    } else {
        let tag = image.tag.as_deref().unwrap_or("latest");
        format!("{}_{}__{tag}", image.registry, image.repository)
            .replace('/', "_")
            .replace(':', "_")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ImageManagerError {
    #[error("invalid image reference: {0}")]
    Reference(#[from] reference::ReferenceError),
    #[error("pull error: {0}")]
    Pull(#[from] PullError),
    #[error("store error: {0}")]
    Store(#[from] store::StoreError),
    #[error("signature verification failed: {0}")]
    Signature(#[from] SignatureError),
    #[error("config blob not found for service {service} (digest {digest})")]
    ConfigNotFound { service: String, digest: Digest },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn manager_init() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = ImageManager::new(dir.path().join("oci"), Credentials::Anonymous);
        mgr.init().await.unwrap();
        assert!(!mgr.is_cached("nonexistent").await);
    }

    #[test]
    fn with_fleet_signature_policy_sets_field() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = ImageManager::new(dir.path().join("oci"), Credentials::Anonymous);
        assert!(mgr.fleet_signature_policy.is_none());

        let policy = SignaturePolicy {
            key: signature::SigningKey::Ed25519(vec![0u8; 32]),
        };
        let mgr = mgr.with_fleet_signature_policy(FleetSignaturePolicy {
            policy,
            enforce: false,
        });
        let stored = mgr.fleet_signature_policy.as_ref().unwrap();
        assert!(!stored.enforce);
    }

    #[test]
    fn manifest_key_consistency() {
        let image: ImageReference = "ghcr.io/org/app:v1.0".parse().unwrap();
        let key = pull_manifest_key(&image);
        assert_eq!(key, "ghcr.io_org_app__v1.0");
    }
}
