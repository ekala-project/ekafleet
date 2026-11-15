//! Container images on the agent.
//!
//! The server pins every container image to a digest at apply time. For each
//! container service the agent pulls that digest into a per-service bundle
//! (in the background, verifying the fleet signature policy again), and only
//! starts or switches the service once the bundle is unpacked: a service
//! keeps running its previous image while a new one is pulled. Bundles no
//! service needs are garbage collected when no pull is in flight.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, RwLock};

use super::oci::auth::{self, Credentials};
use super::oci::bundle::{self, ProcessOverrides, ProcessUser};
use super::oci::pull::{self, Verification};
use super::oci::reference::ImageReference;
use super::oci::registry::RegistryClient;
use super::oci::signature::SignaturePolicy;
use super::oci::store::ImageStore;
use crate::proto::ServiceSpec;

/// How long a failed pull waits before it is retried.
const RETRY_AFTER: Duration = Duration::from_secs(30);

/// The image store under the agent's data directory.
pub fn oci_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("oci")
}

/// The pinned image of a container service and its digest hex, if the
/// service name and image are valid and the image carries a digest.
pub fn pinned_image(spec: &ServiceSpec) -> Option<(ImageReference, String)> {
    crate::secrets::validate_name("service", &spec.name).ok()?;
    let image: ImageReference = spec.container_image.parse().ok()?;
    let hex = image.digest.as_ref()?.hex().to_string();
    Some((image, hex))
}

/// The bundle a container service runs from.
pub fn bundle_path(oci_dir: &Path, spec: &ServiceSpec) -> Option<PathBuf> {
    let (_, hex) = pinned_image(spec)?;
    Some(ImageStore::new(oci_dir).bundle_path(&spec.name, &hex))
}

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("image '{0}' is not pinned to a digest")]
    NotPinned(String),
    #[error("{0}")]
    Policy(String),
    #[error("registry credentials: {0}")]
    Credentials(String),
    #[error(transparent)]
    Pull(#[from] pull::PullError),
    #[error("bundle: {0}")]
    Bundle(#[from] bundle::BundleError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Whether a container service can start.
#[derive(Debug)]
pub enum Readiness {
    /// The bundle is unpacked and configured; the process runs as `user`.
    Ready { user: ProcessUser },
    /// The image is being pulled (or waits to be retried).
    Pulling,
    /// The image cannot be run as specified.
    Invalid(String),
}

/// The fleet signature policy as delivered with the desired state.
struct Policy {
    policy: SignaturePolicy,
    enforce: bool,
}

#[derive(Default)]
struct PullState {
    /// (service, digest hex) being pulled.
    pulling: HashSet<(String, String)>,
    /// (service, digest hex) whose last pull failed, and when.
    failed: HashMap<(String, String), Instant>,
}

pub struct ImageManager {
    store: ImageStore,
    secrets_dir: PathBuf,
    state: Mutex<PullState>,
    /// `Err` when the delivered policy does not parse: every pull fails.
    policy: Mutex<Result<Option<Arc<Policy>>, String>>,
    /// Pulls hold it shared; garbage collection exclusively.
    store_lock: RwLock<()>,
    ready: Notify,
}

impl ImageManager {
    /// An image manager for the store under `data_dir`, reading registry
    /// credentials from the delivered secrets under `secrets_dir`.
    pub fn new(data_dir: &Path, secrets_dir: &Path) -> Self {
        Self {
            store: ImageStore::new(oci_dir(data_dir)),
            secrets_dir: secrets_dir.to_path_buf(),
            state: Mutex::new(PullState::default()),
            policy: Mutex::new(Ok(None)),
            store_lock: RwLock::new(()),
            ready: Notify::new(),
        }
    }

    /// Install the fleet signature policy from a desired state (empty for
    /// none). An unparseable policy refuses every pull rather than letting
    /// unverified images run.
    pub fn set_signature_policy(&self, json: &str) -> Result<(), String> {
        let policy = parse_policy(json);
        *self.policy.lock().unwrap() = policy.clone();
        policy.map(|_| ())
    }

    /// Resolves when a pull finished or a failed pull is due for a retry:
    /// time to converge again.
    pub async fn ready(&self) {
        self.ready.notified().await
    }

    /// Whether `spec`'s image can run now. Starts a background pull when the
    /// bundle is missing; when it is present, (re)writes the bundle's
    /// process configuration for `spec`.
    pub async fn prepare(self: &Arc<Self>, spec: &ServiceSpec) -> Readiness {
        let Some((image, hex)) = pinned_image(spec) else {
            return Readiness::Invalid(
                ImageError::NotPinned(spec.container_image.clone()).to_string(),
            );
        };
        if !self.store.has_bundle(&spec.name, &hex).await {
            self.start_pull(spec, image, hex);
            return Readiness::Pulling;
        }
        match self.configure(spec, &hex).await {
            Ok(user) => Readiness::Ready { user },
            Err(e) => Readiness::Invalid(e.to_string()),
        }
    }

    /// Forget failed pulls of services no longer assigned here.
    pub fn retain_services(&self, services: &HashSet<&str>) {
        let mut state = self.state.lock().unwrap();
        state
            .failed
            .retain(|(s, _), _| services.contains(s.as_str()));
    }

    fn start_pull(self: &Arc<Self>, spec: &ServiceSpec, image: ImageReference, hex: String) {
        let key = (spec.name.clone(), hex);
        {
            let mut state = self.state.lock().unwrap();
            if state.pulling.contains(&key) {
                return;
            }
            if let Some(at) = state.failed.get(&key)
                && at.elapsed() < RETRY_AFTER
            {
                return;
            }
            state.failed.remove(&key);
            state.pulling.insert(key.clone());
        }
        let this = self.clone();
        let auth_secret = spec
            .container
            .as_ref()
            .map(|c| c.registry_auth_secret.clone())
            .filter(|s| !s.is_empty());
        tokio::spawn(async move {
            let result = this.pull(&key.0, &image, auth_secret.as_deref()).await;
            let mut state = this.state.lock().unwrap();
            state.pulling.remove(&key);
            if let Err(e) = result {
                tracing::error!(
                    service = %key.0,
                    image = %image,
                    error = %e,
                    retry_in = ?RETRY_AFTER,
                    "Cannot pull image"
                );
                state.failed.insert(key, Instant::now());
                let this = this.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(RETRY_AFTER).await;
                    this.ready.notify_one();
                });
            }
            drop(state);
            this.ready.notify_one();
        });
    }

    async fn pull(
        &self,
        service: &str,
        image: &ImageReference,
        auth_secret: Option<&str>,
    ) -> Result<(), ImageError> {
        let credentials = self.credentials(service, image, auth_secret).await?;
        let client = RegistryClient::new(credentials);
        let policy = self
            .policy
            .lock()
            .unwrap()
            .clone()
            .map_err(ImageError::Policy)?;
        let verification = policy.as_ref().map(|p| Verification {
            policy: &p.policy,
            enforce: p.enforce,
        });
        let _shared = self.store_lock.read().await;
        self.store.init().await.map_err(pull::PullError::from)?;
        pull::pull_pinned(&client, &self.store, image, service, verification).await?;
        Ok(())
    }

    /// Credentials for `image`'s registry from the service's Docker
    /// config.json secret, if it names one.
    async fn credentials(
        &self,
        service: &str,
        image: &ImageReference,
        auth_secret: Option<&str>,
    ) -> Result<Credentials, ImageError> {
        let Some(secret) = auth_secret else {
            return Ok(Credentials::Anonymous);
        };
        crate::secrets::validate_name("secret", secret).map_err(ImageError::Credentials)?;
        let path = self.secrets_dir.join(service).join(secret);
        let json =
            zeroize::Zeroizing::new(tokio::fs::read(&path).await.map_err(|e| {
                ImageError::Credentials(format!("cannot read secret '{secret}': {e}"))
            })?);
        auth::docker_config_credentials(&json, &image.registry)
            .map_err(|e| ImageError::Credentials(format!("secret '{secret}': {e}")))
    }

    /// Write the bundle's config.json for `spec`; returns the process user.
    async fn configure(&self, spec: &ServiceSpec, hex: &str) -> Result<ProcessUser, ImageError> {
        let pulled = pull::read_bundle(&self.store, &spec.name, hex).await?;
        let options = spec.container.clone().unwrap_or_default();
        let mut env: Vec<(String, String)> = spec
            .environment
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        env.sort();
        env.push((
            "SPIFFE_ENDPOINT_SOCKET".into(),
            format!("unix://{}", crate::spiffe::socket::DEFAULT_SOCKET_PATH),
        ));
        env.push(("EKAFLEET_SERVICE".into(), spec.name.clone()));
        let overrides = ProcessOverrides {
            entrypoint: options.entrypoint.map(|l| l.items),
            args: options.args.map(|l| l.items),
            working_dir: Some(options.working_dir).filter(|d| !d.is_empty()),
            env,
        };
        let rootfs = self.store.rootfs_path(&spec.name, hex);
        let process = {
            let config = pulled.config.clone();
            tokio::task::spawn_blocking(move || bundle::process_spec(&config, &overrides, &rootfs))
                .await
                .map_err(std::io::Error::other)??
        };
        bundle::write_bundle_config(&pulled.bundle, &process, &[]).await?;
        Ok(process.user)
    }

    /// Remove bundles, manifests and blobs not needed by `keep` (service,
    /// digest hex), unless a pull is in flight.
    pub async fn collect_garbage(&self, keep: &HashSet<(String, String)>) {
        let Ok(_exclusive) = self.store_lock.try_write() else {
            return;
        };
        if !self.state.lock().unwrap().pulling.is_empty() || !self.store.root().is_dir() {
            return;
        }
        if let Err(e) = super::oci::gc::collect(&self.store, keep).await {
            tracing::warn!(error = %e, "Image garbage collection failed");
        }
    }
}

fn parse_policy(json: &str) -> Result<Option<Arc<Policy>>, String> {
    if json.is_empty() {
        return Ok(None);
    }
    let config: crate::config::SignaturePolicyConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid signature policy: {e}"))?;
    let policy = config
        .to_runtime_policy()
        .map_err(|e| format!("invalid signature policy: {e}"))?;
    Ok(Some(Arc::new(Policy {
        policy,
        enforce: config.enforce,
    })))
}

/// Give each volume of a container service running as a non-root user to
/// that user, so the process can write to it.
pub async fn chown_volumes(service_dir: &Path, spec: &ServiceSpec, user: &ProcessUser) {
    if user.uid == 0 {
        return;
    }
    for volume in &spec.volumes {
        if crate::secrets::validate_name("volume", &volume.name).is_err() {
            continue;
        }
        let path = service_dir.join(&volume.name);
        let Ok(meta) = tokio::fs::symlink_metadata(&path).await else {
            continue;
        };
        use std::os::unix::fs::MetadataExt;
        if !meta.is_dir() || (meta.uid() == user.uid && meta.gid() == user.gid) {
            continue;
        }
        if let Err(e) = std::os::unix::fs::lchown(&path, Some(user.uid), Some(user.gid)) {
            tracing::warn!(
                service = %spec.name,
                volume = %volume.name,
                uid = user.uid,
                error = %e,
                "Cannot give volume to the container user"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::oci::store::IMAGE_CONFIG_FILE;

    fn container(name: &str, image: &str) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            container_image: image.into(),
            ..Default::default()
        }
    }

    #[test]
    fn only_pinned_images_of_valid_services_have_bundles() {
        let hex = "ab".repeat(32);
        let oci = Path::new("/var/lib/ekafleet/oci");
        let spec = container("web", &format!("ghcr.io/org/web:v1@sha256:{hex}"));
        assert_eq!(
            bundle_path(oci, &spec).unwrap(),
            oci.join("bundles/web").join(&hex)
        );
        assert!(bundle_path(oci, &container("web", "ghcr.io/org/web:v1")).is_none());
        assert!(
            bundle_path(
                oci,
                &container("../x", &format!("ghcr.io/org/web@sha256:{hex}"))
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn unpinned_images_are_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let images = Arc::new(ImageManager::new(dir.path(), dir.path()));
        let readiness = images
            .prepare(&container("web", "ghcr.io/org/web:v1"))
            .await;
        assert!(matches!(readiness, Readiness::Invalid(_)), "{readiness:?}");
    }

    #[tokio::test]
    async fn present_bundles_are_configured_for_the_spec() {
        let dir = tempfile::tempdir().unwrap();
        let images = Arc::new(ImageManager::new(dir.path(), dir.path()));
        let hex = "cd".repeat(32);
        let bundle = images.store.bundle_path("web", &hex);
        tokio::fs::create_dir_all(bundle.join("rootfs"))
            .await
            .unwrap();
        tokio::fs::write(
            bundle.join(IMAGE_CONFIG_FILE),
            br#"{"config":{"Entrypoint":["/bin/web"],"Cmd":["--default"],"Env":["MODE=dev"]}}"#,
        )
        .await
        .unwrap();

        let mut spec = container("web", &format!("registry.invalid/web:v1@sha256:{hex}"));
        spec.environment.insert("MODE".into(), "prod".into());
        spec.container = Some(crate::proto::ContainerOptions {
            args: Some(crate::proto::StringList {
                items: vec!["--serve".into()],
            }),
            ..Default::default()
        });
        let readiness = images.prepare(&spec).await;
        assert!(
            matches!(readiness, Readiness::Ready { ref user } if user.uid == 0),
            "{readiness:?}"
        );
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bundle.join("config.json")).unwrap()).unwrap();
        assert_eq!(
            config["process"]["args"],
            serde_json::json!(["/bin/web", "--serve"])
        );
        let env: Vec<&str> = config["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect();
        assert!(env.contains(&"MODE=prod") && !env.contains(&"MODE=dev"));
        assert!(env.contains(&"EKAFLEET_SERVICE=web"));
        // The image sets no PATH: the conventional one is used.
        assert!(env.contains(&format!("PATH={}", bundle::DEFAULT_PATH).as_str()));
    }

    #[tokio::test]
    async fn missing_bundles_pull_in_the_background_and_failures_wait_to_retry() {
        let dir = tempfile::tempdir().unwrap();
        let images = Arc::new(ImageManager::new(dir.path(), dir.path()));
        let hex = "ef".repeat(32);
        let mut spec = container("web", &format!("registry.invalid/web@sha256:{hex}"));
        // A missing credentials secret fails the pull without the network.
        spec.container = Some(crate::proto::ContainerOptions {
            registry_auth_secret: "registry".into(),
            ..Default::default()
        });
        assert!(matches!(images.prepare(&spec).await, Readiness::Pulling));
        tokio::time::timeout(Duration::from_secs(5), images.ready())
            .await
            .expect("the failed pull notifies");
        let key = ("web".to_string(), hex);
        assert!(images.state.lock().unwrap().failed.contains_key(&key));
        // Not retried before its time.
        assert!(matches!(images.prepare(&spec).await, Readiness::Pulling));
        assert!(!images.state.lock().unwrap().pulling.contains(&key));
    }

    #[test]
    fn signature_policies_must_parse() {
        let dir = tempfile::tempdir().unwrap();
        let images = ImageManager::new(dir.path(), dir.path());
        assert!(images.set_signature_policy("").is_ok());
        assert!(images.set_signature_policy("{not json").is_err());
        assert!(
            images
                .set_signature_policy(r#"{"publicKeyPem":"garbage"}"#)
                .is_err()
        );
        assert!(images.policy.lock().unwrap().is_err());
    }
}
