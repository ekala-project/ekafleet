//! Pinning container images at apply time.
//!
//! Every container image is resolved to a digest when a configuration is
//! applied, and that digest is recorded with the configuration revision: all
//! agents run the same image, a moved tag never changes a running fleet, and
//! a rollback runs exactly the image the earlier revision ran. A configured
//! signature policy is checked against the pinned digest here (failing the
//! apply when enforced) and again by every agent that pulls it.

use std::collections::{BTreeMap, HashMap};

use crate::agent::oci::auth::{self, Credentials};
use crate::agent::oci::reference::ImageReference;
use crate::agent::oci::registry::RegistryClient;
use crate::agent::oci::signature::{self, SignaturePolicy};
use crate::config::{ContainerPullPolicy, FleetConfig};
use crate::raft::state::ConfigRevision;
use crate::secrets::store::SecretStore;

/// Stored sealed secrets: service → name → (sealed value, version).
pub type SealedSecrets = HashMap<String, HashMap<String, (Vec<u8>, u64)>>;

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("service '{service}': invalid image '{image}': {reason}")]
    InvalidImage {
        service: String,
        image: String,
        reason: String,
    },
    #[error("service '{service}': registry credentials: {reason}")]
    Credentials { service: String, reason: String },
    #[error("service '{service}': cannot resolve {image}: {reason}")]
    Resolve {
        service: String,
        image: String,
        reason: String,
    },
    #[error(
        "service '{service}': {image} is not signed as the signature policy requires: {reason}"
    )]
    Unsigned {
        service: String,
        image: String,
        reason: String,
    },
    #[error("invalid signature policy: {0}")]
    Policy(String),
}

/// Pinned images by service, and warnings for the operator.
#[derive(Debug, Default)]
pub struct Pinned {
    pub images: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

/// Pin the image of every container service of `config`.
///
/// `previous` is the revision being replaced: with `IfNotPresent`, an
/// unchanged image reference keeps its earlier pin without asking the
/// registry. `progress` is told about each registry lookup.
pub async fn pin_images<F, Fut>(
    config: &FleetConfig,
    previous: Option<&ConfigRevision>,
    secrets: &SealedSecrets,
    store: &SecretStore,
    progress: F,
) -> Result<Pinned, ImageError>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let policy = config
        .signature_policy
        .as_ref()
        .map(|p| {
            p.to_runtime_policy()
                .map(|policy| (policy, p.enforce))
                .map_err(|e| ImageError::Policy(e.to_string()))
        })
        .transpose()?;
    // As written, before its pins were substituted.
    let previous_config =
        previous.and_then(|r| serde_json::from_str::<FleetConfig>(&r.config_json).ok());

    let mut pinned = Pinned::default();
    let mut services: Vec<_> = config.services.iter().collect();
    services.sort_by_key(|(name, _)| name.as_str());
    for (name, service) in services {
        let Some(container) = &service.container else {
            continue;
        };
        let invalid = |reason: String| ImageError::InvalidImage {
            service: name.clone(),
            image: container.image.clone(),
            reason,
        };
        let image: ImageReference = container
            .image
            .parse()
            .map_err(|e: crate::agent::oci::reference::ReferenceError| invalid(e.to_string()))?;

        if image.digest.is_none() && container.pull_policy == ContainerPullPolicy::IfNotPresent {
            let unchanged = previous_config
                .as_ref()
                .and_then(|c| c.services.get(name))
                .and_then(|s| s.container.as_ref())
                .is_some_and(|c| c.image == container.image);
            if unchanged && let Some(pin) = previous.and_then(|r| r.images.get(name)) {
                pinned.images.insert(name.clone(), pin.clone());
                continue;
            }
        }
        if image.digest.is_none() && container.pull_policy == ContainerPullPolicy::Never {
            return Err(invalid(
                "pullPolicy Never needs an image pinned with @sha256:...".into(),
            ));
        }

        let credentials = credentials(
            name,
            &image,
            container.registry_auth_secret.as_deref(),
            secrets,
            store,
        )?;
        let client = RegistryClient::new(credentials);
        let resolve_error = |reason: String| ImageError::Resolve {
            service: name.clone(),
            image: image.to_string(),
            reason,
        };
        let digest = match &image.digest {
            Some(digest) => digest.clone(),
            None => {
                progress(format!("Resolving image {image} for {name}")).await;
                // The manifest is fetched whole, so its digest is computed
                // here rather than taken from a response header.
                client
                    .fetch_manifest(&image)
                    .await
                    .map_err(|e| resolve_error(e.to_string()))?
                    .digest
            }
        };
        let pin = ImageReference {
            digest: Some(digest.clone()),
            ..image.clone()
        };
        if let Some((policy, enforce)) = &policy
            && let Err(e) = verify(&client, &pin, &digest, policy).await
        {
            if *enforce {
                return Err(ImageError::Unsigned {
                    service: name.clone(),
                    image: pin.to_string(),
                    reason: e.to_string(),
                });
            }
            pinned.warnings.push(format!(
                "service '{name}': {pin} is not signed as the signature policy asks ({e}); \
                     running it because the policy is advisory"
            ));
        }
        pinned.images.insert(name.clone(), pin.to_string());
    }
    Ok(pinned)
}

async fn verify(
    client: &RegistryClient,
    image: &ImageReference,
    digest: &crate::agent::oci::digest::Digest,
    policy: &SignaturePolicy,
) -> Result<(), signature::SignatureError> {
    signature::verify_image_signature(client, image, digest, policy).await
}

/// Credentials for `image`'s registry from the service's Docker config.json
/// secret, if it names one.
fn credentials(
    service: &str,
    image: &ImageReference,
    secret: Option<&str>,
    secrets: &SealedSecrets,
    store: &SecretStore,
) -> Result<Credentials, ImageError> {
    let Some(secret) = secret else {
        return Ok(Credentials::Anonymous);
    };
    let error = |reason: String| ImageError::Credentials {
        service: service.to_string(),
        reason,
    };
    let (sealed, _) = secrets
        .get(service)
        .and_then(|s| s.get(secret))
        .ok_or_else(|| {
            error(format!(
                "registryAuthSecret '{secret}' has no value; set it with `ekafleet secret set {service} {secret}`"
            ))
        })?;
    let json = store
        .open(service, secret, sealed)
        .map_err(|e| error(format!("cannot open '{secret}': {e}")))?;
    auth::docker_config_credentials(&json, &image.registry)
        .map_err(|e| error(format!("secret '{secret}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet(image: &str, policy: ContainerPullPolicy) -> FleetConfig {
        serde_json::from_value(fleet_json(image, policy)).unwrap()
    }

    fn fleet_json(image: &str, policy: ContainerPullPolicy) -> serde_json::Value {
        serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "services": {
                "web": {
                    "container": { "image": image, "pullPolicy": policy },
                }
            }
        })
    }

    /// A revision as `nix eval` recorded it.
    fn revision(config: serde_json::Value, images: &[(&str, &str)]) -> ConfigRevision {
        ConfigRevision {
            revision: 1,
            flake_ref: String::new(),
            config_json: config.to_string(),
            applied_at: 0,
            applied_by: String::new(),
            rollback_of: None,
            closures: BTreeMap::new(),
            images: images
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    async fn no_progress(_: String) -> bool {
        true
    }

    #[tokio::test]
    async fn digests_are_kept_without_the_registry() {
        let hex = "ab".repeat(32);
        let image = format!("registry.invalid/web:v1@sha256:{hex}");
        let config = fleet(&image, ContainerPullPolicy::Always);
        let store = SecretStore::new(&[7; 32]);
        let pinned = pin_images(&config, None, &HashMap::new(), &store, no_progress)
            .await
            .unwrap();
        assert_eq!(pinned.images["web"], image);
    }

    #[tokio::test]
    async fn if_not_present_reuses_the_previous_pin_of_an_unchanged_reference() {
        let config = fleet("registry.invalid/web:v1", ContainerPullPolicy::IfNotPresent);
        let pin = format!("registry.invalid/web:v1@sha256:{}", "cd".repeat(32));
        let previous = revision(
            fleet_json("registry.invalid/web:v1", ContainerPullPolicy::IfNotPresent),
            &[("web", &pin)],
        );
        let store = SecretStore::new(&[7; 32]);
        let pinned = pin_images(
            &config,
            Some(&previous),
            &HashMap::new(),
            &store,
            no_progress,
        )
        .await
        .unwrap();
        assert_eq!(pinned.images["web"], pin);

        // A changed reference is resolved again (and this registry does not
        // exist).
        let moved = fleet("registry.invalid/web:v2", ContainerPullPolicy::IfNotPresent);
        let err = pin_images(
            &moved,
            Some(&previous),
            &HashMap::new(),
            &store,
            no_progress,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ImageError::Resolve { .. }), "{err}");
    }

    #[tokio::test]
    async fn registry_credentials_come_from_the_named_static_secret() {
        let mut config = fleet("registry.invalid/web:v1", ContainerPullPolicy::Always);
        config
            .services
            .get_mut("web")
            .unwrap()
            .container
            .as_mut()
            .unwrap()
            .registry_auth_secret = Some("registry".into());
        let store = SecretStore::new(&[7; 32]);
        let err = pin_images(&config, None, &HashMap::new(), &store, no_progress)
            .await
            .unwrap_err();
        assert!(matches!(err, ImageError::Credentials { .. }), "{err}");

        let docker_config = br#"{"auths":{"registry.invalid":{"auth":"dXNlcjpwYXNz"}}}"#;
        let sealed = store.seal("web", "registry", docker_config).unwrap();
        let secrets = HashMap::from([(
            "web".to_string(),
            HashMap::from([("registry".to_string(), (sealed, 1))]),
        )]);
        let image: ImageReference = "registry.invalid/web:v1".parse().unwrap();
        let creds = credentials("web", &image, Some("registry"), &secrets, &store).unwrap();
        assert!(matches!(creds, Credentials::Basic { ref username, .. } if username == "user"));
    }
}
