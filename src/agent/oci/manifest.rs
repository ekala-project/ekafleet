//! OCI image manifest, image index, and image configuration types.
//!
//! Implements the subset of the OCI Image Specification needed for
//! pulling and unpacking images.

use serde::{Deserialize, Serialize};

use super::digest::Digest;

// ---------------------------------------------------------------------------
// Media types
// ---------------------------------------------------------------------------

pub const MEDIA_TYPE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MEDIA_TYPE_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MEDIA_TYPE_CONFIG: &str = "application/vnd.oci.image.config.v1+json";

// Docker-originated types that registries still serve.
pub const MEDIA_TYPE_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const MEDIA_TYPE_DOCKER_MANIFEST_LIST: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

/// All manifest-like media types the client accepts.
pub const ACCEPT_MANIFESTS: &[&str] = &[
    MEDIA_TYPE_MANIFEST,
    MEDIA_TYPE_INDEX,
    MEDIA_TYPE_DOCKER_MANIFEST,
    MEDIA_TYPE_DOCKER_MANIFEST_LIST,
];

// ---------------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------------

/// Content descriptor referencing a blob by digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
    /// Platform selector (present in image index entries).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// Arbitrary descriptor annotations. Cosign stores the signature payload
    /// and (for keyless signing) the Fulcio certificate and Rekor bundle here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

/// Target platform for a multi-arch image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
}

impl Platform {
    /// Return the platform of the current host.
    pub fn current() -> Self {
        Self {
            architecture: std::env::consts::ARCH.to_string(),
            os: std::env::consts::OS.to_string(),
            variant: None,
            os_version: None,
        }
    }

    /// Check whether this platform matches `other` (ignoring variant if unset).
    pub fn matches(&self, other: &Platform) -> bool {
        let arch_match = self.architecture == other.architecture
            || (self.architecture == "amd64" && other.architecture == "x86_64")
            || (self.architecture == "x86_64" && other.architecture == "amd64")
            || (self.architecture == "arm64" && other.architecture == "aarch64")
            || (self.architecture == "aarch64" && other.architecture == "arm64");

        let os_match = self.os == other.os;

        let variant_match = match (&self.variant, &other.variant) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };

        arch_match && os_match && variant_match
    }
}

// ---------------------------------------------------------------------------
// Image Manifest (single-platform)
// ---------------------------------------------------------------------------

/// An OCI image manifest describing a single image.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub media_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

// ---------------------------------------------------------------------------
// Image Index (multi-platform / fat manifest)
// ---------------------------------------------------------------------------

/// An OCI image index listing per-platform manifests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageIndex {
    pub schema_version: u32,
    #[serde(default)]
    pub media_type: Option<String>,
    pub manifests: Vec<Descriptor>,
}

impl ImageIndex {
    /// Select the manifest descriptor matching the given platform.
    pub fn select_platform(&self, target: &Platform) -> Option<&Descriptor> {
        self.manifests
            .iter()
            .find(|d| d.platform.as_ref().is_some_and(|p| p.matches(target)))
    }
}

// ---------------------------------------------------------------------------
// Parsed manifest envelope
// ---------------------------------------------------------------------------

/// A parsed manifest that could be either a single-platform manifest
/// or a multi-platform index.
#[derive(Debug, Clone)]
pub enum ManifestKind {
    Manifest(ImageManifest),
    Index(ImageIndex),
}

impl ManifestKind {
    /// Parse raw manifest JSON, using the Content-Type to disambiguate.
    pub fn from_json(media_type: &str, data: &[u8]) -> Result<Self, ManifestError> {
        match media_type {
            MEDIA_TYPE_MANIFEST | MEDIA_TYPE_DOCKER_MANIFEST => {
                let m: ImageManifest = serde_json::from_slice(data)?;
                Ok(Self::Manifest(m))
            }
            MEDIA_TYPE_INDEX | MEDIA_TYPE_DOCKER_MANIFEST_LIST => {
                let idx: ImageIndex = serde_json::from_slice(data)?;
                Ok(Self::Index(idx))
            }
            other => Err(ManifestError::UnsupportedMediaType(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("unsupported manifest media type: {0}")]
    UnsupportedMediaType(String),
    #[error("manifest JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Image Configuration
// ---------------------------------------------------------------------------

/// Subset of the OCI image configuration needed for execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub config: Option<ContainerConfig>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
}

/// Container execution parameters from the image config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub labels: Option<std::collections::HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest() {
        let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                    "size": 5678
                }
            ]
        }"#;

        let kind = ManifestKind::from_json(MEDIA_TYPE_MANIFEST, json.as_bytes()).unwrap();
        match kind {
            ManifestKind::Manifest(m) => {
                assert_eq!(m.schema_version, 2);
                assert_eq!(m.layers.len(), 1);
            }
            ManifestKind::Index(_) => panic!("expected Manifest"),
        }
    }

    #[test]
    fn parse_index() {
        let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                    "size": 1234,
                    "platform": {
                        "architecture": "amd64",
                        "os": "linux"
                    }
                }
            ]
        }"#;

        let kind = ManifestKind::from_json(MEDIA_TYPE_INDEX, json.as_bytes()).unwrap();
        match kind {
            ManifestKind::Index(idx) => {
                assert_eq!(idx.manifests.len(), 1);
                let target = Platform {
                    architecture: "x86_64".to_string(),
                    os: "linux".to_string(),
                    variant: None,
                    os_version: None,
                };
                assert!(idx.select_platform(&target).is_some());
            }
            ManifestKind::Manifest(_) => panic!("expected Index"),
        }
    }

    #[test]
    fn platform_matching() {
        let amd64 = Platform {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            variant: None,
            os_version: None,
        };
        let x86_64 = Platform {
            architecture: "x86_64".to_string(),
            os: "linux".to_string(),
            variant: None,
            os_version: None,
        };
        assert!(amd64.matches(&x86_64));
        assert!(x86_64.matches(&amd64));

        let arm64 = Platform {
            architecture: "arm64".to_string(),
            os: "linux".to_string(),
            variant: None,
            os_version: None,
        };
        assert!(!amd64.matches(&arm64));
    }

    #[test]
    fn parse_image_config() {
        let json = r#"{
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": "1000",
                "Env": ["PATH=/usr/bin", "HOME=/app"],
                "Entrypoint": ["/app/server"],
                "Cmd": ["--port", "8080"],
                "WorkingDir": "/app"
            }
        }"#;

        let cfg: ImageConfig = serde_json::from_str(json).unwrap();
        let cc = cfg.config.unwrap();
        assert_eq!(
            cc.entrypoint.as_deref(),
            Some(&["/app/server".to_string()][..])
        );
        assert_eq!(
            cc.cmd.as_deref(),
            Some(&["--port".to_string(), "8080".to_string()][..])
        );
        assert_eq!(cc.working_dir.as_deref(), Some("/app"));
    }
}
