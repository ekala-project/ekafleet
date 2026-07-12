//! OCI image reference parsing.
//!
//! Parses image references in the standard Docker/OCI format:
//!   `[registry/]repository[:tag][@sha256:hex]`

use std::fmt;
use std::str::FromStr;

use super::digest::Digest;

/// A parsed OCI image reference.
///
/// Examples:
///   - `docker.io/library/alpine:3.19`
///   - `ghcr.io/myorg/myapp@sha256:abcd...`
///   - `registry.internal:5000/team/svc:v1.2@sha256:abcd...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    /// Registry host (e.g. `docker.io`, `ghcr.io`). Defaults to `docker.io`.
    pub registry: String,
    /// Repository path (e.g. `library/alpine`, `myorg/myapp`).
    pub repository: String,
    /// Optional tag (e.g. `latest`, `3.19`).
    pub tag: Option<String>,
    /// Optional digest for content-addressed pinning.
    pub digest: Option<Digest>,
}

impl ImageReference {
    /// The reference string used in registry API calls (tag or digest).
    pub fn api_reference(&self) -> String {
        if let Some(d) = &self.digest {
            d.to_string()
        } else {
            self.tag.clone().unwrap_or_else(|| "latest".to_string())
        }
    }

    /// Whether this reference is pinned to a specific digest.
    pub fn is_pinned(&self) -> bool {
        self.digest.is_some()
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

impl FromStr for ImageReference {
    type Err = ReferenceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ReferenceError::Empty);
        }

        // Split off @digest suffix first
        let (name_tag, digest) = match s.rsplit_once('@') {
            Some((before, digest_str)) => {
                let digest: Digest = digest_str
                    .parse()
                    .map_err(|_| ReferenceError::InvalidDigest)?;
                (before, Some(digest))
            }
            None => (s, None),
        };

        // Split off :tag
        // Careful: registry:port/repo must not be confused with repo:tag.
        // A tag is the part after the last colon that does NOT contain a slash.
        let (name, tag) = match name_tag.rsplit_once(':') {
            Some((before, after)) if !after.contains('/') => (before, Some(after.to_string())),
            _ => (name_tag, None),
        };

        // Split registry from repository.
        // A component is a registry if it contains a dot or colon, or is "localhost".
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest.to_string())
            }
            _ => {
                // Docker Hub default: add library/ prefix for single-component names
                let repo = if name.contains('/') {
                    name.to_string()
                } else {
                    format!("library/{name}")
                };
                ("docker.io".to_string(), repo)
            }
        };

        if repository.is_empty() {
            return Err(ReferenceError::EmptyRepository);
        }

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReferenceError {
    #[error("empty image reference")]
    Empty,
    #[error("empty repository")]
    EmptyRepository,
    #[error("invalid digest in image reference")]
    InvalidDigest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_image() {
        let r: ImageReference = "alpine".parse().unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, None);
        assert!(!r.is_pinned());
    }

    #[test]
    fn image_with_tag() {
        let r: ImageReference = "alpine:3.19".parse().unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("3.19"));
    }

    #[test]
    fn namespaced_image() {
        let r: ImageReference = "myorg/myapp:latest".parse().unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "myorg/myapp");
        assert_eq!(r.tag.as_deref(), Some("latest"));
    }

    #[test]
    fn custom_registry() {
        let r: ImageReference = "ghcr.io/myorg/myapp:v1.2".parse().unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "myorg/myapp");
        assert_eq!(r.tag.as_deref(), Some("v1.2"));
    }

    #[test]
    fn registry_with_port() {
        let r: ImageReference = "registry.internal:5000/team/svc:v1".parse().unwrap();
        assert_eq!(r.registry, "registry.internal:5000");
        assert_eq!(r.repository, "team/svc");
        assert_eq!(r.tag.as_deref(), Some("v1"));
    }

    #[test]
    fn digest_only() {
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let input = format!("ghcr.io/org/app@{digest}");
        let r: ImageReference = input.parse().unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/app");
        assert_eq!(r.tag, None);
        assert!(r.is_pinned());
        assert_eq!(r.digest.unwrap().to_string(), digest);
    }

    #[test]
    fn tag_and_digest() {
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let input = format!("myorg/myapp:v1.0@{digest}");
        let r: ImageReference = input.parse().unwrap();
        assert_eq!(r.tag.as_deref(), Some("v1.0"));
        assert!(r.is_pinned());
    }

    #[test]
    fn localhost_registry() {
        let r: ImageReference = "localhost/myapp:dev".parse().unwrap();
        assert_eq!(r.registry, "localhost");
        assert_eq!(r.repository, "myapp");
    }

    #[test]
    fn display_round_trip() {
        let input = "ghcr.io/org/app:v1.0";
        let r: ImageReference = input.parse().unwrap();
        assert_eq!(r.to_string(), input);
    }

    #[test]
    fn empty_rejected() {
        assert!("".parse::<ImageReference>().is_err());
    }
}
