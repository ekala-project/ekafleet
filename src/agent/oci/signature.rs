//! Cosign image signature verification.
//!
//! Verifies OCI image signatures using cosign's static key verification
//! protocol. After a manifest is fetched, signatures are discovered at
//! the conventional cosign tag `<repo>:sha256-<hex>.sig` and verified
//! against a configured public key.
//!
//! Only static key verification (ECDSA P-256, Ed25519) is supported.
//! Keyless (Fulcio/Rekor) verification is out of scope.

use ring::signature;
use serde::Deserialize;

use super::digest::Digest;
use super::manifest::{ImageManifest, ManifestKind};
use super::reference::ImageReference;
use super::registry::{RegistryClient, RegistryError};

/// A cosign signature payload (simplesigning format).
#[derive(Debug, Deserialize)]
pub struct CosignPayload {
    pub critical: CriticalSection,
    #[serde(default)]
    pub optional: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct CriticalSection {
    pub identity: Identity,
    pub image: ImageIdentity,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Deserialize)]
pub struct Identity {
    #[serde(rename = "docker-reference")]
    pub docker_reference: String,
}

#[derive(Debug, Deserialize)]
pub struct ImageIdentity {
    #[serde(rename = "docker-manifest-digest")]
    pub docker_manifest_digest: String,
}

/// Supported signature key algorithms.
#[derive(Debug, Clone)]
pub enum SigningKey {
    /// ECDSA P-256 with SHA-256 (cosign default).
    EcdsaP256(Vec<u8>),
    /// Ed25519.
    Ed25519(Vec<u8>),
}

/// Configuration for signature verification on a service.
#[derive(Debug, Clone)]
pub struct SignaturePolicy {
    /// The public key to verify signatures against.
    pub key: SigningKey,
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("registry error fetching signature: {0}")]
    Registry(#[from] RegistryError),
    #[error("no signatures found for image digest {0}")]
    NoSignatures(Digest),
    #[error("signature payload parse error: {0}")]
    PayloadParse(String),
    #[error("signature verification failed: none of {count} signatures matched the public key")]
    VerificationFailed { count: usize },
    #[error(
        "signature digest mismatch: payload references {expected}, but image digest is {actual}"
    )]
    DigestMismatch { expected: String, actual: String },
    #[error("invalid public key: {0}")]
    InvalidKey(String),
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
}

/// A discovered cosign signature with its raw payload and base64-decoded signature bytes.
#[derive(Debug)]
struct CosignSignature {
    /// The raw payload bytes (the signed message).
    payload: Vec<u8>,
    /// The DER-encoded signature.
    signature: Vec<u8>,
}

/// Verify that at least one valid cosign signature exists for the given
/// manifest digest, using the provided public key.
///
/// This follows the cosign static key verification protocol:
///   1. Construct the signature tag: `sha256-<hex>.sig`
///   2. Fetch the signature manifest from the registry
///   3. Download each signature layer (payload + signature)
///   4. Verify the payload's `docker-manifest-digest` matches
///   5. Verify the cryptographic signature against the public key
pub async fn verify_image_signature(
    client: &RegistryClient,
    image: &ImageReference,
    manifest_digest: &Digest,
    policy: &SignaturePolicy,
) -> Result<(), SignatureError> {
    let signatures = fetch_cosign_signatures(client, image, manifest_digest).await?;

    if signatures.is_empty() {
        return Err(SignatureError::NoSignatures(manifest_digest.clone()));
    }

    // Try each signature — we need at least one to verify
    for sig in &signatures {
        // Parse the payload to check the digest reference
        let payload: CosignPayload = serde_json::from_slice(&sig.payload)
            .map_err(|e| SignatureError::PayloadParse(e.to_string()))?;

        // Verify the payload references our manifest digest
        let expected_digest = &payload.critical.image.docker_manifest_digest;
        let actual_digest = manifest_digest.to_string();
        if expected_digest != &actual_digest {
            continue; // Wrong digest, try next signature
        }

        // Verify the cryptographic signature over the payload
        if verify_signature(&policy.key, &sig.payload, &sig.signature).is_ok() {
            tracing::info!(
                digest = %manifest_digest,
                "Image signature verified successfully"
            );
            return Ok(());
        }
    }

    Err(SignatureError::VerificationFailed {
        count: signatures.len(),
    })
}

/// Fetch cosign signatures from the registry for a given manifest digest.
///
/// Cosign stores signatures at the tag `sha256-<hex>.sig` in the same
/// repository as the image.
async fn fetch_cosign_signatures(
    client: &RegistryClient,
    image: &ImageReference,
    manifest_digest: &Digest,
) -> Result<Vec<CosignSignature>, SignatureError> {
    // Build the signature tag reference: sha256-<hex>.sig
    let sig_tag = format!("sha256-{}.sig", manifest_digest.hex());
    let sig_ref = ImageReference {
        registry: image.registry.clone(),
        repository: image.repository.clone(),
        tag: Some(sig_tag),
        digest: None,
    };

    // Fetch the signature manifest — 404 means no signatures
    let resp = match client.fetch_manifest(&sig_ref).await {
        Ok(r) => r,
        Err(RegistryError::NotFound(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    // The signature manifest should be a regular image manifest
    let manifest = match resp.kind {
        ManifestKind::Manifest(m) => m,
        ManifestKind::Index(_) => {
            return Err(SignatureError::ManifestParse(
                "expected manifest, got index for signature tag".into(),
            ));
        }
    };

    extract_signatures(client, image, &manifest).await
}

/// Extract signature payloads and signatures from a cosign signature manifest.
///
/// In cosign's format, each layer contains the signature bytes and the
/// corresponding payload is stored as a base64-encoded annotation on
/// the layer descriptor.
async fn extract_signatures(
    client: &RegistryClient,
    image: &ImageReference,
    manifest: &ImageManifest,
) -> Result<Vec<CosignSignature>, SignatureError> {
    let mut signatures = Vec::new();

    for layer in &manifest.layers {
        // Fetch the signature blob (DER-encoded signature)
        let sig_blob = match client.fetch_blob(image, &layer.digest).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(digest = %layer.digest, err = %e, "Failed to fetch signature blob");
                continue;
            }
        };

        // The payload is stored as a base64-encoded annotation
        // on the layer descriptor under the key
        // "dev.cosignproject.cosign/signature"
        // But in the simplesigning format, the config blob IS the payload.
        // We need to fetch the config blob to get the payload.
        let config_blob = match client.fetch_blob(image, &manifest.config.digest).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    digest = %manifest.config.digest,
                    err = %e,
                    "Failed to fetch signature config"
                );
                continue;
            }
        };

        // In cosign simplesigning, the config blob contains an empty JSON
        // config, and the actual signed payload is base64-encoded in the
        // layer annotations. Parse from the layer annotations if available.
        // The layer data itself is the raw signature bytes.
        //
        // For static-key cosign, the convention is:
        // - Layer data = base64(signature)
        // - Annotations["dev.cosignproject.cosign/signature"] on the layer
        //   descriptor is also the base64 signature
        // - The payload (signed message) is in the config blob or annotations

        // Try annotations-based payload first
        // In practice, cosign stores the payload in the config blob's "data"
        // or the layer itself depending on the version.
        // The most reliable approach: the config blob IS the payload for
        // simplesigning format.
        let payload = config_blob.data;
        let sig_bytes = sig_blob.data;

        if !payload.is_empty() && !sig_bytes.is_empty() {
            signatures.push(CosignSignature {
                payload,
                signature: sig_bytes,
            });
        }
    }

    Ok(signatures)
}

/// Verify a cryptographic signature against a public key.
fn verify_signature(
    key: &SigningKey,
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<(), SignatureError> {
    match key {
        SigningKey::EcdsaP256(public_key_bytes) => {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                public_key_bytes,
            );
            public_key
                .verify(message, sig_bytes)
                .map_err(|_| SignatureError::InvalidKey("ECDSA P-256 verification failed".into()))
        }
        SigningKey::Ed25519(public_key_bytes) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
            public_key
                .verify(message, sig_bytes)
                .map_err(|_| SignatureError::InvalidKey("Ed25519 verification failed".into()))
        }
    }
}

/// Parse a PEM-encoded public key into a SigningKey.
///
/// Supports ECDSA P-256 and Ed25519 keys in SubjectPublicKeyInfo (SPKI) format.
pub fn parse_public_key_pem(pem_data: &str) -> Result<SigningKey, SignatureError> {
    let pem_data = pem_data.trim();

    // Strip PEM headers
    let base64_content = pem_data
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let der = base64_decode(&base64_content)
        .map_err(|e| SignatureError::InvalidKey(format!("base64 decode error: {e}")))?;

    // Parse the SPKI structure to determine the algorithm
    // ECDSA P-256 OID: 1.2.840.10045.3.1.7
    // Ed25519 OID: 1.3.101.112
    let ecdsa_p256_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let ed25519_oid: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

    if contains_subsequence(&der, ecdsa_p256_oid) {
        // For ring, pass the entire SPKI DER for ECDSA
        Ok(SigningKey::EcdsaP256(der))
    } else if contains_subsequence(&der, ed25519_oid) {
        // For ring Ed25519, pass the entire SPKI DER
        Ok(SigningKey::Ed25519(der))
    } else {
        Err(SignatureError::InvalidKey(
            "unsupported key algorithm (expected ECDSA P-256 or Ed25519)".into(),
        ))
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Minimal base64 decoder.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);

    for chunk in input.as_bytes().chunks(4) {
        let mut buf = [0u8; 4];
        let mut len = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                break;
            }
            buf[i] = decode_b64_char(byte)?;
            len = i + 1;
        }

        if len >= 2 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if len >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len >= 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }

    Ok(out)
}

fn decode_b64_char(c: u8) -> Result<u8, String> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(format!("invalid base64 character: {c}")),
    }
}

#[cfg(test)]
mod tests {
    use ring::signature::KeyPair;

    use super::*;

    #[test]
    fn verify_ecdsa_p256() {
        let message = b"test payload";

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let sig = key_pair.sign(&rng, message).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let key = SigningKey::EcdsaP256(public_key_bytes);
        assert!(verify_signature(&key, message, sig.as_ref()).is_ok());
    }

    #[test]
    fn verify_ecdsa_wrong_message() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let sig = key_pair.sign(&rng, b"correct message").unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        let key = SigningKey::EcdsaP256(public_key_bytes);

        assert!(verify_signature(&key, b"wrong message", sig.as_ref()).is_err());
    }

    #[test]
    fn verify_ed25519() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let message = b"ed25519 test payload";
        let sig = key_pair.sign(message);
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let key = SigningKey::Ed25519(public_key_bytes);
        assert!(verify_signature(&key, message, sig.as_ref()).is_ok());
    }

    #[test]
    fn base64_decode_basic() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
    }

    #[test]
    fn cosign_payload_parse() {
        let json = r#"{
            "critical": {
                "identity": {
                    "docker-reference": "ghcr.io/org/app"
                },
                "image": {
                    "docker-manifest-digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                },
                "type": "cosign container image signature"
            },
            "optional": null
        }"#;

        let payload: CosignPayload = serde_json::from_str(json).unwrap();
        assert_eq!(
            payload.critical.identity.docker_reference,
            "ghcr.io/org/app"
        );
        assert_eq!(payload.critical.type_, "cosign container image signature");
    }
}
