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
///
/// Cosign supports two verification modes:
///
/// * **Static key** — the signature is verified directly against a configured
///   public key.
/// * **Keyless** — the signature is made by an ephemeral key whose public half
///   is bound to an OIDC identity by a short-lived Fulcio-issued X.509
///   certificate, and whose existence is recorded in the Rekor transparency
///   log. Verification checks the certificate chains to a trusted Fulcio root,
///   its embedded identity matches policy, the signature verifies against the
///   certificate's public key, and (optionally) the Rekor inclusion proof is
///   valid.
#[derive(Debug, Clone)]
pub enum SignaturePolicy {
    /// Verify against a fixed public key.
    Key(SigningKey),
    /// Verify a Fulcio/Rekor keyless signature.
    Keyless(Box<KeylessPolicy>),
}

impl SignaturePolicy {
    /// Convenience constructor for a static-key policy.
    pub fn key(key: SigningKey) -> Self {
        SignaturePolicy::Key(key)
    }
}

/// Policy for verifying sigstore keyless (Fulcio/Rekor) signatures.
#[derive(Debug, Clone)]
pub struct KeylessPolicy {
    /// Trusted Fulcio root/intermediate CA certificates, DER-encoded. A
    /// signing certificate must chain to one of these to be trusted.
    pub fulcio_roots: Vec<Vec<u8>>,
    /// Accepted signer identities. A signing certificate must match at least
    /// one of these (SAN identity + OIDC issuer).
    pub identities: Vec<KeylessIdentity>,
    /// Rekor transparency-log public key (DER SPKI, ECDSA P-256). When present,
    /// the signature bundle's Rekor Signed Entry Timestamp is verified against
    /// this key. When absent, transparency-log verification is skipped.
    pub rekor_public_key: Option<Vec<u8>>,
}

/// An accepted keyless signer identity. Both fields must match the values
/// embedded in the Fulcio certificate for the identity to be accepted.
#[derive(Debug, Clone)]
pub struct KeylessIdentity {
    /// The Subject Alternative Name identity of the signer, e.g. an email
    /// address or a workflow URI. Matched exactly.
    pub subject: String,
    /// The OIDC issuer that authenticated the signer, e.g.
    /// `https://accounts.google.com` or a GitHub Actions issuer URL. Matched
    /// exactly against the Fulcio issuer extension.
    pub issuer: String,
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
    #[error("keyless signature missing Fulcio certificate")]
    MissingCertificate,
    #[error("certificate parse error: {0}")]
    CertificateParse(String),
    #[error("signing certificate does not chain to a trusted Fulcio root")]
    UntrustedCertificate,
    #[error("signing certificate is not valid at the current time")]
    CertificateExpired,
    #[error("signer identity {subject:?} (issuer {issuer:?}) does not match any allowed identity")]
    IdentityMismatch { subject: String, issuer: String },
    #[error("Rekor transparency-log verification failed: {0}")]
    RekorVerification(String),
}

/// A discovered cosign signature with its raw payload and base64-decoded signature bytes.
#[derive(Debug)]
struct CosignSignature {
    /// The raw payload bytes (the signed message).
    payload: Vec<u8>,
    /// The DER-encoded signature.
    signature: Vec<u8>,
    /// For keyless signatures, the PEM-encoded Fulcio signing certificate from
    /// the `dev.sigstore.cosign/certificate` layer annotation, if present.
    certificate_pem: Option<String>,
    /// For keyless signatures, the Rekor bundle JSON from the
    /// `dev.sigstore.cosign/bundle` layer annotation, if present.
    bundle_json: Option<String>,
}

/// Verify that at least one valid cosign signature exists for the given
/// manifest digest, according to the supplied policy.
///
/// Common steps (both modes):
///   1. Construct the signature tag: `sha256-<hex>.sig`
///   2. Fetch the signature manifest from the registry
///   3. Download each signature layer (payload + signature + annotations)
///   4. Verify the payload's `docker-manifest-digest` matches
///
/// Then, per mode:
///   * **Static key** — verify the signature against the configured key.
///   * **Keyless** — verify the Fulcio certificate chain, signer identity,
///     signature, and (optionally) the Rekor inclusion.
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

    match policy {
        SignaturePolicy::Key(key) => verify_static_key(key, &signatures, manifest_digest),
        SignaturePolicy::Keyless(keyless) => verify_keyless(keyless, &signatures, manifest_digest),
    }
}

/// Verify signatures against a fixed public key (cosign static-key mode).
fn verify_static_key(
    key: &SigningKey,
    signatures: &[CosignSignature],
    manifest_digest: &Digest,
) -> Result<(), SignatureError> {
    for sig in signatures {
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
        if verify_signature(key, &sig.payload, &sig.signature).is_ok() {
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

/// Verify a sigstore keyless (Fulcio/Rekor) signature.
///
/// For each candidate signature that carries a Fulcio certificate, this:
///   1. Confirms the payload references the expected manifest digest.
///   2. Parses the signing certificate and checks its validity window.
///   3. Confirms the certificate chains to a trusted Fulcio root.
///   4. Extracts the signer's SAN identity and OIDC issuer and requires them
///      to match an allowed identity in the policy.
///   5. Verifies the cosign signature over the payload using the certificate's
///      public key.
///   6. Optionally verifies the Rekor Signed Entry Timestamp.
fn verify_keyless(
    policy: &KeylessPolicy,
    signatures: &[CosignSignature],
    manifest_digest: &Digest,
) -> Result<(), SignatureError> {
    let mut last_err: Option<SignatureError> = None;

    for sig in signatures {
        let Some(cert_pem) = &sig.certificate_pem else {
            continue; // Not a keyless signature; skip.
        };

        // Payload must reference our manifest digest.
        let payload: CosignPayload = serde_json::from_slice(&sig.payload)
            .map_err(|e| SignatureError::PayloadParse(e.to_string()))?;
        if payload.critical.image.docker_manifest_digest != manifest_digest.to_string() {
            continue;
        }

        match verify_keyless_signature(policy, cert_pem, sig, manifest_digest) {
            Ok(()) => {
                tracing::info!(
                    digest = %manifest_digest,
                    "Keyless image signature verified successfully"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(err = %e, "Keyless signature candidate rejected");
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or(SignatureError::MissingCertificate))
}

/// Fulcio OIDC-issuer certificate extension OIDs.
///
/// `1.3.6.1.4.1.57264.1.1` is the original UTF8String issuer extension;
/// `1.3.6.1.4.1.57264.1.8` is the newer DER-encoded issuer (V2). Both encode
/// the OIDC issuer that authenticated the signer.
const FULCIO_ISSUER_OID_V1: &str = "1.3.6.1.4.1.57264.1.1";
const FULCIO_ISSUER_OID_V2: &str = "1.3.6.1.4.1.57264.1.8";

/// Verify a single keyless signature candidate end-to-end.
fn verify_keyless_signature(
    policy: &KeylessPolicy,
    cert_pem: &str,
    sig: &CosignSignature,
    manifest_digest: &Digest,
) -> Result<(), SignatureError> {
    // Decode the leaf certificate from PEM.
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| SignatureError::CertificateParse(format!("PEM parse: {e}")))?;
    let leaf = pem
        .parse_x509()
        .map_err(|e| SignatureError::CertificateParse(format!("X.509 parse: {e}")))?;

    // 1. Validity window.
    if !leaf.validity().is_valid() {
        return Err(SignatureError::CertificateExpired);
    }

    // 2. Chain to a trusted Fulcio root: the leaf's signature must verify under
    //    at least one configured root's public key.
    if !leaf_chains_to_root(&leaf, &policy.fulcio_roots) {
        return Err(SignatureError::UntrustedCertificate);
    }

    // 3. Signer identity: SAN + OIDC issuer must match an allowed identity.
    let subjects = extract_san_identities(&leaf);
    let issuer = extract_oidc_issuer(&leaf);
    let identity_ok = policy.identities.iter().any(|allowed| {
        subjects.iter().any(|s| s == &allowed.subject)
            && issuer.as_deref() == Some(allowed.issuer.as_str())
    });
    if !identity_ok {
        return Err(SignatureError::IdentityMismatch {
            subject: subjects.first().cloned().unwrap_or_default(),
            issuer: issuer.unwrap_or_default(),
        });
    }

    // 4. Verify the signature over the payload using the certificate's key.
    //    ring's ASN.1 ECDSA verifier expects the raw uncompressed public-key
    //    point (0x04 || X || Y), which is the SPKI subjectPublicKey bit string.
    let raw_point = leaf.public_key().subject_public_key.data.to_vec();
    let key = SigningKey::EcdsaP256(raw_point);
    verify_signature(&key, &sig.payload, &sig.signature)?;

    // 5. Optional Rekor transparency-log verification.
    if let Some(rekor_key) = &policy.rekor_public_key {
        verify_rekor_bundle(
            rekor_key,
            sig.bundle_json.as_deref(),
            &sig.payload,
            &sig.signature,
            manifest_digest,
        )?;
    }

    Ok(())
}

/// Check that a leaf certificate's signature verifies under at least one of the
/// provided trust-anchor certificates (DER-encoded Fulcio roots/intermediates).
fn leaf_chains_to_root(
    leaf: &x509_parser::certificate::X509Certificate,
    roots_der: &[Vec<u8>],
) -> bool {
    use x509_parser::prelude::*;

    for root_der in roots_der {
        let Ok((_, root)) = X509Certificate::from_der(root_der) else {
            continue;
        };
        // The leaf must be issued by this root (issuer/subject match) and its
        // signature must verify under the root's public key.
        if leaf.issuer() == root.subject() && leaf.verify_signature(Some(root.public_key())).is_ok()
        {
            return true;
        }
    }
    false
}

/// Extract Subject Alternative Name identities (email addresses and URIs) from
/// a certificate.
fn extract_san_identities(cert: &x509_parser::certificate::X509Certificate) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::*;

    let mut out = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::RFC822Name(s) => out.push(s.to_string()),
                    GeneralName::URI(s) => out.push(s.to_string()),
                    _ => {}
                }
            }
        }
    }
    out
}

/// Extract the OIDC issuer from a Fulcio certificate, checking both the legacy
/// (V1) UTF8String extension and the newer (V2) DER-encoded extension.
fn extract_oidc_issuer(cert: &x509_parser::certificate::X509Certificate) -> Option<String> {
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if oid == FULCIO_ISSUER_OID_V1 {
            // V1: the extension value is a raw UTF-8 string.
            return Some(String::from_utf8_lossy(ext.value).to_string());
        }
        if oid == FULCIO_ISSUER_OID_V2 {
            // V2: the value is a DER-encoded UTF8String. Strip the DER tag and
            // length prefix if present, otherwise fall back to lossy UTF-8.
            return Some(decode_der_utf8_string(ext.value));
        }
    }
    None
}

/// Best-effort decode of a DER-encoded UTF8String (tag 0x0C). Falls back to a
/// lossy UTF-8 interpretation of the raw bytes if the encoding is unexpected.
fn decode_der_utf8_string(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0x0c {
        let len = bytes[1] as usize;
        if bytes.len() >= 2 + len {
            return String::from_utf8_lossy(&bytes[2..2 + len]).to_string();
        }
    }
    String::from_utf8_lossy(bytes).to_string()
}

/// Verify the Rekor Signed Entry Timestamp (SET) from a cosign bundle.
///
/// The bundle's `SignedEntryTimestamp` is an ECDSA signature (by Rekor) over
/// the canonicalized `Payload` object. We reconstruct the canonical form and
/// verify it against the configured Rekor public key.
fn verify_rekor_bundle(
    rekor_key_der: &[u8],
    bundle_json: Option<&str>,
    _payload: &[u8],
    _signature: &[u8],
    _manifest_digest: &Digest,
) -> Result<(), SignatureError> {
    let bundle_json = bundle_json.ok_or_else(|| {
        SignatureError::RekorVerification(
            "keyless policy requires Rekor bundle but none present".into(),
        )
    })?;

    let bundle: RekorBundle = serde_json::from_str(bundle_json)
        .map_err(|e| SignatureError::RekorVerification(format!("bundle parse: {e}")))?;

    let set = base64_decode(&bundle.signed_entry_timestamp)
        .map_err(|e| SignatureError::RekorVerification(format!("SET base64: {e}")))?;

    // Rekor canonicalizes the Payload object with sorted keys and no extra
    // whitespace before signing. serde_json::to_vec on a BTreeMap-backed value
    // yields lexicographically sorted keys, matching Rekor's canonical form.
    let canonical = canonical_json(&bundle.payload)
        .map_err(|e| SignatureError::RekorVerification(format!("canonicalize: {e}")))?;

    let key = SigningKey::EcdsaP256(rekor_key_der.to_vec());
    verify_signature(&key, &canonical, &set)
        .map_err(|_| SignatureError::RekorVerification("SET signature invalid".into()))?;

    Ok(())
}

/// A cosign Rekor bundle as embedded in the `dev.sigstore.cosign/bundle`
/// annotation.
#[derive(Debug, Deserialize)]
struct RekorBundle {
    #[serde(rename = "SignedEntryTimestamp")]
    signed_entry_timestamp: String,
    #[serde(rename = "Payload")]
    payload: serde_json::Value,
}

/// Produce a canonical JSON serialization (lexicographically sorted object
/// keys, no insignificant whitespace), matching Rekor's canonicalization.
fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    fn write(value: &serde_json::Value, out: &mut Vec<u8>) {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push(b'{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(serde_json::to_string(k).unwrap_or_default().as_bytes());
                    out.push(b':');
                    write(&map[*k], out);
                }
                out.push(b'}');
            }
            serde_json::Value::Array(arr) => {
                out.push(b'[');
                for (i, v) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write(v, out);
                }
                out.push(b']');
            }
            other => {
                out.extend_from_slice(other.to_string().as_bytes());
            }
        }
    }

    let mut out = Vec::new();
    write(value, &mut out);
    Ok(out)
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

        // For keyless signatures, cosign attaches the Fulcio certificate and
        // Rekor bundle as layer-descriptor annotations.
        let (certificate_pem, bundle_json) = match &layer.annotations {
            Some(ann) => (
                ann.get("dev.sigstore.cosign/certificate").cloned(),
                ann.get("dev.sigstore.cosign/bundle").cloned(),
            ),
            None => (None, None),
        };

        if !payload.is_empty() && !sig_bytes.is_empty() {
            signatures.push(CosignSignature {
                payload,
                signature: sig_bytes,
                certificate_pem,
                bundle_json,
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
    fn verify_ed25519_wrong_key() {
        let rng = ring::rand::SystemRandom::new();

        // Generate two key pairs
        let pkcs8_a = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair_a = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_a.as_ref()).unwrap();

        let pkcs8_b = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair_b = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_b.as_ref()).unwrap();

        // Sign with key A, verify with key B's public key
        let message = b"signed by A";
        let sig = key_pair_a.sign(message);
        let wrong_public_key = key_pair_b.public_key().as_ref().to_vec();

        let key = SigningKey::Ed25519(wrong_public_key);
        assert!(verify_signature(&key, message, sig.as_ref()).is_err());
    }

    #[test]
    fn verify_ed25519_wrong_message() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let sig = key_pair.sign(b"original");
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let key = SigningKey::Ed25519(public_key_bytes);
        assert!(verify_signature(&key, b"tampered", sig.as_ref()).is_err());
    }

    #[test]
    fn verify_ecdsa_wrong_key() {
        let rng = ring::rand::SystemRandom::new();

        let pkcs8_a = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair_a = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_a.as_ref(),
            &rng,
        )
        .unwrap();

        let pkcs8_b = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair_b = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_b.as_ref(),
            &rng,
        )
        .unwrap();

        let sig = key_pair_a.sign(&rng, b"message").unwrap();
        let wrong_public_key = key_pair_b.public_key().as_ref().to_vec();

        let key = SigningKey::EcdsaP256(wrong_public_key);
        assert!(verify_signature(&key, b"message", sig.as_ref()).is_err());
    }

    #[test]
    fn verify_empty_signature_fails() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let key = SigningKey::Ed25519(public_key_bytes);
        assert!(verify_signature(&key, b"message", &[]).is_err());
    }

    #[test]
    fn verify_truncated_signature_fails() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let message = b"test";
        let sig = key_pair.sign(message);
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        // Truncate signature to half its length
        let truncated = &sig.as_ref()[..sig.as_ref().len() / 2];

        let key = SigningKey::Ed25519(public_key_bytes);
        assert!(verify_signature(&key, message, truncated).is_err());
    }

    #[test]
    fn base64_decode_invalid_char() {
        assert!(base64_decode("abc!").is_err());
    }

    #[test]
    fn base64_decode_with_whitespace() {
        // base64 decoder should handle whitespace within input
        assert_eq!(base64_decode("aGVs\nbG8=").unwrap(), b"hello");
    }

    #[test]
    fn base64_decode_no_padding() {
        // "ab" in base64 without padding
        assert_eq!(base64_decode("YWI").unwrap(), b"ab");
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

    #[test]
    fn cosign_payload_without_optional() {
        // optional field is absent entirely
        let json = r#"{
            "critical": {
                "identity": {
                    "docker-reference": "ghcr.io/org/app"
                },
                "image": {
                    "docker-manifest-digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                },
                "type": "cosign container image signature"
            }
        }"#;

        let payload: CosignPayload = serde_json::from_str(json).unwrap();
        assert!(payload.optional.is_none());
    }

    #[test]
    fn cosign_payload_with_optional_annotations() {
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
            "optional": {"creator": "test", "timestamp": 1234567890}
        }"#;

        let payload: CosignPayload = serde_json::from_str(json).unwrap();
        assert!(payload.optional.is_some());
    }

    #[test]
    fn cosign_payload_invalid_json_rejected() {
        let bad = r#"{"not": "a cosign payload"}"#;
        assert!(serde_json::from_str::<CosignPayload>(bad).is_err());
    }

    #[test]
    fn contains_subsequence_found() {
        assert!(contains_subsequence(b"hello world", b"world"));
        assert!(contains_subsequence(b"hello world", b"hello"));
        assert!(contains_subsequence(b"abc", b"abc"));
    }

    #[test]
    fn contains_subsequence_not_found() {
        assert!(!contains_subsequence(b"hello", b"world"));
        assert!(!contains_subsequence(b"ab", b"abc"));
        assert!(!contains_subsequence(b"", b"a"));
    }

    // -- Keyless (Fulcio/Rekor) verification tests ---------------------------

    /// A Fulcio-style keyless test fixture: a self-signed root CA, a leaf
    /// certificate issued by that root carrying a SAN identity and OIDC issuer
    /// extension, and a cosign signature over a payload produced with the
    /// leaf's private key.
    struct KeylessFixture {
        root_der: Vec<u8>,
        signature: CosignSignature,
        manifest_digest: Digest,
        subject: String,
        issuer: String,
    }

    fn build_keyless_fixture(subject: &str, issuer: &str) -> KeylessFixture {
        use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, SanType};

        // Root CA.
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-fulcio-root");
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_der = root_cert.der().to_vec();

        // Leaf key (also used to sign the cosign payload).
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec![]).unwrap();
        leaf_params
            .subject_alt_names
            .push(SanType::Rfc822Name(subject.to_string().try_into().unwrap()));
        // Fulcio V1 OIDC issuer extension: raw UTF-8 string content.
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
                issuer.as_bytes().to_vec(),
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();
        let leaf_pem = leaf_cert.pem();

        // Build a cosign payload referencing a manifest digest.
        let manifest_digest = Digest::from_bytes(b"keyless-test-image");
        let payload = serde_json::json!({
            "critical": {
                "identity": {"docker-reference": "registry/app"},
                "image": {"docker-manifest-digest": manifest_digest.to_string()},
                "type": "cosign container image signature"
            },
            "optional": null
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // Sign the payload with the leaf private key using ring (ASN.1 ECDSA).
        let pkcs8 = leaf_key.serialize_der();
        let rng = ring::rand::SystemRandom::new();
        let signing = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &pkcs8,
            &rng,
        )
        .unwrap();
        let sig = signing.sign(&rng, &payload_bytes).unwrap();

        KeylessFixture {
            root_der,
            signature: CosignSignature {
                payload: payload_bytes,
                signature: sig.as_ref().to_vec(),
                certificate_pem: Some(leaf_pem),
                bundle_json: None,
            },
            manifest_digest,
            subject: subject.to_string(),
            issuer: issuer.to_string(),
        }
    }

    #[test]
    fn keyless_verifies_matching_identity() {
        let subject = "ci@example.com";
        let issuer = "https://accounts.example.com";
        let fx = build_keyless_fixture(subject, issuer);

        let policy = KeylessPolicy {
            fulcio_roots: vec![fx.root_der.clone()],
            identities: vec![KeylessIdentity {
                subject: subject.to_string(),
                issuer: issuer.to_string(),
            }],
            rekor_public_key: None,
        };

        verify_keyless(
            &policy,
            std::slice::from_ref(&fx.signature),
            &fx.manifest_digest,
        )
        .expect("keyless verification must succeed for a matching identity");
    }

    #[test]
    fn keyless_rejects_wrong_identity() {
        let fx = build_keyless_fixture("ci@example.com", "https://accounts.example.com");

        let policy = KeylessPolicy {
            fulcio_roots: vec![fx.root_der.clone()],
            identities: vec![KeylessIdentity {
                subject: "attacker@evil.com".to_string(),
                issuer: fx.issuer.clone(),
            }],
            rekor_public_key: None,
        };

        let err = verify_keyless(
            &policy,
            std::slice::from_ref(&fx.signature),
            &fx.manifest_digest,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureError::IdentityMismatch { .. }));
    }

    #[test]
    fn keyless_rejects_untrusted_root() {
        let fx = build_keyless_fixture("ci@example.com", "https://accounts.example.com");
        // A different, unrelated CA that did not issue the leaf.
        let other = build_keyless_fixture("other@example.com", "https://accounts.example.com");

        let policy = KeylessPolicy {
            fulcio_roots: vec![other.root_der.clone()],
            identities: vec![KeylessIdentity {
                subject: fx.subject.clone(),
                issuer: fx.issuer.clone(),
            }],
            rekor_public_key: None,
        };

        let err = verify_keyless(
            &policy,
            std::slice::from_ref(&fx.signature),
            &fx.manifest_digest,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureError::UntrustedCertificate));
    }

    #[test]
    fn keyless_rejects_tampered_payload_signature() {
        let fx = build_keyless_fixture("ci@example.com", "https://accounts.example.com");
        let mut tampered = CosignSignature {
            payload: fx.signature.payload.clone(),
            signature: fx.signature.signature.clone(),
            certificate_pem: fx.signature.certificate_pem.clone(),
            bundle_json: None,
        };
        // Flip a byte in the signature so cryptographic verification fails.
        tampered.signature[10] ^= 0xff;

        let policy = KeylessPolicy {
            fulcio_roots: vec![fx.root_der.clone()],
            identities: vec![KeylessIdentity {
                subject: fx.subject.clone(),
                issuer: fx.issuer.clone(),
            }],
            rekor_public_key: None,
        };

        assert!(
            verify_keyless(
                &policy,
                std::slice::from_ref(&tampered),
                &fx.manifest_digest
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let value = serde_json::json!({"b": 1, "a": {"d": 2, "c": 3}});
        let bytes = canonical_json(&value).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"a":{"c":3,"d":2},"b":1}"#
        );
    }
}
