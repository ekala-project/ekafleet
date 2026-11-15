//! Cosign image signature verification.
//!
//! Verifies OCI image signatures using cosign's static key verification
//! protocol. After a manifest is fetched, signatures are discovered at
//! the conventional cosign tag `<repo>:sha256-<hex>.sig` and verified
//! against a configured public key.
//!
//! Static keys (ECDSA P-256, Ed25519) and sigstore keyless signatures
//! (a Fulcio certificate, logged in Rekor) are supported.

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
    /// Rekor transparency-log public key (the raw ECDSA P-256 point). The
    /// signature's Rekor bundle must carry a Signed Entry Timestamp by this
    /// key: Fulcio certificates live for minutes, so the time Rekor logged
    /// the signature is what proves the certificate was valid when used.
    pub rekor_public_key: Vec<u8>,
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
    #[error("signing certificate was not valid when the signature was logged")]
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
///   2. Confirms the certificate chains to a trusted Fulcio root.
///   3. Extracts the signer's SAN identity and OIDC issuer and requires them
///      to match an allowed identity in the policy.
///   4. Verifies the cosign signature over the payload using the certificate's
///      public key.
///   5. Verifies the Rekor Signed Entry Timestamp, that the logged entry is
///      this signature over this payload, and that the certificate was valid
///      at the logged time.
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

    // 1. Chain to a trusted Fulcio root: the leaf's signature must verify under
    //    at least one configured root's public key.
    if !leaf_chains_to_root(&leaf, &policy.fulcio_roots) {
        return Err(SignatureError::UntrustedCertificate);
    }

    // 2. Signer identity: SAN + OIDC issuer must match an allowed identity.
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

    // 3. Verify the signature over the payload using the certificate's key.
    //    ring's ASN.1 ECDSA verifier expects the raw uncompressed public-key
    //    point (0x04 || X || Y), which is the SPKI subjectPublicKey bit string.
    let raw_point = leaf.public_key().subject_public_key.data.to_vec();
    let key = SigningKey::EcdsaP256(raw_point);
    verify_signature(&key, &sig.payload, &sig.signature)?;

    // 4. Rekor: the entry is logged, and the certificate (valid for minutes)
    //    was valid at the time it was.
    let logged_at = verify_rekor_bundle(
        &policy.rekor_public_key,
        sig.bundle_json.as_deref(),
        &sig.payload,
        &sig.signature,
    )?;
    let validity = leaf.validity();
    if logged_at < validity.not_before.timestamp() || logged_at > validity.not_after.timestamp() {
        return Err(SignatureError::CertificateExpired);
    }
    tracing::debug!(digest = %manifest_digest, logged_at, "Rekor entry verified");

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

/// Verify the Rekor Signed Entry Timestamp (SET) from a cosign bundle and
/// return the time the entry was logged.
///
/// The bundle's `SignedEntryTimestamp` is an ECDSA signature (by Rekor) over
/// the canonicalized `Payload` object. We reconstruct the canonical form and
/// verify it against the configured Rekor public key, then require the logged
/// entry to be a `hashedrekord` of exactly this signature over this payload,
/// so a timestamp for some other entry cannot be replayed.
fn verify_rekor_bundle(
    rekor_key: &[u8],
    bundle_json: Option<&str>,
    payload: &[u8],
    signature: &[u8],
) -> Result<i64, SignatureError> {
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

    let key = SigningKey::EcdsaP256(rekor_key.to_vec());
    verify_signature(&key, &canonical, &set)
        .map_err(|_| SignatureError::RekorVerification("SET signature invalid".into()))?;

    let entry: RekorEntryPayload = serde_json::from_value(bundle.payload)
        .map_err(|e| SignatureError::RekorVerification(format!("bundle payload: {e}")))?;
    let body = base64_decode(&entry.body)
        .map_err(|e| SignatureError::RekorVerification(format!("entry body base64: {e}")))?;
    let body: HashedRekord = serde_json::from_slice(&body)
        .map_err(|e| SignatureError::RekorVerification(format!("entry body: {e}")))?;
    if body.kind != "hashedrekord" {
        return Err(SignatureError::RekorVerification(format!(
            "unsupported entry kind {:?}",
            body.kind
        )));
    }
    let hash = &body.spec.data.hash;
    let payload_hash = hex_lower(ring::digest::digest(&ring::digest::SHA256, payload).as_ref());
    if hash.algorithm != "sha256" || !hash.value.eq_ignore_ascii_case(&payload_hash) {
        return Err(SignatureError::RekorVerification(
            "logged entry is for a different payload".into(),
        ));
    }
    let logged_signature = base64_decode(&body.spec.signature.content)
        .map_err(|e| SignatureError::RekorVerification(format!("entry signature: {e}")))?;
    if logged_signature != signature {
        return Err(SignatureError::RekorVerification(
            "logged entry is for a different signature".into(),
        ));
    }
    Ok(entry.integrated_time)
}

/// The fields of a Rekor bundle payload used for verification.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorEntryPayload {
    /// Base64 of the canonical entry body.
    body: String,
    /// Unix time the entry was logged.
    integrated_time: i64,
}

/// A Rekor `hashedrekord` entry body.
#[derive(Debug, Deserialize)]
struct HashedRekord {
    kind: String,
    spec: HashedRekordSpec,
}

#[derive(Debug, Deserialize)]
struct HashedRekordSpec {
    data: HashedRekordData,
    signature: HashedRekordSignature,
}

#[derive(Debug, Deserialize)]
struct HashedRekordData {
    hash: HashedRekordHash,
}

#[derive(Debug, Deserialize)]
struct HashedRekordHash {
    algorithm: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct HashedRekordSignature {
    content: String,
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
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

/// Most signatures read from one signature manifest.
const MAX_SIGNATURES: usize = 16;

/// Largest signature payload fetched (simplesigning payloads are tiny).
const MAX_SIGNATURE_PAYLOAD: u64 = 1 << 20;

/// Extract signature payloads and signatures from a cosign signature manifest.
///
/// Each layer of a cosign signature manifest is a simplesigning payload (the
/// signed message); its descriptor carries the base64 signature in the
/// `dev.cosignproject.cosign/signature` annotation and, for keyless
/// signatures, the Fulcio certificate and Rekor bundle.
async fn extract_signatures(
    client: &RegistryClient,
    image: &ImageReference,
    manifest: &ImageManifest,
) -> Result<Vec<CosignSignature>, SignatureError> {
    let mut signatures = Vec::new();

    for layer in manifest.layers.iter().take(MAX_SIGNATURES) {
        let Some(annotations) = &layer.annotations else {
            continue;
        };
        let Some(encoded) = annotations.get("dev.cosignproject.cosign/signature") else {
            continue;
        };
        if layer.size > MAX_SIGNATURE_PAYLOAD {
            tracing::warn!(digest = %layer.digest, size = layer.size, "Skipping oversized signature payload");
            continue;
        }
        let signature = match base64_decode(encoded) {
            Ok(sig) if !sig.is_empty() => sig,
            _ => {
                tracing::warn!(digest = %layer.digest, "Skipping malformed signature annotation");
                continue;
            }
        };
        // fetch_blob verifies the payload against its descriptor digest.
        let payload = match client.fetch_blob(image, &layer.digest).await {
            Ok(b) => b.data,
            Err(e) => {
                tracing::warn!(digest = %layer.digest, err = %e, "Failed to fetch signature payload");
                continue;
            }
        };
        signatures.push(CosignSignature {
            payload,
            signature,
            certificate_pem: annotations.get("dev.sigstore.cosign/certificate").cloned(),
            bundle_json: annotations.get("dev.sigstore.cosign/bundle").cloned(),
        });
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
/// Supports ECDSA P-256 and Ed25519 keys in SubjectPublicKeyInfo (SPKI)
/// format (`-----BEGIN PUBLIC KEY-----`, as written by `cosign generate-key-pair`).
/// The key is reduced to the raw public key ring verifies with.
pub fn parse_public_key_pem(pem_data: &str) -> Result<SigningKey, SignatureError> {
    use x509_parser::prelude::FromDer;

    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_data.trim().as_bytes())
        .map_err(|e| SignatureError::InvalidKey(format!("PEM parse: {e}")))?;
    if pem.label != "PUBLIC KEY" {
        return Err(SignatureError::InvalidKey(format!(
            "expected a PUBLIC KEY PEM block, found {:?}",
            pem.label
        )));
    }
    let (rest, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&pem.contents)
        .map_err(|e| SignatureError::InvalidKey(format!("SPKI parse: {e}")))?;
    if !rest.is_empty() {
        return Err(SignatureError::InvalidKey(
            "trailing data after SPKI".into(),
        ));
    }
    let key = spki.subject_public_key.data.to_vec();
    match spki.algorithm.algorithm.to_id_string().as_str() {
        // id-ecPublicKey, on prime256v1 only.
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| oid.to_id_string());
            if curve.as_deref() != Some("1.2.840.10045.3.1.7") {
                return Err(SignatureError::InvalidKey(
                    "unsupported EC curve (expected P-256)".into(),
                ));
            }
            Ok(SigningKey::EcdsaP256(key))
        }
        "1.3.101.112" => Ok(SigningKey::Ed25519(key)),
        _ => Err(SignatureError::InvalidKey(
            "unsupported key algorithm (expected ECDSA P-256 or Ed25519)".into(),
        )),
    }
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
    fn public_keys_parse_to_raw_keys() {
        let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        match parse_public_key_pem(&ec.public_key_pem()).unwrap() {
            SigningKey::EcdsaP256(raw) => assert_eq!(raw, ec.public_key_raw()),
            other => panic!("unexpected key {other:?}"),
        }
        let ed = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        match parse_public_key_pem(&ed.public_key_pem()).unwrap() {
            SigningKey::Ed25519(raw) => assert_eq!(raw, ed.public_key_raw()),
            other => panic!("unexpected key {other:?}"),
        }
        // P-384 and private keys are refused.
        let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        assert!(parse_public_key_pem(&p384.public_key_pem()).is_err());
        assert!(parse_public_key_pem(&ec.serialize_pem()).is_err());
    }

    #[test]
    fn static_key_signatures_verify_against_a_pem_key() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let digest = Digest::from_bytes(b"image");
        let payload = serde_json::to_vec(&serde_json::json!({
            "critical": {
                "identity": {"docker-reference": "registry/app"},
                "image": {"docker-manifest-digest": digest.to_string()},
                "type": "cosign container image signature"
            },
            "optional": null
        }))
        .unwrap();
        let rng = ring::rand::SystemRandom::new();
        let signer = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &key.serialize_der(),
            &rng,
        )
        .unwrap();
        let sig = CosignSignature {
            payload: payload.clone(),
            signature: signer.sign(&rng, &payload).unwrap().as_ref().to_vec(),
            certificate_pem: None,
            bundle_json: None,
        };
        let parsed = parse_public_key_pem(&key.public_key_pem()).unwrap();
        verify_static_key(&parsed, std::slice::from_ref(&sig), &digest).unwrap();
        // The same signature does not vouch for another digest.
        assert!(verify_static_key(&parsed, &[sig], &Digest::from_bytes(b"other")).is_err());
    }

    // -- Keyless (Fulcio/Rekor) verification tests ---------------------------

    /// When the fixture's leaf certificate is valid: a ten-minute window,
    /// long past, like a real Fulcio certificate.
    const LEAF_NOT_BEFORE: i64 = 1_600_000_000;
    const LEAF_NOT_AFTER: i64 = LEAF_NOT_BEFORE + 600;

    /// A Fulcio-style keyless test fixture: a self-signed root CA, a leaf
    /// certificate issued by that root carrying a SAN identity and OIDC issuer
    /// extension, a cosign signature over a payload produced with the leaf's
    /// private key, and a Rekor bundle logging it at `logged_at`.
    struct KeylessFixture {
        root_der: Vec<u8>,
        rekor_key: Vec<u8>,
        signature: CosignSignature,
        manifest_digest: Digest,
        subject: String,
        issuer: String,
    }

    impl KeylessFixture {
        fn policy(&self) -> KeylessPolicy {
            KeylessPolicy {
                fulcio_roots: vec![self.root_der.clone()],
                identities: vec![KeylessIdentity {
                    subject: self.subject.clone(),
                    issuer: self.issuer.clone(),
                }],
                rekor_public_key: self.rekor_key.clone(),
            }
        }

        fn verify(&self, policy: &KeylessPolicy) -> Result<(), SignatureError> {
            verify_keyless(
                policy,
                std::slice::from_ref(&self.signature),
                &self.manifest_digest,
            )
        }
    }

    fn ecdsa_signer(pkcs8: &[u8]) -> ring::signature::EcdsaKeyPair {
        ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap()
    }

    /// A Rekor bundle logging a hashedrekord of `signature` over `payload`.
    fn rekor_bundle(
        rekor: &ring::signature::EcdsaKeyPair,
        payload: &[u8],
        signature: &[u8],
        logged_at: i64,
    ) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {
                    "algorithm": "sha256",
                    "value": hex_lower(ring::digest::digest(&ring::digest::SHA256, payload).as_ref()),
                }},
                "signature": {"content": b64.encode(signature), "publicKey": {"content": ""}},
            },
        });
        let entry = serde_json::json!({
            "body": b64.encode(serde_json::to_vec(&body).unwrap()),
            "integratedTime": logged_at,
            "logIndex": 7,
            "logID": "c0ffee",
        });
        let set = rekor
            .sign(
                &ring::rand::SystemRandom::new(),
                &canonical_json(&entry).unwrap(),
            )
            .unwrap();
        serde_json::json!({
            "SignedEntryTimestamp": b64.encode(set.as_ref()),
            "Payload": entry,
        })
        .to_string()
    }

    fn build_keyless_fixture(subject: &str, issuer: &str, logged_at: i64) -> KeylessFixture {
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
        leaf_params.not_before =
            time::OffsetDateTime::from_unix_timestamp(LEAF_NOT_BEFORE).unwrap();
        leaf_params.not_after = time::OffsetDateTime::from_unix_timestamp(LEAF_NOT_AFTER).unwrap();
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

        // Build a cosign payload referencing a manifest digest.
        let manifest_digest = Digest::from_bytes(b"keyless-test-image");
        let payload = serde_json::to_vec(&serde_json::json!({
            "critical": {
                "identity": {"docker-reference": "registry/app"},
                "image": {"docker-manifest-digest": manifest_digest.to_string()},
                "type": "cosign container image signature"
            },
            "optional": null
        }))
        .unwrap();
        let rng = ring::rand::SystemRandom::new();
        let sig = ecdsa_signer(&leaf_key.serialize_der())
            .sign(&rng, &payload)
            .unwrap()
            .as_ref()
            .to_vec();

        let rekor_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let rekor = ecdsa_signer(rekor_pkcs8.as_ref());
        let bundle = rekor_bundle(&rekor, &payload, &sig, logged_at);

        KeylessFixture {
            root_der,
            rekor_key: rekor.public_key().as_ref().to_vec(),
            signature: CosignSignature {
                payload,
                signature: sig,
                certificate_pem: Some(leaf_cert.pem()),
                bundle_json: Some(bundle),
            },
            manifest_digest,
            subject: subject.to_string(),
            issuer: issuer.to_string(),
        }
    }

    const SUBJECT: &str = "ci@example.com";
    const ISSUER: &str = "https://accounts.example.com";

    #[test]
    fn keyless_verifies_matching_identity() {
        // The certificate expired long ago; it was valid when logged.
        let fx = build_keyless_fixture(SUBJECT, ISSUER, LEAF_NOT_BEFORE + 60);
        fx.verify(&fx.policy())
            .expect("keyless verification must succeed for a matching identity");
    }

    #[test]
    fn keyless_rejects_signatures_logged_outside_the_certificate_validity() {
        let fx = build_keyless_fixture(SUBJECT, ISSUER, LEAF_NOT_AFTER + 1);
        assert!(matches!(
            fx.verify(&fx.policy()),
            Err(SignatureError::CertificateExpired)
        ));
    }

    #[test]
    fn keyless_requires_a_rekor_entry_for_this_signature() {
        let mut fx = build_keyless_fixture(SUBJECT, ISSUER, LEAF_NOT_BEFORE + 60);
        let policy = fx.policy();

        // An entry signed by another log is refused.
        let other = build_keyless_fixture(SUBJECT, ISSUER, LEAF_NOT_BEFORE + 60);
        let mut foreign = policy.clone();
        foreign.rekor_public_key = other.rekor_key.clone();
        assert!(matches!(
            fx.verify(&foreign),
            Err(SignatureError::RekorVerification(_))
        ));

        // A genuine entry for a different signature is not replayable.
        fx.signature.bundle_json = other.signature.bundle_json.clone();
        let mut replayed = policy.clone();
        replayed.rekor_public_key = other.rekor_key.clone();
        assert!(matches!(
            fx.verify(&replayed),
            Err(SignatureError::RekorVerification(_))
        ));

        fx.signature.bundle_json = None;
        assert!(matches!(
            fx.verify(&policy),
            Err(SignatureError::RekorVerification(_))
        ));
    }

    #[test]
    fn keyless_rejects_wrong_identity() {
        let fx = build_keyless_fixture(SUBJECT, ISSUER, LEAF_NOT_BEFORE + 60);
        let mut policy = fx.policy();
        policy.identities[0].subject = "attacker@evil.com".to_string();
        assert!(matches!(
            fx.verify(&policy),
            Err(SignatureError::IdentityMismatch { .. })
        ));
    }

    #[test]
    fn keyless_rejects_untrusted_root() {
        let fx = build_keyless_fixture(SUBJECT, ISSUER, LEAF_NOT_BEFORE + 60);
        // A different, unrelated CA that did not issue the leaf.
        let other = build_keyless_fixture("other@example.com", ISSUER, LEAF_NOT_BEFORE + 60);
        let mut policy = fx.policy();
        policy.fulcio_roots = vec![other.root_der.clone()];
        assert!(matches!(
            fx.verify(&policy),
            Err(SignatureError::UntrustedCertificate)
        ));
    }

    #[test]
    fn keyless_rejects_tampered_payload_signature() {
        let mut fx = build_keyless_fixture(SUBJECT, ISSUER, LEAF_NOT_BEFORE + 60);
        // Flip a byte in the signature so cryptographic verification fails.
        fx.signature.signature[10] ^= 0xff;
        assert!(fx.verify(&fx.policy()).is_err());
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
