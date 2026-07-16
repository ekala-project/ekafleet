use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::RwLock;

/// Root Certificate Authority for the fleet.
/// Generates and manages the root CA key/cert, issues
/// leaf certificates with SPIFFE-compatible identities.
#[derive(Clone)]
pub struct RootCa {
    inner: Arc<RwLock<CaState>>,
}

/// Default lifetime of an intermediate CA certificate. Intermediates are
/// short-lived relative to the root so they can be rotated (and, on
/// compromise, allowed to expire) without touching the long-lived root key.
const DEFAULT_INTERMEDIATE_TTL: Duration = Duration::from_secs(90 * 24 * 3600); // 90 days

/// Re-issue the intermediate when its remaining lifetime drops below this
/// threshold, so leaves are never signed by an intermediate that will expire
/// before the leaves they sign.
const INTERMEDIATE_RENEW_BEFORE: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days

struct CaState {
    /// Fleet domain for SPIFFE URIs (e.g., fleet.internal)
    domain: String,
    /// Root CA keypair. Signs only intermediate CA certificates, never leaves.
    root_keypair: Option<KeyPair>,
    /// Root CA certificate (PEM-encoded)
    root_cert_pem: Option<String>,
    /// Root CA certificate (DER-encoded, for distribution)
    root_cert_der: Option<Vec<u8>>,
    /// Short-lived intermediate CA keypair. Signs all leaf certificates.
    intermediate_keypair: Option<KeyPair>,
    /// Intermediate CA certificate (PEM-encoded), signed by the root.
    intermediate_cert_pem: Option<String>,
    /// Unix-epoch second at which the current intermediate certificate expires.
    intermediate_expires_at: u64,
    /// Default leaf certificate lifetime
    default_ttl: Duration,
}

impl RootCa {
    pub fn new(domain: &str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CaState {
                domain: domain.to_string(),
                root_keypair: None,
                root_cert_pem: None,
                root_cert_der: None,
                intermediate_keypair: None,
                intermediate_cert_pem: None,
                intermediate_expires_at: 0,
                default_ttl: Duration::from_secs(3600), // 1 hour default
            })),
        }
    }

    /// Initialize the CA. Generates a new root key/cert if none exists,
    /// or loads from persisted PEM state. Always ensures a valid short-lived
    /// intermediate CA exists (loading a persisted one, or minting a fresh one
    /// signed by the root).
    pub async fn initialize(
        &self,
        stored_key_pem: Option<&str>,
        stored_cert_pem: Option<&str>,
    ) -> Result<(), CaError> {
        self.initialize_with_intermediate(stored_key_pem, stored_cert_pem, None, None)
            .await
    }

    /// Like [`initialize`], but also accepts a persisted intermediate CA
    /// key/cert. When the stored intermediate is missing, unparsable, or within
    /// [`INTERMEDIATE_RENEW_BEFORE`] of expiry, a fresh intermediate is minted.
    pub async fn initialize_with_intermediate(
        &self,
        stored_key_pem: Option<&str>,
        stored_cert_pem: Option<&str>,
        stored_int_key_pem: Option<&str>,
        stored_int_cert_pem: Option<&str>,
    ) -> Result<(), CaError> {
        let mut state = self.inner.write().await;
        match (stored_key_pem, stored_cert_pem) {
            (Some(key_pem), Some(cert_pem)) => {
                tracing::info!("Loading existing root CA");
                let keypair = KeyPair::from_pem(key_pem)
                    .map_err(|e| CaError::KeyGeneration(format!("failed to load CA key: {e}")))?;

                // Parse the cert to extract DER
                let cert_der = pem_to_der(cert_pem)?;

                state.root_keypair = Some(keypair);
                state.root_cert_pem = Some(cert_pem.to_string());
                state.root_cert_der = Some(cert_der);
            }
            _ => {
                tracing::info!("Generating new root CA keypair");
                let keypair = KeyPair::generate()
                    .map_err(|e| CaError::KeyGeneration(format!("keypair generation: {e}")))?;

                let mut params = CertificateParams::new(vec![])
                    .map_err(|e| CaError::KeyGeneration(format!("cert params: {e}")))?;
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.distinguished_name.push(
                    DnType::CommonName,
                    format!("ekafleet Root CA ({})", state.domain),
                );
                params
                    .distinguished_name
                    .push(DnType::OrganizationName, "ekafleet");
                params.key_usages.push(KeyUsagePurpose::KeyCertSign);
                params.key_usages.push(KeyUsagePurpose::CrlSign);
                // CA cert valid for 10 years
                params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

                // Generate a random serial number
                let serial = generate_serial()?;
                params.serial_number = Some(serial);

                let cert = params.self_signed(&keypair).map_err(|e| {
                    CaError::KeyGeneration(format!("self-signed cert generation: {e}"))
                })?;

                let cert_pem = cert.pem();
                let cert_der = cert.der().to_vec();

                tracing::info!(
                    domain = %state.domain,
                    "Root CA generated"
                );

                state.root_keypair = Some(keypair);
                state.root_cert_pem = Some(cert_pem);
                state.root_cert_der = Some(cert_der);
            }
        }

        // Load a persisted intermediate if it is still comfortably valid;
        // otherwise mint a fresh one signed by the root.
        let now = unix_now();
        let loaded = match (stored_int_key_pem, stored_int_cert_pem) {
            (Some(int_key_pem), Some(int_cert_pem)) => match KeyPair::from_pem(int_key_pem) {
                Ok(kp) => match intermediate_not_after(int_cert_pem) {
                    Ok(expires_at)
                        if expires_at > now.saturating_add(INTERMEDIATE_RENEW_BEFORE.as_secs()) =>
                    {
                        state.intermediate_keypair = Some(kp);
                        state.intermediate_cert_pem = Some(int_cert_pem.to_string());
                        state.intermediate_expires_at = expires_at;
                        tracing::info!("Loaded existing intermediate CA");
                        true
                    }
                    _ => {
                        tracing::info!(
                            "Persisted intermediate CA is missing, expired, or near expiry; \
                                 minting a fresh intermediate"
                        );
                        false
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to load intermediate CA key; minting fresh");
                    false
                }
            },
            _ => false,
        };

        if !loaded {
            Self::mint_intermediate(&mut state)?;
        }

        Ok(())
    }

    /// Rotate the intermediate CA: mint a fresh intermediate signed by the
    /// root, replacing the current one. Returns the new intermediate cert PEM
    /// and its private-key PEM so the caller can persist them.
    pub async fn rotate_intermediate(&self) -> Result<(String, String), CaError> {
        let mut state = self.inner.write().await;
        Self::mint_intermediate(&mut state)?;
        let cert = state
            .intermediate_cert_pem
            .clone()
            .ok_or(CaError::NotInitialized)?;
        let key = state
            .intermediate_keypair
            .as_ref()
            .map(|kp| kp.serialize_pem())
            .ok_or(CaError::NotInitialized)?;
        Ok((cert, key))
    }

    /// Mint a fresh intermediate CA certificate signed by the root, and store
    /// it in `state`. The root must already be present.
    fn mint_intermediate(state: &mut CaState) -> Result<(), CaError> {
        let root_keypair = state.root_keypair.as_ref().ok_or(CaError::NotInitialized)?;
        let root_cert_pem = state
            .root_cert_pem
            .as_ref()
            .ok_or(CaError::NotInitialized)?;

        let int_keypair = KeyPair::generate()
            .map_err(|e| CaError::KeyGeneration(format!("intermediate keypair: {e}")))?;

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CaError::KeyGeneration(format!("intermediate params: {e}")))?;
        // Path length 0: this intermediate may sign leaves but not further CAs.
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name.push(
            DnType::CommonName,
            format!("ekafleet Intermediate CA ({})", state.domain),
        );
        params
            .distinguished_name
            .push(DnType::OrganizationName, "ekafleet");
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(DEFAULT_INTERMEDIATE_TTL.as_secs() as i64);
        params.serial_number = Some(generate_serial()?);

        // Reconstruct the root issuer to sign the intermediate.
        let root_params = CertificateParams::from_ca_cert_pem(root_cert_pem)
            .map_err(|e| CaError::Signing(format!("parse root cert: {e}")))?;
        let root_cert = root_params
            .self_signed(root_keypair)
            .map_err(|e| CaError::Signing(format!("reconstruct root cert: {e}")))?;

        let int_cert = params
            .signed_by(&int_keypair, &root_cert, root_keypair)
            .map_err(|e| CaError::Signing(format!("sign intermediate: {e}")))?;

        let expires_at = unix_now().saturating_add(DEFAULT_INTERMEDIATE_TTL.as_secs());

        tracing::info!(domain = %state.domain, expires_at, "Intermediate CA issued");

        state.intermediate_keypair = Some(int_keypair);
        state.intermediate_cert_pem = Some(int_cert.pem());
        state.intermediate_expires_at = expires_at;
        Ok(())
    }

    /// Issue a leaf certificate for a service identity.
    /// Returns (certificate_pem, chain_pem, expires_at_epoch).
    pub async fn issue_certificate(
        &self,
        service_name: &str,
        _csr_der: &[u8],
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let state = self.inner.read().await;
        let issuer = state.intermediate_issuer()?;

        // Workload attestation: verify the Nix store path if provided
        if let Some(path) = store_path
            && !path.starts_with("/nix/store/")
        {
            return Err(CaError::AttestationFailed("invalid store path".into()));
        }

        let spiffe_uri = format!("spiffe://{}/service/{}", state.domain, service_name);
        let expires_at = unix_now() + state.default_ttl.as_secs();

        // Generate a leaf keypair and certificate signed by the intermediate CA.
        let leaf_keypair = KeyPair::generate()
            .map_err(|e| CaError::Signing(format!("leaf keypair generation: {e}")))?;

        let mut leaf_params = CertificateParams::new(vec![service_name.to_string()])
            .map_err(|e| CaError::Signing(format!("leaf cert params: {e}")))?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, service_name);
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, "ekafleet");
        leaf_params.subject_alt_names.push(SanType::URI(
            spiffe_uri
                .clone()
                .try_into()
                .map_err(|e| CaError::Signing(format!("invalid SPIFFE URI: {e}")))?,
        ));
        leaf_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        leaf_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        leaf_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        leaf_params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(state.default_ttl.as_secs() as i64);

        let serial = generate_serial()?;
        leaf_params.serial_number = Some(serial);

        let leaf_cert = leaf_params
            .signed_by(&leaf_keypair, &issuer.cert, issuer.keypair)
            .map_err(|e| CaError::Signing(format!("sign leaf cert: {e}")))?;

        tracing::info!(
            service = %service_name,
            spiffe = %spiffe_uri,
            ttl = ?state.default_ttl,
            "Certificate issued"
        );

        // Return: leaf cert+key PEM combined, CA chain PEM (intermediate+root), expiry
        let leaf_pem = format!("{}\n{}", leaf_cert.pem(), leaf_keypair.serialize_pem());
        let chain_pem = state.chain_pem()?;

        Ok((leaf_pem.into_bytes(), chain_pem.into_bytes(), expires_at))
    }

    /// Sign a PKCS#10 Certificate Signing Request.
    ///
    /// The CSR's signature is validated (proving the requester holds the private key),
    /// then a certificate is issued using the public key from the CSR. The private key
    /// never leaves the requester — only the public key is embedded in the certificate.
    ///
    /// Returns (cert_pem, chain_pem, expires_at_epoch). Unlike `issue_certificate`,
    /// the returned cert_pem does NOT contain the private key.
    pub async fn sign_csr(
        &self,
        csr_der: &[u8],
        service_name: &str,
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let state = self.inner.read().await;
        let issuer = state.intermediate_issuer()?;

        // Workload attestation: verify the Nix store path if provided
        if let Some(path) = store_path
            && !path.starts_with("/nix/store/")
        {
            return Err(CaError::AttestationFailed("invalid store path".into()));
        }

        // Parse and validate the CSR (this verifies the signature)
        let csr_der_typed = rustls_pki_types::CertificateSigningRequestDer::from(csr_der.to_vec());
        let mut csr_params = CertificateSigningRequestParams::from_der(&csr_der_typed)
            .map_err(|e| CaError::InvalidCsr(format!("failed to parse CSR: {e}")))?;

        // Override TTL and serial on the CSR's params
        let expires_at = unix_now() + state.default_ttl.as_secs();

        // Set validity period on the CSR params
        csr_params.params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(state.default_ttl.as_secs() as i64);

        let serial = generate_serial()?;
        csr_params.params.serial_number = Some(serial);

        // Sign the CSR with the intermediate CA key — the cert uses the CSR's
        // public key.
        let signed_cert = csr_params
            .signed_by(&issuer.cert, issuer.keypair)
            .map_err(|e| CaError::Signing(format!("sign CSR: {e}")))?;

        let spiffe_uri = format!("spiffe://{}/service/{}", state.domain, service_name);
        tracing::info!(
            service = %service_name,
            spiffe = %spiffe_uri,
            ttl = ?state.default_ttl,
            "Certificate issued from CSR"
        );

        // Return cert PEM only (no private key — it stays with the requester),
        // plus the intermediate+root chain.
        let cert_pem = signed_cert.pem();
        let chain_pem = state.chain_pem()?;

        Ok((cert_pem.into_bytes(), chain_pem.into_bytes(), expires_at))
    }

    /// Issue a certificate for the server with a SPIFFE SVID identity.
    ///
    /// Returns (cert_pem + key_pem combined, chain_pem, expires_at).
    /// The server SVID uses `spiffe://<domain>/server/<server_id>`.
    pub async fn issue_server_svid(
        &self,
        server_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let state = self.inner.read().await;
        let spiffe_name = format!("server/{server_id}");
        let spiffe_uri = format!("spiffe://{}/{}", state.domain, spiffe_name);
        drop(state);

        // Issue a certificate with both the server hostname and SPIFFE URI as SANs
        self.issue_certificate_with_uri(&format!("ekafleet-server-{server_id}"), &spiffe_uri)
            .await
    }

    /// Issue a leaf certificate with a custom SPIFFE URI SAN.
    async fn issue_certificate_with_uri(
        &self,
        cn: &str,
        spiffe_uri: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let state = self.inner.read().await;
        let issuer = state.intermediate_issuer()?;

        let expires_at = unix_now() + state.default_ttl.as_secs();

        let leaf_keypair = KeyPair::generate()
            .map_err(|e| CaError::Signing(format!("leaf keypair generation: {e}")))?;

        let mut leaf_params = CertificateParams::new(vec![cn.to_string(), "ekafleet".to_string()])
            .map_err(|e| CaError::Signing(format!("leaf cert params: {e}")))?;
        leaf_params.distinguished_name.push(DnType::CommonName, cn);
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, "ekafleet");
        leaf_params.subject_alt_names.push(SanType::URI(
            spiffe_uri
                .to_string()
                .try_into()
                .map_err(|e| CaError::Signing(format!("invalid SPIFFE URI: {e}")))?,
        ));
        leaf_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        leaf_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        leaf_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        leaf_params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(state.default_ttl.as_secs() as i64);

        let serial = generate_serial()?;
        leaf_params.serial_number = Some(serial);

        let leaf_cert = leaf_params
            .signed_by(&leaf_keypair, &issuer.cert, issuer.keypair)
            .map_err(|e| CaError::Signing(format!("sign leaf cert: {e}")))?;

        tracing::info!(
            cn = %cn,
            spiffe = %spiffe_uri,
            ttl = ?state.default_ttl,
            "SVID certificate issued"
        );

        // The cert bundle includes the intermediate so a TLS peer presenting
        // this identity sends leaf → intermediate, letting a root-anchored
        // verifier build the path. Then the private key.
        let intermediate_pem = state
            .intermediate_cert_pem
            .as_ref()
            .ok_or(CaError::NotInitialized)?;
        let leaf_pem = format!(
            "{}\n{}\n{}",
            leaf_cert.pem(),
            intermediate_pem,
            leaf_keypair.serialize_pem()
        );
        let chain_pem = state.chain_pem()?;

        Ok((leaf_pem.into_bytes(), chain_pem.into_bytes(), expires_at))
    }

    /// Get the root CA certificate PEM (for trust anchors).
    pub async fn root_certificate_pem(&self) -> Option<String> {
        let state = self.inner.read().await;
        state.root_cert_pem.clone()
    }

    /// Get the root CA certificate DER (for trust anchors).
    pub async fn root_certificate_der(&self) -> Option<Vec<u8>> {
        let state = self.inner.read().await;
        state.root_cert_der.clone()
    }

    /// Get the root CA private key PEM (for persistence — must be encrypted at rest).
    pub async fn root_key_pem(&self) -> Option<String> {
        let state = self.inner.read().await;
        state.root_keypair.as_ref().map(|kp| kp.serialize_pem())
    }

    /// Get the intermediate CA certificate PEM (for persistence and for
    /// distribution as part of issued chains).
    pub async fn intermediate_certificate_pem(&self) -> Option<String> {
        let state = self.inner.read().await;
        state.intermediate_cert_pem.clone()
    }

    /// Get the intermediate CA private key PEM (for persistence — must be
    /// encrypted at rest, same as the root key).
    pub async fn intermediate_key_pem(&self) -> Option<String> {
        let state = self.inner.read().await;
        state
            .intermediate_keypair
            .as_ref()
            .map(|kp| kp.serialize_pem())
    }

    /// Set the default TTL for issued certificates.
    pub async fn set_default_ttl(&self, ttl: Duration) {
        let mut state = self.inner.write().await;
        state.default_ttl = ttl;
    }
}

/// A reconstructed intermediate CA issuer usable for signing leaves: the
/// intermediate certificate (rebuilt from its stored PEM) plus a borrow of the
/// intermediate private key.
struct IntermediateIssuer<'a> {
    cert: rcgen::Certificate,
    keypair: &'a KeyPair,
}

impl CaState {
    /// Rebuild the intermediate issuer for leaf signing. rcgen's `signed_by`
    /// takes the issuer's certificate (for its subject DN) and the issuer's
    /// private key; reconstructing the intermediate via `self_signed` with the
    /// correct DN yields an issuer whose subject matches the persisted
    /// intermediate, so leaves chain correctly to intermediate → root.
    fn intermediate_issuer(&self) -> Result<IntermediateIssuer<'_>, CaError> {
        let keypair = self
            .intermediate_keypair
            .as_ref()
            .ok_or(CaError::NotInitialized)?;
        let cert_pem = self
            .intermediate_cert_pem
            .as_ref()
            .ok_or(CaError::NotInitialized)?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| CaError::Signing(format!("parse intermediate cert: {e}")))?;
        let cert = params
            .self_signed(keypair)
            .map_err(|e| CaError::Signing(format!("reconstruct intermediate cert: {e}")))?;
        Ok(IntermediateIssuer { cert, keypair })
    }

    /// The CA chain to return with a leaf: the intermediate certificate
    /// followed by the root certificate, so a verifier anchored on the root can
    /// build the full path.
    fn chain_pem(&self) -> Result<String, CaError> {
        let intermediate = self
            .intermediate_cert_pem
            .as_ref()
            .ok_or(CaError::NotInitialized)?;
        let root = self.root_cert_pem.as_ref().ok_or(CaError::NotInitialized)?;
        Ok(format!("{intermediate}\n{root}"))
    }
}

/// Current time as Unix epoch seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse an intermediate certificate PEM and return its `notAfter` as Unix
/// epoch seconds.
fn intermediate_not_after(cert_pem: &str) -> Result<u64, CaError> {
    let der = pem_to_der(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| CaError::KeyGeneration(format!("parse intermediate cert: {e}")))?;
    let ts = cert.validity().not_after.timestamp();
    Ok(ts.max(0) as u64)
}

/// Generate a random 20-byte serial number for X.509 certificates.
fn generate_serial() -> Result<SerialNumber, CaError> {
    let rng = SystemRandom::new();
    let mut serial_bytes = [0u8; 20];
    rng.fill(&mut serial_bytes)
        .map_err(|_| CaError::KeyGeneration("RNG failure for serial".into()))?;
    // Ensure the first byte is not zero (valid positive integer)
    serial_bytes[0] |= 0x01;
    Ok(SerialNumber::from_slice(&serial_bytes))
}

/// Extract DER bytes from a PEM-encoded certificate.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, CaError> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CaError::KeyGeneration(format!("PEM parse error: {e}")))?;
    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| CaError::KeyGeneration("no certificate found in PEM".into()))
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("CA not initialized")]
    NotInitialized,
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("certificate signing failed: {0}")]
    Signing(String),
    #[error("workload attestation failed: {0}")]
    AttestationFailed(String),
    #[error("invalid CSR: {0}")]
    InvalidCsr(String),
}

#[cfg(test)]
#[path = "root_tests.rs"]
mod tests;
