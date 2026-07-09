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

struct CaState {
    /// Fleet domain for SPIFFE URIs (e.g., fleet.internal)
    domain: String,
    /// Root CA keypair (used for signing leaf certificates)
    root_keypair: Option<KeyPair>,
    /// Root CA certificate (PEM-encoded)
    root_cert_pem: Option<String>,
    /// Root CA certificate (DER-encoded, for distribution)
    root_cert_der: Option<Vec<u8>>,
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
                default_ttl: Duration::from_secs(3600), // 1 hour default
            })),
        }
    }

    /// Initialize the CA. Generates a new root key/cert if none exists,
    /// or loads from persisted PEM state.
    pub async fn initialize(
        &self,
        stored_key_pem: Option<&str>,
        stored_cert_pem: Option<&str>,
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
                    format!("ekafleet CA ({})", state.domain),
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

        let keypair = state.root_keypair.as_ref().ok_or(CaError::NotInitialized)?;
        let ca_cert_pem = state
            .root_cert_pem
            .as_ref()
            .ok_or(CaError::NotInitialized)?;

        // Workload attestation: verify the Nix store path if provided
        if let Some(path) = store_path
            && !path.starts_with("/nix/store/")
        {
            return Err(CaError::AttestationFailed("invalid store path".into()));
        }

        let spiffe_uri = format!("spiffe://{}/service/{}", state.domain, service_name);
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + state.default_ttl.as_secs();

        // Generate a leaf keypair and certificate signed by our CA
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

        // Parse the CA cert for signing
        let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| CaError::Signing(format!("parse CA cert: {e}")))?;
        let ca_cert = ca_cert_params
            .self_signed(keypair)
            .map_err(|e| CaError::Signing(format!("reconstruct CA cert: {e}")))?;

        let leaf_cert = leaf_params
            .signed_by(&leaf_keypair, &ca_cert, keypair)
            .map_err(|e| CaError::Signing(format!("sign leaf cert: {e}")))?;

        tracing::info!(
            service = %service_name,
            spiffe = %spiffe_uri,
            ttl = ?state.default_ttl,
            "Certificate issued"
        );

        // Return: leaf cert+key PEM combined, CA chain PEM, expiry
        let leaf_pem = format!("{}\n{}", leaf_cert.pem(), leaf_keypair.serialize_pem());
        let chain_pem = ca_cert_pem.clone();

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

        let keypair = state.root_keypair.as_ref().ok_or(CaError::NotInitialized)?;
        let ca_cert_pem = state
            .root_cert_pem
            .as_ref()
            .ok_or(CaError::NotInitialized)?;

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
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + state.default_ttl.as_secs();

        // Set validity period on the CSR params
        csr_params.params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(state.default_ttl.as_secs() as i64);

        let serial = generate_serial()?;
        csr_params.params.serial_number = Some(serial);

        // Parse the CA cert for signing
        let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| CaError::Signing(format!("parse CA cert: {e}")))?;
        let ca_cert = ca_cert_params
            .self_signed(keypair)
            .map_err(|e| CaError::Signing(format!("reconstruct CA cert: {e}")))?;

        // Sign the CSR with the CA key — the cert uses the CSR's public key
        let signed_cert = csr_params
            .signed_by(&ca_cert, keypair)
            .map_err(|e| CaError::Signing(format!("sign CSR: {e}")))?;

        let spiffe_uri = format!("spiffe://{}/service/{}", state.domain, service_name);
        tracing::info!(
            service = %service_name,
            spiffe = %spiffe_uri,
            ttl = ?state.default_ttl,
            "Certificate issued from CSR"
        );

        // Return cert PEM only (no private key — it stays with the requester)
        let cert_pem = signed_cert.pem();
        let chain_pem = ca_cert_pem.clone();

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

        let keypair = state.root_keypair.as_ref().ok_or(CaError::NotInitialized)?;
        let ca_cert_pem = state
            .root_cert_pem
            .as_ref()
            .ok_or(CaError::NotInitialized)?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + state.default_ttl.as_secs();

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

        let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| CaError::Signing(format!("parse CA cert: {e}")))?;
        let ca_cert = ca_cert_params
            .self_signed(keypair)
            .map_err(|e| CaError::Signing(format!("reconstruct CA cert: {e}")))?;

        let leaf_cert = leaf_params
            .signed_by(&leaf_keypair, &ca_cert, keypair)
            .map_err(|e| CaError::Signing(format!("sign leaf cert: {e}")))?;

        tracing::info!(
            cn = %cn,
            spiffe = %spiffe_uri,
            ttl = ?state.default_ttl,
            "SVID certificate issued"
        );

        let leaf_pem = format!("{}\n{}", leaf_cert.pem(), leaf_keypair.serialize_pem());
        let chain_pem = ca_cert_pem.clone();

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

    /// Set the default TTL for issued certificates.
    pub async fn set_default_ttl(&self, ttl: Duration) {
        let mut state = self.inner.write().await;
        state.default_ttl = ttl;
    }
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
