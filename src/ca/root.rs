use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

/// Root Certificate Authority for the fleet.
/// Generates and manages the root CA key/cert, issues intermediate
/// and leaf certificates with SPIFFE-compatible identities.
#[derive(Clone)]
pub struct RootCa {
    inner: Arc<RwLock<CaState>>,
}

struct CaState {
    /// Fleet domain for SPIFFE URIs (e.g., fleet.internal)
    domain: String,
    /// Root CA private key (DER-encoded)
    /// WARNING: not yet encrypted at rest — requires encryption before production use
    root_key: Option<Vec<u8>>,
    /// Root CA certificate (DER-encoded)
    root_cert: Option<Vec<u8>>,
    /// Default leaf certificate lifetime
    default_ttl: Duration,
}

impl RootCa {
    pub fn new(domain: &str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CaState {
                domain: domain.to_string(),
                root_key: None,
                root_cert: None,
                default_ttl: Duration::from_secs(3600), // 1 hour default
            })),
        }
    }

    /// Initialize the CA. Generates a new root key/cert if none exists,
    /// or loads from persisted state.
    pub async fn initialize(&self, stored_key: Option<Vec<u8>>, stored_cert: Option<Vec<u8>>) {
        let mut state = self.inner.write().await;
        match (stored_key, stored_cert) {
            (Some(key), Some(cert)) => {
                tracing::info!("Loading existing root CA");
                state.root_key = Some(key);
                state.root_cert = Some(cert);
            }
            _ => {
                tracing::info!("Generating new root CA keypair");
                // TODO: use rcgen to generate self-signed root CA
                // For now, store placeholder
                state.root_key = Some(vec![0; 32]); // placeholder
                state.root_cert = Some(vec![0; 32]); // placeholder
            }
        }
    }

    /// Issue a leaf certificate for a service identity.
    /// Returns (certificate_der, chain_der, expires_at_epoch).
    pub async fn issue_certificate(
        &self,
        service_name: &str,
        csr_der: &[u8],
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let state = self.inner.read().await;

        if state.root_key.is_none() {
            return Err(CaError::NotInitialized);
        }

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

        tracing::info!(
            service = %service_name,
            spiffe = %spiffe_uri,
            ttl = ?state.default_ttl,
            "Issuing certificate"
        );

        // TODO: actually sign the CSR with the root key using rcgen/ring
        // For now, return placeholders
        let _ = csr_der; // will be used when real signing is implemented
        let cert = vec![0; 64]; // placeholder certificate
        let chain = state.root_cert.clone().unwrap_or_default();

        Ok((cert, chain, expires_at))
    }

    /// Get the root CA certificate (for trust anchors).
    pub async fn root_certificate(&self) -> Option<Vec<u8>> {
        let state = self.inner.read().await;
        state.root_cert.clone()
    }

    /// Set the default TTL for issued certificates.
    pub async fn set_default_ttl(&self, ttl: Duration) {
        let mut state = self.inner.write().await;
        state.default_ttl = ttl;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("CA not initialized")]
    NotInitialized,
    #[error("workload attestation failed: {0}")]
    AttestationFailed(String),
    #[error("invalid CSR: {0}")]
    InvalidCsr(String),
}
