use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

/// Agent-side certificate management.
/// Requests certificates from server, tracks expiry, auto-renews.
#[derive(Clone)]
pub struct CertClient {
    inner: Arc<RwLock<CertState>>,
}

struct CertState {
    node_id: String,
    certificates: Vec<ManagedCert>,
}

struct ManagedCert {
    service_name: String,
    cert_der: Vec<u8>,
    chain_der: Vec<u8>,
    expires_at: u64,
}

impl ManagedCert {
    fn needs_renewal(&self, buffer: Duration) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expires_at.saturating_sub(buffer.as_secs()) <= now
    }
}

impl CertClient {
    pub fn new(node_id: &str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CertState {
                node_id: node_id.to_string(),
                certificates: Vec::new(),
            })),
        }
    }

    /// Store a received certificate.
    pub async fn store_certificate(
        &self,
        service_name: &str,
        cert: Vec<u8>,
        chain: Vec<u8>,
        expires_at: u64,
    ) {
        let mut state = self.inner.write().await;

        // Replace existing cert for this service
        state
            .certificates
            .retain(|c| c.service_name != service_name);

        state.certificates.push(ManagedCert {
            service_name: service_name.to_string(),
            cert_der: cert,
            chain_der: chain,
            expires_at,
        });

        tracing::info!(
            service = %service_name,
            expires_at,
            "Certificate stored"
        );
    }

    /// Get services that need certificate renewal.
    pub async fn needs_renewal(&self) -> Vec<String> {
        let state = self.inner.read().await;
        let renewal_buffer = Duration::from_secs(300); // renew 5 min before expiry
        state
            .certificates
            .iter()
            .filter(|c| c.needs_renewal(renewal_buffer))
            .map(|c| c.service_name.clone())
            .collect()
    }

    /// Get the certificate for a service (if available).
    pub async fn get_certificate(&self, service_name: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let state = self.inner.read().await;
        state
            .certificates
            .iter()
            .find(|c| c.service_name == service_name)
            .map(|c| (c.cert_der.clone(), c.chain_der.clone()))
    }
}
