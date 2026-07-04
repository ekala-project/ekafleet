use super::root::{CaError, RootCa};

/// Certificate issuance service.
/// Validates CSRs, performs attestation, and delegates to RootCa for signing.
pub struct CertIssuer {
    ca: RootCa,
}

impl CertIssuer {
    pub fn new(ca: RootCa) -> Self {
        Self { ca }
    }

    /// Process a certificate request from an agent.
    pub async fn process_request(
        &self,
        node_id: &str,
        service_name: &str,
        csr_der: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        tracing::info!(
            node_id = %node_id,
            service = %service_name,
            csr_len = csr_der.len(),
            "Processing certificate request"
        );

        // TODO: validate CSR fields, check service is actually assigned to this node
        self.ca.issue_certificate(service_name, csr_der, None).await
    }
}
