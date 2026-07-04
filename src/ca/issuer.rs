use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::root::{CaError, RootCa};

/// Certificate issuance service.
/// Validates CSRs, performs attestation, checks service assignment,
/// and delegates to RootCa for signing.
pub struct CertIssuer {
    ca: RootCa,
    /// node_id → list of service names assigned to that node
    assignments: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl CertIssuer {
    pub fn new(ca: RootCa) -> Self {
        Self {
            ca,
            assignments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update the service assignments for a node.
    pub async fn update_assignments(&self, node_id: &str, services: Vec<String>) {
        let mut assignments = self.assignments.write().await;
        assignments.insert(node_id.to_string(), services);
    }

    /// Process a certificate request from an agent.
    /// Validates that the requesting node is authorized for the requested service.
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

        // Validate CSR is non-empty
        if csr_der.is_empty() {
            return Err(CaError::InvalidCsr("empty CSR".into()));
        }

        // Validate service name is reasonable
        if service_name.is_empty() || service_name.len() > 253 {
            return Err(CaError::InvalidCsr("invalid service name length".into()));
        }
        if !service_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(CaError::InvalidCsr(
                "service name contains invalid characters".into(),
            ));
        }

        // Check that the service is actually assigned to this node
        let assignments = self.assignments.read().await;
        let authorized = assignments
            .get(node_id)
            .is_some_and(|services| services.contains(&service_name.to_string()));

        if !authorized {
            tracing::warn!(
                node_id = %node_id,
                service = %service_name,
                "Certificate request denied: service not assigned to node"
            );
            return Err(CaError::AttestationFailed(format!(
                "service '{service_name}' is not assigned to node '{node_id}'"
            )));
        }

        self.ca.issue_certificate(service_name, csr_der, None).await
    }
}
