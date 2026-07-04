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

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_issuer() -> CertIssuer {
        let ca = RootCa::new("test.internal");
        ca.initialize(None, None).await.unwrap();
        CertIssuer::new(ca)
    }

    #[tokio::test]
    async fn authorized_node_gets_certificate() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["my-service".to_string()])
            .await;

        let result = issuer
            .process_request("node-1", "my-service", b"dummy-csr")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn unauthorized_node_denied() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["allowed-service".to_string()])
            .await;

        let result = issuer
            .process_request("node-1", "other-service", b"dummy-csr")
            .await;

        assert!(matches!(result, Err(CaError::AttestationFailed(_))));
    }

    #[tokio::test]
    async fn unknown_node_denied() {
        let issuer = test_issuer().await;
        // No assignments registered for node-99

        let result = issuer
            .process_request("node-99", "any-service", b"csr")
            .await;

        assert!(matches!(result, Err(CaError::AttestationFailed(_))));
    }

    #[tokio::test]
    async fn empty_csr_rejected() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["svc".to_string()])
            .await;

        let result = issuer.process_request("node-1", "svc", b"").await;

        assert!(matches!(result, Err(CaError::InvalidCsr(_))));
    }

    #[tokio::test]
    async fn invalid_service_name_rejected() {
        let issuer = test_issuer().await;

        // Empty name
        let result = issuer.process_request("node-1", "", b"csr").await;
        assert!(matches!(result, Err(CaError::InvalidCsr(_))));

        // Special characters
        let result = issuer
            .process_request("node-1", "svc;drop table", b"csr")
            .await;
        assert!(matches!(result, Err(CaError::InvalidCsr(_))));

        // Too long
        let long_name = "a".repeat(254);
        let result = issuer.process_request("node-1", &long_name, b"csr").await;
        assert!(matches!(result, Err(CaError::InvalidCsr(_))));
    }

    #[tokio::test]
    async fn valid_service_name_formats_accepted() {
        let issuer = test_issuer().await;
        let valid_names = vec!["my-service", "my_service", "my.service.v2", "svc123", "a"];

        for name in valid_names {
            issuer
                .update_assignments("node-1", vec![name.to_string()])
                .await;
            let result = issuer.process_request("node-1", name, b"csr").await;
            assert!(result.is_ok(), "valid name '{name}' should be accepted");
        }
    }

    #[tokio::test]
    async fn assignment_update_replaces_previous() {
        let issuer = test_issuer().await;

        issuer
            .update_assignments("node-1", vec!["svc-a".to_string()])
            .await;
        // Replace with svc-b only
        issuer
            .update_assignments("node-1", vec!["svc-b".to_string()])
            .await;

        let result = issuer.process_request("node-1", "svc-a", b"csr").await;
        assert!(
            matches!(result, Err(CaError::AttestationFailed(_))),
            "old assignment should no longer be valid"
        );

        let result = issuer.process_request("node-1", "svc-b", b"csr").await;
        assert!(result.is_ok(), "new assignment should be valid");
    }
}
