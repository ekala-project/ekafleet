use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::root::CaError;
use super::{CaSigner, SvidSubject};

/// Which services each node is currently assigned (node name → service
/// names). Shared between the scheduler side, which publishes each node's full
/// assignment whenever it pushes desired state, and [`CertIssuer`], which only
/// signs service SVIDs for assigned services.
#[derive(Clone, Default)]
pub struct ServiceAssignments {
    inner: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl ServiceAssignments {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the full set of services assigned to a node.
    pub async fn set(&self, node_id: &str, services: Vec<String>) {
        self.inner
            .write()
            .await
            .insert(node_id.to_string(), services);
    }

    /// Forget all assignments for a node.
    pub async fn remove(&self, node_id: &str) {
        self.inner.write().await.remove(node_id);
    }

    /// Whether `service_name` is currently assigned to `node_id`.
    pub async fn is_assigned(&self, node_id: &str, service_name: &str) -> bool {
        self.inner
            .read()
            .await
            .get(node_id)
            .is_some_and(|services| services.iter().any(|s| s == service_name))
    }
}

/// Certificate issuance service.
/// Validates CSRs, checks service assignment, and delegates to a `CaSigner`
/// implementation for signing.
#[derive(Clone)]
pub struct CertIssuer {
    ca: Arc<dyn CaSigner>,
    assignments: ServiceAssignments,
}

impl CertIssuer {
    pub fn new(ca: Arc<dyn CaSigner>) -> Self {
        Self::with_assignments(ca, ServiceAssignments::new())
    }

    /// Create an issuer that authorizes requests against a shared
    /// assignment table (normally `FleetState::service_assignments`).
    pub fn with_assignments(ca: Arc<dyn CaSigner>, assignments: ServiceAssignments) -> Self {
        Self { ca, assignments }
    }

    /// Replace the full set of services assigned to a node. Only assigned
    /// services may obtain SVIDs through [`Self::process_request`].
    pub async fn update_assignments(&self, node_id: &str, services: Vec<String>) {
        self.assignments.set(node_id, services).await;
    }

    /// Forget all assignments for a node (e.g. when it leaves the fleet).
    pub async fn remove_node(&self, node_id: &str) {
        self.assignments.remove(node_id).await;
    }

    /// Whether `service_name` is currently assigned to `node_id`.
    pub async fn is_assigned(&self, node_id: &str, service_name: &str) -> bool {
        self.assignments.is_assigned(node_id, service_name).await
    }

    /// Process a certificate request from an agent.
    ///
    /// `node_id` must be the *authenticated* identity of the requesting
    /// agent (taken from its control stream), never a value the agent put in
    /// the request. The request is honoured only when `service_name` is
    /// currently assigned to that node, and only as a proper PKCS#10 CSR: the
    /// CA never generates workload private keys.
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

        if csr_der.is_empty() {
            return Err(CaError::InvalidCsr("empty CSR".into()));
        }
        let subject = SvidSubject::Service(service_name.to_string());
        subject.validate()?;

        if !self.is_assigned(node_id, service_name).await {
            tracing::warn!(
                node_id = %node_id,
                service = %service_name,
                "Certificate request denied: service not assigned to node"
            );
            return Err(CaError::AttestationFailed(format!(
                "service '{service_name}' is not assigned to node '{node_id}'"
            )));
        }

        self.ca.sign_csr(csr_der, &subject, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::root::RootCa;
    use crate::ca::signer::DirectCaSigner;

    async fn test_issuer() -> CertIssuer {
        let ca = RootCa::new("test.internal");
        ca.initialize(None, None).await.unwrap();
        CertIssuer::new(Arc::new(DirectCaSigner::new(ca)))
    }

    fn csr(service: &str) -> Vec<u8> {
        crate::ca::csr::generate_service_csr("test.internal", service)
            .unwrap()
            .csr_der
    }

    fn cert_spiffe_id(cert_pem: &[u8]) -> Option<String> {
        crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(
            std::str::from_utf8(cert_pem).unwrap(),
        )
    }

    #[tokio::test]
    async fn authorized_node_gets_certificate() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["my-service".to_string()])
            .await;

        let (cert, _chain, _expires) = issuer
            .process_request("node-1", "my-service", &csr("my-service"))
            .await
            .unwrap();

        let cert_str = String::from_utf8(cert.clone()).unwrap();
        assert!(cert_str.contains("BEGIN CERTIFICATE"));
        assert!(
            !cert_str.contains("PRIVATE KEY"),
            "cert from CSR signing must not contain private key"
        );
        assert_eq!(
            cert_spiffe_id(&cert).as_deref(),
            Some("spiffe://test.internal/service/my-service")
        );
    }

    #[tokio::test]
    async fn unauthorized_node_denied() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["allowed-service".to_string()])
            .await;

        let result = issuer
            .process_request("node-1", "other-service", &csr("other-service"))
            .await;

        assert!(matches!(result, Err(CaError::AttestationFailed(_))));
    }

    #[tokio::test]
    async fn service_assigned_elsewhere_denied() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["db".to_string()])
            .await;
        issuer
            .update_assignments("node-2", vec!["web".to_string()])
            .await;

        let result = issuer.process_request("node-2", "db", &csr("db")).await;
        assert!(matches!(result, Err(CaError::AttestationFailed(_))));
    }

    #[tokio::test]
    async fn unknown_node_denied() {
        let issuer = test_issuer().await;
        // No assignments registered for node-99

        let result = issuer
            .process_request("node-99", "any-service", &csr("any-service"))
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
    async fn non_der_csr_rejected_without_server_keygen() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["legacy-svc".to_string()])
            .await;

        // The removed legacy path used to mint a server-generated keypair
        // for any non-DER "CSR" such as [0x01].
        let result = issuer
            .process_request("node-1", "legacy-svc", &[0x01])
            .await;
        assert!(matches!(result, Err(CaError::InvalidCsr(_))));
    }

    #[tokio::test]
    async fn invalid_service_name_rejected() {
        let issuer = test_issuer().await;

        for name in [
            "",
            "svc;drop table",
            "../server/x",
            "-svc",
            &"a".repeat(254),
        ] {
            issuer
                .update_assignments("node-1", vec![name.to_string()])
                .await;
            let result = issuer.process_request("node-1", name, &csr("x")).await;
            assert!(
                matches!(result, Err(CaError::InvalidCsr(_))),
                "name {name:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn valid_service_name_formats_accepted() {
        let issuer = test_issuer().await;
        let valid_names = vec!["my-service", "my_service", "my.service.v2", "svc123", "a"];

        for name in valid_names {
            issuer
                .update_assignments("node-1", vec![name.to_string()])
                .await;
            let result = issuer.process_request("node-1", name, &csr(name)).await;
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

        let result = issuer
            .process_request("node-1", "svc-a", &csr("svc-a"))
            .await;
        assert!(
            matches!(result, Err(CaError::AttestationFailed(_))),
            "old assignment should no longer be valid"
        );

        let result = issuer
            .process_request("node-1", "svc-b", &csr("svc-b"))
            .await;
        assert!(result.is_ok(), "new assignment should be valid");

        issuer.remove_node("node-1").await;
        let result = issuer
            .process_request("node-1", "svc-b", &csr("svc-b"))
            .await;
        assert!(matches!(result, Err(CaError::AttestationFailed(_))));
    }

    #[tokio::test]
    async fn csr_requesting_other_identity_gets_assigned_identity() {
        let issuer = test_issuer().await;
        issuer
            .update_assignments("node-1", vec!["web".to_string()])
            .await;

        // A CSR whose SAN claims a server identity must still yield a cert
        // for the assigned service only.
        let forged = crate::ca::csr::generate_node_csr("test.internal", "x").unwrap();
        let (cert, _, _) = issuer
            .process_request("node-1", "web", &forged.csr_der)
            .await
            .unwrap();
        assert_eq!(
            cert_spiffe_id(&cert).as_deref(),
            Some("spiffe://test.internal/service/web")
        );
    }
}
