//! `FleetBootstrap`: node attestation for agents that have no identity yet.
//!
//! This service is mounted *without* the authentication interceptor. The
//! one-time, name-bound join token in the request is the credential: a
//! valid token for `node_name` plus a CSR yields the node SVID
//! `spiffe://<domain>/agent/<node_name>`, signed over the agent's own key.
//! The server never sees the node's private key.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use super::audit::{AuditAction, AuditLog, AuditOutcome};
use crate::attestation::join_token::{self, JoinTokenStore};
use crate::ca::{CaSigner, SvidSubject};
use crate::proto::fleet_bootstrap_server::FleetBootstrap;
use crate::proto::{NodeAttestationRequest, NodeAttestationResult};

/// Upper bound on an accepted CSR (a P-256 CSR is a few hundred bytes).
const MAX_CSR_LEN: usize = 8 * 1024;

pub struct FleetBootstrapService {
    join_tokens: JoinTokenStore,
    ca: Arc<dyn CaSigner>,
    domain: String,
    trust_bundle_pem: String,
    audit_log: AuditLog,
}

impl FleetBootstrapService {
    pub fn new(
        join_tokens: JoinTokenStore,
        ca: Arc<dyn CaSigner>,
        domain: &str,
        trust_bundle_pem: String,
        audit_log: AuditLog,
    ) -> Self {
        Self {
            join_tokens,
            ca,
            domain: domain.to_string(),
            trust_bundle_pem,
            audit_log,
        }
    }

    async fn audit(&self, node_name: &str, detail: &str, outcome: AuditOutcome) {
        self.audit_log
            .record(
                "join-token",
                AuditAction::NodeAttest,
                &format!("agent/{node_name}"),
                detail,
                outcome,
            )
            .await;
    }

    async fn attest_join_token(
        &self,
        req: &NodeAttestationRequest,
        source: Option<std::net::IpAddr>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), String> {
        if req.attestation_type != "join_token" {
            return Err(format!(
                "unsupported attestation type '{}'",
                req.attestation_type
            ));
        }
        // Check the CSR (including its self-signature) before the token is
        // spent, so a malformed request does not burn it.
        if req.csr.is_empty() || req.csr.len() > MAX_CSR_LEN {
            return Err("a DER CSR of at most 8 KiB is required".into());
        }
        let csr_der = rustls_pki_types::CertificateSigningRequestDer::from(req.csr.clone());
        rcgen::CertificateSigningRequestParams::from_der(&csr_der)
            .map_err(|e| format!("invalid CSR: {e}"))?;

        join_token::attest(
            &self.join_tokens,
            &req.attestation_data,
            &req.node_name,
            source,
        )
        .await
        .map_err(|e| e.to_string())?;

        match self
            .ca
            .sign_csr(&req.csr, &SvidSubject::Agent(req.node_name.clone()), None)
            .await
        {
            Ok(issued) => Ok(issued),
            Err(e) => {
                // Not the node's fault: let it retry with the same token.
                tracing::error!(node = %req.node_name, error = %e, "Node SVID signing failed");
                let token = String::from_utf8_lossy(&req.attestation_data);
                self.join_tokens.release(&token).await;
                Err("the CA could not sign the node SVID; retry later".into())
            }
        }
    }
}

#[tonic::async_trait]
impl FleetBootstrap for FleetBootstrapService {
    async fn attest(
        &self,
        request: Request<NodeAttestationRequest>,
    ) -> Result<Response<NodeAttestationResult>, Status> {
        let source = request.remote_addr().map(|a| a.ip());
        let req = request.into_inner();
        tracing::info!(
            node = %req.node_name,
            attestation_type = %req.attestation_type,
            source = ?source,
            "Node attestation request"
        );

        match self.attest_join_token(&req, source).await {
            Ok((cert, chain, expires_at)) => {
                let spiffe_id = SvidSubject::Agent(req.node_name.clone()).spiffe_id(&self.domain);
                self.audit(&req.node_name, "node SVID issued", AuditOutcome::Success)
                    .await;
                tracing::info!(node = %req.node_name, %spiffe_id, "Node attested");
                Ok(Response::new(NodeAttestationResult {
                    success: true,
                    node_spiffe_id: spiffe_id,
                    node_certificate: cert,
                    trust_bundle: self.trust_bundle_pem.as_bytes().to_vec(),
                    error_message: String::new(),
                    trust_domain: self.domain.clone(),
                    chain,
                    expires_at,
                }))
            }
            Err(error) => {
                tracing::warn!(node = %req.node_name, source = ?source, %error, "Node attestation failed");
                self.audit(&req.node_name, &error, AuditOutcome::Denied)
                    .await;
                Ok(Response::new(NodeAttestationResult {
                    success: false,
                    error_message: error,
                    ..Default::default()
                }))
            }
        }
    }
}
