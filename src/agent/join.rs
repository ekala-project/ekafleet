//! Agent side of join-token node attestation.
//!
//! A new agent has no credentials except a one-time join token. It calls the
//! `Attest` RPC (the one RPC the server accepts without a bearer token or
//! client certificate) over server-authenticated TLS, presenting the token and
//! its stable node ID. The server validates and consumes the token, then
//! returns a node SVID for `spiffe://<domain>/agent/<node_id>`. The agent
//! persists that SVID and uses it as its mTLS client certificate from then on,
//! so the join token is needed exactly once.

use tonic::transport::Channel;
use zeroize::Zeroizing;

use crate::proto::NodeAttestationRequest;
use crate::proto::fleet_control_client::FleetControlClient;

/// Node identity material returned by a successful attestation.
pub struct AttestedNode {
    /// Node SVID certificate PEM.
    pub cert_pem: String,
    /// Node SVID private key PEM.
    pub key_pem: Zeroizing<String>,
    /// `spiffe://<domain>/agent/<node_id>`.
    pub spiffe_id: String,
    /// SVID expiry (unix seconds).
    pub expires_at: u64,
    /// The fleet's trust domain.
    pub trust_domain: String,
}

/// Errors from join-token attestation.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    /// The RPC itself failed (transport error or non-OK status).
    #[error("attestation RPC failed: {0}")]
    Rpc(Box<tonic::Status>),
    /// The server refused the token (unknown, consumed, expired or bound
    /// to another node).
    #[error("server rejected attestation: {0}")]
    Rejected(String),
    /// The server's response did not contain a usable SVID for this node.
    #[error("malformed attestation response: {0}")]
    Malformed(String),
}

/// Attest this node with `join_token` and return its node SVID.
///
/// `channel` must be a TLS channel that verifies the server against the fleet
/// CA: the join token is a bearer secret until the server consumes it.
pub async fn attest_with_join_token(
    channel: Channel,
    join_token: &str,
    node_id: &str,
) -> Result<AttestedNode, JoinError> {
    let mut client = FleetControlClient::new(channel);
    let result = client
        .attest(NodeAttestationRequest {
            attestation_type: "join_token".to_string(),
            attestation_data: join_token.as_bytes().to_vec(),
            csr: Vec::new(),
            node_id: node_id.to_string(),
        })
        .await
        .map_err(|status| JoinError::Rpc(Box::new(status)))?
        .into_inner();

    if !result.success {
        return Err(JoinError::Rejected(result.error_message));
    }
    if result.node_id != node_id {
        return Err(JoinError::Malformed(format!(
            "server issued an SVID for node '{}', requested '{node_id}'",
            result.node_id
        )));
    }

    let bundle = String::from_utf8(result.node_certificate)
        .map_err(|_| JoinError::Malformed("node certificate is not UTF-8".into()))?;
    let (cert_pem, key_pem) = split_cert_and_key(&bundle)
        .ok_or_else(|| JoinError::Malformed("node certificate has no cert or key".into()))?;

    let cert_id = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&cert_pem);
    let expected_suffix = format!("/agent/{node_id}");
    if cert_id.as_deref() != Some(result.node_spiffe_id.as_str())
        || !result.node_spiffe_id.ends_with(&expected_suffix)
    {
        return Err(JoinError::Malformed(format!(
            "SVID identity {cert_id:?} does not match {}",
            result.node_spiffe_id
        )));
    }

    Ok(AttestedNode {
        cert_pem,
        key_pem,
        spiffe_id: result.node_spiffe_id,
        expires_at: result.expires_at,
        trust_domain: result.trust_domain,
    })
}

/// Split a PEM bundle holding a certificate followed by its private key.
///
/// Returns `None` unless the bundle has both a `CERTIFICATE` block and a
/// `PRIVATE KEY` block, with the certificate first.
pub fn split_cert_and_key(bundle: &str) -> Option<(String, Zeroizing<String>)> {
    let key_start = bundle.find("-----BEGIN PRIVATE KEY-----")?;
    let (cert, key) = bundle.split_at(key_start);
    if !cert.contains("-----BEGIN CERTIFICATE-----") || !key.contains("-----END PRIVATE KEY-----") {
        return None;
    }
    Some((
        cert.trim().to_string() + "\n",
        Zeroizing::new(key.trim().to_string() + "\n"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_cert_and_key_separates_blocks() {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["n".into()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let bundle = format!("{}\n{}", cert.pem(), key_pair.serialize_pem());

        let (cert_pem, key_pem) = split_cert_and_key(&bundle).unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!cert_pem.contains("PRIVATE KEY"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(!key_pem.contains("CERTIFICATE"));
    }

    #[test]
    fn split_cert_and_key_requires_both() {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["n".into()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        assert!(split_cert_and_key(&cert.pem()).is_none());
        assert!(split_cert_and_key(&key_pair.serialize_pem()).is_none());
        // Key before certificate is not the format the server sends.
        let reversed = format!("{}\n{}", key_pair.serialize_pem(), cert.pem());
        assert!(split_cert_and_key(&reversed).is_none());
    }
}
