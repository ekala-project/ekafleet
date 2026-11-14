//! Node identity bootstrap: exchange a one-time join token for a node SVID.
//!
//! The agent generates its own key, sends only a CSR plus the join token to
//! `FleetBootstrap.Attest` over server-authenticated TLS (no client
//! certificate yet), checks that the returned certificate certifies its key
//! as `spiffe://<domain>/agent/<name>`, and persists it. Every later
//! connection authenticates with that SVID.

use std::time::Duration;

use super::types::NodeIdentity;
use crate::proto::NodeAttestationRequest;
use crate::proto::fleet_bootstrap_client::FleetBootstrapClient;

/// TLS client config that verifies the server against `ca_pem`. A server
/// addressed by IP is verified under its canonical name `ekafleet`.
pub fn tls_config(server_addr: &str, ca_pem: &str) -> tonic::transport::ClientTlsConfig {
    let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
    let mut tls = tonic::transport::ClientTlsConfig::new().ca_certificate(ca_cert);
    if server_addr.starts_with(|c: char| c.is_ascii_digit()) {
        tls = tls.domain_name("ekafleet");
    }
    tls
}

/// Attest as `node_name` with `join_token` and install the issued SVID.
pub async fn join(
    server_addr: &str,
    ca_pem: &str,
    node_name: &str,
    join_token: &str,
    identity: &mut NodeIdentity,
) -> anyhow::Result<()> {
    let csr = crate::ca::csr::generate_node_csr(None, node_name)
        .map_err(|e| anyhow::anyhow!("node CSR: {e}"))?;

    let channel = tonic::transport::Endpoint::from_shared(format!("https://{server_addr}"))?
        .tls_config(tls_config(server_addr, ca_pem))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("connect to {server_addr} to join: {e}"))?;
    let result = FleetBootstrapClient::new(channel)
        .attest(NodeAttestationRequest {
            attestation_type: "join_token".into(),
            attestation_data: join_token.as_bytes().to_vec(),
            csr: csr.csr_der,
            node_name: node_name.to_string(),
        })
        .await?
        .into_inner();
    if !result.success {
        anyhow::bail!("join refused by server: {}", result.error_message);
    }

    let cert_pem = String::from_utf8(result.node_certificate)?;
    if !super::helpers::cert_certifies_key(&cert_pem, &csr.keypair) {
        anyhow::bail!("server returned a node SVID that does not certify this node's key");
    }
    let expected = format!("spiffe://{}/agent/{node_name}", result.trust_domain);
    let certified = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&cert_pem);
    if certified.as_deref() != Some(expected.as_str()) {
        anyhow::bail!(
            "server returned a node SVID for {} instead of {expected}",
            certified.as_deref().unwrap_or("<no SPIFFE ID>")
        );
    }

    let chain = String::from_utf8(result.chain)?;
    let key_pem = zeroize::Zeroizing::new(csr.keypair.serialize_pem());
    identity
        .install(format!("{}\n{chain}", cert_pem.trim_end()), key_pem)
        .await?;
    tracing::info!(spiffe_id = %expected, "Joined the fleet");
    Ok(())
}
