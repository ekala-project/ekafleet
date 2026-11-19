use std::sync::Arc;

use tokio::sync::RwLock;

use super::types::{NODE_CERT_KEY, NodeIdentity, PendingKeyStore};
use crate::proto::NodeResources;
use crate::spiffe::workload_api::WorkloadManager;

/// Install an SVID received from the server's CertificateResponse.
///
/// The certificate is paired with the private key this agent generated for
/// the matching CSR. A certificate with no pending keypair is rejected: the
/// server never generates workload keys, so an unsolicited response is either
/// stale (already installed) or not ours.
pub(super) async fn install_received_svid(
    mgr: &WorkloadManager,
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    response: &crate::proto::CertificateResponse,
) -> Result<(), std::io::Error> {
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
    if response.service_name.is_empty() {
        return Err(invalid("certificate response has no service name".into()));
    }
    let service_name = &response.service_name;

    let keypair = pending_keys
        .write()
        .await
        .take(service_name)
        .ok_or_else(|| invalid(format!("no pending CSR for service '{service_name}'")))?;

    let cert_pem =
        String::from_utf8(response.certificate.clone()).map_err(|e| invalid(e.to_string()))?;
    if !cert_certifies_key(&cert_pem, &keypair) {
        return Err(invalid(format!(
            "certificate for '{service_name}' does not match the pending CSR key"
        )));
    }
    let chain_pem =
        String::from_utf8(response.chain.clone()).map_err(|e| invalid(e.to_string()))?;
    let key_pem = zeroize::Zeroizing::new(keypair.serialize_pem());

    mgr.install_svid_split(
        service_name,
        &cert_pem,
        &key_pem,
        &chain_pem,
        response.expires_at,
    )
    .await?;
    Ok(())
}

/// Ask the server to renew this node's SVID (sent on the mTLS stream, so the
/// server signs only for the stream's own node), unless a renewal is already
/// in flight. The new key never leaves the agent.
pub(super) async fn request_node_svid(
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    tx: &tokio::sync::mpsc::Sender<crate::proto::AgentMessage>,
    node_id: &str,
) {
    if pending_keys.read().await.in_flight(NODE_CERT_KEY) {
        return;
    }
    match crate::ca::csr::generate_node_csr(None, node_id) {
        Ok(csr) => {
            pending_keys.write().await.store(NODE_CERT_KEY, csr.keypair);
            tracing::info!("Requesting node SVID renewal");
            let _ = tx
                .send(crate::proto::AgentMessage {
                    payload: Some(crate::proto::agent_message::Payload::CertRequest(
                        crate::proto::CertificateRequest {
                            node_id: node_id.to_string(),
                            service_name: String::new(),
                            csr: csr.csr_der,
                            request_type: crate::proto::CertRequestType::NodeCert as i32,
                        },
                    )),
                })
                .await;
        }
        Err(e) => tracing::error!(error = %e, "Node CSR generation failed"),
    }
}

/// Install a renewed node SVID. It must certify the pending renewal key and
/// carry the same SPIFFE ID as the current node SVID. The new certificate
/// is used from the next connection on.
pub(super) async fn install_node_svid(
    identity: &Arc<RwLock<NodeIdentity>>,
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    response: &crate::proto::CertificateResponse,
) -> Result<(), std::io::Error> {
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
    let keypair = pending_keys
        .write()
        .await
        .take(NODE_CERT_KEY)
        .ok_or_else(|| invalid("no pending node SVID renewal".into()))?;
    let cert_pem =
        String::from_utf8(response.certificate.clone()).map_err(|e| invalid(e.to_string()))?;
    if !cert_certifies_key(&cert_pem, &keypair) {
        return Err(invalid(
            "renewed node SVID does not match the pending key".into(),
        ));
    }
    let mut identity = identity.write().await;
    let renewed = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&cert_pem);
    if renewed.is_none() || renewed != identity.spiffe_id {
        return Err(invalid(format!(
            "renewed node SVID is for {renewed:?}, not {:?}",
            identity.spiffe_id
        )));
    }
    let chain = String::from_utf8(response.chain.clone()).map_err(|e| invalid(e.to_string()))?;
    let key_pem = zeroize::Zeroizing::new(keypair.serialize_pem());
    identity
        .install(format!("{}\n{chain}", cert_pem.trim_end()), key_pem)
        .await
}

/// Whether the first certificate in `cert_pem` certifies `keypair`'s public key.
pub(super) fn cert_certifies_key(cert_pem: &str, keypair: &rcgen::KeyPair) -> bool {
    let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
    let Some(Ok(der)) = crate::ca::pki::pem_certs(&mut reader).next() else {
        return false;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) else {
        return false;
    };
    cert.public_key().subject_public_key.data.as_ref() == keypair.public_key_raw()
}

/// Request an X.509-SVID for `service_name` unless a request is already in
/// flight. The keypair is generated here and never leaves the agent; only the
/// CSR is sent.
pub(super) async fn request_service_svid(
    mgr: &WorkloadManager,
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    tx: &tokio::sync::mpsc::Sender<crate::proto::AgentMessage>,
    node_id: &str,
    service_name: &str,
) {
    if pending_keys.read().await.in_flight(service_name) {
        return;
    }
    let trust_domain = mgr
        .trust_domain_str()
        .await
        .unwrap_or_else(|| "fleet.internal".to_string());
    match crate::ca::csr::generate_service_csr(&trust_domain, service_name) {
        Ok(csr_output) => {
            pending_keys
                .write()
                .await
                .store(service_name, csr_output.keypair);
            tracing::info!(service = %service_name, "Requesting SVID for service");
            let _ = tx
                .send(crate::proto::AgentMessage {
                    payload: Some(crate::proto::agent_message::Payload::CertRequest(
                        crate::proto::CertificateRequest {
                            node_id: node_id.to_string(),
                            service_name: service_name.to_string(),
                            csr: csr_output.csr_der,
                            request_type: crate::proto::CertRequestType::ServiceCert as i32,
                        },
                    )),
                })
                .await;
        }
        Err(e) => {
            tracing::error!(service = %service_name, error = %e, "CSR generation failed");
        }
    }
}

/// The short system hostname (everything before the first `.`), used as the
/// default node name.
pub fn system_hostname() -> anyhow::Result<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for `buf.len()` bytes; gethostname writes a
    // NUL-terminated name (possibly truncated) into it.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "gethostname failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let full = std::str::from_utf8(&buf[..end])
        .map_err(|_| anyhow::anyhow!("system hostname is not valid UTF-8"))?;
    let short = full.split('.').next().unwrap_or_default();
    if short.is_empty() {
        anyhow::bail!("system hostname is empty; set --node-name");
    }
    Ok(short.to_string())
}

pub(crate) fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn collect_resources() -> NodeResources {
    let cpu_millicores = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.matches("processor").count() as u64 * 1000)
        .unwrap_or(0);

    let memory_mb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemAvailable:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb / 1024)
        })
        .unwrap_or(0);

    let disk_mb = std::fs::read_to_string("/proc/mounts")
        .ok()
        .and_then(|mounts| {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "/" {
                    #[cfg(unix)]
                    {
                        use std::ffi::CString;
                        let path = CString::new(parts[1]).ok()?;
                        unsafe {
                            let mut stat: libc::statvfs = std::mem::zeroed();
                            if libc::statvfs(path.as_ptr(), &mut stat) == 0 {
                                return Some(
                                    (stat.f_bavail as u64 * stat.f_frsize as u64) / (1024 * 1024),
                                );
                            }
                        }
                    }
                }
            }
            None
        })
        .unwrap_or(0);

    NodeResources {
        cpu_millicores,
        memory_mb,
        disk_mb,
    }
}
