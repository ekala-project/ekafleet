use std::path::Path;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::types::PendingKeyStore;
use crate::proto::NodeResources;
use crate::spiffe::workload_api::WorkloadManager;

/// Install an SVID received from the server's CertificateResponse.
///
/// If a pending keypair exists for this service (proper CSR flow), the cert
/// is paired with the local private key. Otherwise falls back to the legacy
/// combined cert+key format.
pub(super) async fn install_received_svid(
    mgr: &WorkloadManager,
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    response: &crate::proto::CertificateResponse,
) -> Result<(), std::io::Error> {
    // Determine service name: prefer the explicit field, fall back to CN extraction
    let service_name = if !response.service_name.is_empty() {
        response.service_name.clone()
    } else {
        let cert_pem = String::from_utf8(response.certificate.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        extract_cn_from_pem(&cert_pem).unwrap_or_else(|| "unknown".to_string())
    };

    // Check if we have a pending keypair for this service (proper CSR flow)
    let local_keypair = pending_keys.write().await.take(&service_name);

    if let Some(keypair) = local_keypair {
        // Proper CSR flow: pair server-signed cert with our local private key
        let cert_pem = String::from_utf8(response.certificate.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let chain_pem = String::from_utf8(response.chain.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let key_pem = keypair.serialize_pem();

        mgr.install_svid_split(
            &service_name,
            &cert_pem,
            &key_pem,
            &chain_pem,
            response.expires_at,
        )
        .await?;
    } else {
        // Legacy flow: cert+key combined from server
        mgr.install_svid(
            &service_name,
            &response.certificate,
            &response.chain,
            response.expires_at,
        )
        .await?;
    }

    Ok(())
}

/// Extract the Common Name (CN) from a PEM certificate by parsing the DER.
pub(super) fn extract_cn_from_pem(pem: &str) -> Option<String> {
    let cert_start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let cert_end = pem.find("-----END CERTIFICATE-----")? + "-----END CERTIFICATE-----".len();
    let cert_pem = &pem[cert_start..cert_end];

    let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let der = certs.first()?;

    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?;
    Some(cn.to_string())
}

/// Load this agent's stable node ID from `<data_dir>/node-id`, creating it on
/// first start.
///
/// On first start the ID is `requested` if given, otherwise a random UUID.
/// Once written, the ID never changes: it is the agent's SPIFFE identity
/// (`spiffe://<domain>/agent/<node-id>`). Asking for a different ID than the
/// persisted one is an error rather than a silent identity change.
pub(super) fn get_node_id(data_dir: &Path, requested: Option<&str>) -> anyhow::Result<String> {
    if let Some(id) = requested {
        crate::attestation::join_token::validate_node_id(id)?;
    }
    let id_path = data_dir.join("node-id");
    if id_path.exists() {
        let id = std::fs::read_to_string(&id_path)?.trim().to_string();
        if let Some(requested) = requested
            && requested != id
        {
            anyhow::bail!(
                "--node-id {requested} does not match the persisted node ID {id} in {}",
                id_path.display()
            );
        }
        Ok(id)
    } else {
        let id = requested
            .map(str::to_string)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if let Some(parent) = id_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&id_path, &id)?;
        Ok(id)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_is_generated_once_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let first = get_node_id(dir.path(), None).unwrap();
        assert!(uuid::Uuid::parse_str(&first).is_ok());
        assert_eq!(get_node_id(dir.path(), None).unwrap(), first);
        assert_eq!(get_node_id(dir.path(), Some(&first)).unwrap(), first);
    }

    #[test]
    fn requested_node_id_is_used_on_first_start() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(get_node_id(dir.path(), Some("web-1")).unwrap(), "web-1");
        assert_eq!(get_node_id(dir.path(), None).unwrap(), "web-1");
    }

    #[test]
    fn requested_node_id_cannot_change_persisted_identity() {
        let dir = tempfile::tempdir().unwrap();
        get_node_id(dir.path(), Some("web-1")).unwrap();
        assert!(get_node_id(dir.path(), Some("web-2")).is_err());
        assert_eq!(get_node_id(dir.path(), None).unwrap(), "web-1");
    }

    #[test]
    fn invalid_requested_node_id_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(get_node_id(dir.path(), Some("../escape")).is_err());
        assert!(!dir.path().join("node-id").exists());
    }
}
