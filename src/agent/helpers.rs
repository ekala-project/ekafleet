use std::sync::Arc;

use tokio::sync::RwLock;

use super::types::PendingKeyStore;
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
