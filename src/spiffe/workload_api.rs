use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

/// Manages SPIFFE workload identities on an agent node.
///
/// Each service gets an X.509-SVID (certificate + private key) and access
/// to the trust bundle (CA certificate). These are written to a per-service
/// directory and exposed via a well-known path structure that SPIFFE-aware
/// workloads can consume directly.
///
/// Directory layout:
/// ```text
/// <data_dir>/spiffe/<service_name>/
///   svid.pem          — leaf certificate PEM
///   svid-key.pem      — leaf private key PEM
///   bundle.pem        — CA trust bundle PEM
/// ```
///
/// The paths follow conventions compatible with Envoy SDS file-based config,
/// application libraries (go-spiffe, rust-spiffe), and direct TLS consumers.
pub struct WorkloadManager {
    data_dir: PathBuf,
    inner: Arc<RwLock<WorkloadState>>,
}

struct WorkloadState {
    /// trust_domain for SPIFFE IDs (e.g., "fleet.internal")
    trust_domain: String,
    /// CA trust bundle PEM
    trust_bundle_pem: Option<String>,
    /// service_name → issued SVID
    svids: HashMap<String, Svid>,
}

/// An X.509-SVID for a workload.
#[derive(Clone)]
struct Svid {
    /// SPIFFE ID: spiffe://<trust_domain>/service/<name>
    spiffe_id: String,
    /// Leaf certificate PEM
    cert_pem: String,
    /// Leaf private key PEM
    key_pem: String,
    /// Certificate chain PEM (CA cert)
    chain_pem: String,
    /// Expiry as unix epoch seconds
    expires_at: u64,
}

impl WorkloadManager {
    pub fn new(data_dir: &Path, trust_domain: &str) -> Self {
        Self {
            data_dir: data_dir.join("spiffe"),
            inner: Arc::new(RwLock::new(WorkloadState {
                trust_domain: trust_domain.to_string(),
                trust_bundle_pem: None,
                svids: HashMap::new(),
            })),
        }
    }

    /// Update the CA trust bundle. Called when the agent receives
    /// the CA certificate from the server.
    pub async fn set_trust_bundle(&self, ca_cert_pem: &str) -> Result<(), std::io::Error> {
        let mut state = self.inner.write().await;
        state.trust_bundle_pem = Some(ca_cert_pem.to_string());

        // Write bundle to every existing service's directory
        for service_name in state.svids.keys() {
            let bundle_path = self.data_dir.join(service_name).join("bundle.pem");
            if bundle_path.parent().is_some_and(|p| p.exists()) {
                tokio::fs::write(&bundle_path, ca_cert_pem).await?;
            }
        }

        tracing::info!("SPIFFE trust bundle updated");
        Ok(())
    }

    /// Get the current trust bundle PEM.
    pub async fn trust_bundle(&self) -> Option<String> {
        let state = self.inner.read().await;
        state.trust_bundle_pem.clone()
    }

    /// Install an X.509-SVID for a service. The certificate material is
    /// split from the combined cert+key PEM returned by the CA.
    ///
    /// Writes files to `<data_dir>/spiffe/<service_name>/` with
    /// restrictive permissions.
    pub async fn install_svid(
        &self,
        service_name: &str,
        cert_and_key_pem: &[u8],
        chain_pem: &[u8],
        expires_at: u64,
    ) -> Result<PathBuf, std::io::Error> {
        let combined = String::from_utf8(cert_and_key_pem.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let chain = String::from_utf8(chain_pem.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Split the combined PEM into cert and key
        let (cert_pem, key_pem) = split_cert_and_key(&combined)?;

        let svc_dir = self.data_dir.join(service_name);
        tokio::fs::create_dir_all(&svc_dir).await?;

        let cert_path = svc_dir.join("svid.pem");
        let key_path = svc_dir.join("svid-key.pem");
        let bundle_path = svc_dir.join("bundle.pem");

        // Write certificate
        tokio::fs::write(&cert_path, &cert_pem).await?;

        // Write private key with restrictive permissions
        tokio::fs::write(&key_path, &key_pem).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o400);
            tokio::fs::set_permissions(&key_path, perms).await?;
        }

        // Write trust bundle
        let state = self.inner.read().await;
        let bundle = state
            .trust_bundle_pem
            .clone()
            .unwrap_or_else(|| chain.clone());
        drop(state);
        tokio::fs::write(&bundle_path, &bundle).await?;

        // Store SVID in memory
        let spiffe_id = {
            let state = self.inner.read().await;
            format!("spiffe://{}/service/{}", state.trust_domain, service_name)
        };

        let mut state = self.inner.write().await;
        state.svids.insert(
            service_name.to_string(),
            Svid {
                spiffe_id: spiffe_id.clone(),
                cert_pem,
                key_pem,
                chain_pem: chain,
                expires_at,
            },
        );

        tracing::info!(
            service = %service_name,
            spiffe_id = %spiffe_id,
            expires_at,
            path = %svc_dir.display(),
            "SVID installed"
        );

        Ok(svc_dir)
    }

    /// Get the SPIFFE ID for a service.
    pub async fn spiffe_id(&self, service_name: &str) -> Option<String> {
        let state = self.inner.read().await;
        state.svids.get(service_name).map(|s| s.spiffe_id.clone())
    }

    /// Get the SVID cert PEM for a service (for programmatic access).
    pub async fn get_svid(&self, service_name: &str) -> Option<(String, String, String, u64)> {
        let state = self.inner.read().await;
        state.svids.get(service_name).map(|s| {
            (
                s.cert_pem.clone(),
                s.key_pem.clone(),
                s.chain_pem.clone(),
                s.expires_at,
            )
        })
    }

    /// Get services whose SVIDs need renewal (within 5 minutes of expiry).
    pub async fn needs_renewal(&self) -> Vec<String> {
        let state = self.inner.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let buffer = 300; // 5 minutes

        state
            .svids
            .iter()
            .filter(|(_, svid)| svid.expires_at.saturating_sub(buffer) <= now)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Remove SVID material for a service.
    pub async fn remove_svid(&self, service_name: &str) -> Result<(), std::io::Error> {
        let svc_dir = self.data_dir.join(service_name);
        if svc_dir.exists() {
            tokio::fs::remove_dir_all(&svc_dir).await?;
        }
        let mut state = self.inner.write().await;
        state.svids.remove(service_name);
        tracing::info!(service = %service_name, "SVID removed");
        Ok(())
    }

    /// Get the filesystem path for a service's SPIFFE directory.
    pub fn svid_dir(&self, service_name: &str) -> PathBuf {
        self.data_dir.join(service_name)
    }

    /// List all services with active SVIDs.
    pub async fn active_services(&self) -> Vec<(String, String, u64)> {
        let state = self.inner.read().await;
        state
            .svids
            .iter()
            .map(|(name, svid)| (name.clone(), svid.spiffe_id.clone(), svid.expires_at))
            .collect()
    }
}

/// Split a combined PEM (certificate + private key) into separate parts.
fn split_cert_and_key(combined: &str) -> Result<(String, String), std::io::Error> {
    let cert_marker = "-----BEGIN CERTIFICATE-----";
    let cert_end_marker = "-----END CERTIFICATE-----";
    let key_markers = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    ];

    // Extract certificate
    let cert_start = combined.find(cert_marker).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no certificate found in PEM",
        )
    })?;
    let cert_end = combined[cert_start..]
        .find(cert_end_marker)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no certificate end marker found",
            )
        })?
        + cert_start
        + cert_end_marker.len();
    let cert_pem = combined[cert_start..cert_end].trim().to_string();

    // Extract private key
    let key_start = key_markers
        .iter()
        .filter_map(|marker| combined.find(marker))
        .min()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no private key found in PEM",
            )
        })?;
    let key_pem = combined[key_start..].trim().to_string();

    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert_and_key() -> String {
        // Minimal PEM structure for testing split logic
        "-----BEGIN CERTIFICATE-----\n\
         MIIB...\n\
         -----END CERTIFICATE-----\n\
         -----BEGIN PRIVATE KEY-----\n\
         MIGHAgEA...\n\
         -----END PRIVATE KEY-----\n"
            .to_string()
    }

    #[test]
    fn split_cert_and_key_works() {
        let combined = sample_cert_and_key();
        let (cert, key) = split_cert_and_key(&combined).unwrap();

        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.ends_with("-----END CERTIFICATE-----"));
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key.ends_with("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn split_rejects_missing_cert() {
        let result =
            split_cert_and_key("-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----");
        assert!(result.is_err());
    }

    #[test]
    fn split_rejects_missing_key() {
        let result =
            split_cert_and_key("-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn install_and_retrieve_svid() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");

        let cert_and_key = b"-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n\
                             -----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n";
        let chain = b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";

        let svc_dir = mgr
            .install_svid("my-svc", cert_and_key, chain, 9999999999)
            .await
            .unwrap();

        // Files should exist
        assert!(svc_dir.join("svid.pem").exists());
        assert!(svc_dir.join("svid-key.pem").exists());
        assert!(svc_dir.join("bundle.pem").exists());

        // SPIFFE ID should be set
        let id = mgr.spiffe_id("my-svc").await;
        assert_eq!(id.unwrap(), "spiffe://test.internal/service/my-svc");

        // Key file should be read-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(svc_dir.join("svid-key.pem"))
                .unwrap()
                .permissions();
            assert_eq!(perms.mode() & 0o777, 0o400);
        }
    }

    #[tokio::test]
    async fn trust_bundle_propagates_to_services() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");

        let cert_and_key = b"-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n\
                             -----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n";
        let chain = b"-----BEGIN CERTIFICATE-----\nOLD_CA\n-----END CERTIFICATE-----\n";

        mgr.install_svid("svc-a", cert_and_key, chain, 99999)
            .await
            .unwrap();

        // Update trust bundle
        let new_bundle = "-----BEGIN CERTIFICATE-----\nNEW_CA\n-----END CERTIFICATE-----\n";
        mgr.set_trust_bundle(new_bundle).await.unwrap();

        let bundle_content =
            tokio::fs::read_to_string(dir.path().join("spiffe").join("svc-a").join("bundle.pem"))
                .await
                .unwrap();
        assert!(bundle_content.contains("NEW_CA"));
    }

    #[tokio::test]
    async fn remove_svid_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");

        let cert_and_key = b"-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n\
                             -----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n";
        let chain = b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";

        let svc_dir = mgr
            .install_svid("svc", cert_and_key, chain, 99999)
            .await
            .unwrap();
        assert!(svc_dir.exists());

        mgr.remove_svid("svc").await.unwrap();
        assert!(!svc_dir.exists());
        assert!(mgr.spiffe_id("svc").await.is_none());
    }

    #[tokio::test]
    async fn needs_renewal_detects_expiring_svids() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");

        let cert_and_key = b"-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n\
                             -----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n";
        let chain = b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Expiring soon (within 5 min buffer)
        mgr.install_svid("expiring", cert_and_key, chain, now + 60)
            .await
            .unwrap();
        // Not expiring
        mgr.install_svid("fresh", cert_and_key, chain, now + 7200)
            .await
            .unwrap();

        let renewals = mgr.needs_renewal().await;
        assert!(renewals.contains(&"expiring".to_string()));
        assert!(!renewals.contains(&"fresh".to_string()));
    }
}
