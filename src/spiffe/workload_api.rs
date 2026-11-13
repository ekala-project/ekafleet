use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{RwLock, watch};
use zeroize::Zeroizing;

use crate::fsutil::write_atomic as write_file_atomic;

/// Manages SPIFFE workload identities on an agent node.
///
/// Each service gets an X.509-SVID (certificate + private key) and access
/// to the trust bundle (CA certificate). The agent serves them to workloads
/// over the Workload API and also writes them to a per-service directory:
///
/// ```text
/// <data_dir>/spiffe/<service_name>/
///   svid.pem          — leaf certificate PEM
///   svid-key.pem      — leaf private key PEM (mode 0400)
///   bundle.pem        — CA trust bundle PEM
/// ```
///
/// Files are replaced atomically (write to a temporary file, then rename),
/// so readers never observe a partially written certificate or key.
pub struct WorkloadManager {
    data_dir: PathBuf,
    inner: Arc<RwLock<WorkloadState>>,
    /// Bumped on every change to SVIDs or bundles; Workload API streams
    /// subscribe to push updates.
    changes: watch::Sender<u64>,
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
    key_pem: Zeroizing<String>,
    /// Certificate chain PEM (intermediate + root)
    chain_pem: String,
    /// Expiry as unix epoch seconds
    expires_at: u64,
}

/// A snapshot of one workload's X.509-SVID material.
pub struct SvidMaterial {
    pub spiffe_id: String,
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
    pub chain_pem: String,
    pub expires_at: u64,
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
            changes: watch::channel(0).0,
        }
    }

    /// Subscribe to change notifications. The receiver is marked changed
    /// whenever an SVID is installed or removed or a bundle is updated.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn notify(&self) {
        self.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Get the current trust domain string.
    pub async fn trust_domain_str(&self) -> Option<String> {
        let state = self.inner.read().await;
        Some(state.trust_domain.clone())
    }

    /// Update the trust domain. Called when the agent receives
    /// a TrustBundleUpdate from the server with the authoritative domain.
    pub async fn set_trust_domain(&self, domain: &str) {
        let mut state = self.inner.write().await;
        if state.trust_domain != domain {
            tracing::info!(
                old = %state.trust_domain,
                new = %domain,
                "SPIFFE trust domain updated"
            );
            state.trust_domain = domain.to_string();
            drop(state);
            self.notify();
        }
    }

    /// Update the CA trust bundle. Called when the agent receives
    /// the CA certificate from the server.
    pub async fn set_trust_bundle(&self, ca_cert_pem: &str) -> Result<(), std::io::Error> {
        let mut state = self.inner.write().await;
        state.trust_bundle_pem = Some(ca_cert_pem.to_string());

        // Write bundle to every existing service's directory
        for service_name in state.svids.keys() {
            let svc_dir = self.data_dir.join(service_name);
            if svc_dir.exists() {
                write_file_atomic(&svc_dir.join("bundle.pem"), ca_cert_pem.as_bytes(), 0o644)
                    .await?;
            }
        }
        drop(state);
        self.notify();

        tracing::info!("SPIFFE trust bundle updated");
        Ok(())
    }

    /// Get the current trust bundle PEM.
    pub async fn trust_bundle(&self) -> Option<String> {
        let state = self.inner.read().await;
        state.trust_bundle_pem.clone()
    }

    /// Install an X.509-SVID for a service. The agent generated the keypair
    /// itself (CSR flow); the private key never leaves the node.
    ///
    /// Writes files to `<data_dir>/spiffe/<service_name>/`, with the key
    /// created at mode 0400.
    pub async fn install_svid_split(
        &self,
        service_name: &str,
        cert_pem: &str,
        key_pem: &str,
        chain_pem: &str,
        expires_at: u64,
    ) -> Result<PathBuf, std::io::Error> {
        crate::ca::validate_identity_name(service_name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let svc_dir = self.data_dir.join(service_name);
        tokio::fs::create_dir_all(&svc_dir).await?;

        write_file_atomic(&svc_dir.join("svid.pem"), cert_pem.as_bytes(), 0o644).await?;
        write_file_atomic(&svc_dir.join("svid-key.pem"), key_pem.as_bytes(), 0o400).await?;

        let mut state = self.inner.write().await;
        let bundle = state
            .trust_bundle_pem
            .clone()
            .unwrap_or_else(|| chain_pem.to_string());
        write_file_atomic(&svc_dir.join("bundle.pem"), bundle.as_bytes(), 0o644).await?;

        let spiffe_id = format!("spiffe://{}/service/{}", state.trust_domain, service_name);
        state.svids.insert(
            service_name.to_string(),
            Svid {
                spiffe_id: spiffe_id.clone(),
                cert_pem: cert_pem.to_string(),
                key_pem: Zeroizing::new(key_pem.to_string()),
                chain_pem: chain_pem.to_string(),
                expires_at,
            },
        );
        drop(state);
        self.notify();

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

    /// Get a snapshot of a service's SVID material.
    pub async fn get_svid(&self, service_name: &str) -> Option<SvidMaterial> {
        let state = self.inner.read().await;
        state.svids.get(service_name).map(|s| SvidMaterial {
            spiffe_id: s.spiffe_id.clone(),
            cert_pem: s.cert_pem.clone(),
            key_pem: s.key_pem.clone(),
            chain_pem: s.chain_pem.clone(),
            expires_at: s.expires_at,
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
        let mut state = self.inner.write().await;
        state.svids.remove(service_name);
        let svc_dir = self.data_dir.join(service_name);
        if crate::ca::validate_identity_name(service_name).is_ok() && svc_dir.exists() {
            tokio::fs::remove_dir_all(&svc_dir).await?;
        }
        drop(state);
        self.notify();
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

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n";
    const CHAIN: &str = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";

    #[tokio::test]
    async fn install_and_retrieve_svid() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");

        let svc_dir = mgr
            .install_svid_split("my-svc", CERT, KEY, CHAIN, 9999999999)
            .await
            .unwrap();

        // Files should exist
        assert!(svc_dir.join("svid.pem").exists());
        assert!(svc_dir.join("svid-key.pem").exists());
        assert!(svc_dir.join("bundle.pem").exists());

        // SPIFFE ID should be set
        let id = mgr.spiffe_id("my-svc").await;
        assert_eq!(id.unwrap(), "spiffe://test.internal/service/my-svc");
        let svid = mgr.get_svid("my-svc").await.unwrap();
        assert_eq!(svid.key_pem.as_str(), KEY);

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
    async fn renewal_replaces_read_only_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");
        mgr.install_svid_split("svc", CERT, KEY, CHAIN, 1)
            .await
            .unwrap();
        let new_key = "-----BEGIN PRIVATE KEY-----\nNEW\n-----END PRIVATE KEY-----\n";
        let svc_dir = mgr
            .install_svid_split("svc", CERT, new_key, CHAIN, 2)
            .await
            .unwrap();
        let on_disk = std::fs::read_to_string(svc_dir.join("svid-key.pem")).unwrap();
        assert_eq!(on_disk, new_key);
        assert!(!svc_dir.join("svid-key.pem.tmp").exists());
    }

    #[tokio::test]
    async fn rejects_path_escaping_service_name() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");
        let err = mgr
            .install_svid_split("../escape", CERT, KEY, CHAIN, 1)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!dir.path().join("escape").exists());
    }

    #[tokio::test]
    async fn changes_are_notified() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");
        let mut rx = mgr.subscribe();
        rx.mark_unchanged();

        mgr.install_svid_split("svc", CERT, KEY, CHAIN, 1)
            .await
            .unwrap();
        assert!(rx.has_changed().unwrap());
        rx.mark_unchanged();

        mgr.set_trust_bundle(CHAIN).await.unwrap();
        assert!(rx.has_changed().unwrap());
        rx.mark_unchanged();

        mgr.remove_svid("svc").await.unwrap();
        assert!(rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn trust_bundle_propagates_to_services() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");

        let old = "-----BEGIN CERTIFICATE-----\nOLD_CA\n-----END CERTIFICATE-----\n";
        mgr.install_svid_split("svc-a", CERT, KEY, old, 99999)
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

        let svc_dir = mgr
            .install_svid_split("svc", CERT, KEY, CHAIN, 99999)
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

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Expiring soon (within 5 min buffer)
        mgr.install_svid_split("expiring", CERT, KEY, CHAIN, now + 60)
            .await
            .unwrap();
        // Not expiring
        mgr.install_svid_split("fresh", CERT, KEY, CHAIN, now + 7200)
            .await
            .unwrap();

        let renewals = mgr.needs_renewal().await;
        assert!(renewals.contains(&"expiring".to_string()));
        assert!(!renewals.contains(&"fresh".to_string()));
    }
}
