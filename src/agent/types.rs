use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The agent's own SPIFFE node identity (spiffe://<domain>/agent/<node-id>).
/// Persisted to disk and used for mTLS with the server.
pub struct NodeIdentity {
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub spiffe_id: Option<String>,
    pub expires_at: u64,
    data_dir: PathBuf,
}

#[allow(dead_code)]
impl NodeIdentity {
    pub(super) fn new(data_dir: &Path) -> Self {
        Self {
            cert_pem: None,
            key_pem: None,
            spiffe_id: None,
            expires_at: 0,
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// Try to load a persisted node SVID from disk.
    pub(super) async fn load(&mut self) -> bool {
        let cert_path = self.data_dir.join("node-svid.pem");
        let key_path = self.data_dir.join("node-svid-key.pem");

        match (
            tokio::fs::read_to_string(&cert_path).await,
            tokio::fs::read_to_string(&key_path).await,
        ) {
            (Ok(cert), Ok(key)) => {
                // Extract SPIFFE ID from cert SAN
                let spiffe_id =
                    crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&cert);
                tracing::info!(spiffe_id = ?spiffe_id, "Loaded persisted node SVID");
                self.cert_pem = Some(cert);
                self.key_pem = Some(key);
                self.spiffe_id = spiffe_id;
                true
            }
            _ => false,
        }
    }

    /// Persist node SVID to disk with restrictive permissions.
    pub(super) async fn save(&self) -> Result<(), std::io::Error> {
        if let (Some(cert), Some(key)) = (&self.cert_pem, &self.key_pem) {
            let cert_path = self.data_dir.join("node-svid.pem");
            let key_path = self.data_dir.join("node-svid-key.pem");

            tokio::fs::create_dir_all(&self.data_dir).await?;
            tokio::fs::write(&cert_path, cert).await?;
            tokio::fs::write(&key_path, key).await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o400);
                tokio::fs::set_permissions(&key_path, perms).await?;
            }

            tracing::info!(
                spiffe_id = ?self.spiffe_id,
                "Node SVID persisted to disk"
            );
        }
        Ok(())
    }

    /// Install a node SVID received from attestation.
    pub(super) async fn install(
        &mut self,
        cert_pem: String,
        key_pem: String,
        spiffe_id: String,
        expires_at: u64,
    ) -> Result<(), std::io::Error> {
        self.cert_pem = Some(cert_pem);
        self.key_pem = Some(key_pem);
        self.spiffe_id = Some(spiffe_id);
        self.expires_at = expires_at;
        self.save().await
    }

    /// Check if the node SVID exists and is valid.
    pub fn has_valid_svid(&self) -> bool {
        self.cert_pem.is_some() && self.key_pem.is_some()
    }
}

/// Holds keypairs for pending certificate requests.
/// When the agent generates a CSR, the keypair is stored here.
/// When the signed certificate arrives, the keypair is retrieved and
/// paired with the certificate.
pub(super) struct PendingKeyStore {
    keys: HashMap<String, rcgen::KeyPair>,
}

impl PendingKeyStore {
    pub(super) fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub(super) fn store(&mut self, service_name: &str, keypair: rcgen::KeyPair) {
        self.keys.insert(service_name.to_string(), keypair);
    }

    pub(super) fn take(&mut self, service_name: &str) -> Option<rcgen::KeyPair> {
        self.keys.remove(service_name)
    }
}

#[allow(dead_code)]
pub struct AgentConfig {
    pub server_addr: String,
    /// Legacy bearer token for authentication.
    pub token: String,
    /// One-time join token for SPIFFE node attestation (replaces token).
    pub join_token: Option<String>,
    pub data_dir: PathBuf,
    pub ca_cert_pem: Option<String>,
}

/// Tracks local desired state as received from server.
#[derive(Default)]
pub(super) struct LocalState {
    pub(super) desired_services: HashMap<String, crate::proto::ServiceSpec>,
    pub(super) system_path: String,
}
