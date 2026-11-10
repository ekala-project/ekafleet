use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The agent's own SPIFFE node identity (spiffe://<domain>/agent/<node-id>).
/// Persisted to disk and used for mTLS with the server.
pub struct NodeIdentity {
    pub cert_pem: Option<String>,
    pub key_pem: Option<zeroize::Zeroizing<String>>,
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
                let expires_at = cert_not_after(&cert).unwrap_or(0);
                tracing::info!(spiffe_id = ?spiffe_id, expires_at, "Loaded persisted node SVID");
                self.cert_pem = Some(cert);
                self.key_pem = Some(zeroize::Zeroizing::new(key));
                self.spiffe_id = spiffe_id;
                self.expires_at = expires_at;
                true
            }
            _ => false,
        }
    }

    /// Persist node SVID to disk with restrictive permissions.
    ///
    /// The key file is created with mode 0600 before any key material is
    /// written, so the key is never readable by other users, even briefly.
    pub(super) async fn save(&self) -> Result<(), std::io::Error> {
        if let (Some(cert), Some(key)) = (&self.cert_pem, &self.key_pem) {
            let cert_path = self.data_dir.join("node-svid.pem");
            let key_path = self.data_dir.join("node-svid-key.pem");

            tokio::fs::create_dir_all(&self.data_dir).await?;
            write_private(&key_path, key.as_bytes()).await?;
            tokio::fs::write(&cert_path, cert).await?;

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
        key_pem: zeroize::Zeroizing<String>,
        spiffe_id: String,
        expires_at: u64,
    ) -> Result<(), std::io::Error> {
        self.cert_pem = Some(cert_pem);
        self.key_pem = Some(key_pem);
        self.spiffe_id = Some(spiffe_id);
        self.expires_at = expires_at;
        self.save().await
    }

    /// Check if the node SVID exists and has not expired.
    pub fn has_valid_svid(&self) -> bool {
        self.cert_pem.is_some() && self.key_pem.is_some() && self.expires_at > now_epoch()
    }

    /// Whether the SVID names `spiffe://<any domain>/agent/<node_id>`.
    pub fn is_for_node(&self, node_id: &str) -> bool {
        self.spiffe_id
            .as_deref()
            .and_then(|id| id.strip_prefix("spiffe://"))
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(_, path)| path.strip_prefix("agent/") == Some(node_id))
    }
}

/// Read the `notAfter` time (unix seconds) of the first certificate in `pem`.
pub(super) fn cert_not_after(pem: &str) -> Option<u64> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let der = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    u64::try_from(cert.validity().not_after.timestamp()).ok()
}

/// Write `data` to `path`, creating or truncating it with mode 0600.
async fn write_private(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    // An existing file keeps its old mode, so tighten it explicitly too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
    }
    file.write_all(data).await?;
    file.sync_all().await
}

fn now_epoch() -> u64 {
    super::helpers::now_epoch()
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
    /// Node ID to use on first start. Ignored if `<data_dir>/node-id` already
    /// holds the same ID; an error if it holds a different one.
    pub node_id: Option<String>,
    /// UDP address for gossip; `None` disables it. Gossip starts once the
    /// server sends the cluster key.
    pub gossip_listen: Option<std::net::SocketAddr>,
    /// Join the WireGuard mesh; `None` leaves WireGuard untouched.
    pub wireguard: Option<WireguardConfig>,
    pub data_dir: PathBuf,
    pub ca_cert_pem: Option<String>,
}

/// WireGuard mesh settings for this agent.
#[derive(Debug, Clone, Copy)]
pub struct WireguardConfig {
    /// Address other nodes use to reach this node's WireGuard port.
    pub endpoint: std::net::SocketAddr,
    /// Unique index that determines this node's mesh address.
    pub mesh_index: u16,
}

/// Tracks local desired state as received from server.
#[derive(Default)]
pub(super) struct LocalState {
    pub(super) desired_services: HashMap<String, crate::proto::ServiceSpec>,
    pub(super) system_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(spiffe_id: &str) -> NodeIdentity {
        let dir = tempfile::tempdir().unwrap();
        let mut ni = NodeIdentity::new(dir.path());
        ni.spiffe_id = Some(spiffe_id.to_string());
        ni
    }

    #[test]
    fn is_for_node_matches_agent_path_only() {
        assert!(identity("spiffe://fleet.internal/agent/web-1").is_for_node("web-1"));
        assert!(!identity("spiffe://fleet.internal/agent/web-1").is_for_node("web-2"));
        assert!(!identity("spiffe://fleet.internal/server/web-1").is_for_node("web-1"));
        assert!(!identity("spiffe://fleet.internal/agent/web-1/x").is_for_node("web-1"));
    }

    #[tokio::test]
    async fn installed_svid_round_trips_with_private_key_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["n".into()]).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            "spiffe://fleet.internal/agent/n".try_into().unwrap(),
        ));
        let cert = params.self_signed(&key_pair).unwrap();
        let expires_at = cert_not_after(&cert.pem()).unwrap();
        assert!(expires_at > now_epoch());

        let mut ni = NodeIdentity::new(dir.path());
        ni.install(
            cert.pem(),
            zeroize::Zeroizing::new(key_pair.serialize_pem()),
            "spiffe://fleet.internal/agent/n".into(),
            expires_at,
        )
        .await
        .unwrap();
        let mode = std::fs::metadata(dir.path().join("node-svid-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let mut loaded = NodeIdentity::new(dir.path());
        assert!(loaded.load().await);
        assert!(loaded.has_valid_svid());
        assert!(loaded.is_for_node("n"));
        assert_eq!(loaded.expires_at, expires_at);
    }

    #[test]
    fn expired_svid_is_not_valid() {
        let mut ni = identity("spiffe://fleet.internal/agent/n");
        ni.cert_pem = Some(String::new());
        ni.key_pem = Some(zeroize::Zeroizing::new(String::new()));
        ni.expires_at = 1;
        assert!(!ni.has_valid_svid());
    }
}
