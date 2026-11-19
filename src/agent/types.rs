use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// `PendingKeyStore` slot for an in-flight node SVID renewal. Service names
/// must start with a letter or digit, so this cannot collide with one.
pub(super) const NODE_CERT_KEY: &str = "@node";

/// The agent's own SPIFFE node identity (`spiffe://<domain>/agent/<name>`).
/// Persisted to disk and used for mTLS with the server.
pub struct NodeIdentity {
    /// Leaf certificate followed by the intermediate + root chain.
    pub cert_pem: Option<String>,
    pub key_pem: Option<zeroize::Zeroizing<String>>,
    pub spiffe_id: Option<String>,
    pub not_before: u64,
    pub expires_at: u64,
    data_dir: PathBuf,
}

/// SPIFFE ID and validity window (Unix seconds) of the first certificate in
/// `cert_pem`.
fn leaf_info(cert_pem: &str) -> Option<(Option<String>, u64, u64)> {
    let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
    let der = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let validity = cert.validity();
    let not_before = u64::try_from(validity.not_before.timestamp()).unwrap_or(0);
    let not_after = u64::try_from(validity.not_after.timestamp()).unwrap_or(0);
    let spiffe_id = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_der(&der);
    Some((spiffe_id, not_before, not_after))
}

impl NodeIdentity {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            cert_pem: None,
            key_pem: None,
            spiffe_id: None,
            not_before: 0,
            expires_at: 0,
            data_dir: data_dir.to_path_buf(),
        }
    }

    fn cert_path(&self) -> PathBuf {
        self.data_dir.join("node-svid.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.data_dir.join("node-svid-key.pem")
    }

    /// Load the persisted node SVID. Returns false when there is none, or
    /// when the certificate is unreadable or does not certify the key (e.g.
    /// a crash between writing the two files).
    pub async fn load(&mut self) -> bool {
        let (Ok(cert), Ok(key)) = (
            tokio::fs::read_to_string(self.cert_path()).await,
            tokio::fs::read_to_string(self.key_path()).await,
        ) else {
            return false;
        };
        let key = zeroize::Zeroizing::new(key);
        match rcgen::KeyPair::from_pem(&key) {
            Ok(keypair) if super::helpers::cert_certifies_key(&cert, &keypair) => {}
            _ => {
                tracing::warn!("Persisted node SVID does not match its key; ignoring it");
                return false;
            }
        }
        let Some((spiffe_id, not_before, expires_at)) = leaf_info(&cert) else {
            tracing::warn!("Persisted node SVID is not a readable certificate; ignoring it");
            return false;
        };
        tracing::info!(spiffe_id = ?spiffe_id, expires_at, "Loaded persisted node SVID");
        self.cert_pem = Some(cert);
        self.key_pem = Some(key);
        self.spiffe_id = spiffe_id;
        self.not_before = not_before;
        self.expires_at = expires_at;
        true
    }

    /// Replace the node SVID (in memory and on disk, atomically per file;
    /// the key is written first and is 0400).
    pub(crate) async fn install(
        &mut self,
        cert_pem: String,
        key_pem: zeroize::Zeroizing<String>,
    ) -> std::io::Result<()> {
        let invalid = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
        let (spiffe_id, not_before, expires_at) =
            leaf_info(&cert_pem).ok_or_else(|| invalid("node SVID is not a certificate"))?;
        tokio::fs::create_dir_all(&self.data_dir).await?;
        crate::fsutil::write_atomic(&self.key_path(), key_pem.as_bytes(), 0o400).await?;
        crate::fsutil::write_atomic(&self.cert_path(), cert_pem.as_bytes(), 0o644).await?;
        tracing::info!(spiffe_id = ?spiffe_id, expires_at, "Node SVID installed");
        self.cert_pem = Some(cert_pem);
        self.key_pem = Some(key_pem);
        self.spiffe_id = spiffe_id;
        self.not_before = not_before;
        self.expires_at = expires_at;
        Ok(())
    }

    /// Whether this identity certifies `spiffe://<any domain>/agent/<name>`.
    pub fn certifies_node(&self, name: &str) -> bool {
        self.spiffe_id
            .as_deref()
            .and_then(|id| id.strip_prefix("spiffe://"))
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(_, path)| path == format!("agent/{name}"))
    }

    /// Whether a certificate and key are loaded and the certificate has not
    /// expired.
    pub fn has_valid_svid(&self) -> bool {
        self.cert_pem.is_some() && self.key_pem.is_some() && super::now_epoch() < self.expires_at
    }

    /// Whether the SVID is past half its lifetime and should be renewed.
    pub(super) fn needs_renewal(&self) -> bool {
        let lifetime = self.expires_at.saturating_sub(self.not_before);
        self.cert_pem.is_some() && super::now_epoch() >= self.not_before + lifetime / 2
    }
}

/// Holds keypairs for pending certificate requests.
/// When the agent generates a CSR, the keypair is stored here.
/// When the signed certificate arrives, the keypair is retrieved and
/// paired with the certificate.
pub(super) struct PendingKeyStore {
    keys: HashMap<String, (rcgen::KeyPair, std::time::Instant)>,
}

/// How long a certificate request is considered in flight. The server sends
/// no response when it denies a request, so after this the agent may retry.
pub(super) const CSR_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

impl PendingKeyStore {
    pub(super) fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub(super) fn store(&mut self, service_name: &str, keypair: rcgen::KeyPair) {
        self.keys.insert(
            service_name.to_string(),
            (keypair, std::time::Instant::now()),
        );
    }

    pub(super) fn take(&mut self, service_name: &str) -> Option<rcgen::KeyPair> {
        self.keys.remove(service_name).map(|(kp, _)| kp)
    }

    /// Whether a request for `service_name` was sent recently enough that a
    /// response may still arrive.
    pub(super) fn in_flight(&self, service_name: &str) -> bool {
        self.keys
            .get(service_name)
            .is_some_and(|(_, at)| at.elapsed() < CSR_RETRY_AFTER)
    }

    /// Drop pending requests for services not in `keep`.
    pub(super) fn retain(&mut self, keep: impl Fn(&str) -> bool) {
        self.keys.retain(|name, _| keep(name));
    }
}

pub struct AgentConfig {
    pub server_addr: String,
    /// Bearer token; only `ekafleet dev` accepts bearer-authenticated agents.
    pub token: Option<zeroize::Zeroizing<String>>,
    /// One-time join token, exchanged for a node SVID when the agent has no
    /// valid one.
    pub join_token: Option<zeroize::Zeroizing<String>>,
    /// This node's name (= its `machines.<name>` key and the `<name>` in its
    /// SPIFFE ID `spiffe://<domain>/agent/<name>`).
    pub node_name: String,
    pub data_dir: PathBuf,
    pub ca_cert_pem: Option<String>,
    pub mesh: crate::mesh::peers::MeshSettings,
    pub dns: crate::dns::agent::DnsSettings,
}

/// Tracks local desired state as received from server.
#[derive(Default)]
pub(super) struct LocalState {
    pub(super) desired_services: HashMap<String, crate::proto::ServiceSpec>,
    pub(super) system_path: String,
}
