pub mod api;
pub mod audit;
pub mod deployer;
pub mod events;
pub mod federation;
pub mod namespace;
pub mod nix;
pub mod policy;
pub mod quota;
pub mod rbac;
pub mod rebalance;
pub mod reconciler;
pub mod scaling;
pub mod scheduler;
pub mod state;
pub mod webhook;

use std::path::{Path, PathBuf};

use state::FleetState;

use crate::ca::issuer::CertIssuer;
use crate::ca::root::RootCa;

pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub peers: Vec<String>,
    pub grpc_listen: String,
    pub http_listen: String,
    pub token: String,
    /// Trust domain for SPIFFE identities (e.g., "fleet.internal").
    pub domain: String,
}

pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    tracing::info!(
        data_dir = %config.data_dir.display(),
        peers = ?config.peers,
        grpc = %config.grpc_listen,
        http = %config.http_listen,
        "Starting ekafleet server"
    );

    let grpc_addr = config.grpc_listen.parse()?;
    let http_addr = config.http_listen.parse()?;

    // Initialize the fleet CA with configurable trust domain
    let ca = RootCa::new(&config.domain);

    // Try to load persisted CA key/cert, or generate new ones
    let ca_key_path = config.data_dir.join("ca-key.pem");
    let ca_cert_path = config.data_dir.join("ca-cert.pem");

    let (stored_key, stored_cert) = match (
        tokio::fs::read_to_string(&ca_key_path).await,
        tokio::fs::read_to_string(&ca_cert_path).await,
    ) {
        (Ok(key), Ok(cert)) => (Some(key), Some(cert)),
        _ => (None, None),
    };

    ca.initialize(stored_key.as_deref(), stored_cert.as_deref())
        .await?;

    // Persist CA key and cert if newly generated
    if stored_key.is_none()
        && let (Some(key_pem), Some(cert_pem)) =
            (ca.root_key_pem().await, ca.root_certificate_pem().await)
    {
        tokio::fs::create_dir_all(&config.data_dir).await?;
        tokio::fs::write(&ca_key_path, &key_pem).await?;
        tokio::fs::write(&ca_cert_path, &cert_pem).await?;

        // Restrict CA key file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&ca_key_path, perms).await?;
        }

        tracing::info!("CA key and certificate persisted to disk");
    }

    // Generate or load server identity
    let server_id = get_server_id(&config.data_dir)?;
    tracing::info!(server_id = %server_id, domain = %config.domain, "Server identity established");

    // Issue a server SVID for gRPC TLS: spiffe://<domain>/server/<server-id>
    let (server_cert_pem, ca_chain_pem, _expires_at) = ca.issue_server_svid(&server_id).await?;

    let tls = api::TlsConfig {
        cert_pem: String::from_utf8(server_cert_pem)?,
        ca_cert_pem: String::from_utf8(ca_chain_pem)?,
    };

    // Initialize certificate issuer for SPIFFE SVID issuance
    let cert_issuer = CertIssuer::new(ca.clone());

    let trust_bundle_pem = ca.root_certificate_pem().await.unwrap_or_default();

    // Generate or load fleet encryption key for secret distribution
    let fleet_key = get_or_create_fleet_key(&config.data_dir)?;

    let fleet_state = FleetState::new();
    let event_store = events::EventStore::new();

    // Initialize RBAC token store with the startup token as admin
    let token_store = rbac::TokenStore::new();
    token_store
        .register(&config.token, rbac::Role::Admin, "initial admin token")
        .await;

    // Start gRPC and HTTP servers concurrently
    let (grpc_result, http_result) = tokio::join!(
        api::serve_grpc(
            grpc_addr,
            fleet_state.clone(),
            token_store.clone(),
            &tls,
            cert_issuer,
            ca,
            trust_bundle_pem,
            &config.domain,
            fleet_key,
        ),
        api::serve_http(http_addr, fleet_state, event_store, token_store),
    );

    grpc_result?;
    http_result?;

    Ok(())
}

/// Get or create a persistent fleet encryption key (256-bit).
fn get_or_create_fleet_key(data_dir: &Path) -> anyhow::Result<Vec<u8>> {
    let key_path = data_dir.join("fleet-key");
    if key_path.exists() {
        let hex_str = std::fs::read_to_string(&key_path)?.trim().to_string();
        let key: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid fleet key hex: {e}"))?;
        if key.len() != 32 {
            anyhow::bail!("fleet key must be 32 bytes, got {}", key.len());
        }
        tracing::info!("Fleet encryption key loaded from disk");
        Ok(key)
    } else {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&key_path, &hex)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&key_path, perms)?;
        }
        tracing::info!("Fleet encryption key generated and persisted");
        Ok(key.to_vec())
    }
}

/// Get or create a persistent server identity (UUIDv4).
fn get_server_id(data_dir: &Path) -> anyhow::Result<String> {
    let id_path = data_dir.join("server-id");
    if id_path.exists() {
        Ok(std::fs::read_to_string(&id_path)?.trim().to_string())
    } else {
        let id = uuid::Uuid::new_v4().to_string();
        if let Some(parent) = id_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&id_path, &id)?;
        Ok(id)
    }
}
