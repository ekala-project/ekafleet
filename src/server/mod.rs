pub mod api;
pub mod deployer;
pub mod nix;
pub mod reconciler;
pub mod scaling;
pub mod scheduler;
pub mod state;

use std::path::PathBuf;

use state::FleetState;

use crate::ca::root::RootCa;

pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub peers: Vec<String>,
    pub grpc_listen: String,
    pub http_listen: String,
    pub token: String,
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

    // Initialize the fleet CA
    let ca = RootCa::new("fleet.internal");

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

    // Issue a server certificate for gRPC TLS
    let (server_cert_pem, ca_chain_pem, _expires_at) =
        ca.issue_certificate("ekafleet-server", &[], None).await?;

    let tls = api::TlsConfig {
        cert_pem: String::from_utf8(server_cert_pem)?,
        ca_cert_pem: String::from_utf8(ca_chain_pem)?,
    };

    let fleet_state = FleetState::new();

    // Start gRPC and HTTP servers concurrently
    let (grpc_result, http_result) = tokio::join!(
        api::serve_grpc(grpc_addr, fleet_state, &config.token, &tls),
        api::serve_http(http_addr, config.token.clone()),
    );

    grpc_result?;
    http_result?;

    Ok(())
}
