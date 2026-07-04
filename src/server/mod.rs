mod api;
pub mod deployer;
pub mod nix;
pub mod reconciler;
pub mod scheduler;
pub mod state;

use std::path::PathBuf;

use state::FleetState;

pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub peers: Vec<String>,
    pub grpc_listen: String,
    pub http_listen: String,
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

    let fleet_state = FleetState::new();

    // Start gRPC and HTTP servers concurrently
    let (grpc_result, http_result) = tokio::join!(
        api::serve_grpc(grpc_addr, fleet_state),
        api::serve_http(http_addr),
    );

    grpc_result?;
    http_result?;

    Ok(())
}
