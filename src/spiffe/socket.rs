use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

use crate::spiffe::workload_api::WorkloadManager;
use crate::spiffe::workload_server::WorkloadApiService;
use crate::workload_proto::spiffe_workload_api_server::SpiffeWorkloadApiServer;

/// Default path for the SPIFFE Workload API socket.
pub const DEFAULT_SOCKET_PATH: &str = "/run/ekafleet/workload-api.sock";

/// Start the SPIFFE Workload API gRPC server over a Unix domain socket.
///
/// The socket is created at the given path (default: `/run/ekafleet/workload-api.sock`).
/// Workloads connect using the `SPIFFE_ENDPOINT_SOCKET` environment variable.
pub async fn serve_workload_api(
    workload_mgr: Arc<WorkloadManager>,
    socket_path: Option<&str>,
) -> anyhow::Result<()> {
    let path = PathBuf::from(socket_path.unwrap_or(DEFAULT_SOCKET_PATH));

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Remove stale socket file if it exists
    if path.exists() {
        tokio::fs::remove_file(&path).await?;
    }

    let listener = UnixListener::bind(&path)?;

    // Set socket permissions (owner + group can connect)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o770);
        tokio::fs::set_permissions(&path, perms).await?;
    }

    tracing::info!(
        path = %path.display(),
        "SPIFFE Workload API listening on Unix socket"
    );

    let service = WorkloadApiService::new(workload_mgr);
    let uds_stream = UnixListenerStream::new(listener);

    tonic::transport::Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(service))
        .serve_with_incoming(uds_stream)
        .await?;

    // Cleanup socket on shutdown
    cleanup_socket(&path).await;

    Ok(())
}

/// Remove the socket file on shutdown.
async fn cleanup_socket(path: &Path) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        tracing::warn!(path = %path.display(), error = %e, "Failed to clean up socket");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_is_set() {
        assert_eq!(DEFAULT_SOCKET_PATH, "/run/ekafleet/workload-api.sock");
    }

    #[tokio::test]
    async fn socket_creates_and_listens() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        let mgr = Arc::new(WorkloadManager::new(dir.path(), "test.internal"));

        // Start the server in a background task
        let handle = tokio::spawn(async move {
            serve_workload_api(mgr, Some(&sock_str)).await
        });

        // Give it a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify socket file exists
        assert!(sock_path.exists(), "socket file should exist");

        // Abort the server
        handle.abort();
    }
}
