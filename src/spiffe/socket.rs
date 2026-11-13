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
    shutdown: tokio_util::sync::CancellationToken,
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

    // Any local process may connect: workloads run under arbitrary (often
    // dynamic) users. Access control is per call — every request is attested
    // from the kernel-provided peer credentials, and processes outside an
    // ekafleet service cgroup are refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o666);
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
        .serve_with_incoming_shutdown(uds_stream, shutdown.cancelled())
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
        let shutdown = tokio_util::sync::CancellationToken::new();
        let test_shutdown = shutdown.clone();

        // Start the server in a background task
        let handle =
            tokio::spawn(
                async move { serve_workload_api(mgr, Some(&sock_str), test_shutdown).await },
            );

        // Give it a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify socket file exists
        assert!(sock_path.exists(), "socket file should exist");

        // Gracefully stop the server
        shutdown.cancel();
        let _ = handle.await;
    }

    /// Connect a Workload API client to a Unix socket path.
    async fn uds_client(
        path: PathBuf,
    ) -> crate::workload_proto::spiffe_workload_api_client::SpiffeWorkloadApiClient<
        tonic::transport::Channel,
    > {
        let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = path.clone();
                async move {
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        tokio::net::UnixStream::connect(path).await?,
                    ))
                }
            }))
            .await
            .unwrap();
        crate::workload_proto::spiffe_workload_api_client::SpiffeWorkloadApiClient::new(channel)
    }

    /// Calls without the `workload.spiffe.io: true` header are refused before
    /// attestation (SPIFFE Workload API spec).
    #[tokio::test]
    async fn security_header_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("wapi.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        let mgr = Arc::new(WorkloadManager::new(dir.path(), "test.internal"));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let handle =
            tokio::spawn(
                async move { serve_workload_api(mgr, Some(&sock_str), server_shutdown).await },
            );
        for _ in 0..50 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let mut client = uds_client(sock_path.clone()).await;
        let err = client
            .fetch_x509svid(crate::workload_proto::X509svidRequest {})
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let mut req = tonic::Request::new(crate::workload_proto::X509svidRequest {});
        req.metadata_mut().insert(
            crate::spiffe::workload_server::SECURITY_HEADER,
            "false".parse().unwrap(),
        );
        let err = client.fetch_x509svid(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&sock_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o666);
        }

        shutdown.cancel();
        let _ = handle.await;
    }

    /// The caller PID must come from SO_PEERCRED, not from a client-supplied
    /// header. A client claiming another process's PID via metadata must be
    /// attested as itself (and here rejected, since the test process is not
    /// an ekafleet-managed service).
    #[tokio::test]
    async fn caller_pid_comes_from_peer_credentials_not_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("wapi.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        let mgr = Arc::new(WorkloadManager::new(dir.path(), "test.internal"));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let handle =
            tokio::spawn(
                async move { serve_workload_api(mgr, Some(&sock_str), server_shutdown).await },
            );
        for _ in 0..50 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let mut client = uds_client(sock_path.clone()).await;
        let mut req = tonic::Request::new(crate::workload_proto::X509svidRequest {});
        req.metadata_mut().insert(
            crate::spiffe::workload_server::SECURITY_HEADER,
            "true".parse().unwrap(),
        );
        // Attempt to impersonate PID 1 via the legacy (spoofable) header.
        req.metadata_mut()
            .insert("x-ekafleet-peer-pid", "1".parse().unwrap());
        let err = client.fetch_x509svid(req).await.unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let own_pid = std::process::id().to_string();
        assert!(
            err.message().contains(&format!("PID {own_pid} ")),
            "server must attest the real peer PID ({own_pid}), got: {}",
            err.message()
        );

        shutdown.cancel();
        let _ = handle.await;
    }
}
