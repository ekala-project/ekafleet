//! CA signer implementations and standalone daemon.
//!
//! `DirectCaSigner` wraps an in-process `RootCa` for convenience modes.
//! `RemoteCaSigner` connects to a `ca-signer` daemon over a Unix socket.
//! `serve` runs the standalone daemon.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use super::root::{CaError, RootCa};
use super::CaSigner;

// --- Wire protocol ---
//
// Simple length-prefixed JSON over a Unix stream socket.
// Request:  4-byte big-endian length + JSON payload
// Response: 4-byte big-endian length + JSON payload
//
// This avoids pulling in a full gRPC stack for a localhost-only,
// single-client socket.

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "method")]
enum Request {
    SignCsr {
        csr_der: Vec<u8>,
        service_name: String,
        store_path: Option<String>,
    },
    IssueCertificate {
        service_name: String,
        csr_der: Vec<u8>,
        store_path: Option<String>,
    },
    IssueServerSvid {
        server_id: String,
    },
    TrustBundle,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum Response {
    CertResult {
        cert_pem: Vec<u8>,
        chain_pem: Vec<u8>,
        expires_at: u64,
    },
    TrustBundle {
        pem: String,
    },
    Error {
        message: String,
    },
}

async fn send_msg(stream: &mut UnixStream, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn recv_msg(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// DirectCaSigner — in-process RootCa wrapper
// ---------------------------------------------------------------------------

/// In-process CA signer. Used by `ekafleet server` and `ekafleet dev`.
pub struct DirectCaSigner {
    ca: RootCa,
}

impl DirectCaSigner {
    pub fn new(ca: RootCa) -> Self {
        Self { ca }
    }
}

#[tonic::async_trait]
impl CaSigner for DirectCaSigner {
    async fn sign_csr(
        &self,
        csr_der: &[u8],
        service_name: &str,
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        self.ca.sign_csr(csr_der, service_name, store_path).await
    }

    async fn issue_certificate(
        &self,
        service_name: &str,
        csr_der: &[u8],
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        self.ca
            .issue_certificate(service_name, csr_der, store_path)
            .await
    }

    async fn issue_server_svid(
        &self,
        server_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        self.ca.issue_server_svid(server_id).await
    }

    async fn trust_bundle_pem(&self) -> Result<String, CaError> {
        self.ca
            .root_certificate_pem()
            .await
            .ok_or(CaError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// RemoteCaSigner — Unix socket client
// ---------------------------------------------------------------------------

/// Remote CA signer client. Connects to a `ca-signer` daemon over a Unix socket.
pub struct RemoteCaSigner {
    socket_path: PathBuf,
}

impl RemoteCaSigner {
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
        }
    }

    async fn call(&self, req: &Request) -> Result<Response, CaError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| CaError::Signing(format!("ca-signer connect: {e}")))?;
        let payload = serde_json::to_vec(req)
            .map_err(|e| CaError::Signing(format!("serialize request: {e}")))?;
        send_msg(&mut stream, &payload)
            .await
            .map_err(|e| CaError::Signing(format!("ca-signer send: {e}")))?;
        let resp_bytes = recv_msg(&mut stream)
            .await
            .map_err(|e| CaError::Signing(format!("ca-signer recv: {e}")))?;
        let resp: Response = serde_json::from_slice(&resp_bytes)
            .map_err(|e| CaError::Signing(format!("deserialize response: {e}")))?;
        Ok(resp)
    }

    fn into_cert_result(resp: Response) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        match resp {
            Response::CertResult {
                cert_pem,
                chain_pem,
                expires_at,
            } => Ok((cert_pem, chain_pem, expires_at)),
            Response::Error { message } => Err(CaError::Signing(message)),
            _ => Err(CaError::Signing("unexpected response type".into())),
        }
    }
}

#[tonic::async_trait]
impl CaSigner for RemoteCaSigner {
    async fn sign_csr(
        &self,
        csr_der: &[u8],
        service_name: &str,
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let resp = self
            .call(&Request::SignCsr {
                csr_der: csr_der.to_vec(),
                service_name: service_name.to_string(),
                store_path: store_path.map(String::from),
            })
            .await?;
        Self::into_cert_result(resp)
    }

    async fn issue_certificate(
        &self,
        service_name: &str,
        csr_der: &[u8],
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let resp = self
            .call(&Request::IssueCertificate {
                service_name: service_name.to_string(),
                csr_der: csr_der.to_vec(),
                store_path: store_path.map(String::from),
            })
            .await?;
        Self::into_cert_result(resp)
    }

    async fn issue_server_svid(
        &self,
        server_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let resp = self
            .call(&Request::IssueServerSvid {
                server_id: server_id.to_string(),
            })
            .await?;
        Self::into_cert_result(resp)
    }

    async fn trust_bundle_pem(&self) -> Result<String, CaError> {
        let resp = self.call(&Request::TrustBundle).await?;
        match resp {
            Response::TrustBundle { pem } => Ok(pem),
            Response::Error { message } => Err(CaError::Signing(message)),
            _ => Err(CaError::Signing("unexpected response type".into())),
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone CA signer daemon
// ---------------------------------------------------------------------------

pub struct CaSignerConfig {
    pub data_dir: PathBuf,
    pub domain: String,
    pub socket_path: PathBuf,
}

/// Run the standalone CA signer daemon.
///
/// Loads (or generates) the root CA key from `data_dir`, then listens on a
/// Unix socket for signing requests. The process holds the CA private key
/// and nothing else — no network listeners, no HTTP, no gRPC.
pub async fn serve(config: CaSignerConfig) -> anyhow::Result<()> {
    tracing::info!(
        data_dir = %config.data_dir.display(),
        socket = %config.socket_path.display(),
        domain = %config.domain,
        "Starting CA signer daemon"
    );

    let ca = RootCa::new(&config.domain);

    // Load or generate CA key material
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

    // Persist if newly generated
    if stored_key.is_none() {
        if let (Some(key_pem), Some(cert_pem)) =
            (ca.root_key_pem().await, ca.root_certificate_pem().await)
        {
            tokio::fs::create_dir_all(&config.data_dir).await?;
            tokio::fs::write(&ca_key_path, &key_pem).await?;
            tokio::fs::write(&ca_cert_path, &cert_pem).await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                tokio::fs::set_permissions(&ca_key_path, perms).await?;
            }

            tracing::info!("CA key and certificate persisted to disk");
        }
    }

    let ca = Arc::new(ca);

    // Clean up stale socket
    let _ = tokio::fs::remove_file(&config.socket_path).await;
    if let Some(parent) = config.socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let listener = UnixListener::bind(&config.socket_path)?;

    // Restrict socket permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o660);
        tokio::fs::set_permissions(&config.socket_path, perms).await?;
    }

    tracing::info!(
        socket = %config.socket_path.display(),
        "CA signer listening"
    );

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let ca = ca.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, &ca).await {
                                tracing::warn!(error = %e, "CA signer connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "CA signer accept error");
                    }
                }
            }
            _ = &mut shutdown => {
                tracing::info!("CA signer shutting down");
                break;
            }
        }
    }

    let _ = tokio::fs::remove_file(&config.socket_path).await;
    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    ca: &RootCa,
) -> anyhow::Result<()> {
    let req_bytes = recv_msg(&mut stream).await?;
    let req: Request = serde_json::from_slice(&req_bytes)?;

    let resp = match req {
        Request::SignCsr {
            csr_der,
            service_name,
            store_path,
        } => match ca
            .sign_csr(&csr_der, &service_name, store_path.as_deref())
            .await
        {
            Ok((cert_pem, chain_pem, expires_at)) => Response::CertResult {
                cert_pem,
                chain_pem,
                expires_at,
            },
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },
        Request::IssueCertificate {
            service_name,
            csr_der,
            store_path,
        } => match ca
            .issue_certificate(&service_name, &csr_der, store_path.as_deref())
            .await
        {
            Ok((cert_pem, chain_pem, expires_at)) => Response::CertResult {
                cert_pem,
                chain_pem,
                expires_at,
            },
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },
        Request::IssueServerSvid { server_id } => match ca.issue_server_svid(&server_id).await {
            Ok((cert_pem, chain_pem, expires_at)) => Response::CertResult {
                cert_pem,
                chain_pem,
                expires_at,
            },
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },
        Request::TrustBundle => match ca.root_certificate_pem().await {
            Some(pem) => Response::TrustBundle { pem },
            None => Response::Error {
                message: "CA not initialized".into(),
            },
        },
    };

    let resp_bytes = serde_json::to_vec(&resp)?;
    send_msg(&mut stream, &resp_bytes).await?;
    Ok(())
}
