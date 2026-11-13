//! CA signer implementations and standalone daemon.
//!
//! `DirectCaSigner` wraps an in-process `RootCa` for convenience modes.
//! `RemoteCaSigner` connects to a `ca-signer` daemon over a Unix socket.
//! `serve` runs the standalone daemon.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use super::jwt::{JWT_SVID_TTL, JwtSigner};
use super::root::{CaError, RootCa};
use super::{CaSigner, SvidSubject};

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
        subject: SvidSubject,
        store_path: Option<String>,
    },
    IssueServerSvid {
        server_id: String,
    },
    TrustBundle,
    SignJwtSvid {
        subject: SvidSubject,
        audience: Vec<String>,
    },
    JwtBundle,
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
    JwtSvid {
        token: String,
        expires_at: u64,
    },
    JwtBundle {
        jwks: String,
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
    jwt: JwtSigner,
}

impl DirectCaSigner {
    pub fn new(ca: RootCa, jwt: JwtSigner) -> Self {
        Self { ca, jwt }
    }
}

/// Sign a JWT-SVID for `subject` in `ca`'s trust domain. Shared by the
/// in-process signer and the daemon so both validate identically.
async fn sign_jwt(
    ca: &RootCa,
    jwt: &JwtSigner,
    subject: &SvidSubject,
    audience: &[String],
) -> Result<(String, u64), CaError> {
    subject.validate()?;
    super::validate_jwt_audience(audience)?;
    let spiffe_id = subject.spiffe_id(&ca.domain().await);
    jwt.sign(&spiffe_id, audience, JWT_SVID_TTL)
        .map_err(|e| CaError::Signing(e.to_string()))
}

#[tonic::async_trait]
impl CaSigner for DirectCaSigner {
    async fn sign_csr(
        &self,
        csr_der: &[u8],
        subject: &SvidSubject,
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        self.ca.sign_csr(csr_der, subject, store_path).await
    }

    async fn issue_server_svid(&self, server_id: &str) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        self.ca.issue_server_svid(server_id).await
    }

    async fn trust_bundle_pem(&self) -> Result<String, CaError> {
        self.ca
            .root_certificate_pem()
            .await
            .ok_or(CaError::NotInitialized)
    }

    async fn sign_jwt_svid(
        &self,
        subject: &SvidSubject,
        audience: &[String],
    ) -> Result<(String, u64), CaError> {
        sign_jwt(&self.ca, &self.jwt, subject, audience).await
    }

    async fn jwt_bundle(&self) -> Result<String, CaError> {
        Ok(self.jwt.jwks())
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
        subject: &SvidSubject,
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
        let resp = self
            .call(&Request::SignCsr {
                csr_der: csr_der.to_vec(),
                subject: subject.clone(),
                store_path: store_path.map(String::from),
            })
            .await?;
        Self::into_cert_result(resp)
    }

    async fn issue_server_svid(&self, server_id: &str) -> Result<(Vec<u8>, Vec<u8>, u64), CaError> {
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

    async fn sign_jwt_svid(
        &self,
        subject: &SvidSubject,
        audience: &[String],
    ) -> Result<(String, u64), CaError> {
        let resp = self
            .call(&Request::SignJwtSvid {
                subject: subject.clone(),
                audience: audience.to_vec(),
            })
            .await?;
        match resp {
            Response::JwtSvid { token, expires_at } => Ok((token, expires_at)),
            Response::Error { message } => Err(CaError::Signing(message)),
            _ => Err(CaError::Signing("unexpected response type".into())),
        }
    }

    async fn jwt_bundle(&self) -> Result<String, CaError> {
        match self.call(&Request::JwtBundle).await? {
            Response::JwtBundle { jwks } => Ok(jwks),
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

    let ca = super::persist::open_ca(&config.data_dir, &config.domain).await?;
    let jwt = super::persist::open_jwt_signer(&config.data_dir).await?;
    let keys = Arc::new((ca, jwt));

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
                        let keys = keys.clone();
                        tokio::spawn(async move {
                            let (ca, jwt) = &*keys;
                            if let Err(e) = handle_connection(stream, ca, jwt).await {
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
    jwt: &JwtSigner,
) -> anyhow::Result<()> {
    let req_bytes = recv_msg(&mut stream).await?;
    let req: Request = serde_json::from_slice(&req_bytes)?;

    let resp = match req {
        Request::SignCsr {
            csr_der,
            subject,
            store_path,
        } => match ca.sign_csr(&csr_der, &subject, store_path.as_deref()).await {
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
        Request::SignJwtSvid { subject, audience } => {
            match sign_jwt(ca, jwt, &subject, &audience).await {
                Ok((token, expires_at)) => Response::JwtSvid { token, expires_at },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::JwtBundle => Response::JwtBundle { jwks: jwt.jwks() },
    };

    let resp_bytes = serde_json::to_vec(&resp)?;
    send_msg(&mut stream, &resp_bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `RemoteCaSigner` talking to the daemon's connection handler over a
    /// real Unix socket gives the same results as signing in-process.
    #[tokio::test]
    async fn remote_signer_round_trips_jwt_and_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ca.sock");
        let ca = RootCa::new("test.internal");
        ca.initialize(None, None).await.unwrap();
        let (jwt, _) = JwtSigner::generate().unwrap();
        let keys = Arc::new((ca, jwt));

        let listener = UnixListener::bind(&socket).unwrap();
        let server_keys = keys.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let keys = server_keys.clone();
                tokio::spawn(async move {
                    let (ca, jwt) = &*keys;
                    let _ = handle_connection(stream, ca, jwt).await;
                });
            }
        });

        let remote = RemoteCaSigner::new(&socket);
        let jwks = remote.jwt_bundle().await.unwrap();
        assert_eq!(jwks, keys.1.jwks());

        let subject = SvidSubject::Service("web".into());
        let (token, _) = remote
            .sign_jwt_svid(&subject, &["db".to_string()])
            .await
            .unwrap();
        let v = crate::ca::jwt::verify_jwt_svid(&token, &jwks, "test.internal", "db").unwrap();
        assert_eq!(v.spiffe_id, "spiffe://test.internal/service/web");

        // Validation happens in the daemon too.
        assert!(remote.sign_jwt_svid(&subject, &[]).await.is_err());
        let bad = SvidSubject::Service("../server/x".into());
        assert!(
            remote
                .sign_jwt_svid(&bad, &["db".to_string()])
                .await
                .is_err()
        );

        let root = remote.trust_bundle_pem().await.unwrap();
        assert_eq!(Some(root), keys.0.root_certificate_pem().await);
    }
}
