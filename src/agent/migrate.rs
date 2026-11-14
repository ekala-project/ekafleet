//! Moving a stateful service's volumes between nodes.
//!
//! The node a service leaves is told (ExportVolumesCommand) to stop the
//! service and grant one pull of its volumes to the node it moves to; the
//! destination (MigrateVolumeCommand) then connects to the source's
//! transfer listener over the mesh. Both ends authenticate with their node
//! SVIDs: the destination accepts only the SPIFFE ID the server named for
//! the source, and the source serves only the destination it was granted.
//!
//! Protocol, over TLS 1.2+: the client sends one JSON line
//! `{"service": "<name>"}`; the server answers `OK` or `ERR <reason>` on a
//! line, followed (after `OK`) by a tar archive of the service's volume
//! directory and a TLS close.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use super::storage::VolumeManager;
use super::types::NodeIdentity;
use crate::proxy::mtls::SpiffeAuthorizer;

/// TCP port of every agent's volume transfer listener (mesh only).
pub const VOLUME_TRANSFER_PORT: u16 = 7403;

const MAX_LINE: usize = 1024;
const CHUNK: usize = 64 * 1024;
/// Longest a transfer may stall before it is abandoned.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("no node SVID or CA bundle for volume transfers")]
    NoIdentity,
    #[error("TLS: {0}")]
    Tls(String),
    #[error("refused by the source: {0}")]
    Refused(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("transfer stalled")]
    Stalled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PullRequest {
    service: String,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The node SVID chain and key, and the CA roots peers chain to.
struct Material {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    roots: Arc<RootCertStore>,
}

async fn material(
    identity: &RwLock<NodeIdentity>,
    ca_pem: Option<&str>,
) -> Result<Material, TransferError> {
    let ca_pem = ca_pem.ok_or(TransferError::NoIdentity)?;
    let identity = identity.read().await;
    let (Some(cert_pem), Some(key_pem)) = (&identity.cert_pem, &identity.key_pem) else {
        return Err(TransferError::NoIdentity);
    };
    let tls = |e: std::io::Error| TransferError::Tls(e.to_string());
    let chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(tls)?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(tls)?
        .ok_or(TransferError::NoIdentity)?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots
            .add(cert.map_err(tls)?)
            .map_err(|e| TransferError::Tls(e.to_string()))?;
    }
    if chain.is_empty() || roots.is_empty() {
        return Err(TransferError::NoIdentity);
    }
    Ok(Material {
        chain,
        key,
        roots: Arc::new(roots),
    })
}

fn server_config(m: Material) -> Result<rustls::ServerConfig, TransferError> {
    let tls = |e: rustls::Error| TransferError::Tls(e.to_string());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(m.roots, provider())
        .build()
        .map_err(|e| TransferError::Tls(e.to_string()))?;
    rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(m.chain, m.key)
        .map_err(tls)
}

fn client_config(m: Material, expected: &str) -> Result<rustls::ClientConfig, TransferError> {
    let tls = |e: rustls::Error| TransferError::Tls(e.to_string());
    let verifier = SpiffeServerVerifier {
        roots: m.roots,
        expected: expected.to_string(),
        provider: provider(),
    };
    rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(tls)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(m.chain, m.key)
        .map_err(tls)
}

/// Accepts a server certificate that chains to the fleet CA and carries
/// exactly the expected SPIFFE ID (SVIDs have no DNS names to check).
#[derive(Debug)]
struct SpiffeServerVerifier {
    roots: Arc<RootCertStore>,
    expected: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        match SpiffeAuthorizer::extract_spiffe_id_from_der(end_entity.as_ref()) {
            Some(id) if id == self.expected => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Serve granted volume pulls on `listen` until `stop`.
pub async fn serve(
    listen: SocketAddr,
    volumes: Arc<VolumeManager>,
    identity: Arc<RwLock<NodeIdentity>>,
    stop: CancellationToken,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "Volume transfer listener started");
    loop {
        let (tcp, peer) = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let volumes = volumes.clone();
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one(tcp, &volumes, &identity).await {
                tracing::warn!(%peer, error = %e, "Volume transfer failed");
            }
        });
    }
}

async fn serve_one(
    tcp: tokio::net::TcpStream,
    volumes: &VolumeManager,
    identity: &RwLock<NodeIdentity>,
) -> Result<(), TransferError> {
    let config = server_config(material(identity, volumes.ca_pem()).await?)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let tls = tokio::time::timeout(STALL_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| TransferError::Stalled)??;
    let peer_id = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| SpiffeAuthorizer::extract_spiffe_id_from_der(cert.as_ref()))
        .ok_or_else(|| TransferError::Protocol("peer presented no SPIFFE ID".into()))?;
    let mut stream = BufReader::new(tls);
    let line = read_line(&mut stream).await?;
    let request: PullRequest = serde_json::from_str(&line)
        .map_err(|e| TransferError::Protocol(format!("bad request: {e}")))?;
    let service = request.service;
    let refuse = |reason: &str| format!("ERR {reason}\n");
    if crate::secrets::validate_name("service", &service).is_err()
        || !volumes.take_export(&service, &peer_id)
    {
        tracing::warn!(peer = %peer_id, service = %service, "Volume pull refused: not granted");
        stream
            .write_all(refuse("no export of this service is granted to you").as_bytes())
            .await?;
        stream.shutdown().await?;
        return Err(TransferError::Refused(format!("{peer_id} for {service}")));
    }
    let dir = volumes.service_dir(&service);
    if !dir.is_dir() {
        stream
            .write_all(refuse("the service has no volumes here").as_bytes())
            .await?;
        stream.shutdown().await?;
        return Err(TransferError::Refused(format!("{service} has no volumes")));
    }
    stream.write_all(b"OK\n").await?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
    let packer = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut builder = tar::Builder::new(ChannelWriter::new(tx));
        builder.follow_symlinks(false);
        builder.append_dir_all(".", &dir)?;
        builder.into_inner()?.flush()
    });
    let mut sent: u64 = 0;
    while let Some(chunk) = rx.recv().await {
        tokio::time::timeout(STALL_TIMEOUT, stream.write_all(&chunk))
            .await
            .map_err(|_| TransferError::Stalled)??;
        sent += chunk.len() as u64;
    }
    // A failed archive must not look complete: drop the connection without
    // a TLS close so the receiver sees a truncated stream.
    packer.await.map_err(std::io::Error::other)??;
    stream.shutdown().await?;
    tracing::info!(peer = %peer_id, service = %service, bytes = sent, "Volumes exported");
    Ok(())
}

/// Pull `service`'s volumes from the agent at `source_addr`, which must
/// present `source_id`, and install them in place of any local copy.
/// Returns the bytes received.
pub async fn pull(
    volumes: &VolumeManager,
    identity: &RwLock<NodeIdentity>,
    source_addr: &str,
    source_id: &str,
    service: &str,
) -> Result<u64, TransferError> {
    crate::secrets::validate_name("service", service).map_err(TransferError::Protocol)?;
    let config = client_config(material(identity, volumes.ca_pem()).await?, source_id)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::time::timeout(STALL_TIMEOUT, tokio::net::TcpStream::connect(source_addr))
        .await
        .map_err(|_| TransferError::Stalled)??;
    let name = ServerName::try_from("ekafleet-volumes").expect("static server name");
    let tls = tokio::time::timeout(STALL_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| TransferError::Stalled)??;
    let mut stream = BufReader::new(tls);
    let mut request = serde_json::to_vec(&PullRequest {
        service: service.to_string(),
    })
    .map_err(std::io::Error::other)?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    stream.flush().await?;
    let status = read_line(&mut stream).await?;
    if let Some(reason) = status.strip_prefix("ERR ") {
        return Err(TransferError::Refused(reason.to_string()));
    }
    if status != "OK" {
        return Err(TransferError::Protocol(format!(
            "unexpected status {status:?}"
        )));
    }

    let incoming = volumes.incoming_dir(service);
    match tokio::fs::remove_dir_all(&incoming).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    tokio::fs::create_dir_all(&incoming).await?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
    let target = incoming.clone();
    let unpacker = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut archive = tar::Archive::new(ChannelReader::new(rx));
        archive.set_preserve_permissions(true);
        archive.set_preserve_ownerships(true);
        archive.set_overwrite(true);
        // `unpack` refuses entries escaping `target` (`..`, absolute paths,
        // writes through symlinks).
        archive.unpack(&target)?;
        // Drain the end-of-archive padding.
        std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
        Ok(())
    });
    let mut received: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    let read_result: Result<(), TransferError> = async {
        loop {
            let n = tokio::time::timeout(STALL_TIMEOUT, stream.read(&mut buf))
                .await
                .map_err(|_| TransferError::Stalled)??;
            if n == 0 {
                return Ok(());
            }
            received += n as u64;
            if tx.send(buf[..n].to_vec()).await.is_err() {
                // The unpacker stopped; its error is reported below.
                return Ok(());
            }
        }
    }
    .await;
    drop(tx);
    let unpacked = unpacker.await.map_err(std::io::Error::other)?;
    if let Err(e) = read_result.and(unpacked.map_err(Into::into)) {
        let _ = tokio::fs::remove_dir_all(&incoming).await;
        return Err(e);
    }
    volumes
        .install_incoming(service)
        .await
        .map_err(|e| TransferError::Io(std::io::Error::other(e.to_string())))?;
    tracing::info!(service, source = %source_id, bytes = received, "Volumes imported");
    Ok(received)
}

async fn read_line<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<String, TransferError> {
    let mut line = Vec::new();
    let read = tokio::time::timeout(
        STALL_TIMEOUT,
        (&mut *stream)
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut line),
    )
    .await
    .map_err(|_| TransferError::Stalled)??;
    if read == 0 || line.last() != Some(&b'\n') {
        return Err(TransferError::Protocol("missing or overlong line".into()));
    }
    line.pop();
    String::from_utf8(line).map_err(|_| TransferError::Protocol("line is not UTF-8".into()))
}

/// A blocking writer feeding an async consumer in chunks.
struct ChannelWriter {
    tx: mpsc::Sender<Vec<u8>>,
    buf: Vec<u8>,
}

impl ChannelWriter {
    fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(CHUNK),
        }
    }

    fn send(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK));
        self.tx
            .blocking_send(chunk)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let n = data.len().min(CHUNK - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == CHUNK {
            self.send()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send()
    }
}

/// A blocking reader over chunks from an async producer; EOF once the
/// producer is gone.
struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            chunk: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos == self.chunk.len() {
            match self.rx.blocking_recv() {
                Some(chunk) => {
                    self.chunk = chunk;
                    self.pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.chunk.len() - self.pos);
        out[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::root::RootCa;
    use std::path::Path;

    async fn ca(domain: &str) -> RootCa {
        let ca = RootCa::new(domain);
        ca.initialize(None, None).await.unwrap();
        ca
    }

    struct Node {
        dir: tempfile::TempDir,
        volumes: Arc<VolumeManager>,
        identity: Arc<RwLock<NodeIdentity>>,
        id: String,
    }

    /// A node with an SVID for `name` issued by `ca`.
    async fn node(ca: &RootCa, name: &str) -> Node {
        let dir = tempfile::tempdir().unwrap();
        let csr = crate::ca::csr::generate_node_csr(None, name).unwrap();
        let (cert, chain, _) = ca
            .sign_csr(
                &csr.csr_der,
                &crate::ca::SvidSubject::Agent(name.into()),
                None,
            )
            .await
            .unwrap();
        let mut identity = NodeIdentity::new(dir.path());
        identity.cert_pem = Some(format!(
            "{}\n{}",
            String::from_utf8(cert).unwrap().trim_end(),
            String::from_utf8(chain).unwrap()
        ));
        identity.key_pem = Some(zeroize::Zeroizing::new(csr.keypair.serialize_pem()));
        let volumes = Arc::new(VolumeManager::new(
            dir.path(),
            ca.root_certificate_pem().await,
        ));
        Node {
            volumes,
            identity: Arc::new(RwLock::new(identity)),
            id: format!("spiffe://{}/agent/{name}", ca.domain().await),
            dir,
        }
    }

    async fn listen(source: &Node, stop: &CancellationToken) -> String {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        tokio::spawn(serve(
            addr,
            source.volumes.clone(),
            source.identity.clone(),
            stop.child_token(),
        ));
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        addr.to_string()
    }

    #[tokio::test]
    async fn granted_destination_pulls_the_volumes_once() {
        let ca = ca("fleet.test").await;
        let (a, b, c) = (
            node(&ca, "a").await,
            node(&ca, "b").await,
            node(&ca, "c").await,
        );
        let data = a.volumes.service_dir("db").join("data");
        std::fs::create_dir_all(data.join("sub")).unwrap();
        std::fs::write(data.join("sub/table"), "rows").unwrap();
        std::fs::write(data.join("big"), vec![7u8; 3 * CHUNK + 5]).unwrap();
        std::os::unix::fs::symlink("sub/table", data.join("link")).unwrap();
        // B already holds a stale copy; it is replaced.
        let stale = b.volumes.service_dir("db").join("data");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("old"), "stale").unwrap();

        let stop = CancellationToken::new();
        let addr = listen(&a, &stop).await;

        // Nothing granted yet.
        let err = pull(&b.volumes, &b.identity, &addr, &a.id, "db")
            .await
            .unwrap_err();
        assert!(matches!(err, TransferError::Refused(_)), "{err}");

        a.volumes.grant_export("db", &b.id, Duration::from_secs(60));
        // Another node cannot use B's grant.
        let err = pull(&c.volumes, &c.identity, &addr, &a.id, "db")
            .await
            .unwrap_err();
        assert!(matches!(err, TransferError::Refused(_)), "{err}");
        // B refuses a source presenting the wrong identity.
        let err = pull(&b.volumes, &b.identity, &addr, &c.id, "db")
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransferError::Io(_) | TransferError::Tls(_)),
            "{err}"
        );

        let bytes = pull(&b.volumes, &b.identity, &addr, &a.id, "db")
            .await
            .unwrap();
        assert!(bytes > 3 * CHUNK as u64);
        let copied = b.volumes.service_dir("db").join("data");
        assert_eq!(
            std::fs::read_to_string(copied.join("sub/table")).unwrap(),
            "rows"
        );
        assert_eq!(
            std::fs::read(copied.join("big")).unwrap().len(),
            3 * CHUNK + 5
        );
        assert_eq!(
            std::fs::read_link(copied.join("link")).unwrap(),
            Path::new("sub/table")
        );
        assert!(!copied.join("old").exists());
        assert!(!b.volumes.incoming_dir("db").exists());

        // The grant was used up.
        let err = pull(&b.volumes, &b.identity, &addr, &a.id, "db")
            .await
            .unwrap_err();
        assert!(matches!(err, TransferError::Refused(_)), "{err}");
        // A refused pull leaves the installed copy alone.
        assert!(copied.join("sub/table").exists());
        stop.cancel();
    }

    #[tokio::test]
    async fn peers_from_another_ca_are_rejected() {
        let ca = ca("fleet.test").await;
        let other = self::ca("fleet.test").await;
        let a = node(&ca, "a").await;
        let mallory = node(&other, "b").await;
        let b_id = format!("spiffe://{}/agent/b", ca.domain().await);
        std::fs::create_dir_all(a.volumes.service_dir("db").join("data")).unwrap();
        a.volumes.grant_export("db", &b_id, Duration::from_secs(60));
        let stop = CancellationToken::new();
        let addr = listen(&a, &stop).await;

        // Mallory trusts its own CA, so it rejects A; and A rejects it.
        assert!(
            pull(&mallory.volumes, &mallory.identity, &addr, &a.id, "db")
                .await
                .is_err()
        );
        let trusting = Arc::new(VolumeManager::new(
            mallory.dir.path(),
            ca.root_certificate_pem().await,
        ));
        assert!(
            pull(&trusting, &mallory.identity, &addr, &a.id, "db")
                .await
                .is_err()
        );
        // The grant is still there for the real B.
        assert!(a.volumes.take_export("db", &b_id));
        stop.cancel();
    }
}
