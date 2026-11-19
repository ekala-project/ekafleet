//! Federation with other ekafleet clusters.
//!
//! Peers are listed in the fleet configuration (`federation.peers`), each
//! with the endpoint of its federation listener, its trust domain and its
//! root CA. Every [`SYNC_INTERVAL`] the server fetches each peer's
//! federation document over mutual TLS:
//!
//! - the peer's certificate must chain to the configured `caCert` and carry
//!   a `spiffe://<peer trust domain>/server/*` ID;
//! - this server presents its own server SVID, which the peer accepts only
//!   if it chains to the CA the peer configured for this trust domain.
//!
//! The document holds the peer's X.509 and JWT bundles and the
//! services it exports (`federation.exportServices`), with the underlay
//! addresses of the nodes serving them. Agents receive the bundles of all
//! peers with the local trust bundle and serve them from the Workload API.
//! Exported services resolve as `<svc>.<peer>.federation.<domain>`.
//! Services of a peer that has not answered for [`SERVICES_STALE_AFTER`]
//! are dropped from DNS; its last bundles are kept while it stays
//! configured.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use super::dns::DnsInputs;
use super::events::{EventCategory, EventLevel, EventStore};
use super::identity::ServerIdentity;
use super::mesh::MeshRegistry;
use super::state::FleetState;
use crate::config::{FederationConfig, FederationPeer};
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{FederatedBundle, ServerMessage, TrustBundleUpdate};
use crate::proxy::mtls::SpiffeAuthorizer;
use crate::raft::state::FleetStateMachine;

/// Path of the federation document on the federation listener.
pub const DOCUMENT_PATH: &str = "/federation/v1";
/// How often every peer is fetched.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(30);
/// A peer's services leave DNS after this long without a successful fetch.
pub const SERVICES_STALE_AFTER: u64 = 300;
/// How often configuration changes are picked up between syncs.
const TICK: Duration = Duration::from_secs(5);
/// Longest a fetch (connect, handshake, request) may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DOCUMENT: usize = 1024 * 1024;
const MAX_SERVICES: usize = 1024;
const MAX_ADDRESSES: usize = 256;
const MAX_PORTS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("connect: {0}")]
    Connect(std::io::Error),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("invalid federation document: {0}")]
    Document(String),
    #[error("timed out")]
    Timeout,
}

/// What a federation listener serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub trust_domain: String,
    /// PEM certificates.
    pub x509_bundle: String,
    /// JWKS document (may be empty).
    #[serde(default)]
    pub jwt_bundle: String,
    #[serde(default)]
    pub services: Vec<ExportedService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedService {
    pub name: String,
    /// Underlay addresses of the nodes serving it.
    pub addresses: Vec<Ipv4Addr>,
    #[serde(default)]
    pub ports: Vec<ExportedPort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedPort {
    pub name: String,
    pub port: u16,
}

// ── SPIFFE helpers ──────────────────────────────────────────────────

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Split `spiffe://<trust domain><path>` into its trust domain and path.
pub fn split_spiffe_id(id: &str) -> Option<(&str, &str)> {
    let rest = id.strip_prefix("spiffe://")?;
    let (domain, path) = rest.split_at(rest.find('/')?);
    (!domain.is_empty()).then_some((domain, path))
}

/// Whether `cert` carries a server SVID of `trust_domain`.
fn is_server_of(cert: &CertificateDer<'_>, trust_domain: &str) -> bool {
    SpiffeAuthorizer::extract_spiffe_id_from_der(cert.as_ref()).is_some_and(|id| {
        split_spiffe_id(&id).is_some_and(|(domain, path)| {
            domain == trust_domain && path.starts_with("/server/") && path.len() > "/server/".len()
        })
    })
}

fn roots_from_pem(pem: &str) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
        roots
            .add(cert.map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    }
    if roots.is_empty() {
        return Err("no certificate".into());
    }
    Ok(roots)
}

fn bad_certificate() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}

/// Verifies client certificates of peer servers: the certificate's trust
/// domain picks the peer, and the chain must lead to that peer's CA, so
/// one peer cannot pose as another.
#[derive(Debug, Clone, Default)]
pub struct TrustedPeers {
    /// Trust domain → (peer name, verifier anchored at its CA).
    peers: Arc<std::sync::RwLock<HashMap<String, PeerVerifier>>>,
}

/// A peer's name and a client verifier anchored at its CA.
type PeerVerifier = (String, Arc<dyn ClientCertVerifier>);

impl TrustedPeers {
    /// Trust exactly the peers of `federation`. Peers whose CA does not
    /// parse are left out (configuration validation rejects them).
    pub fn set(&self, federation: &FederationConfig) {
        let mut peers = HashMap::new();
        for (name, peer) in &federation.peers {
            let verifier = roots_from_pem(&peer.ca_cert).and_then(|roots| {
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider(),
                )
                .build()
                .map_err(|e| e.to_string())
            });
            match verifier {
                Ok(verifier) => {
                    peers.insert(peer.trust_domain.clone(), (name.clone(), verifier));
                }
                Err(e) => tracing::warn!(peer = %name, error = %e, "Federation peer CA unusable"),
            }
        }
        *self.peers.write().unwrap_or_else(|e| e.into_inner()) = peers;
    }

    fn lookup(&self, cert: &CertificateDer<'_>) -> Option<(String, Arc<dyn ClientCertVerifier>)> {
        let id = SpiffeAuthorizer::extract_spiffe_id_from_der(cert.as_ref())?;
        let (domain, path) = split_spiffe_id(&id)?;
        if !path.starts_with("/server/") || path.len() <= "/server/".len() {
            return None;
        }
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
        peers.get(domain).cloned()
    }

    /// The peer `cert` belongs to, if it is a peer server's certificate.
    fn peer_name(&self, cert: &CertificateDer<'_>) -> Option<String> {
        self.lookup(cert).map(|(name, _)| name)
    }
}

#[derive(Debug)]
struct PeerClientVerifier {
    trusted: TrustedPeers,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PeerClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, verifier) = self
            .trusted
            .lookup(end_entity)
            .ok_or_else(bad_certificate)?;
        verifier.verify_client_cert(end_entity, intermediates, now)
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

/// Accepts a peer server certificate that chains to the peer's configured
/// CA and carries a server SVID of its trust domain (SVIDs have no DNS
/// names to check).
#[derive(Debug)]
struct PeerServerVerifier {
    roots: Arc<RootCertStore>,
    trust_domain: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PeerServerVerifier {
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
        if is_server_of(end_entity, &self.trust_domain) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(bad_certificate())
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

// ── What peers learned ──────────────────────────────────────────────

/// The last valid document of a peer.
#[derive(Debug, Clone)]
pub struct PeerView {
    pub document: Document,
    /// When it was fetched (unix seconds).
    pub synced_at: u64,
}

/// What this server learned from its peers, shared with DNS and the agent
/// streams.
#[derive(Clone, Default)]
pub struct FederationView {
    peers: Arc<RwLock<BTreeMap<String, PeerView>>>,
}

impl FederationView {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bundles of every peer, by trust domain.
    pub async fn bundles(&self) -> Vec<FederatedBundle> {
        let peers = self.peers.read().await;
        let mut bundles: Vec<FederatedBundle> = peers
            .values()
            .map(|view| FederatedBundle {
                trust_domain: view.document.trust_domain.clone(),
                ca_certificates_pem: view.document.x509_bundle.as_bytes().to_vec(),
                jwt_bundle_jwks: view.document.jwt_bundle.as_bytes().to_vec(),
            })
            .collect();
        bundles.sort_by(|a, b| a.trust_domain.cmp(&b.trust_domain));
        bundles
    }

    /// Services of peers synced within [`SERVICES_STALE_AFTER`] of `now`,
    /// by (peer, service).
    pub async fn services(&self, now: u64) -> BTreeMap<(String, String), ExportedService> {
        let peers = self.peers.read().await;
        let mut out = BTreeMap::new();
        for (peer, view) in peers.iter() {
            if now.saturating_sub(view.synced_at) > SERVICES_STALE_AFTER {
                continue;
            }
            for service in &view.document.services {
                out.insert((peer.clone(), service.name.clone()), service.clone());
            }
        }
        out
    }

    async fn update(&self, peer: &str, view: PeerView) {
        self.peers.write().await.insert(peer.to_string(), view);
    }

    async fn retain(&self, peers: &BTreeSet<String>) {
        self.peers
            .write()
            .await
            .retain(|name, _| peers.contains(name));
    }
}

/// The trust bundle message agents receive: the local bundles and those
/// of every federated trust domain.
pub fn trust_bundle_message(
    domain: &str,
    bundle_pem: &str,
    jwks: &str,
    federated: Vec<FederatedBundle>,
) -> ServerMessage {
    ServerMessage {
        payload: Some(ServerPayload::TrustBundle(TrustBundleUpdate {
            trust_domain: domain.to_string(),
            ca_certificate_pem: bundle_pem.as_bytes().to_vec(),
            jwt_bundle_jwks: jwks.as_bytes().to_vec(),
            federated_bundles: federated,
        })),
    }
}

/// Check a fetched document against what is configured for `peer`.
pub fn validate_document(document: &Document, peer: &FederationPeer) -> Result<(), String> {
    if document.trust_domain != peer.trust_domain {
        return Err(format!(
            "trust domain '{}' is not the configured '{}'",
            document.trust_domain, peer.trust_domain
        ));
    }
    roots_from_pem(&document.x509_bundle).map_err(|e| format!("x509Bundle: {e}"))?;
    if !document.jwt_bundle.is_empty() {
        let jwks: serde_json::Value =
            serde_json::from_str(&document.jwt_bundle).map_err(|e| format!("jwtBundle: {e}"))?;
        if !jwks.get("keys").is_some_and(serde_json::Value::is_array) {
            return Err("jwtBundle is not a JWKS document".into());
        }
    }
    if document.services.len() > MAX_SERVICES {
        return Err(format!("more than {MAX_SERVICES} services"));
    }
    let mut names = BTreeSet::new();
    for service in &document.services {
        if !crate::config::is_dns_label(&service.name) {
            return Err(format!(
                "service name '{}' is not a DNS label",
                service.name
            ));
        }
        if !names.insert(service.name.as_str()) {
            return Err(format!("service '{}' is listed twice", service.name));
        }
        if service.addresses.len() > MAX_ADDRESSES || service.ports.len() > MAX_PORTS {
            return Err(format!(
                "service '{}' has too many addresses or ports",
                service.name
            ));
        }
        if service.ports.iter().any(|p| p.port == 0) {
            return Err(format!("service '{}' has port 0", service.name));
        }
    }
    Ok(())
}

// ── Serving our document ────────────────────────────────────────────

/// Builds this cluster's federation document.
#[derive(Clone)]
pub struct Exporter {
    pub domain: String,
    pub bundle_pem: String,
    pub jwks: String,
    pub raft_state: FleetStateMachine,
    pub state: FleetState,
    pub mesh: MeshRegistry,
}

impl Exporter {
    pub async fn document(&self) -> Document {
        let exports = match self.raft_state.current_config().await.map(|r| r.config()) {
            Some(Ok(config)) => config.federation.export_services,
            Some(Err(e)) => {
                tracing::error!(error = %e, "Cannot read the exported services");
                Vec::new()
            }
            None => Vec::new(),
        };
        let inputs = DnsInputs::gather(&self.state).await;
        let underlay = self.mesh.underlay_addresses().await;
        Document {
            trust_domain: self.domain.clone(),
            x509_bundle: self.bundle_pem.clone(),
            jwt_bundle: self.jwks.clone(),
            services: exported_services(&exports, &inputs, &underlay),
        }
    }
}

/// The exported services' serving default-namespace replicas, at the
/// underlay addresses of their nodes.
pub fn exported_services(
    exports: &[String],
    inputs: &DnsInputs,
    underlay: &BTreeMap<String, Ipv4Addr>,
) -> Vec<ExportedService> {
    let mut services = Vec::new();
    for name in exports.iter().collect::<BTreeSet<_>>() {
        let mut addresses = BTreeSet::new();
        let mut ports = BTreeMap::new();
        for (node, specs) in &inputs.assignments {
            for spec in specs.iter().filter(|s| {
                &s.name == name && crate::agent::netns::is_default_namespace(&s.namespace)
            }) {
                for port in spec.ports.iter().filter(|p| p.port != 0) {
                    if let Ok(number) = u16::try_from(port.port) {
                        ports.insert(port.name.clone(), number);
                    }
                }
                if inputs.serving.contains(&(node.clone(), spec.name.clone()))
                    && let Some(ip) = underlay.get(node)
                {
                    addresses.insert(*ip);
                }
            }
        }
        services.push(ExportedService {
            name: name.clone(),
            addresses: addresses.into_iter().collect(),
            ports: ports
                .into_iter()
                .map(|(name, port)| ExportedPort { name, port })
                .collect(),
        });
    }
    services
}

/// Serve the federation document to peer servers on `listener` until
/// `shutdown`.
pub async fn serve(
    listener: tokio::net::TcpListener,
    identity: ServerIdentity,
    trusted: TrustedPeers,
    exporter: Exporter,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let verifier = Arc::new(PeerClientVerifier {
        trusted: trusted.clone(),
        provider: provider(),
    });
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(identity));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    tracing::info!(listen = ?listener.local_addr().ok(), "Federation listener started");

    let router = axum::Router::new().route(
        DOCUMENT_PATH,
        get(move || {
            let exporter = exporter.clone();
            async move { axum::Json(exporter.document().await) }
        }),
    );
    loop {
        let (tcp, remote) = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!(error = %e, "Federation accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let trusted = trusted.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(FETCH_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::warn!(%remote, error = %e, "Federation handshake refused");
                    return;
                }
                Err(_) => return,
            };
            let peer = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| trusted.peer_name(cert));
            tracing::debug!(%remote, peer = ?peer, "Federation peer connected");
            let io = hyper_util::rt::TokioIo::new(tls);
            let service = hyper_util::service::TowerToHyperService::new(router);
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(FETCH_TIMEOUT)
                .serve_connection(io, service);
            if let Err(e) = conn.await {
                tracing::debug!(%remote, error = %e, "Federation connection error");
            }
        });
    }
}

// ── Fetching peers ──────────────────────────────────────────────────

/// Fetch `peer`'s document, authenticating as `identity`.
pub async fn fetch(
    peer: &FederationPeer,
    identity: &ServerIdentity,
) -> Result<Document, FederationError> {
    tokio::time::timeout(FETCH_TIMEOUT, fetch_inner(peer, identity))
        .await
        .map_err(|_| FederationError::Timeout)?
}

async fn fetch_inner(
    peer: &FederationPeer,
    identity: &ServerIdentity,
) -> Result<Document, FederationError> {
    let tls_err = |e: &dyn std::fmt::Display| FederationError::Tls(e.to_string());
    let roots = roots_from_pem(&peer.ca_cert).map_err(|e| tls_err(&e))?;
    let pem = identity.pem();
    let chain = rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| tls_err(&e))?;
    let key = rustls_pemfile::private_key(&mut pem.as_bytes())
        .map_err(|e| tls_err(&e))?
        .ok_or_else(|| FederationError::Tls("no server SVID key".into()))?;
    let verifier = PeerServerVerifier {
        roots: Arc::new(roots),
        trust_domain: peer.trust_domain.clone(),
        provider: provider(),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| tls_err(&e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(chain, key)
        .map_err(|e| tls_err(&e))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let host = peer
        .endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.trim_start_matches('[').trim_end_matches(']'))
        .unwrap_or(&peer.endpoint)
        .to_string();
    let server_name = ServerName::try_from(host.clone()).map_err(|e| tls_err(&e))?;
    let tcp = tokio::net::TcpStream::connect(&peer.endpoint)
        .await
        .map_err(FederationError::Connect)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|e| tls_err(&e))?;

    let http_err = |e: &dyn std::fmt::Display| FederationError::Http(e.to_string());
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|e| http_err(&e))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = hyper::Request::get(DOCUMENT_PATH)
        .header(hyper::header::HOST, host)
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| http_err(&e))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| http_err(&e))?;
    if !response.status().is_success() {
        return Err(FederationError::Http(format!(
            "status {}",
            response.status()
        )));
    }
    let body = http_body_util::Limited::new(response.into_body(), MAX_DOCUMENT)
        .collect()
        .await
        .map_err(|e| http_err(&e))?
        .to_bytes();
    let document: Document =
        serde_json::from_slice(&body).map_err(|e| FederationError::Document(e.to_string()))?;
    validate_document(&document, peer).map_err(FederationError::Document)?;
    Ok(document)
}

/// Keeps [`FederationView`] in line with the peers of the current
/// configuration, and pushes bundle changes to connected agents.
pub struct FederationManager {
    pub raft_state: FleetStateMachine,
    pub view: FederationView,
    pub trusted: TrustedPeers,
    pub identity: ServerIdentity,
    pub state: FleetState,
    pub events: EventStore,
    pub domain: String,
    pub bundle_pem: String,
    pub jwks: String,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

impl FederationManager {
    pub fn spawn(self, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut revision = None;
            let mut last_sync: Option<tokio::time::Instant> = None;
            // Peers whose last fetch failed.
            let mut failing = BTreeSet::new();
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => {}
                }
                let current = self.raft_state.current_config().await;
                let changed = current.as_ref().map(|r| r.revision) != revision;
                if !changed && last_sync.is_some_and(|at| at.elapsed() < SYNC_INTERVAL) {
                    continue;
                }
                let federation = match current.as_ref().map(|r| r.config()).transpose() {
                    Ok(config) => config.map(|c| c.federation).unwrap_or_default(),
                    Err(e) => {
                        tracing::error!(error = %e, "Cannot read the federation configuration");
                        continue;
                    }
                };
                revision = current.as_ref().map(|r| r.revision);
                last_sync = Some(tokio::time::Instant::now());
                self.sync(&federation, &mut failing).await;
            }
        })
    }

    /// Fetch every configured peer once.
    pub async fn sync(&self, federation: &FederationConfig, failing: &mut BTreeSet<String>) {
        self.trusted.set(federation);
        let before = self.view.bundles().await;
        let names: BTreeSet<String> = federation.peers.keys().cloned().collect();
        self.view.retain(&names).await;
        failing.retain(|name| names.contains(name));

        let fetches: Vec<_> = federation
            .peers
            .iter()
            .map(|(name, peer)| {
                let (name, peer, identity) = (name.clone(), peer.clone(), self.identity.clone());
                tokio::spawn(async move {
                    let result = fetch(&peer, &identity).await;
                    (name, result)
                })
            })
            .collect();
        for handle in fetches {
            let Ok((name, result)) = handle.await else {
                continue;
            };
            match result {
                Ok(document) => {
                    self.view
                        .update(
                            &name,
                            PeerView {
                                document,
                                synced_at: now(),
                            },
                        )
                        .await;
                    if failing.remove(&name) {
                        self.report(&name, None).await;
                    }
                }
                Err(e) => {
                    if failing.insert(name.clone()) {
                        self.report(&name, Some(&e)).await;
                    } else {
                        tracing::debug!(peer = %name, error = %e, "Federation peer still unreachable");
                    }
                }
            }
        }

        let after = self.view.bundles().await;
        if after != before {
            tracing::info!(trust_domains = after.len(), "Federated bundles changed");
            let message = trust_bundle_message(&self.domain, &self.bundle_pem, &self.jwks, after);
            for node in self.state.connected_nodes().await {
                self.state.send_to_agent(&node, message.clone()).await;
            }
        }
    }

    async fn report(&self, peer: &str, error: Option<&FederationError>) {
        let (kind, level, message) = match error {
            Some(e) => {
                tracing::warn!(peer, error = %e, "Federation peer unreachable");
                (
                    "federation.peer.unreachable",
                    EventLevel::Warning,
                    format!("Federation peer {peer} unreachable: {e}"),
                )
            }
            None => {
                tracing::info!(peer, "Federation peer reachable again");
                (
                    "federation.peer.synced",
                    EventLevel::Info,
                    format!("Federation peer {peer} reachable again"),
                )
            }
        };
        self.events
            .emit_kind(kind, level, EventCategory::Health, None, None, &message)
            .await;
    }
}

#[cfg(test)]
#[path = "federation_tests.rs"]
mod tests;
