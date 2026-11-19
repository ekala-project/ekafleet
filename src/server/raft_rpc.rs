//! Raft RPCs between control-plane servers over the gRPC mTLS listener.
//!
//! [`RaftService`] serves `RaftInternal` to callers presenting a server
//! SVID of this trust domain and nobody else (no bearer token, not even
//! the admin's). [`GrpcNetwork`] is the openraft network that dials peers
//! with this server's SVID and accepts only their server SVIDs back.
//! Requests and results travel as openraft's own serde JSON.

// tonic's `Status` and openraft's `RPCError` are the errors these APIs use.
#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use openraft::BasicNode;
use openraft::error::{
    InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable,
};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tonic::{Request, Response, Status};

use zeroize::Zeroizing;

use super::identity::ServerIdentity;
use crate::proto::RaftMessage;
use crate::proto::raft_internal_client::RaftInternalClient;
use crate::proto::raft_internal_server::RaftInternal;
use crate::raft::consensus::{NodeId, Raft, TypeConfig};
use crate::raft::state::FleetStateMachine;

/// Largest Raft message either side accepts (entries batches, snapshot
/// chunks; see `consensus::raft_config`).
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// How long a peer connection may take to establish.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The caller's server SPIFFE ID, if it presented a server SVID of
/// `domain`. The certificate chain was verified against the fleet CA in
/// the TLS handshake.
fn server_peer<T>(request: &Request<T>, domain: &str) -> Result<String, Status> {
    let certs = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("Raft requires a server SVID"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| Status::unauthenticated("Raft requires a server SVID"))?;
    if !super::federation::is_server_of(leaf, domain) {
        return Err(Status::permission_denied("Raft is served to servers only"));
    }
    Ok(crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_der(leaf).unwrap_or_default())
}

fn decode<T: DeserializeOwned>(message: RaftMessage) -> Result<T, Status> {
    serde_json::from_slice(&message.data)
        .map_err(|e| Status::invalid_argument(format!("Raft message: {e}")))
}

fn encode<T: Serialize>(value: &T) -> Result<Response<RaftMessage>, Status> {
    serde_json::to_vec(value)
        .map(|data| Response::new(RaftMessage { data }))
        .map_err(|e| Status::internal(format!("Raft message: {e}")))
}

/// Serves this server's Raft node to its peers.
pub struct RaftService {
    raft_state: FleetStateMachine,
    domain: String,
    fleet_key: Option<Arc<tokio::sync::RwLock<super::api::FleetKeyState>>>,
}

impl RaftService {
    pub fn new(raft_state: FleetStateMachine, domain: &str) -> Self {
        Self {
            raft_state,
            domain: domain.to_string(),
            fleet_key: None,
        }
    }

    /// Serve `fleet_key` to peers whose copy is out of date.
    pub fn with_fleet_key(
        mut self,
        fleet_key: Arc<tokio::sync::RwLock<super::api::FleetKeyState>>,
    ) -> Self {
        self.fleet_key = Some(fleet_key);
        self
    }

    fn raft<T>(&self, request: &Request<T>) -> Result<&Raft, Status> {
        let peer = server_peer(request, &self.domain)?;
        tracing::trace!(%peer, "Raft RPC");
        self.raft_state
            .raft()
            .ok_or_else(|| Status::unavailable("Raft is not running"))
    }
}

#[tonic::async_trait]
impl RaftInternal for RaftService {
    async fn append_entries(
        &self,
        request: Request<RaftMessage>,
    ) -> Result<Response<RaftMessage>, Status> {
        let raft = self.raft(&request)?;
        let rpc: AppendEntriesRequest<TypeConfig> = decode(request.into_inner())?;
        encode(&raft.append_entries(rpc).await)
    }

    async fn vote(&self, request: Request<RaftMessage>) -> Result<Response<RaftMessage>, Status> {
        let raft = self.raft(&request)?;
        let rpc: VoteRequest<NodeId> = decode(request.into_inner())?;
        encode(&raft.vote(rpc).await)
    }

    async fn install_snapshot(
        &self,
        request: Request<RaftMessage>,
    ) -> Result<Response<RaftMessage>, Status> {
        let raft = self.raft(&request)?;
        let rpc: InstallSnapshotRequest<TypeConfig> = decode(request.into_inner())?;
        encode(&raft.install_snapshot(rpc).await)
    }

    async fn status(
        &self,
        request: Request<crate::proto::RaftStatusRequest>,
    ) -> Result<Response<crate::proto::RaftStatusResponse>, Status> {
        let raft = self.raft(&request)?;
        Ok(Response::new(super::leadership::raft_status(raft)))
    }

    async fn fleet_key(
        &self,
        request: Request<crate::proto::FleetKeyRequest>,
    ) -> Result<Response<crate::proto::FleetKeyResponse>, Status> {
        let peer = server_peer(&request, &self.domain)?;
        let fleet_key = self
            .fleet_key
            .as_ref()
            .ok_or_else(|| Status::unavailable("no fleet key here"))?
            .read()
            .await;
        if !super::fleetkey::has_check(&fleet_key.key, &request.get_ref().check) {
            return Err(Status::failed_precondition(
                "this server does not hold the requested fleet key",
            ));
        }
        tracing::info!(%peer, "Sending the current fleet key to a peer");
        Ok(Response::new(crate::proto::FleetKeyResponse {
            key: fleet_key.key.to_vec(),
        }))
    }
}

/// Dials Raft peers over mTLS with this server's SVID.
#[derive(Clone)]
pub struct GrpcNetwork {
    tls: Arc<rustls::ClientConfig>,
}

impl GrpcNetwork {
    /// Present `identity` (renewals apply to new connections) and accept
    /// peers holding a server SVID of `domain` issued under `ca_pem`.
    pub fn new(identity: ServerIdentity, ca_pem: &str, domain: &str) -> anyhow::Result<Self> {
        let roots = super::federation::roots_from_pem(ca_pem)
            .map_err(|e| anyhow::anyhow!("fleet CA PEM: {e}"))?;
        let tls =
            Self::verifying(Arc::new(roots), domain)?.with_client_cert_resolver(Arc::new(identity));
        Ok(Self::from_config(tls))
    }

    /// A client config accepting only server SVIDs of `domain`.
    fn verifying(
        roots: Arc<rustls::RootCertStore>,
        domain: &str,
    ) -> anyhow::Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>>
    {
        let verifier = super::federation::PeerServerVerifier::new(roots, domain);
        Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier)))
    }

    fn from_config(mut tls: rustls::ClientConfig) -> Self {
        tls.alpn_protocols = vec![b"h2".to_vec()];
        Self { tls: Arc::new(tls) }
    }

    /// A lazily connecting channel to the peer at `addr` (`host:port`).
    fn channel(&self, addr: &str) -> Result<tonic::transport::Channel, String> {
        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .map_err(|e| format!("Raft peer address {addr}: {e}"))?
            .connect_timeout(CONNECT_TIMEOUT)
            .http2_keep_alive_interval(Duration::from_secs(20))
            .keep_alive_timeout(Duration::from_secs(10));
        let tls = self.tls.clone();
        let addr = addr.to_string();
        let connector = tower::service_fn(move |_: tonic::transport::Uri| {
            let tls = tls.clone();
            let addr = addr.clone();
            async move {
                let host = addr
                    .rsplit_once(':')
                    .map_or(addr.as_str(), |(host, _)| host)
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string();
                let name =
                    rustls::pki_types::ServerName::try_from(host).map_err(std::io::Error::other)?;
                let tcp = tokio::net::TcpStream::connect(&addr).await?;
                tcp.set_nodelay(true)?;
                let stream = tokio_rustls::TlsConnector::from(tls)
                    .connect(name, tcp)
                    .await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        });
        Ok(endpoint.connect_with_connector_lazy(connector))
    }
}

impl GrpcNetwork {
    /// What the server at `addr` knows of the cluster.
    pub async fn status(&self, addr: &str) -> anyhow::Result<crate::proto::RaftStatusResponse> {
        let channel = self.channel(addr).map_err(anyhow::Error::msg)?;
        let status = tokio::time::timeout(
            CONNECT_TIMEOUT,
            RaftInternalClient::new(channel).status(crate::proto::RaftStatusRequest {}),
        )
        .await
        .map_err(|_| anyhow::anyhow!("{addr} did not answer"))??;
        Ok(status.into_inner())
    }

    /// The fleet key with check value `check`, from the server at `addr`.
    pub async fn fleet_key(&self, addr: &str, check: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let channel = self.channel(addr).map_err(anyhow::Error::msg)?;
        let response = tokio::time::timeout(
            CONNECT_TIMEOUT,
            RaftInternalClient::new(channel).fleet_key(crate::proto::FleetKeyRequest {
                check: check.to_vec(),
            }),
        )
        .await
        .map_err(|_| anyhow::anyhow!("{addr} did not answer"))??;
        Ok(Zeroizing::new(std::mem::take(
            &mut response.into_inner().key,
        )))
    }
}

impl RaftNetworkFactory<TypeConfig> for GrpcNetwork {
    type Network = GrpcPeer;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> GrpcPeer {
        let client = self.channel(&node.addr).map(|channel| {
            RaftInternalClient::new(channel)
                .max_decoding_message_size(MAX_MESSAGE)
                .max_encoding_message_size(MAX_MESSAGE)
        });
        GrpcPeer { target, client }
    }
}

/// One peer's Raft connection.
pub struct GrpcPeer {
    target: NodeId,
    client: Result<RaftInternalClient<tonic::transport::Channel>, String>,
}

type Call<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Response<RaftMessage>, Status>> + Send + 'a>,
>;

impl GrpcPeer {
    /// Send `rpc` with `call` and decode the peer's `Result`.
    async fn send<Req, Resp, E>(
        &mut self,
        rpc: &Req,
        option: &RPCOption,
        call: impl for<'a> FnOnce(
            &'a mut RaftInternalClient<tonic::transport::Channel>,
            RaftMessage,
        ) -> Call<'a>,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, E>>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        let client = self.client.as_mut().map_err(|e| {
            RPCError::Unreachable(Unreachable::new(&std::io::Error::other(e.clone())))
        })?;
        let data = serde_json::to_vec(rpc).map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let response = tokio::time::timeout(option.hard_ttl(), call(client, RaftMessage { data }))
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?
            .map_err(|status| match status.code() {
                tonic::Code::Unavailable | tonic::Code::Unknown => {
                    RPCError::Unreachable(Unreachable::new(&status))
                }
                _ => RPCError::Network(NetworkError::new(&status)),
            })?;
        let result: Result<Resp, E> = serde_json::from_slice(&response.into_inner().data)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

impl RaftNetwork<TypeConfig> for GrpcPeer {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.send(&rpc, &option, |client, message| {
            Box::pin(client.append_entries(message))
        })
        .await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        self.send(&rpc, &option, |client, message| {
            Box::pin(client.install_snapshot(message))
        })
        .await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.send(&rpc, &option, |client, message| {
            Box::pin(client.vote(message))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;

    use super::*;
    use crate::ca::CaSigner;
    use crate::ca::signer::DirectCaSigner;
    use crate::proto::raft_internal_server::RaftInternalServer;
    use crate::raft::consensus::{self, Proposal};
    use crate::raft::state::Command;

    const DOMAIN: &str = "fleet.test";

    async fn signer(dir: &std::path::Path) -> Arc<dyn CaSigner> {
        let root = crate::ca::persist::open_ca(dir, DOMAIN).await.unwrap();
        let jwt = crate::ca::persist::open_jwt_signer(dir).await.unwrap();
        Arc::new(DirectCaSigner::new(root, jwt))
    }

    struct Server {
        addr: SocketAddr,
        identity: ServerIdentity,
        ca_pem: String,
        state: FleetStateMachine,
        fleet_key: Arc<tokio::sync::RwLock<super::super::api::FleetKeyState>>,
        _shutdown: tokio_util::sync::DropGuard,
    }

    /// Serve `RaftInternal` on the production TLS listener setup.
    async fn serve(ca: &Arc<dyn CaSigner>, id: &str) -> Server {
        let (pem, chain, expires_at) = ca.issue_server_svid(id).await.unwrap();
        let identity = ServerIdentity::from_pem(
            zeroize::Zeroizing::new(String::from_utf8(pem).unwrap()),
            expires_at,
        )
        .unwrap();
        let tls = super::super::api::TlsConfig {
            identity: identity.clone(),
            ca_cert_pem: String::from_utf8(chain).unwrap(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let incoming = super::super::api::grpc_incoming(
            listener,
            super::super::api::grpc_tls_config(&tls).unwrap(),
            shutdown.clone(),
        );
        let state = FleetStateMachine::new();
        let fleet_key = Arc::new(tokio::sync::RwLock::new(super::super::api::FleetKeyState {
            key: Zeroizing::new(vec![1; 32]),
            version: 1,
        }));
        let service = RaftInternalServer::new(
            RaftService::new(state.clone(), DOMAIN).with_fleet_key(fleet_key.clone()),
        );
        let stop = shutdown.clone();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, stop.cancelled())
                .await
                .unwrap();
        });
        Server {
            addr,
            identity,
            ca_pem: tls.ca_cert_pem,
            state,
            fleet_key,
            _shutdown: shutdown.drop_guard(),
        }
    }

    fn config() -> openraft::Config {
        openraft::Config {
            heartbeat_interval: 50,
            election_timeout_min: 300,
            election_timeout_max: 600,
            ..Default::default()
        }
        .validate()
        .unwrap()
    }

    #[tokio::test]
    async fn servers_replicate_over_mtls() {
        let ca_dir = tempfile::tempdir().unwrap();
        let ca = signer(ca_dir.path()).await;
        let servers = [serve(&ca, "s1").await, serve(&ca, "s2").await];
        let members: BTreeMap<NodeId, BasicNode> = servers
            .iter()
            .enumerate()
            .map(|(i, s)| (i as NodeId + 1, BasicNode::new(s.addr.to_string())))
            .collect();
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let mut rafts = Vec::new();
        for (i, server) in servers.iter().enumerate() {
            let storage = Arc::new(crate::raft::storage::RaftStorage::new(
                dirs[i].path(),
                &[3; 32],
            ));
            storage.initialize().await.unwrap();
            let network =
                GrpcNetwork::new(server.identity.clone(), &server.ca_pem, DOMAIN).unwrap();
            let raft = consensus::boot(
                &server.state,
                storage,
                i as NodeId + 1,
                &server.addr.to_string(),
                network,
                config(),
            )
            .await
            .unwrap();
            rafts.push(raft);
        }
        // The second server already answers for the cluster it will join,
        // which is still empty: the first forms it.
        assert!(
            consensus::form_cluster(&rafts[0], members.clone(), |_, _| async { false })
                .await
                .unwrap()
        );
        assert!(
            !consensus::form_cluster(&rafts[1], members, |_, _| async { false })
                .await
                .unwrap()
        );
        let leader = rafts[0]
            .wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader.is_some(), "leader")
            .await
            .unwrap()
            .current_leader
            .unwrap();
        rafts[(leader - 1) as usize]
            .client_write(Proposal::new(Command::KvPut {
                key: "k".into(),
                value: b"replicated".to_vec(),
            }))
            .await
            .unwrap();
        for server in &servers {
            let mut value = None;
            for _ in 0..100 {
                value = server.state.kv_get("k").await;
                if value.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(value.as_deref(), Some(&b"replicated"[..]));
        }
        // Peers report the cluster to each other's server SVIDs.
        let network =
            GrpcNetwork::new(servers[0].identity.clone(), &servers[0].ca_pem, DOMAIN).unwrap();
        let status = network.status(&servers[1].addr.to_string()).await.unwrap();
        assert_eq!(status.node_id, 2);
        assert_eq!(status.leader_id, leader);
        assert_eq!(status.members.len(), 2);

        // A fleet key rotated on the leader reaches the other server.
        use super::super::fleetkey::{FleetKeySync, key_check};
        let (rotated, stale) = (
            &servers[(leader - 1) as usize],
            &servers[(2 - leader) as usize],
        );
        rotated.fleet_key.write().await.key = Zeroizing::new(vec![2; 32]);
        rafts[(leader - 1) as usize]
            .client_write(Proposal::new(Command::SetFleetKeyCheck {
                check: key_check(&[2; 32]),
            }))
            .await
            .unwrap();
        let key_dir = tempfile::tempdir().unwrap();
        let sync = FleetKeySync {
            raft_state: stale.state.clone(),
            fleet_key: stale.fleet_key.clone(),
            secret_store: Arc::new(tokio::sync::RwLock::new(
                crate::secrets::store::SecretStore::new(&[1; 32]),
            )),
            network: GrpcNetwork::new(stale.identity.clone(), &stale.ca_pem, DOMAIN).unwrap(),
            state: super::super::state::FleetState::new(),
            data_dir: key_dir.path().to_path_buf(),
            domain: DOMAIN.into(),
        };
        for _ in 0..100 {
            if sync.sync().await && stale.fleet_key.read().await.key[..] == [2; 32] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(stale.fleet_key.read().await.key[..], [2; 32]);
        assert_eq!(stale.fleet_key.read().await.version, 2);
        assert!(key_dir.path().join("fleet-key").exists());
        // Only the key asked for is served.
        let other = network
            .fleet_key(&servers[1].addr.to_string(), &key_check(&[9; 32]))
            .await
            .unwrap_err();
        assert!(other.to_string().contains("does not hold"), "{other}");

        for raft in rafts {
            raft.shutdown().await.unwrap();
        }
    }

    /// Send a Vote RPC to `server` over `tls`, with an optional bearer token.
    async fn vote(server: &Server, tls: rustls::ClientConfig, bearer: Option<&str>) -> Status {
        let channel = GrpcNetwork::from_config(tls)
            .channel(&server.addr.to_string())
            .unwrap();
        let rpc = VoteRequest::new(openraft::Vote::new(1, 9), None);
        let mut request = Request::new(RaftMessage {
            data: serde_json::to_vec(&rpc).unwrap(),
        });
        if let Some(token) = bearer {
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
        }
        RaftInternalClient::new(channel)
            .vote(request)
            .await
            .expect_err("refused")
    }

    #[tokio::test]
    async fn only_server_svids_reach_raft() {
        let ca_dir = tempfile::tempdir().unwrap();
        let ca = signer(ca_dir.path()).await;
        let server = serve(&ca, "s1").await;
        let roots = Arc::new(super::super::federation::roots_from_pem(&server.ca_pem).unwrap());

        // No client certificate, with or without a bearer token.
        for bearer in [None, Some("admin-token")] {
            let tls = GrpcNetwork::verifying(roots.clone(), DOMAIN)
                .unwrap()
                .with_no_client_auth();
            let status = vote(&server, tls, bearer).await;
            assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status}");
        }

        // An agent SVID from the same CA.
        let csr = crate::ca::csr::generate_node_csr(None, "node-1").unwrap();
        let (cert, _chain, _) = ca
            .sign_csr(
                &csr.csr_der,
                &crate::ca::SvidSubject::Agent("node-1".into()),
                None,
            )
            .await
            .unwrap();
        let chain = rustls_pemfile::certs(&mut cert.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::try_from(csr.keypair.serialize_der()).unwrap();
        let tls = GrpcNetwork::verifying(roots, DOMAIN)
            .unwrap()
            .with_client_auth_cert(chain, key)
            .unwrap();
        let status = vote(&server, tls, Some("admin-token")).await;
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status}");
    }
}
