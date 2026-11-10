//! Shared helpers: run the production gRPC server (`serve_grpc`) on a free
//! port with a fresh CA, and talk to it as the CLI or an agent would.

#![allow(dead_code)] // each test crate uses a different subset

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::{AgentMessage, CreateJoinTokenRequest, Heartbeat, agent_message};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub const ADMIN_TOKEN: &str = "join-test-admin-token";
pub const DOMAIN: &str = "fleet.internal";
pub const FLEET_KEY: [u8; 32] = [7u8; 32];

pub struct TestServer {
    pub addr: SocketAddr,
    pub root_ca_pem: String,
    /// Fleet key the server was started with.
    pub fleet_key: [u8; 32],
    shutdown: tokio_util::sync::CancellationToken,
    _data_dir: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Start the production gRPC server on a free port with a fresh CA.
pub async fn start_server() -> TestServer {
    start_server_with_gossip(None).await
}

/// Like [`start_server`], with the given gossip membership.
pub async fn start_server_with_gossip(
    gossip: Option<ekafleet::server::api::ServerGossip>,
) -> TestServer {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let data_dir = tempfile::tempdir().unwrap();

    let root_ca = ekafleet::ca::root::RootCa::new(DOMAIN);
    root_ca.initialize(None, None).await.unwrap();
    let root_ca_pem = root_ca.root_certificate_pem().await.unwrap();
    let ca: Arc<dyn ekafleet::ca::CaSigner> =
        Arc::new(ekafleet::ca::signer::DirectCaSigner::new(root_ca));

    let (server_cert, chain, _) = ca.issue_server_svid("test-server").await.unwrap();
    let tls = ekafleet::server::api::TlsConfig {
        cert_pem: String::from_utf8(server_cert).unwrap(),
        ca_cert_pem: String::from_utf8(chain).unwrap(),
    };
    let trust_bundle_pem = ca.trust_bundle_pem().await.unwrap();

    let raft_state = ekafleet::raft::state::FleetStateMachine::new();
    let config = ekafleet::server::api::GrpcServerConfig {
        addr,
        tls,
        cert_issuer: ekafleet::ca::issuer::CertIssuer::new(ca.clone()),
        ca,
        trust_bundle_pem,
        domain: DOMAIN.to_string(),
        fleet_key: zeroize::Zeroizing::new(FLEET_KEY.to_vec()),
        join_token_store: ekafleet::attestation::join_token::JoinTokenStore::new(),
        raft_state: raft_state.clone(),
        instance_tracker: ekafleet::server::cloud::instance_tracker::InstanceTracker::new(
            raft_state,
        ),
        event_store: ekafleet::server::events::EventStore::new(),
        data_dir: data_dir.path().to_path_buf(),
        gossip,
    };

    let token_store = ekafleet::server::rbac::TokenStore::new();
    token_store
        .register(
            ADMIN_TOKEN,
            ekafleet::server::rbac::Role::Admin,
            "test admin",
        )
        .await;

    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_shutdown = shutdown.clone();
    tokio::spawn(async move {
        ekafleet::server::api::serve_grpc(
            config,
            ekafleet::server::state::FleetState::new(),
            token_store,
            server_shutdown,
        )
        .await
        .unwrap();
    });

    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    TestServer {
        addr,
        root_ca_pem,
        fleet_key: FLEET_KEY,
        shutdown,
        _data_dir: data_dir,
    }
}

/// TLS channel to the server, optionally presenting a client identity.
pub async fn channel(server: &TestServer, identity: Option<Identity>) -> Channel {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&server.root_ca_pem))
        .domain_name("ekafleet");
    if let Some(identity) = identity {
        tls = tls.identity(identity);
    }
    Endpoint::from_shared(format!("https://{}", server.addr))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

/// Create a join token over the API, authenticated with `bearer`.
pub async fn create_token(
    server: &TestServer,
    bearer: Option<&str>,
    node_id: &str,
) -> Result<String, tonic::Status> {
    let mut client = FleetControlClient::new(channel(server, None).await);
    let mut req = tonic::Request::new(CreateJoinTokenRequest {
        node_id: node_id.to_string(),
    });
    if let Some(bearer) = bearer {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    }
    Ok(client.create_join_token(req).await?.into_inner().token)
}

/// Open `StreamControl` over mTLS and send a heartbeat claiming `node_id`.
pub async fn heartbeat(
    server: &TestServer,
    identity: Identity,
    node_id: &str,
) -> Result<(), tonic::Status> {
    let mut client = FleetControlClient::new(channel(server, Some(identity)).await);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(AgentMessage {
        payload: Some(agent_message::Payload::Heartbeat(Heartbeat {
            node_id: node_id.to_string(),
            timestamp: 0,
            available_resources: None,
            pool: String::new(),
            version: String::new(),
            mesh_ip: String::new(),
        })),
    })
    .await
    .unwrap();
    // Keep the sender alive so the server sees an open stream, not EOF.
    let _tx = tx;
    client
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .map(|_| ())
}

pub fn identity_of(node: &ekafleet::agent::join::AttestedNode) -> Identity {
    Identity::from_pem(node.cert_pem.as_bytes(), node.key_pem.as_bytes())
}
