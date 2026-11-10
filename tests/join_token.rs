//! End-to-end join-token flow against the real gRPC server (`serve_grpc`).
//!
//! Covers: an admin creates a token over the API, a credential-less agent
//! presents it to `Attest`, receives a node SVID bound to its node ID, and uses
//! that SVID for mTLS on `StreamControl`. Also covers the rejection paths:
//! replay, binding mismatch, takeover of an attested node ID, unauthenticated
//! token creation and an SVID speaking for another node.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ekafleet::agent::join::{JoinError, attest_with_join_token};
use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::{AgentMessage, CreateJoinTokenRequest, Heartbeat, agent_message};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

const ADMIN_TOKEN: &str = "join-test-admin-token";
const DOMAIN: &str = "fleet.internal";

struct TestServer {
    addr: SocketAddr,
    root_ca_pem: String,
    shutdown: tokio_util::sync::CancellationToken,
    _data_dir: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Start the production gRPC server on a free port with a fresh CA.
async fn start_server() -> TestServer {
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
        fleet_key: zeroize::Zeroizing::new(vec![7u8; 32]),
        join_token_store: ekafleet::attestation::join_token::JoinTokenStore::new(),
        raft_state: raft_state.clone(),
        instance_tracker: ekafleet::server::cloud::instance_tracker::InstanceTracker::new(
            raft_state,
        ),
        event_store: ekafleet::server::events::EventStore::new(),
        data_dir: data_dir.path().to_path_buf(),
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
        shutdown,
        _data_dir: data_dir,
    }
}

/// TLS channel to the server, optionally presenting a client identity.
async fn channel(server: &TestServer, identity: Option<Identity>) -> Channel {
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
async fn create_token(
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
async fn heartbeat(
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

fn identity_of(node: &ekafleet::agent::join::AttestedNode) -> Identity {
    Identity::from_pem(node.cert_pem.as_bytes(), node.key_pem.as_bytes())
}

#[tokio::test(flavor = "multi_thread")]
async fn join_token_flow_issues_working_node_svid() {
    let server = start_server().await;

    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    assert_eq!(token.len(), 64, "token is 32 random bytes, hex-encoded");

    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .expect("attestation with a fresh token succeeds");
    assert_eq!(node.spiffe_id, "spiffe://fleet.internal/agent/node-a");
    assert_eq!(node.trust_domain, DOMAIN);
    assert!(node.expires_at > 0);

    heartbeat(&server, identity_of(&node), "node-a")
        .await
        .expect("node SVID authenticates StreamControl");
}

#[tokio::test(flavor = "multi_thread")]
async fn join_token_cannot_be_replayed() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();

    attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();
    let replay = attest_with_join_token(channel(&server, None).await, &token, "node-b").await;
    assert!(
        matches!(replay, Err(JoinError::Rejected(_))),
        "a consumed token must not attest again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_join_token_is_rejected() {
    let server = start_server().await;
    let result = attest_with_join_token(channel(&server, None).await, "not-a-token", "n").await;
    assert!(matches!(result, Err(JoinError::Rejected(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn bound_join_token_only_attests_its_node() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "node-a")
        .await
        .unwrap();

    let wrong = attest_with_join_token(channel(&server, None).await, &token, "node-b").await;
    assert!(matches!(wrong, Err(JoinError::Rejected(_))));

    // The failed attempt must not have burned the token.
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();
    assert!(node.spiffe_id.ends_with("/agent/node-a"));
}

#[tokio::test(flavor = "multi_thread")]
async fn unbound_join_token_cannot_take_over_attested_node() {
    let server = start_server().await;
    let first = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    attest_with_join_token(channel(&server, None).await, &first, "node-a")
        .await
        .unwrap();

    let second = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let takeover = attest_with_join_token(channel(&server, None).await, &second, "node-a").await;
    assert!(
        matches!(takeover, Err(JoinError::Rejected(_))),
        "an unbound token must not mint a second SVID for an attested node"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn node_svid_cannot_speak_for_another_node() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();

    let status = heartbeat(&server, identity_of(&node), "node-b")
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_join_token_requires_admin_bearer_token() {
    let server = start_server().await;

    let anonymous = create_token(&server, None, "").await.unwrap_err();
    assert_eq!(anonymous.code(), tonic::Code::Unauthenticated);

    let wrong = create_token(&server, Some("wrong"), "").await.unwrap_err();
    assert_eq!(wrong.code(), tonic::Code::Unauthenticated);

    let invalid_id = create_token(&server, Some(ADMIN_TOKEN), "../etc")
        .await
        .unwrap_err();
    assert_eq!(invalid_id.code(), tonic::Code::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread")]
async fn node_svid_is_not_admin() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();

    // An attested agent must not be able to mint join tokens for others.
    let mut client = FleetControlClient::new(channel(&server, Some(identity_of(&node))).await);
    let status = client
        .create_join_token(CreateJoinTokenRequest {
            node_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}
