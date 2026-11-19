//! Node join workflow against the production server (`server::run`, the
//! real TLS config and authentication interceptor):
//!
//! operator creates a name-bound join token → agent attests over TLS with
//! no client certificate → node SVID → mTLS control stream → node SVID
//! renewal over the stream. Bearer-token agents are refused.

use std::net::SocketAddr;
use std::time::Duration;

use ekafleet::proto::agent_message::Payload;
use ekafleet::proto::fleet_bootstrap_client::FleetBootstrapClient;
use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::server_message::Payload as ServerPayload;
use ekafleet::proto::{
    AgentMessage, CertRequestType, CertificateRequest, CreateJoinTokenRequest, Heartbeat,
    NodeAttestationRequest, StatusRequest,
};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity};

const ADMIN_TOKEN: &str = "workflow-admin-token";
const DOMAIN: &str = "workflow.test";

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Server {
    grpc: SocketAddr,
    ca_pem: String,
    _dir: tempfile::TempDir,
}

/// Boot `ekafleet server` in-process and wait until it serves TLS.
async fn start_server() -> Server {
    start_server_with(None).await
}

async fn start_server_with(
    embedded_agent: Option<ekafleet::server::EmbeddedAgentConfig>,
) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let grpc = free_addr();
    let config = ekafleet::server::ServerConfig {
        data_dir: dir.path().to_path_buf(),
        peers: Vec::new(),
        grpc_listen: grpc.to_string(),
        http_listen: free_addr().to_string(),
        token: ADMIN_TOKEN.into(),
        domain: DOMAIN.into(),
        ca_socket: None,
        allow_bearer_agents: false,
        embedded_agent,
        federation_listen: None,
    };
    tokio::spawn(async move {
        if let Err(e) = ekafleet::server::run(config).await {
            panic!("server exited: {e:#}");
        }
    });

    let ca_path = dir.path().join("ca-cert.pem");
    for _ in 0..200 {
        if let Ok(ca_pem) = std::fs::read_to_string(&ca_path)
            && tokio::net::TcpStream::connect(grpc).await.is_ok()
        {
            return Server {
                grpc,
                ca_pem,
                _dir: dir,
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not start");
}

impl Server {
    fn tls(&self) -> ClientTlsConfig {
        ekafleet::agent::bootstrap::tls_config(&self.grpc.to_string(), &self.ca_pem)
    }

    async fn channel(&self, tls: ClientTlsConfig) -> Channel {
        Endpoint::from_shared(format!("https://{}", self.grpc))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    /// The CLI's connection: server-authenticated TLS plus a bearer token,
    /// no client certificate.
    async fn admin(
        &self,
    ) -> FleetControlClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl tonic::service::Interceptor + use<>,
        >,
    > {
        let channel = self.channel(self.tls()).await;
        #[allow(clippy::result_large_err)]
        FleetControlClient::with_interceptor(channel, |mut req: tonic::Request<()>| {
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {ADMIN_TOKEN}").parse().unwrap(),
            );
            Ok(req)
        })
    }

    async fn join_token(&self, node: &str) -> String {
        self.admin()
            .await
            .create_join_token(CreateJoinTokenRequest {
                node_name: node.into(),
                ttl_secs: 0,
            })
            .await
            .unwrap()
            .into_inner()
            .token
    }
}

fn heartbeat(node: &str) -> AgentMessage {
    AgentMessage {
        payload: Some(Payload::Heartbeat(Heartbeat {
            node_id: node.into(),
            ..Default::default()
        })),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn bearer_cli_works_without_a_client_certificate() {
    let server = start_server().await;
    let status = server.admin().await.status(StatusRequest {}).await;
    assert!(status.is_ok(), "{status:?}");
}

#[tokio::test]
async fn bearer_agents_are_refused_outside_dev_mode() {
    let server = start_server().await;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(heartbeat("web-1")).await.unwrap();
    let err = server
        .admin()
        .await
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert!(err.message().contains("node SVID"));
}

#[tokio::test]
async fn join_tokens_require_manage_tokens_and_a_valid_name() {
    let server = start_server().await;
    let err = server
        .admin()
        .await
        .create_join_token(CreateJoinTokenRequest {
            node_name: "../server/x".into(),
            ttl_secs: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Unauthenticated callers cannot create join tokens.
    let channel = server.channel(server.tls()).await;
    let err = FleetControlClient::new(channel)
        .create_join_token(CreateJoinTokenRequest {
            node_name: "web-1".into(),
            ttl_secs: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn attest_refuses_bad_tokens_names_and_csrs_without_burning_the_token() {
    let server = start_server().await;
    let token = server.join_token("web-1").await;
    let mut bootstrap = FleetBootstrapClient::new(server.channel(server.tls()).await);
    let csr = ekafleet::ca::csr::generate_node_csr(None, "web-1").unwrap();
    let request = |token: &str, name: &str, csr: Vec<u8>| NodeAttestationRequest {
        attestation_type: "join_token".into(),
        attestation_data: token.as_bytes().to_vec(),
        csr,
        node_name: name.into(),
    };

    for (req, why) in [
        (
            request("not-a-token", "web-1", csr.csr_der.clone()),
            "unknown",
        ),
        (
            request(&token, "web-2", csr.csr_der.clone()),
            "different node",
        ),
        (request(&token, "web-1", b"garbage".to_vec()), "invalid CSR"),
    ] {
        let result = bootstrap.attest(req).await.unwrap().into_inner();
        assert!(!result.success, "{why}");
        assert!(
            result.error_message.contains(why),
            "{}",
            result.error_message
        );
        assert!(result.node_certificate.is_empty());
    }

    // None of the above consumed the token.
    let ok = bootstrap
        .attest(request(&token, "web-1", csr.csr_der.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(ok.success, "{}", ok.error_message);
    assert_eq!(ok.node_spiffe_id, format!("spiffe://{DOMAIN}/agent/web-1"));
    // 24h node SVID.
    assert!(ok.expires_at > now() + 23 * 3600 && ok.expires_at <= now() + 24 * 3600 + 60);

    let replay = bootstrap
        .attest(request(&token, "web-1", csr.csr_der))
        .await
        .unwrap()
        .into_inner();
    assert!(!replay.success);
    assert!(replay.error_message.contains("already used"));
}

#[tokio::test]
async fn joined_agent_streams_over_mtls_and_renews_its_svid() {
    let server = start_server().await;
    let token = server.join_token("web-1").await;

    // The agent's own join path: key + CSR locally, attest, verify, persist.
    let agent_dir = tempfile::tempdir().unwrap();
    let mut identity = ekafleet::agent::NodeIdentity::new(agent_dir.path());
    ekafleet::agent::bootstrap::join(
        &server.grpc.to_string(),
        &server.ca_pem,
        "web-1",
        &token,
        &mut identity,
    )
    .await
    .unwrap();
    assert!(identity.has_valid_svid());
    assert!(identity.certifies_node("web-1"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = agent_dir.path().join("node-svid-key.pem");
        let mode = std::fs::metadata(key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o400);
    }

    // A restart loads the same identity from disk.
    let mut reloaded = ekafleet::agent::NodeIdentity::new(agent_dir.path());
    assert!(reloaded.load().await);
    assert_eq!(reloaded.spiffe_id, identity.spiffe_id);

    let cert = identity.cert_pem.clone().unwrap();
    let key = identity.key_pem.clone().unwrap();
    let mtls = server
        .channel(
            server
                .tls()
                .identity(Identity::from_pem(cert.as_bytes(), key.as_bytes())),
        )
        .await;

    // The SVID names the node: claiming another name is refused.
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(heartbeat("web-2")).await.unwrap();
    let err = FleetControlClient::new(mtls.clone())
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // An agent SVID is not a CLI credential.
    let err = FleetControlClient::new(mtls.clone())
        .create_join_token(CreateJoinTokenRequest {
            node_name: "web-9".into(),
            ttl_secs: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(heartbeat("web-1")).await.unwrap();
    let mut inbound = FleetControlClient::new(mtls)
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    // Renew the node SVID with a fresh key over the stream.
    let renewal = ekafleet::ca::csr::generate_node_csr(None, "web-1").unwrap();
    tx.send(AgentMessage {
        payload: Some(Payload::CertRequest(CertificateRequest {
            node_id: String::new(),
            service_name: String::new(),
            csr: renewal.csr_der,
            request_type: CertRequestType::NodeCert as i32,
        })),
    })
    .await
    .unwrap();

    let renewed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let msg = inbound.message().await.unwrap().expect("stream open");
            if let Some(ServerPayload::Cert(cert)) = msg.payload {
                return cert;
            }
        }
    })
    .await
    .expect("renewed node SVID");
    assert_eq!(renewed.request_type, CertRequestType::NodeCert as i32);
    let renewed_pem = String::from_utf8(renewed.certificate).unwrap();
    assert_eq!(
        ekafleet::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&renewed_pem)
            .as_deref(),
        Some(format!("spiffe://{DOMAIN}/agent/web-1").as_str())
    );
    let (_, parsed) = x509_parser::pem::parse_x509_pem(renewed_pem.as_bytes()).unwrap();
    let parsed = parsed.parse_x509().unwrap();
    assert_eq!(
        parsed.public_key().subject_public_key.data.as_ref(),
        renewal.keypair.public_key_raw()
    );
}

#[tokio::test]
async fn embedded_agent_joins_its_own_server_with_a_node_svid() {
    let agent_dir = tempfile::tempdir().unwrap();
    let server = start_server_with(Some(ekafleet::server::EmbeddedAgentConfig {
        node_name: "embedded".into(),
        data_dir: agent_dir.path().to_path_buf(),
        mesh: ekafleet::mesh::peers::MeshSettings {
            enabled: false,
            ..Default::default()
        },
        dns: ekafleet::dns::agent::DnsSettings::disabled(),
    }))
    .await;

    let mut admin = server.admin().await;
    let mut connected = false;
    for _ in 0..100 {
        let status = admin.status(StatusRequest {}).await.unwrap().into_inner();
        if status.nodes.iter().any(|n| n.node_id == "embedded") {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(connected, "the embedded agent never connected");

    // It joined with a node SVID for its name, persisted for restarts.
    let cert = std::fs::read_to_string(agent_dir.path().join("node-svid.pem")).unwrap();
    let mut reader = std::io::BufReader::new(cert.as_bytes());
    let der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
    assert_eq!(
        ekafleet::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_der(&der).as_deref(),
        Some(format!("spiffe://{DOMAIN}/agent/embedded").as_str())
    );
}
