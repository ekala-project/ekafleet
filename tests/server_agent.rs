//! Integration tests for the server↔agent gRPC workflow.
//!
//! Tests TLS bootstrapping, bearer token authentication, bidirectional streaming,
//! agent registration, heartbeat processing, and the HTTP health/metrics endpoints.

use std::net::SocketAddr;
use std::time::Duration;

/// Find an available TCP port by binding to port 0.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Start the server in background, returning (grpc_addr, http_addr, ca_cert_pem, token).
async fn start_server() -> (SocketAddr, SocketAddr, String, String) {
    let grpc_port = free_port();
    let http_port = free_port();
    let grpc_addr: SocketAddr = format!("127.0.0.1:{grpc_port}").parse().unwrap();
    let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();

    let _dir = tempfile::tempdir().unwrap();
    let token = "integration-test-token".to_string();

    use ekafleet::proto::fleet_control_server::FleetControlServer;

    // Initialize CA
    let ca = ekafleet::ca::root::RootCa::new("fleet.internal");
    ca.initialize(None, None).await.unwrap();

    let ca_cert_pem = ca.root_certificate_pem().await.unwrap();

    // Issue server cert
    let (server_cert_pem, _chain_pem, _) = ca
        .issue_certificate("ekafleet-server", &[], None)
        .await
        .unwrap();
    let cert_pem_str = String::from_utf8(server_cert_pem).unwrap();

    // Build TLS identity
    let identity =
        tonic::transport::Identity::from_pem(cert_pem_str.as_bytes(), cert_pem_str.as_bytes());
    let tls_config = tonic::transport::ServerTlsConfig::new().identity(identity);

    let fleet_state = ekafleet::server::state::FleetState::new();
    let service = ekafleet::server::api::FleetControlService::new(fleet_state.clone());

    let expected_token = format!("Bearer {token}");
    #[allow(clippy::result_large_err)]
    let interceptor = move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
        match req.metadata().get("authorization") {
            Some(val) if val == expected_token.as_str() => Ok(req),
            Some(_) => Err(tonic::Status::unauthenticated("invalid token")),
            None => Err(tonic::Status::unauthenticated(
                "missing authorization header",
            )),
        }
    };

    // Start gRPC server
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(FleetControlServer::with_interceptor(service, interceptor))
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    // Start HTTP server
    let http_token = token.clone();
    tokio::spawn(async move {
        use axum::Router;
        use axum::extract::State;
        use axum::http::StatusCode;
        use axum::routing::get;

        let authenticated = Router::new().route("/metrics", get(|| async { "" })).layer(
            axum::middleware::from_fn_with_state(
                http_token.clone(),
                |State(expected): State<String>,
                 req: axum::http::Request<axum::body::Body>,
                 next: axum::middleware::Next| async move {
                    let expected_header = format!("Bearer {expected}");
                    match req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                    {
                        Some(val) if val == expected_header => Ok(next.run(req).await),
                        _ => Err(StatusCode::UNAUTHORIZED),
                    }
                },
            ),
        );

        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .merge(authenticated);

        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // Wait for servers to bind
    tokio::time::sleep(Duration::from_millis(200)).await;

    (grpc_addr, http_addr, ca_cert_pem, token)
}

/// Create a gRPC client channel with TLS and bearer token.
async fn connect_client(
    grpc_addr: SocketAddr,
    ca_cert_pem: &str,
    token: &str,
) -> ekafleet::proto::fleet_control_client::FleetControlClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        impl FnMut(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status>,
    >,
> {
    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let ca_cert = tonic::transport::Certificate::from_pem(ca_cert_pem);
    let tls_config = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("ekafleet-server");

    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .tls_config(tls_config)
        .unwrap()
        .connect()
        .await
        .unwrap();

    let token_val: tonic::metadata::MetadataValue<_> = format!("Bearer {token}").parse().unwrap();

    #[allow(clippy::result_large_err)]
    ekafleet::proto::fleet_control_client::FleetControlClient::with_interceptor(
        channel,
        move |mut req: tonic::Request<()>| {
            req.metadata_mut()
                .insert("authorization", token_val.clone());
            Ok(req)
        },
    )
}

// ─── Server startup & CA bootstrapping ──────────────────────────────

#[tokio::test]
async fn server_generates_ca_and_starts_tls() {
    let (_grpc, _http, ca_cert_pem, _token) = start_server().await;

    // CA cert should be valid PEM
    assert!(ca_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(ca_cert_pem.len() > 200);
}

// ─── HTTP endpoints ─────────────────────────────────────────────────

#[tokio::test]
async fn health_endpoint_is_public() {
    let (_grpc, http_addr, _, _token) = start_server().await;

    let resp = reqwest::get(format!("http://{http_addr}/health"))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn metrics_endpoint_requires_auth() {
    let (_grpc, http_addr, _, _token) = start_server().await;

    // Without auth → 401
    let resp = reqwest::get(format!("http://{http_addr}/metrics"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn metrics_endpoint_accepts_valid_token() {
    let (_grpc, http_addr, _, token) = start_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{http_addr}/metrics"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn metrics_endpoint_rejects_wrong_token() {
    let (_grpc, http_addr, _, _token) = start_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{http_addr}/metrics"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ─── gRPC authentication ────────────────────────────────────────────

#[tokio::test]
async fn grpc_rejects_unauthenticated_client() {
    let (grpc_addr, _, ca_cert_pem, _token) = start_server().await;

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let ca_cert = tonic::transport::Certificate::from_pem(&ca_cert_pem);
    let tls_config = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("ekafleet-server");

    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .tls_config(tls_config)
        .unwrap()
        .connect()
        .await
        .unwrap();

    // No auth interceptor — raw client
    let mut client = ekafleet::proto::fleet_control_client::FleetControlClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(ekafleet::proto::AgentMessage {
        payload: Some(ekafleet::proto::agent_message::Payload::Heartbeat(
            ekafleet::proto::Heartbeat {
                node_id: "test-node".into(),
                timestamp: 0,
                available_resources: None,
            },
        )),
    })
    .await
    .unwrap();
    drop(tx);

    let result = client
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await;

    assert!(result.is_err(), "unauthenticated request must be rejected");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn grpc_rejects_wrong_token() {
    let (grpc_addr, _, ca_cert_pem, _token) = start_server().await;

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let ca_cert = tonic::transport::Certificate::from_pem(&ca_cert_pem);
    let tls_config = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("ekafleet-server");

    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .tls_config(tls_config)
        .unwrap()
        .connect()
        .await
        .unwrap();

    let bad_token: tonic::metadata::MetadataValue<_> = "Bearer wrong-token".parse().unwrap();

    #[allow(clippy::result_large_err)]
    let mut client = ekafleet::proto::fleet_control_client::FleetControlClient::with_interceptor(
        channel,
        move |mut req: tonic::Request<()>| {
            req.metadata_mut()
                .insert("authorization", bad_token.clone());
            Ok(req)
        },
    );

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(ekafleet::proto::AgentMessage {
        payload: Some(ekafleet::proto::agent_message::Payload::Heartbeat(
            ekafleet::proto::Heartbeat {
                node_id: "test".into(),
                timestamp: 0,
                available_resources: None,
            },
        )),
    })
    .await
    .unwrap();
    drop(tx);

    let result = client
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

// ─── gRPC bidirectional streaming ───────────────────────────────────

#[tokio::test]
async fn agent_connects_and_registers_via_heartbeat() {
    let (grpc_addr, _, ca_cert_pem, token) = start_server().await;
    let mut client = connect_client(grpc_addr, &ca_cert_pem, &token).await;

    let (tx, rx) = tokio::sync::mpsc::channel(16);

    // Send initial heartbeat
    tx.send(ekafleet::proto::AgentMessage {
        payload: Some(ekafleet::proto::agent_message::Payload::Heartbeat(
            ekafleet::proto::Heartbeat {
                node_id: "test-node-1".into(),
                timestamp: 1000,
                available_resources: Some(ekafleet::proto::NodeResources {
                    cpu_millicores: 4000,
                    memory_mb: 8192,
                    disk_mb: 100000,
                }),
            },
        )),
    })
    .await
    .unwrap();

    // Open the stream
    let response = client
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await;

    assert!(response.is_ok(), "authenticated stream must succeed");

    // Keep the stream alive briefly then drop
    drop(tx);
}

#[tokio::test]
async fn stream_requires_heartbeat_or_status_first() {
    let (grpc_addr, _, ca_cert_pem, token) = start_server().await;
    let mut client = connect_client(grpc_addr, &ca_cert_pem, &token).await;

    let (tx, rx) = tokio::sync::mpsc::channel(1);

    // Send a metrics message first (not heartbeat or status)
    tx.send(ekafleet::proto::AgentMessage {
        payload: Some(ekafleet::proto::agent_message::Payload::Metrics(
            ekafleet::proto::MetricsSummary {
                node_id: "test".into(),
                points: vec![],
            },
        )),
    })
    .await
    .unwrap();
    drop(tx);

    let result = client
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await;

    // Should fail because first message must be heartbeat or status
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn status_rpc_returns_fleet_info() {
    let (grpc_addr, _, ca_cert_pem, token) = start_server().await;
    let mut client = connect_client(grpc_addr, &ca_cert_pem, &token).await;

    let resp = client
        .status(ekafleet::proto::StatusRequest {})
        .await
        .unwrap();

    let status = resp.into_inner();
    assert_eq!(status.fleet_name, "ekafleet");
}

// ─── Server CA persistence ──────────────────────────────────────────

#[tokio::test]
async fn server_persists_ca_to_disk() {
    let dir = tempfile::tempdir().unwrap();

    let ca = ekafleet::ca::root::RootCa::new("fleet.internal");
    ca.initialize(None, None).await.unwrap();

    let key_pem = ca.root_key_pem().await.unwrap();
    let cert_pem = ca.root_certificate_pem().await.unwrap();

    let key_path = dir.path().join("ca-key.pem");
    let cert_path = dir.path().join("ca-cert.pem");

    tokio::fs::write(&key_path, &key_pem).await.unwrap();
    tokio::fs::write(&cert_path, &cert_pem).await.unwrap();

    // Load from disk into new CA
    let ca2 = ekafleet::ca::root::RootCa::new("fleet.internal");
    let loaded_key = tokio::fs::read_to_string(&key_path).await.unwrap();
    let loaded_cert = tokio::fs::read_to_string(&cert_path).await.unwrap();
    ca2.initialize(Some(&loaded_key), Some(&loaded_cert))
        .await
        .unwrap();

    // Issue a cert with the loaded CA
    let result = ca2.issue_certificate("test-svc", b"csr", None).await;
    assert!(result.is_ok(), "CA loaded from disk must be functional");

    // The cert PEM should match
    assert_eq!(
        ca2.root_certificate_pem().await.unwrap(),
        cert_pem,
        "loaded cert must match original"
    );
}

// ─── End-to-end secret encryption chain ─────────────────────────────

#[tokio::test]
async fn secret_encrypt_transmit_decrypt_chain() {
    // Simulate the full secret lifecycle:
    // 1. Server encrypts secret
    // 2. Sealed data transmitted (e.g., via gRPC SecretUpdate)
    // 3. Agent decrypts and writes to disk

    let key = [0x42u8; 32];
    let plaintext = b"postgres://user:pass@db:5432/mydb";

    // Server side: encrypt
    let store = ekafleet::secrets::store::SecretStore::new(&key);
    store
        .put("my-app", "DATABASE_URL", plaintext)
        .await
        .unwrap();

    // Get the encrypted value (as would be sent in SecretUpdate)
    let sealed_secrets = store.secrets_for_services(&["my-app".into()]).await;
    assert_eq!(sealed_secrets.len(), 1);

    let (_svc, _name, encrypted_value, version) = &sealed_secrets[0];
    assert_ne!(
        encrypted_value,
        &plaintext.to_vec(),
        "must be encrypted in transit"
    );

    // Agent side: decrypt and inject
    let dir = tempfile::tempdir().unwrap();
    let mut injector = ekafleet::secrets::injector::SecretInjector::new(dir.path(), &key);
    let path = injector
        .inject("my-app", "DATABASE_URL", encrypted_value, *version)
        .await
        .unwrap();

    // Verify the file contains the original plaintext
    let on_disk = tokio::fs::read(&path).await.unwrap();
    assert_eq!(on_disk, plaintext, "decrypted secret must match original");

    // Verify file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o400);
    }
}
