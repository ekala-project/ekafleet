pub mod activation;
pub mod exec;
pub mod health;
pub mod logs;
pub mod migrate;
pub mod oci;
pub mod snapshot;
pub mod storage;
pub mod supervisor;
pub mod template;

mod handlers;
mod helpers;
mod types;

pub(crate) use helpers::now_epoch;
pub use types::{AgentConfig, NodeIdentity};

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::agent::health::HealthChecker;
use crate::ca::csr;
use crate::dns::resolver::DnsResolver;
use crate::mesh::peers::PeerManager;
use crate::mesh::wireguard::WireguardManager;
use crate::policy::nftables::PolicyEnforcer;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::{AgentMessage, CertificateRequest, HealthReport, Heartbeat, StatusReport};
use crate::secrets::injector::SecretInjector;
use crate::spiffe::workload_api::WorkloadManager;

use helpers::{collect_resources, get_node_id};
use types::{LocalState, PendingKeyStore};

pub async fn run(config: AgentConfig) -> anyhow::Result<()> {
    // Validate server address format before connecting
    config
        .server_addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("invalid server address '{}': {e}", config.server_addr))?;

    tracing::info!(
        server = %config.server_addr,
        data_dir = %config.data_dir.display(),
        "Starting ekafleet agent"
    );

    let node_id = get_node_id(&config.data_dir)?;
    tracing::info!(node_id = %node_id, "Agent identity established");

    // Load or prepare node SVID for mTLS
    let node_identity = Arc::new(RwLock::new(NodeIdentity::new(&config.data_dir)));
    {
        let mut ni = node_identity.write().await;
        if ni.load().await {
            tracing::info!("Node SVID loaded from disk");
        } else {
            tracing::info!("No persisted node SVID — will use bearer token auth");
        }
    }

    // Determine authentication mode: mTLS (node SVID) or bearer token
    let ni = node_identity.read().await;
    let use_mtls = ni.has_valid_svid();
    let node_cert_pem = ni.cert_pem.clone();
    let node_key_pem = ni.key_pem.clone();
    drop(ni);

    let channel = if let Some(ca_pem) = &config.ca_cert_pem {
        let endpoint = format!("https://{}", config.server_addr);
        let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
        let mut tls_config = tonic::transport::ClientTlsConfig::new().ca_certificate(ca_cert);

        // When connecting by IP address, override TLS hostname verification.
        // The CA cert already validates the server's identity chain.
        if config.server_addr.starts_with(|c: char| c.is_ascii_digit()) {
            tls_config = tls_config.domain_name("ekafleet");
        }

        // Use node SVID for mTLS if available
        if use_mtls && let (Some(cert), Some(key)) = (&node_cert_pem, &node_key_pem) {
            tracing::info!("Using node SVID for mTLS authentication");
            let identity = tonic::transport::Identity::from_pem(cert.as_bytes(), key.as_bytes());
            tls_config = tls_config.identity(identity);
        }

        tonic::transport::Endpoint::from_shared(endpoint)?
            .tls_config(tls_config)?
            .http2_keep_alive_interval(Duration::from_secs(20))
            .keep_alive_timeout(Duration::from_secs(10))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .connect()
            .await?
    } else {
        // Plaintext fallback (development only)
        tracing::warn!("Connecting without TLS — use --ca-cert in production");
        let endpoint = format!("http://{}", config.server_addr);
        tonic::transport::Endpoint::from_shared(endpoint)?
            .http2_keep_alive_interval(Duration::from_secs(20))
            .keep_alive_timeout(Duration::from_secs(10))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .connect()
            .await?
    };

    // Attach authentication metadata to all outgoing requests
    let token: tonic::metadata::MetadataValue<_> = format!("Bearer {}", config.token).parse()?;
    let mtls_flag = use_mtls;
    #[allow(clippy::result_large_err)]
    let mut client =
        FleetControlClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            if mtls_flag {
                // mTLS authenticated — signal to server interceptor
                req.metadata_mut()
                    .insert("x-ekafleet-mtls", "true".parse().unwrap());
            } else {
                // Legacy bearer token auth
                req.metadata_mut().insert("authorization", token.clone());
            }
            Ok(req)
        });

    let local_state = Arc::new(RwLock::new(LocalState::default()));
    // Trust domain starts as default; updated when TrustBundleUpdate is received from server.
    let workload_mgr = Arc::new(WorkloadManager::new(&config.data_dir, "fleet.internal"));
    let pending_keys = Arc::new(RwLock::new(PendingKeyStore::new()));
    let supervisor = Arc::new(RwLock::new(supervisor::Supervisor::new(&config.data_dir)));
    // Secret injector initialized with zeroed key; updated when FleetKeyUpdate is received
    let secret_injector = Arc::new(RwLock::new(SecretInjector::new(
        &config.data_dir,
        &[0u8; 32],
    )));
    let health_checker = HealthChecker::new();
    let dns_resolver = Arc::new(DnsResolver::new("fleet.internal", vec![]));
    let wg_manager = WireguardManager::new("wg-fleet", 51820);
    let peer_manager = Arc::new(RwLock::new(PeerManager::new(wg_manager)));
    let policy_enforcer = Arc::new(PolicyEnforcer::new());

    // Pre-allocate strings used in every heartbeat to avoid per-tick allocations
    let version: Arc<str> = Arc::from(env!("CARGO_PKG_VERSION"));

    // Channel for outgoing messages to server
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);

    // Send initial heartbeat
    tx.send(AgentMessage {
        payload: Some(Payload::Heartbeat(Heartbeat {
            node_id: node_id.clone(),
            timestamp: now_epoch(),
            available_resources: Some(collect_resources()),
            pool: String::new(),
            version: version.to_string(),
        })),
    })
    .await?;

    // Open bidirectional stream
    let response = client.stream_control(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

    // Create a cancellation token for graceful shutdown
    let shutdown = CancellationToken::new();

    // Spawn SPIFFE Workload API socket listener
    let wapi_mgr = workload_mgr.clone();
    let wapi_shutdown = shutdown.child_token();
    tokio::spawn(async move {
        if let Err(e) = crate::spiffe::socket::serve_workload_api(
            wapi_mgr,
            None,
            b"ekafleet-default-jwt-signing-key",
            wapi_shutdown,
        )
        .await
        {
            tracing::error!(error = %e, "Workload API socket failed");
        }
    });

    // Spawn heartbeat sender
    let heartbeat_tx = tx.clone();
    let hb_node_id: Arc<str> = Arc::from(node_id.as_str());
    let hb_version = version.clone();
    let hb_shutdown = shutdown.child_token();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = hb_shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let msg = AgentMessage {
                payload: Some(Payload::Heartbeat(Heartbeat {
                    node_id: hb_node_id.to_string(),
                    timestamp: now_epoch(),
                    available_resources: Some(collect_resources()),
                    pool: String::new(),
                    version: hb_version.to_string(),
                })),
            };
            if heartbeat_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn periodic status reporter
    let status_tx = tx.clone();
    let status_node_id: Arc<str> = Arc::from(node_id.as_str());
    let status_state = local_state.clone();
    let status_supervisor = supervisor.clone();
    let status_shutdown = shutdown.child_token();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = status_shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let state = status_state.read().await;
            let service_list: Vec<(String, String)> = state
                .desired_services
                .iter()
                .map(|(name, spec)| (name.clone(), spec.store_path.clone()))
                .collect();
            drop(state);

            // Query actual systemd state for each service
            let sv = status_supervisor.read().await;
            let mut running = Vec::with_capacity(service_list.len());
            for (name, store_path) in &service_list {
                let actual_state = sv.service_state(name).await;
                running.push(crate::proto::ServiceInstance {
                    service_name: name.clone(),
                    instance_id: format!("{}-{}", name, status_node_id),
                    store_path: store_path.clone(),
                    state: actual_state as i32,
                });
            }
            drop(sv);

            let msg = AgentMessage {
                payload: Some(Payload::Status(StatusReport {
                    node_id: status_node_id.to_string(),
                    running_services: running,
                    current_system_path: String::new(),
                })),
            };
            if status_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn SVID renewal checker
    let renewal_tx = tx.clone();
    let renewal_node_id: Arc<str> = Arc::from(node_id.as_str());
    let renewal_mgr = workload_mgr.clone();
    let renewal_keys = pending_keys.clone();
    let renewal_shutdown = shutdown.child_token();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = renewal_shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let renewals = renewal_mgr.needs_renewal().await;
            for service_name in renewals {
                tracing::info!(service = %service_name, "Requesting SVID renewal");
                // Get current trust domain for CSR generation
                let trust_domain = renewal_mgr
                    .trust_domain_str()
                    .await
                    .unwrap_or_else(|| "fleet.internal".to_string());
                match csr::generate_service_csr(&trust_domain, &service_name) {
                    Ok(csr_output) => {
                        renewal_keys
                            .write()
                            .await
                            .store(&service_name, csr_output.keypair);
                        let _ = renewal_tx
                            .send(AgentMessage {
                                payload: Some(Payload::CertRequest(CertificateRequest {
                                    node_id: renewal_node_id.to_string(),
                                    service_name,
                                    csr: csr_output.csr_der,
                                    request_type: crate::proto::CertRequestType::ServiceCert as i32,
                                })),
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::error!(
                            service = %service_name,
                            error = %e,
                            "CSR generation failed"
                        );
                    }
                }
            }
        }
    });

    // Spawn periodic health reporter
    let health_tx = tx.clone();
    let health_node_id: Arc<str> = Arc::from(node_id.as_str());
    let health_checker_clone = health_checker.clone();
    let health_shutdown = shutdown.child_token();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = health_shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let services = health_checker_clone.reports(&health_node_id).await;
            if services.is_empty() {
                continue;
            }
            let msg = AgentMessage {
                payload: Some(Payload::Health(HealthReport {
                    node_id: health_node_id.to_string(),
                    services,
                })),
            };
            if health_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Process incoming server messages until stream ends or shutdown
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("Agent shutting down");
                break;
            }
            result = inbound.message() => {
                match result? {
                    Some(msg) => {
                        if let Some(payload) = msg.payload {
                            handlers::handle_server_message(
                                payload,
                                &supervisor,
                                &local_state,
                                &workload_mgr,
                                &pending_keys,
                                &secret_injector,
                                &dns_resolver,
                                &peer_manager,
                                &policy_enforcer,
                                &health_checker,
                                &tx,
                                &node_id,
                            )
                            .await;
                        }
                    }
                    None => {
                        tracing::warn!("Server stream ended");
                        shutdown.cancel();
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
