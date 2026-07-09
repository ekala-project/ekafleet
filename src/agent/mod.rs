pub mod activation;
pub mod exec;
pub mod health;
pub mod logs;
pub mod migrate;
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
            .connect()
            .await?
    } else {
        // Plaintext fallback (development only)
        tracing::warn!("Connecting without TLS — use --ca-cert in production");
        let endpoint = format!("http://{}", config.server_addr);
        tonic::transport::Endpoint::from_shared(endpoint)?
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

    // Channel for outgoing messages to server
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);

    // Send initial heartbeat
    tx.send(AgentMessage {
        payload: Some(Payload::Heartbeat(Heartbeat {
            node_id: node_id.clone(),
            timestamp: now_epoch(),
            available_resources: Some(collect_resources()),
            pool: String::new(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })),
    })
    .await?;

    // Open bidirectional stream
    let response = client.stream_control(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

    // Spawn SPIFFE Workload API socket listener
    let wapi_mgr = workload_mgr.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::spiffe::socket::serve_workload_api(
            wapi_mgr,
            None,
            b"ekafleet-default-jwt-signing-key",
        )
        .await
        {
            tracing::error!(error = %e, "Workload API socket failed");
        }
    });

    // Spawn heartbeat sender
    let heartbeat_tx = tx.clone();
    let hb_node_id = node_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let msg = AgentMessage {
                payload: Some(Payload::Heartbeat(Heartbeat {
                    node_id: hb_node_id.clone(),
                    timestamp: now_epoch(),
                    available_resources: Some(collect_resources()),
                    pool: String::new(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                })),
            };
            if heartbeat_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn periodic status reporter
    let status_tx = tx.clone();
    let status_node_id = node_id.clone();
    let status_state = local_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let state = status_state.read().await;
            let running = state
                .desired_services
                .iter()
                .map(|(name, spec)| crate::proto::ServiceInstance {
                    service_name: name.clone(),
                    instance_id: format!("{}-{}", name, status_node_id),
                    store_path: spec.store_path.clone(),
                    state: crate::proto::ServiceState::ServiceRunning as i32,
                })
                .collect();
            drop(state);

            let msg = AgentMessage {
                payload: Some(Payload::Status(StatusReport {
                    node_id: status_node_id.clone(),
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
    let renewal_node_id = node_id.clone();
    let renewal_mgr = workload_mgr.clone();
    let renewal_keys = pending_keys.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
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
                                    node_id: renewal_node_id.clone(),
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
    let health_node_id = node_id.clone();
    let health_checker_clone = health_checker.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let services = health_checker_clone.reports(&health_node_id).await;
            if services.is_empty() {
                continue;
            }
            let msg = AgentMessage {
                payload: Some(Payload::Health(HealthReport {
                    node_id: health_node_id.clone(),
                    services,
                })),
            };
            if health_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Process incoming server messages
    while let Some(msg) = inbound.message().await? {
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

    tracing::warn!("Server stream ended");
    Ok(())
}
