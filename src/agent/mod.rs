pub mod activation;
pub mod exec;
pub mod health;
pub mod logs;
pub mod migrate;
pub mod netns;
pub mod oci;
pub mod snapshot;
pub mod storage;
pub mod supervisor;
pub mod template;

pub mod bootstrap;
pub mod closures;
mod handlers;
mod helpers;
mod types;

pub(crate) use helpers::now_epoch;
pub use helpers::system_hostname;
pub use types::{AgentConfig, NodeIdentity};

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::agent::health::HealthChecker;
use crate::dns::resolver::DnsResolver;
use crate::mesh::peers::PeerManager;
use crate::mesh::wireguard::WireguardManager;
use crate::policy::nftables::PolicyEnforcer;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::{AgentMessage, HealthReport, Heartbeat, StatusReport};
use crate::secrets::injector::SecretInjector;
use crate::spiffe::workload_api::WorkloadManager;

use helpers::collect_resources;
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

    crate::ca::validate_identity_name(&config.node_name)
        .map_err(|e| anyhow::anyhow!("invalid node name: {e}"))?;
    let node_id = config.node_name.clone();
    tracing::info!(node_id = %node_id, "Agent identity established");

    // Establish the node identity: a persisted node SVID for this name, or
    // a fresh one obtained with the join token.
    let mut identity = NodeIdentity::new(&config.data_dir);
    let loaded = identity.load().await;
    if loaded && !identity.certifies_node(&node_id) {
        // Renamed node or copied data dir: never present an SVID under a
        // name it does not certify.
        let certified = identity.spiffe_id.clone().unwrap_or_default();
        if config.join_token.is_none() {
            anyhow::bail!(
                "persisted node SVID {certified} does not match node name '{node_id}'; \
                 re-join with a join token for '{node_id}'"
            );
        }
        tracing::warn!(%certified, "Persisted node SVID is for another name; re-joining");
    }
    if loaded && identity.certifies_node(&node_id) && identity.has_valid_svid() {
        if config.join_token.is_some() {
            tracing::info!("Node SVID present; the join token is not needed and was not used");
        }
    } else {
        let join_hint = format!(
            "create a join token with `ekafleet token create --type agent --node {node_id}` \
             and start the agent with --join-token-file"
        );
        match (&config.join_token, &config.ca_cert_pem) {
            (Some(join_token), Some(ca_pem)) => {
                bootstrap::join(
                    &config.server_addr,
                    ca_pem,
                    &node_id,
                    join_token,
                    &mut identity,
                )
                .await?;
            }
            (Some(_), None) => anyhow::bail!("--ca-cert is required to join the fleet"),
            (None, _) if config.token.is_some() => tracing::warn!(
                "No valid node SVID; authenticating with a bearer token \
                 (accepted only by `ekafleet dev`)"
            ),
            (None, _) if loaded => anyhow::bail!(
                "node SVID expired at {} (Unix time); {join_hint}",
                identity.expires_at
            ),
            (None, _) => {
                anyhow::bail!("no node SVID in {}; {join_hint}", config.data_dir.display())
            }
        }
    }
    let use_mtls = identity.has_valid_svid();
    let node_identity = Arc::new(RwLock::new(identity));

    let channel = if let Some(ca_pem) = &config.ca_cert_pem {
        let endpoint = format!("https://{}", config.server_addr);
        let mut tls_config = bootstrap::tls_config(&config.server_addr, ca_pem);
        if use_mtls {
            let ni = node_identity.read().await;
            if let (Some(cert), Some(key)) = (&ni.cert_pem, &ni.key_pem) {
                tracing::info!("Using node SVID for mTLS authentication");
                tls_config = tls_config.identity(tonic::transport::Identity::from_pem(
                    cert.as_bytes(),
                    key.as_bytes(),
                ));
            }
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

    // With a node SVID, authentication is the TLS client certificate and no
    // metadata is sent. Without one (dev only) the bearer token is attached.
    let bearer: Option<tonic::metadata::MetadataValue<_>> = match &config.token {
        Some(token) if !use_mtls => Some(format!("Bearer {}", token.as_str()).parse()?),
        _ => None,
    };
    let mut client: closures::AgentClient =
        FleetControlClient::with_interceptor(channel, closures::AgentAuth { bearer });

    let local_state = Arc::new(RwLock::new(LocalState::default()));
    // Trust domain starts as default; updated when TrustBundleUpdate is received from server.
    let workload_mgr = Arc::new(WorkloadManager::new(&config.data_dir, "fleet.internal"));
    let pending_keys = Arc::new(RwLock::new(PendingKeyStore::new()));
    let supervisor = Arc::new(RwLock::new(supervisor::Supervisor::new(&config.data_dir)));
    // Re-adopt services this agent was already running before the restart, so
    // orphaned units get reconciled away and unchanged ones are not needlessly
    // restarted when the next DesiredState arrives.
    match supervisor.write().await.adopt_existing_units().await {
        Ok(adopted) if !adopted.is_empty() => {
            tracing::info!(count = adopted.len(), services = ?adopted, "Re-adopted existing service units");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "Failed to re-adopt existing service units"),
    }
    // Secret injector initialized with zeroed key; updated when FleetKeyUpdate is received
    let secret_injector = Arc::new(RwLock::new(SecretInjector::new(
        &config.data_dir,
        &[0u8; 32],
    )));
    let health_checker = HealthChecker::new();
    let dns_resolver = Arc::new(DnsResolver::new("fleet.internal", vec![]));
    let wg_manager = WireguardManager::new("wg-fleet", config.mesh.listen_port);
    let peer_manager = Arc::new(RwLock::new(PeerManager::new(
        wg_manager,
        config.mesh.clone(),
        &config.server_addr,
    )));
    let policy_enforcer = Arc::new(PolicyEnforcer::new());
    let netns_manager = Arc::new(netns::NamespaceNetworkManager::new());

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

    // JWT-SVID requests from the Workload API go out on this connection.
    workload_mgr.jwt_broker().set_sender(tx.clone()).await;

    // Open bidirectional stream
    let response = client.stream_control(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

    // Create a cancellation token for graceful shutdown
    let shutdown = CancellationToken::new();

    // Spawn SPIFFE Workload API socket listener
    let wapi_mgr = workload_mgr.clone();
    let wapi_shutdown = shutdown.child_token();
    tokio::spawn(async move {
        if let Err(e) =
            crate::spiffe::socket::serve_workload_api(wapi_mgr, None, wapi_shutdown).await
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
    let renewal_identity = node_identity.clone();
    let renewal_mtls = use_mtls;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = renewal_shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            if renewal_mtls && renewal_identity.read().await.needs_renewal() {
                helpers::request_node_svid(&renewal_keys, &renewal_tx, &renewal_node_id).await;
            }
            let renewals = renewal_mgr.needs_renewal().await;
            for service_name in renewals {
                helpers::request_service_svid(
                    &renewal_mgr,
                    &renewal_keys,
                    &renewal_tx,
                    &renewal_node_id,
                    &service_name,
                )
                .await;
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
                                &node_identity,
                                &secret_injector,
                                &dns_resolver,
                                &peer_manager,
                                &policy_enforcer,
                                &health_checker,
                                &netns_manager,
                                &tx,
                                &node_id,
                                &client,
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
