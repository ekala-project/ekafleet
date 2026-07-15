mod agent_msg;
pub mod api;
mod api_system;
pub mod audit;
pub mod cloud;
pub mod deployer;
pub mod events;
pub mod federation;
pub mod namespace;
pub mod nix;
pub mod policy;
pub mod quota;
pub mod rbac;
pub mod rebalance;
pub mod reconciler;
pub mod rest;
pub mod scaling;
pub mod scheduler;
pub mod state;
pub mod webhook;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use state::FleetState;
use tokio_util::sync::CancellationToken;

use crate::attestation::join_token::JoinTokenStore;
use crate::ca::CaSigner;
use crate::ca::issuer::CertIssuer;
use crate::ca::root::RootCa;
use crate::ca::signer::{DirectCaSigner, RemoteCaSigner};
use crate::raft::state::FleetStateMachine;

pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub peers: Vec<String>,
    pub grpc_listen: String,
    pub http_listen: String,
    pub token: String,
    /// Trust domain for SPIFFE identities (e.g., "fleet.internal").
    pub domain: String,
    /// Path to a CA signer Unix socket. When set, the server connects to
    /// an external `ca-signer` daemon instead of loading the CA key in-process.
    pub ca_socket: Option<PathBuf>,
}

pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    tracing::info!(
        data_dir = %config.data_dir.display(),
        peers = ?config.peers,
        grpc = %config.grpc_listen,
        http = %config.http_listen,
        ca_socket = ?config.ca_socket,
        "Starting ekafleet server"
    );

    let grpc_addr = config.grpc_listen.parse()?;
    let http_addr = config.http_listen.parse()?;

    // Build the CA signer — either in-process or remote
    let ca: Arc<dyn CaSigner> = if let Some(socket_path) = &config.ca_socket {
        tracing::info!(socket = %socket_path.display(), "Using remote CA signer");
        Arc::new(RemoteCaSigner::new(socket_path))
    } else {
        tracing::info!("Using in-process CA (embedded mode)");
        let root_ca = RootCa::new(&config.domain);

        let ca_key_path = config.data_dir.join("ca-key.pem");
        let ca_cert_path = config.data_dir.join("ca-cert.pem");

        let (stored_key, stored_cert) = match (
            tokio::fs::read_to_string(&ca_key_path).await,
            tokio::fs::read_to_string(&ca_cert_path).await,
        ) {
            (Ok(key), Ok(cert)) => (Some(key), Some(cert)),
            _ => (None, None),
        };

        root_ca
            .initialize(stored_key.as_deref(), stored_cert.as_deref())
            .await?;

        // Persist CA key and cert if newly generated
        if stored_key.is_none()
            && let (Some(key_pem), Some(cert_pem)) = (
                root_ca.root_key_pem().await,
                root_ca.root_certificate_pem().await,
            )
        {
            tokio::fs::create_dir_all(&config.data_dir).await?;
            tokio::fs::write(&ca_key_path, &key_pem).await?;
            tokio::fs::write(&ca_cert_path, &cert_pem).await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                tokio::fs::set_permissions(&ca_key_path, perms).await?;
            }

            tracing::info!("CA key and certificate persisted to disk");
        }

        Arc::new(DirectCaSigner::new(root_ca))
    };

    // Generate or load server identity
    let server_id = get_server_id(&config.data_dir)?;
    tracing::info!(server_id = %server_id, domain = %config.domain, "Server identity established");

    // Issue a server SVID for gRPC TLS: spiffe://<domain>/server/<server-id>
    let (server_cert_pem, ca_chain_pem, _expires_at) = ca.issue_server_svid(&server_id).await?;

    let tls = api::TlsConfig {
        cert_pem: String::from_utf8(server_cert_pem)?,
        ca_cert_pem: String::from_utf8(ca_chain_pem)?,
    };

    // Initialize certificate issuer for SPIFFE SVID issuance
    let cert_issuer = CertIssuer::new(ca.clone());

    let trust_bundle_pem = ca.trust_bundle_pem().await?;

    // Generate or load fleet encryption key for secret distribution
    let fleet_key = get_or_create_fleet_key(&config.data_dir)?;

    let fleet_state = FleetState::new();
    let event_store = events::EventStore::new();
    let metrics = crate::metrics::aggregator::MetricsAggregator::new();
    let alert_evaluator = crate::metrics::alerting::AlertEvaluator::new();

    // Initialize RBAC token store with persistence and load any saved tokens
    let token_store = rbac::TokenStore::with_persistence(&config.data_dir);
    if let Err(e) = token_store.load().await {
        tracing::warn!(error = %e, "Failed to load persisted tokens, starting fresh");
    }
    token_store
        .register(&config.token, rbac::Role::Admin, "initial admin token")
        .await;

    // Initialize Raft state machine and cloud infrastructure.
    // The ScalingActuator is started later when a fleet config is available
    // (via `ekafleet apply --watch`), since it needs the pool/cloud configuration
    // from the evaluated Nix config. See cloud::actuator::ScalingActuator.
    let raft_state = FleetStateMachine::new();
    let instance_tracker = cloud::instance_tracker::InstanceTracker::new(raft_state.clone());
    let join_token_store = JoinTokenStore::new();

    // Create a cancellation token for graceful shutdown
    let shutdown = CancellationToken::new();

    // Start gRPC and HTTP servers concurrently
    let grpc_config = api::GrpcServerConfig {
        addr: grpc_addr,
        tls,
        cert_issuer,
        ca,
        trust_bundle_pem,
        domain: config.domain,
        fleet_key,
        join_token_store,
        raft_state,
        instance_tracker: instance_tracker.clone(),
        event_store: event_store.clone(),
        data_dir: config.data_dir.clone(),
    };

    let grpc_shutdown = shutdown.clone();
    let http_shutdown = shutdown.clone();
    let hk_shutdown = shutdown.clone();

    // Spawn housekeeping background task for periodic maintenance
    let hk_state = fleet_state.clone();
    let hk_join_tokens = grpc_config.join_token_store.clone();
    let hk_raft = grpc_config.raft_state.clone();
    let hk_metrics = metrics.clone();
    let hk_alerts = alert_evaluator.clone();
    let hk_events = event_store.clone();
    tokio::spawn(async move {
        housekeeping_loop(
            hk_state,
            hk_join_tokens,
            hk_raft,
            hk_metrics,
            hk_alerts,
            hk_events,
            hk_shutdown,
        )
        .await;
    });

    tokio::select! {
        result = api::serve_grpc(grpc_config, fleet_state.clone(), token_store.clone(), grpc_shutdown) => {
            result?;
        }
        result = rest::serve_http(
            http_addr,
            fleet_state,
            event_store,
            token_store,
            metrics,
            alert_evaluator,
            Some(instance_tracker),
            http_shutdown,
        ) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal, stopping server");
            shutdown.cancel();
        }
    }

    Ok(())
}

/// Get or create a persistent fleet encryption key (256-bit).
fn get_or_create_fleet_key(data_dir: &Path) -> anyhow::Result<Vec<u8>> {
    let key_path = data_dir.join("fleet-key");
    if key_path.exists() {
        let hex_str = std::fs::read_to_string(&key_path)?.trim().to_string();
        let key: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid fleet key hex: {e}"))?;
        if key.len() != 32 {
            anyhow::bail!("fleet key must be 32 bytes, got {}", key.len());
        }
        tracing::info!("Fleet encryption key loaded from disk");
        Ok(key)
    } else {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&key_path, &hex)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&key_path, perms)?;
        }
        tracing::info!("Fleet encryption key generated and persisted");
        Ok(key.to_vec())
    }
}

/// Periodic housekeeping loop that runs every 60 seconds to clean up stale
/// resources across all server subsystems.
async fn housekeeping_loop(
    fleet_state: FleetState,
    join_tokens: JoinTokenStore,
    raft_state: FleetStateMachine,
    metrics: crate::metrics::aggregator::MetricsAggregator,
    alerts: crate::metrics::alerting::AlertEvaluator,
    event_store: events::EventStore,
    shutdown: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut tick_count: u64 = 0;

    tracing::info!("Housekeeping background task started");

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.cancelled() => {
                tracing::info!("Housekeeping task shutting down");
                return;
            }
        }

        tick_count += 1;

        // 1. Expire join tokens older than 1 hour
        join_tokens.expire_old(3600).await;

        // 2. Evict nodes with no heartbeat for 5 minutes
        let evicted = fleet_state.evict_dead_nodes(300).await;
        if !evicted.is_empty() {
            tracing::info!(
                count = evicted.len(),
                nodes = ?evicted,
                "Evicted dead nodes during housekeeping"
            );
            for node_id in &evicted {
                event_store
                    .emit_detail(
                        events::EventLevel::Warning,
                        events::EventCategory::NodeLeave,
                        None,
                        Some(node_id),
                        &format!(
                            "Node {node_id} evicted (heartbeat timeout) — \
                             services on this node need rescheduling"
                        ),
                    )
                    .await;
            }
        }

        // 3. Prune metrics for disconnected nodes
        let active_nodes = fleet_state.connected_node_ids().await;
        metrics.prune_stale_nodes(&active_nodes).await;

        // 4. Prune alert history and expired silences
        alerts.prune_history(1000).await;
        alerts.expire_silences().await;

        // 5. Periodic Raft snapshot and log compaction (every ~100 minutes)
        if tick_count % 100 == 0 {
            let snapshot = raft_state.snapshot().await;
            let last = raft_state.last_applied().await;
            if last > 0 {
                tracing::info!(last_applied = last, "Taking periodic Raft snapshot");
                // Store snapshot in Raft state for restore operations.
                // Log compaction would require RaftStorage, which is wired
                // separately when persistent storage is enabled.
                let _ = snapshot; // Snapshot data available for persistence
            }
        }
    }
}

/// Get or create a persistent server identity (UUIDv4).
fn get_server_id(data_dir: &Path) -> anyhow::Result<String> {
    let id_path = data_dir.join("server-id");
    if id_path.exists() {
        Ok(std::fs::read_to_string(&id_path)?.trim().to_string())
    } else {
        let id = uuid::Uuid::new_v4().to_string();
        if let Some(parent) = id_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&id_path, &id)?;
        Ok(id)
    }
}
