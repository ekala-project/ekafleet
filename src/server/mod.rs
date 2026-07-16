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
pub mod seal;
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

    // Apply configurable Nix timeouts and --option passthrough from the
    // environment before any Nix invocation runs.
    nix::init_options(nix::NixOptions::from_env());

    // Build the CA signer — either in-process or remote
    let ca: Arc<dyn CaSigner> = if let Some(socket_path) = &config.ca_socket {
        tracing::info!(socket = %socket_path.display(), "Using remote CA signer");
        Arc::new(RemoteCaSigner::new(socket_path))
    } else {
        tracing::info!("Using in-process CA (embedded mode)");
        let root_ca = RootCa::new(&config.domain);

        let ca_key_path = config.data_dir.join("ca-key.pem");
        let ca_cert_path = config.data_dir.join("ca-cert.pem");
        let int_key_path = config.data_dir.join("ca-intermediate-key.pem");
        let int_cert_path = config.data_dir.join("ca-intermediate-cert.pem");

        let (stored_key, stored_cert) = match (
            seal::read_maybe_sealed(&ca_key_path).await,
            tokio::fs::read_to_string(&ca_cert_path).await,
        ) {
            (Ok(key), Ok(cert)) => (Some(String::from_utf8(key.to_vec())?), Some(cert)),
            _ => (None, None),
        };

        let (stored_int_key, stored_int_cert) = match (
            seal::read_maybe_sealed(&int_key_path).await,
            tokio::fs::read_to_string(&int_cert_path).await,
        ) {
            (Ok(key), Ok(cert)) => (Some(String::from_utf8(key.to_vec())?), Some(cert)),
            _ => (None, None),
        };

        root_ca
            .initialize_with_intermediate(
                stored_key.as_deref(),
                stored_cert.as_deref(),
                stored_int_key.as_deref(),
                stored_int_cert.as_deref(),
            )
            .await?;

        // Persist root CA key and cert if newly generated.
        if stored_key.is_none()
            && let (Some(key_pem), Some(cert_pem)) = (
                root_ca.root_key_pem().await,
                root_ca.root_certificate_pem().await,
            )
        {
            tokio::fs::create_dir_all(&config.data_dir).await?;
            seal::write_maybe_sealed(&ca_key_path, key_pem.as_bytes(), "CA private key").await?;
            tokio::fs::write(&ca_cert_path, &cert_pem).await?;

            tracing::info!("CA key and certificate persisted to disk");
        }

        // Persist the intermediate CA whenever the one held in memory differs
        // from what is on disk (covers both first boot and rotation on expiry).
        if let (Some(int_key), Some(int_cert)) = (
            root_ca.intermediate_key_pem().await,
            root_ca.intermediate_certificate_pem().await,
        ) && stored_int_cert.as_deref() != Some(int_cert.as_str())
        {
            tokio::fs::create_dir_all(&config.data_dir).await?;
            seal::write_maybe_sealed(&int_key_path, int_key.as_bytes(), "intermediate CA key")
                .await?;
            tokio::fs::write(&int_cert_path, &int_cert).await?;
            tracing::info!("Intermediate CA key and certificate persisted to disk");
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

    // Optional HTTPS for the REST API. Opt-in via EKAFLEET_HTTP_TLS; when set,
    // the REST server reuses the server SVID (combined cert-chain + key bundle)
    // to terminate TLS. Left unset, the REST API is served over plaintext HTTP.
    let http_tls = if std::env::var("EKAFLEET_HTTP_TLS")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
    {
        Some(rest::HttpTlsConfig {
            cert_pem: tls.cert_pem.clone(),
            key_pem: tls.cert_pem.clone(),
        })
    } else {
        None
    };

    // Initialize certificate issuer for SPIFFE SVID issuance
    let cert_issuer = CertIssuer::new(ca.clone());

    let trust_bundle_pem = ca.trust_bundle_pem().await?;

    // Generate or load fleet encryption key for secret distribution
    let fleet_key = get_or_create_fleet_key(&config.data_dir).await?;

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

    // Persistent (encrypted) Raft storage for snapshots and log. Encryption
    // reuses the fleet key. On boot we restore the latest snapshot and replay
    // any log entries recorded after it, so fleet state survives restarts.
    let raft_storage = {
        let mut key = [0u8; 32];
        key.copy_from_slice(&fleet_key);
        let storage = Arc::new(crate::raft::storage::RaftStorage::new(
            &config.data_dir,
            &key,
        ));
        if let Err(e) = storage.initialize().await {
            tracing::warn!(error = %e, "Failed to initialize Raft storage");
        }
        if let Err(e) = restore_raft_state(&raft_state, &storage).await {
            tracing::warn!(error = %e, "Failed to restore Raft state from disk, starting empty");
        }
        storage
    };

    let instance_tracker = cloud::instance_tracker::InstanceTracker::new(raft_state.clone());
    let join_token_store = JoinTokenStore::with_persistence(&config.data_dir);
    if let Err(e) = join_token_store.load().await {
        tracing::warn!(error = %e, "Failed to load persisted join tokens, starting fresh");
    }

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
    let hk_deps = HousekeepingDeps {
        fleet_state: fleet_state.clone(),
        join_tokens: grpc_config.join_token_store.clone(),
        raft_state: grpc_config.raft_state.clone(),
        metrics: metrics.clone(),
        alerts: alert_evaluator.clone(),
        event_store: event_store.clone(),
        raft_storage: raft_storage.clone(),
    };
    tokio::spawn(async move {
        housekeeping_loop(hk_deps, hk_shutdown).await;
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
            http_tls,
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
///
/// The key is stored as hex and sealed at rest when a passphrase is configured
/// (see [`seal`]). Legacy plaintext-hex files are read transparently.
async fn get_or_create_fleet_key(data_dir: &Path) -> anyhow::Result<Vec<u8>> {
    let key_path = data_dir.join("fleet-key");
    if key_path.exists() {
        let hex_bytes = seal::read_maybe_sealed(&key_path).await?;
        let hex_str = String::from_utf8(hex_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("invalid fleet key encoding: {e}"))?
            .trim()
            .to_string();
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
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        seal::write_maybe_sealed(&key_path, hex.as_bytes(), "fleet encryption key").await?;
        tracing::info!("Fleet encryption key generated and persisted");
        Ok(key.to_vec())
    }
}

/// Restore fleet state at boot from the persistent Raft store: load the latest
/// snapshot into the state machine, then replay any log entries recorded after
/// the snapshot index. Idempotent — a fresh install with no snapshot/log leaves
/// the state machine empty.
///
/// This is single-node restore-on-boot. True multi-node consensus (leader
/// election, log replication across `--peers`) is not yet implemented; today a
/// single server is authoritative and this restores its own durable state.
async fn restore_raft_state(
    raft_state: &FleetStateMachine,
    storage: &crate::raft::storage::RaftStorage,
) -> anyhow::Result<()> {
    let snapshot_index = match storage.load_latest_snapshot().await? {
        Some((index, data)) => {
            raft_state
                .restore(&data)
                .await
                .map_err(|e| anyhow::anyhow!("snapshot deserialization failed: {e}"))?;
            tracing::info!(snapshot_index = index, "Restored Raft state from snapshot");
            index
        }
        None => 0,
    };

    // Replay any log entries recorded after the snapshot. `apply` is idempotent
    // via the `last_applied` guard, so overlapping entries are ignored.
    let entries = storage.read_log_from(snapshot_index + 1).await?;
    let replayed = entries.len();
    for entry in entries {
        raft_state.apply(entry.index, entry.command).await;
    }
    if replayed > 0 {
        tracing::info!(
            replayed,
            from_index = snapshot_index + 1,
            "Replayed Raft log entries at boot"
        );
    }

    Ok(())
}

/// Dependencies for the periodic housekeeping loop.
struct HousekeepingDeps {
    fleet_state: FleetState,
    join_tokens: JoinTokenStore,
    raft_state: FleetStateMachine,
    metrics: crate::metrics::aggregator::MetricsAggregator,
    alerts: crate::metrics::alerting::AlertEvaluator,
    event_store: events::EventStore,
    raft_storage: Arc<crate::raft::storage::RaftStorage>,
}

/// Periodic housekeeping loop that runs every 60 seconds to clean up stale
/// resources across all server subsystems.
async fn housekeeping_loop(deps: HousekeepingDeps, shutdown: CancellationToken) {
    let HousekeepingDeps {
        fleet_state,
        join_tokens,
        raft_state,
        metrics,
        alerts,
        event_store,
        raft_storage,
    } = deps;
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
        if tick_count.is_multiple_of(100) {
            let last = raft_state.last_applied().await;
            if last > 0 {
                tracing::info!(last_applied = last, "Taking periodic Raft snapshot");
                let snapshot = raft_state.snapshot().await;
                match raft_storage.save_snapshot(last, &snapshot).await {
                    Ok(()) => {
                        // The snapshot subsumes all log entries up to `last`;
                        // compact them so the log does not grow without bound.
                        if let Err(e) = raft_storage.compact_log(last).await {
                            tracing::warn!(error = %e, "Failed to compact Raft log");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to persist Raft snapshot");
                    }
                }
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
