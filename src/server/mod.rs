mod agent_msg;
pub mod api;
mod api_system;
pub mod audit;
pub mod bootstrap;
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
use zeroize::Zeroizing;

use crate::attestation::join_token::JoinTokenStore;
use crate::ca::CaSigner;
use crate::ca::issuer::CertIssuer;
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
    /// Accept agents authenticated by a bearer token instead of a node SVID.
    /// Only `ekafleet dev` sets this.
    pub allow_bearer_agents: bool,
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
        let root_ca = crate::ca::persist::open_ca(&config.data_dir, &config.domain).await?;
        let jwt = crate::ca::persist::open_jwt_signer(&config.data_dir).await?;
        Arc::new(DirectCaSigner::new(root_ca, jwt))
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

    let fleet_state = FleetState::new();

    // Initialize certificate issuer for SPIFFE SVID issuance. It authorizes
    // service SVIDs against the per-node assignments the reconciler publishes.
    let cert_issuer = CertIssuer::with_assignments(ca.clone(), fleet_state.service_assignments());

    let trust_bundle_pem = ca.trust_bundle_pem().await?;
    let jwt_bundle = ca.jwt_bundle().await?;

    // Generate or load fleet encryption key for secret distribution
    let fleet_key = get_or_create_fleet_key(&config.data_dir).await?;

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
    // Fleet state persists in an encrypted, write-ahead Raft log plus
    // snapshots under a dedicated storage key (fleet-key rotation must not
    // strand it). Storage written by older versions under the fleet key is
    // read with it once and re-encrypted. Unreadable state is fatal: the
    // server never silently starts over with an empty fleet.
    let raft_storage = {
        let raft_key = get_or_create_key(&config.data_dir, "raft-key", "Raft storage key").await?;
        let raft_key = key_array(&raft_key)?;
        let legacy_key = key_array(&fleet_key)?;
        let storage = crate::raft::storage::RaftStorage::new(&config.data_dir, &raft_key)
            .with_legacy_key(&legacy_key);
        storage
            .initialize()
            .await
            .map_err(|e| anyhow::anyhow!("initialize Raft storage: {e}"))?;
        Arc::new(storage)
    };
    let raft_state = FleetStateMachine::with_log(raft_storage.clone());
    raft_state.load().await.map_err(|e| {
        anyhow::anyhow!(
            "cannot load fleet state from {}: {e}. Refusing to start with empty state; \
             restore the data directory from backup, or move {} aside to start over",
            config.data_dir.join("raft").display(),
            config.data_dir.join("raft").display(),
        )
    })?;

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
        jwt_bundle: jwt_bundle.clone(),
        domain: config.domain,
        fleet_key,
        join_token_store,
        raft_state,
        instance_tracker: instance_tracker.clone(),
        event_store: event_store.clone(),
        data_dir: config.data_dir.clone(),
        allow_bearer_agents: config.allow_bearer_agents,
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
    };
    tokio::spawn(async move {
        housekeeping_loop(hk_deps, hk_shutdown).await;
    });

    let http_raft_state = grpc_config.raft_state.clone();
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
            http_raft_state,
            jwt_bundle,
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
async fn get_or_create_fleet_key(data_dir: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    get_or_create_key(data_dir, "fleet-key", "fleet encryption key").await
}

/// Get or create a persistent 256-bit key at `data_dir/<file>`.
///
/// The key is stored as hex and sealed at rest when a passphrase is configured
/// (see [`seal`]). Legacy plaintext-hex files are read transparently.
/// The returned key is wrapped in [`Zeroizing`] so it is cleared from memory on
/// drop, consistent with how the WireGuard private key is handled.
async fn get_or_create_key(
    data_dir: &Path,
    file: &str,
    what: &str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let key_path = data_dir.join(file);
    if key_path.exists() {
        let hex_bytes = seal::read_maybe_sealed(&key_path).await?;
        let hex_str = Zeroizing::new(
            String::from_utf8(hex_bytes.to_vec())
                .map_err(|e| anyhow::anyhow!("invalid {what} encoding: {e}"))?
                .trim()
                .to_string(),
        );
        let key: Zeroizing<Vec<u8>> = Zeroizing::new(
            (0..hex_str.len())
                .step_by(2)
                .map(|i| {
                    hex_str
                        .get(i..i + 2)
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                })
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(|| anyhow::anyhow!("invalid {what} hex"))?,
        );
        if key.len() != 32 {
            anyhow::bail!("{what} must be 32 bytes, got {}", key.len());
        }
        tracing::info!("{what} loaded from disk");
        Ok(key)
    } else {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut key = Zeroizing::new([0u8; 32]);
        rng.fill(key.as_mut())
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        let hex: Zeroizing<String> =
            Zeroizing::new(key.iter().map(|b| format!("{b:02x}")).collect());
        seal::write_maybe_sealed(&key_path, hex.as_bytes(), what).await?;
        tracing::info!("{what} generated and persisted");
        Ok(Zeroizing::new(key.to_vec()))
    }
}

/// Copy a 256-bit key into a fixed-size array that is zeroized on drop.
fn key_array(key: &[u8]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    if key.len() != 32 {
        anyhow::bail!("expected a 256-bit key, got {} bytes", key.len());
    }
    out.copy_from_slice(key);
    Ok(out)
}

/// Dependencies for the periodic housekeeping loop.
struct HousekeepingDeps {
    fleet_state: FleetState,
    join_tokens: JoinTokenStore,
    raft_state: FleetStateMachine,
    metrics: crate::metrics::aggregator::MetricsAggregator,
    alerts: crate::metrics::alerting::AlertEvaluator,
    event_store: events::EventStore,
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

        // 1. Drop expired join tokens
        join_tokens.expire().await;

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
            match raft_state.checkpoint().await {
                Ok(Some(index)) => tracing::info!(index, "Raft state checkpointed"),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "Failed to checkpoint Raft state"),
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
