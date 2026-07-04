pub mod health;
pub mod supervisor;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{AgentMessage, Heartbeat, NodeResources, ServiceSpec, StatusReport};

#[allow(dead_code)]
pub struct AgentConfig {
    pub server_addr: String,
    pub token: String,
    pub data_dir: PathBuf,
    pub ca_cert_pem: Option<String>,
}

/// Tracks local desired state as received from server.
#[derive(Default)]
struct LocalState {
    desired_services: HashMap<String, ServiceSpec>,
    system_path: String,
}

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

    let channel = if let Some(ca_pem) = &config.ca_cert_pem {
        // TLS connection with CA certificate verification
        let endpoint = format!("https://{}", config.server_addr);
        let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
        let tls_config = tonic::transport::ClientTlsConfig::new().ca_certificate(ca_cert);
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

    // Attach bearer token to all outgoing requests
    let token: tonic::metadata::MetadataValue<_> = format!("Bearer {}", config.token).parse()?;
    #[allow(clippy::result_large_err)]
    let mut client =
        FleetControlClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    let node_id = get_node_id(&config.data_dir)?;
    tracing::info!(node_id = %node_id, "Agent identity established");

    let local_state = Arc::new(RwLock::new(LocalState::default()));

    // Channel for outgoing messages to server
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);

    // Send initial heartbeat
    tx.send(AgentMessage {
        payload: Some(Payload::Heartbeat(Heartbeat {
            node_id: node_id.clone(),
            timestamp: now_epoch(),
            available_resources: Some(collect_resources()),
        })),
    })
    .await?;

    // Open bidirectional stream
    let response = client.stream_control(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

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

    // Process incoming server messages
    while let Some(msg) = inbound.message().await? {
        match msg.payload {
            Some(ServerPayload::DesiredState(ds)) => {
                tracing::info!(
                    correlation_id = %ds.correlation_id,
                    services = ds.services.len(),
                    "Received desired state"
                );
                let mut state = local_state.write().await;
                state.system_path = ds.system_path;
                state.desired_services.clear();
                for svc in ds.services {
                    state.desired_services.insert(svc.name.clone(), svc);
                }
                // TODO: reconcile local services with desired state
            }
            Some(ServerPayload::Deploy(cmd)) => {
                tracing::info!(
                    deployment_id = %cmd.deployment_id,
                    service = %cmd.service_name,
                    "Received deploy command"
                );
                // TODO: execute deployment
            }
            Some(ServerPayload::Secret(update)) => {
                tracing::info!(
                    service = %update.service_name,
                    secret = %update.secret_name,
                    "Received secret update"
                );
                // TODO: inject secret
            }
            Some(ServerPayload::Dns(update)) => {
                tracing::debug!(records = update.records.len(), "Received DNS update");
                // TODO: update local DNS cache
            }
            Some(ServerPayload::Cert(response)) => {
                tracing::info!(expires = response.expires_at, "Received certificate");
                // TODO: install certificate
            }
            Some(ServerPayload::Peers(update)) => {
                tracing::info!(peers = update.peers.len(), "Received peer update");
                // TODO: update WireGuard peers
            }
            Some(ServerPayload::Policy(update)) => {
                tracing::info!(policies = update.policies.len(), "Received policy update");
                // TODO: apply nftables rules
            }
            None => {}
        }
    }

    tracing::warn!("Server stream ended");
    Ok(())
}

fn get_node_id(data_dir: &Path) -> anyhow::Result<String> {
    let id_path = data_dir.join("node-id");
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

pub(crate) fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn collect_resources() -> NodeResources {
    // TODO: read actual system resources
    NodeResources {
        cpu_millicores: 0,
        memory_mb: 0,
        disk_mb: 0,
    }
}
