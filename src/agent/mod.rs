use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::{AgentMessage, Heartbeat, NodeResources};

#[allow(dead_code)]
pub struct AgentConfig {
    pub server_addr: String,
    pub token: String,
    pub data_dir: PathBuf,
}

pub async fn run(config: AgentConfig) -> anyhow::Result<()> {
    tracing::info!(
        server = %config.server_addr,
        data_dir = %config.data_dir.display(),
        "Starting ekafleet agent"
    );

    let endpoint = format!("http://{}", config.server_addr);
    let mut client = FleetControlClient::connect(endpoint).await?;

    let node_id = get_node_id(&config.data_dir)?;
    tracing::info!(node_id = %node_id, "Agent identity established");

    // Channel for outgoing messages to server
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);

    // Send initial heartbeat
    tx.send(AgentMessage {
        payload: Some(Payload::Heartbeat(Heartbeat {
            node_id: node_id.clone(),
            timestamp: now_epoch(),
            available_resources: Some(NodeResources {
                cpu_millicores: 0,
                memory_mb: 0,
                disk_mb: 0,
            }),
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
                    available_resources: Some(NodeResources {
                        cpu_millicores: 0,
                        memory_mb: 0,
                        disk_mb: 0,
                    }),
                })),
            };
            if heartbeat_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Process incoming server messages
    while let Some(msg) = inbound.message().await? {
        if let Some(payload) = msg.payload {
            tracing::info!(?payload, "Received server message");
            // TODO: dispatch to subsystems
        }
    }

    tracing::warn!("Server stream ended");
    Ok(())
}

fn get_node_id(data_dir: &PathBuf) -> anyhow::Result<String> {
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

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
