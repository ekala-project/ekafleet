#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{RwLock, mpsc};

use crate::proto::{
    HealthStatus, NodeResources, NodeStatus, ServerMessage, ServiceHealth, ServiceState,
    ServiceStatus,
};

/// Shared server state, accessible from gRPC handlers and background tasks.
#[derive(Clone)]
pub struct FleetState {
    inner: Arc<RwLock<FleetStateInner>>,
}

struct FleetStateInner {
    nodes: HashMap<String, NodeInfo>,
}

struct NodeInfo {
    address: String,
    total_resources: NodeResources,
    available_resources: NodeResources,
    last_heartbeat: Instant,
    services: HashMap<String, AgentServiceInfo>,
    tx: mpsc::Sender<ServerMessage>,
}

struct AgentServiceInfo {
    instance_id: String,
    store_path: String,
    state: ServiceState,
    health: HealthStatus,
}

impl Default for FleetState {
    fn default() -> Self {
        Self::new()
    }
}

impl FleetState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(FleetStateInner {
                nodes: HashMap::new(),
            })),
        }
    }

    /// Register a newly connected agent. Returns a receiver for outbound messages.
    pub async fn register_agent(
        &self,
        node_id: &str,
        address: String,
    ) -> mpsc::Receiver<ServerMessage> {
        let (tx, rx) = mpsc::channel(64);
        let mut state = self.inner.write().await;

        state.nodes.insert(
            node_id.to_string(),
            NodeInfo {
                address,
                total_resources: NodeResources {
                    cpu_millicores: 0,
                    memory_mb: 0,
                    disk_mb: 0,
                },
                available_resources: NodeResources {
                    cpu_millicores: 0,
                    memory_mb: 0,
                    disk_mb: 0,
                },
                last_heartbeat: Instant::now(),
                services: HashMap::new(),
                tx,
            },
        );

        tracing::info!(node_id, "Agent registered");
        rx
    }

    /// Remove an agent when it disconnects.
    pub async fn deregister_agent(&self, node_id: &str) {
        let mut state = self.inner.write().await;
        state.nodes.remove(node_id);
        tracing::info!(node_id, "Agent deregistered");
    }

    /// Update heartbeat timestamp and available resources for a node.
    pub async fn update_heartbeat(&self, node_id: &str, resources: Option<NodeResources>) {
        let mut state = self.inner.write().await;
        if let Some(node) = state.nodes.get_mut(node_id) {
            node.last_heartbeat = Instant::now();
            if let Some(res) = resources {
                node.available_resources = res;
            }
        }
    }

    /// Update health reports from an agent.
    pub async fn update_health(&self, node_id: &str, services: Vec<ServiceHealth>) {
        let mut state = self.inner.write().await;
        if let Some(node) = state.nodes.get_mut(node_id) {
            for svc in services {
                if let Some(info) = node.services.get_mut(&svc.service_name) {
                    info.health =
                        HealthStatus::try_from(svc.status).unwrap_or(HealthStatus::HealthUnknown);
                }
            }
        }
    }

    /// Update running service info from agent status report.
    pub async fn update_status(&self, node_id: &str, services: Vec<crate::proto::ServiceInstance>) {
        let mut state = self.inner.write().await;
        if let Some(node) = state.nodes.get_mut(node_id) {
            node.services.clear();
            for svc in services {
                node.services.insert(
                    svc.service_name.clone(),
                    AgentServiceInfo {
                        instance_id: svc.instance_id,
                        store_path: svc.store_path,
                        state: ServiceState::try_from(svc.state).unwrap_or(ServiceState::Unknown),
                        health: HealthStatus::HealthUnknown,
                    },
                );
            }
        }
    }

    /// Send a message to a specific agent.
    pub async fn send_to_agent(&self, node_id: &str, msg: ServerMessage) -> bool {
        let state = self.inner.read().await;
        if let Some(node) = state.nodes.get(node_id) {
            node.tx.send(msg).await.is_ok()
        } else {
            false
        }
    }

    /// Broadcast a message to all connected agents.
    pub async fn broadcast(&self, msg: ServerMessage) {
        let state = self.inner.read().await;
        for (node_id, node) in &state.nodes {
            if node.tx.send(msg.clone()).await.is_err() {
                tracing::warn!(node_id, "Failed to send to agent");
            }
        }
    }

    /// Get a snapshot of fleet status for the Status RPC.
    pub async fn fleet_status(&self) -> (Vec<NodeStatus>, Vec<ServiceStatus>) {
        let state = self.inner.read().await;

        let nodes: Vec<NodeStatus> = state
            .nodes
            .iter()
            .map(|(id, info)| {
                let healthy = info.last_heartbeat.elapsed().as_secs() < 15;
                NodeStatus {
                    node_id: id.clone(),
                    address: info.address.clone(),
                    healthy,
                    total_resources: Some(info.total_resources),
                    available_resources: Some(info.available_resources),
                    last_heartbeat: info.last_heartbeat.elapsed().as_secs(),
                }
            })
            .collect();

        // Aggregate services across all nodes
        let mut svc_map: HashMap<String, ServiceStatus> = HashMap::new();
        for (node_id, node) in &state.nodes {
            for (svc_name, svc_info) in &node.services {
                let entry = svc_map
                    .entry(svc_name.clone())
                    .or_insert_with(|| ServiceStatus {
                        name: svc_name.clone(),
                        desired_count: 0,
                        healthy_count: 0,
                        instances: vec![],
                    });
                if svc_info.health == HealthStatus::Healthy {
                    entry.healthy_count += 1;
                }
                entry.instances.push(crate::proto::InstanceStatus {
                    instance_id: svc_info.instance_id.clone(),
                    node_id: node_id.clone(),
                    state: svc_info.state as i32,
                    health: svc_info.health as i32,
                });
            }
        }

        (nodes, svc_map.into_values().collect())
    }

    /// Get list of connected node IDs.
    pub async fn connected_nodes(&self) -> Vec<String> {
        let state = self.inner.read().await;
        state.nodes.keys().cloned().collect()
    }
}
