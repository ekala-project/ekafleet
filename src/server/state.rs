#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{RwLock, mpsc, oneshot};
use tonic::Status;

use crate::proto::{
    HealthStatus, NodeResources, NodeStatus, PoolStatus, ServerMessage, ServiceHealth,
    ServiceState, ServiceStatus,
};

/// Shared server state, accessible from gRPC handlers and background tasks.
#[derive(Clone)]
pub struct FleetState {
    inner: Arc<RwLock<FleetStateInner>>,
}

struct FleetStateInner {
    nodes: HashMap<String, NodeInfo>,
    /// Pending request-response correlations for agent commands.
    pending_requests:
        HashMap<String, oneshot::Sender<crate::proto::AgentCommandResponse>>,
}

struct NodeInfo {
    address: String,
    pool: String,
    total_resources: NodeResources,
    available_resources: NodeResources,
    last_heartbeat: Instant,
    services: HashMap<String, AgentServiceInfo>,
    tx: mpsc::Sender<ServerMessage>,
    /// Whether this node is eligible for new scheduling.
    /// Set to false during maintenance windows.
    schedulable: bool,
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
                pending_requests: HashMap::new(),
            })),
        }
    }

    /// Register a newly connected agent. Returns a receiver for outbound messages.
    pub async fn register_agent(
        &self,
        node_id: &str,
        address: String,
        pool: String,
    ) -> mpsc::Receiver<ServerMessage> {
        let (tx, rx) = mpsc::channel(64);
        let mut state = self.inner.write().await;

        state.nodes.insert(
            node_id.to_string(),
            NodeInfo {
                address,
                pool,
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
                schedulable: true,
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
    /// Clones senders under a read lock, then sends outside the lock to avoid
    /// holding it across .await points.
    pub async fn broadcast(&self, msg: ServerMessage) {
        let senders: Vec<(String, mpsc::Sender<ServerMessage>)> = {
            let state = self.inner.read().await;
            state
                .nodes
                .iter()
                .map(|(id, node)| (id.clone(), node.tx.clone()))
                .collect()
        };

        for (node_id, tx) in senders {
            if tx.send(msg.clone()).await.is_err() {
                tracing::warn!(node_id, "Failed to send to agent");
            }
        }
    }

    /// Get a snapshot of fleet status for the Status RPC.
    /// Takes a short read lock to snapshot node data, then aggregates outside the lock.
    pub async fn fleet_status(&self) -> (Vec<NodeStatus>, Vec<ServiceStatus>, Vec<PoolStatus>) {
        // Snapshot all data we need under a short read lock
        struct NodeSnapshot {
            node_id: String,
            address: String,
            pool: String,
            total_resources: NodeResources,
            available_resources: NodeResources,
            heartbeat_elapsed_secs: u64,
            services: Vec<(String, String, ServiceState, HealthStatus)>,
        }

        let snapshots: Vec<NodeSnapshot> = {
            let state = self.inner.read().await;
            state
                .nodes
                .iter()
                .map(|(id, info)| NodeSnapshot {
                    node_id: id.clone(),
                    address: info.address.clone(),
                    pool: info.pool.clone(),
                    total_resources: info.total_resources,
                    available_resources: info.available_resources,
                    heartbeat_elapsed_secs: info.last_heartbeat.elapsed().as_secs(),
                    services: info
                        .services
                        .iter()
                        .map(|(name, svc)| {
                            (name.clone(), svc.instance_id.clone(), svc.state, svc.health)
                        })
                        .collect(),
                })
                .collect()
        };
        // Lock is now released — aggregate on the snapshot

        let nodes: Vec<NodeStatus> = snapshots
            .iter()
            .map(|s| NodeStatus {
                node_id: s.node_id.clone(),
                address: s.address.clone(),
                healthy: s.heartbeat_elapsed_secs < 15,
                total_resources: Some(s.total_resources),
                available_resources: Some(s.available_resources),
                last_heartbeat: s.heartbeat_elapsed_secs,
                pool: s.pool.clone(),
            })
            .collect();

        // Aggregate services across all nodes
        let mut svc_map: HashMap<String, ServiceStatus> = HashMap::new();
        for snap in &snapshots {
            for (svc_name, instance_id, state, health) in &snap.services {
                let entry = svc_map
                    .entry(svc_name.clone())
                    .or_insert_with(|| ServiceStatus {
                        name: svc_name.clone(),
                        desired_count: 0,
                        healthy_count: 0,
                        instances: vec![],
                    });
                if *health == HealthStatus::Healthy {
                    entry.healthy_count += 1;
                }
                entry.instances.push(crate::proto::InstanceStatus {
                    instance_id: instance_id.clone(),
                    node_id: snap.node_id.clone(),
                    state: *state as i32,
                    health: *health as i32,
                });
            }
        }

        // Aggregate pool status
        let mut pool_map: HashMap<String, PoolStatus> = HashMap::new();
        for snap in &snapshots {
            let entry = pool_map
                .entry(snap.pool.clone())
                .or_insert_with(|| PoolStatus {
                    name: snap.pool.clone(),
                    machine_count: 0,
                    total_schedulable: Some(NodeResources {
                        cpu_millicores: 0,
                        memory_mb: 0,
                        disk_mb: 0,
                    }),
                    total_allocated: Some(NodeResources {
                        cpu_millicores: 0,
                        memory_mb: 0,
                        disk_mb: 0,
                    }),
                    labels: HashMap::new(),
                });
            entry.machine_count += 1;
            if let Some(ref mut sched) = entry.total_schedulable {
                sched.cpu_millicores += snap.total_resources.cpu_millicores;
                sched.memory_mb += snap.total_resources.memory_mb;
            }
            if let Some(ref mut alloc) = entry.total_allocated {
                let used_cpu = snap
                    .total_resources
                    .cpu_millicores
                    .saturating_sub(snap.available_resources.cpu_millicores);
                let used_mem = snap
                    .total_resources
                    .memory_mb
                    .saturating_sub(snap.available_resources.memory_mb);
                alloc.cpu_millicores += used_cpu;
                alloc.memory_mb += used_mem;
            }
        }

        (
            nodes,
            svc_map.into_values().collect(),
            pool_map.into_values().collect(),
        )
    }

    /// Get list of connected node IDs.
    pub async fn connected_nodes(&self) -> Vec<String> {
        let state = self.inner.read().await;
        state.nodes.keys().cloned().collect()
    }

    /// Set whether a node is eligible for new scheduling.
    /// Use `false` during maintenance windows to prevent new placements
    /// without draining existing workloads.
    pub async fn set_schedulable(&self, node_id: &str, schedulable: bool) {
        let mut state = self.inner.write().await;
        if let Some(node) = state.nodes.get_mut(node_id) {
            node.schedulable = schedulable;
            tracing::info!(node_id, schedulable, "Node scheduling eligibility updated");
        }
    }

    /// Check if a node is eligible for scheduling.
    pub async fn is_schedulable(&self, node_id: &str) -> bool {
        let state = self.inner.read().await;
        state.nodes.get(node_id).is_some_and(|n| n.schedulable)
    }

    /// Send a command to an agent and wait for the correlated response.
    ///
    /// Inserts a oneshot channel keyed by `correlation_id`, sends the message
    /// to the agent, and awaits the response with a timeout. Returns an error
    /// status if the agent is unreachable or the response times out.
    pub async fn send_command(
        &self,
        node_id: &str,
        msg: ServerMessage,
        correlation_id: String,
        timeout: Duration,
    ) -> Result<crate::proto::AgentCommandResponse, Status> {
        let (tx, rx) = oneshot::channel();

        {
            let mut state = self.inner.write().await;
            state.pending_requests.insert(correlation_id.clone(), tx);
        }

        if !self.send_to_agent(node_id, msg).await {
            let mut state = self.inner.write().await;
            state.pending_requests.remove(&correlation_id);
            return Err(Status::unavailable(format!(
                "agent '{node_id}' is not connected"
            )));
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                // Sender was dropped (agent disconnected)
                Err(Status::unavailable(format!(
                    "agent '{node_id}' disconnected before responding"
                )))
            }
            Err(_) => {
                // Timeout — clean up the pending entry
                let mut state = self.inner.write().await;
                state.pending_requests.remove(&correlation_id);
                Err(Status::deadline_exceeded(format!(
                    "agent '{node_id}' did not respond within {timeout:?}"
                )))
            }
        }
    }

    /// Complete a pending request-response correlation.
    ///
    /// Called when the server receives an `AgentCommandResponse` from an agent.
    /// If the correlation_id matches a pending request, the response is forwarded
    /// to the waiting handler. Otherwise a warning is logged (the request may
    /// have timed out).
    pub async fn complete_request(
        &self,
        correlation_id: &str,
        response: crate::proto::AgentCommandResponse,
    ) {
        let sender = {
            let mut state = self.inner.write().await;
            state.pending_requests.remove(correlation_id)
        };

        match sender {
            Some(tx) => {
                let _ = tx.send(response);
            }
            None => {
                tracing::warn!(
                    correlation_id,
                    "Received response for unknown or timed-out correlation"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::server_message::Payload as ServerPayload;

    #[tokio::test]
    async fn send_command_returns_response() {
        let state = FleetState::new();
        let _rx = state
            .register_agent("node-1", "127.0.0.1:5000".into(), "default".into())
            .await;

        let cid = "test-correlation-1".to_string();
        let msg = ServerMessage {
            payload: Some(ServerPayload::ListGenerationsCommand(
                crate::proto::ListGenerationsCommand {
                    correlation_id: cid.clone(),
                },
            )),
        };

        let state2 = state.clone();
        let cid2 = cid.clone();
        // Complete the request from another task after a short delay.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let cid_for_response = cid2.clone();
            state2
                .complete_request(
                    &cid2,
                    crate::proto::AgentCommandResponse {
                        correlation_id: cid_for_response,
                        success: true,
                        error_message: String::new(),
                        result: None,
                    },
                )
                .await;
        });

        let resp = state
            .send_command(&"node-1", msg, cid, Duration::from_secs(5))
            .await;
        assert!(resp.is_ok());
        assert!(resp.unwrap().success);
    }

    #[tokio::test]
    async fn send_command_times_out() {
        let state = FleetState::new();
        let _rx = state
            .register_agent("node-1", "127.0.0.1:5000".into(), "default".into())
            .await;

        let cid = "timeout-test".to_string();
        let msg = ServerMessage {
            payload: Some(ServerPayload::ListGenerationsCommand(
                crate::proto::ListGenerationsCommand {
                    correlation_id: cid.clone(),
                },
            )),
        };

        // Don't complete the request — it should time out.
        let resp = state
            .send_command(&"node-1", msg, cid, Duration::from_millis(100))
            .await;
        assert!(resp.is_err());
        let status = resp.unwrap_err();
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
    }

    #[tokio::test]
    async fn send_command_fails_for_disconnected_agent() {
        let state = FleetState::new();
        // Don't register any agent.
        let cid = "no-agent".to_string();
        let msg = ServerMessage {
            payload: Some(ServerPayload::ListGenerationsCommand(
                crate::proto::ListGenerationsCommand {
                    correlation_id: cid.clone(),
                },
            )),
        };

        let resp = state
            .send_command(&"nonexistent", msg, cid, Duration::from_secs(5))
            .await;
        assert!(resp.is_err());
        let status = resp.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn complete_unknown_correlation_does_not_panic() {
        let state = FleetState::new();
        // Complete a request with no pending entries — should just log a warning.
        state
            .complete_request(
                "unknown-id",
                crate::proto::AgentCommandResponse {
                    correlation_id: "unknown-id".to_string(),
                    success: true,
                    error_message: String::new(),
                    result: None,
                },
            )
            .await;
        // No panic = success.
    }
}
