use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, RwLock, mpsc, oneshot};
use tonic::Status;

use crate::proto::{
    HealthStatus, NodeResources, NodeStatus, PoolStatus, ServerMessage, ServiceHealth,
    ServiceState, ServiceStatus,
};
use crate::types::NodeId;

/// A trigger that wakes the reconciliation loop out-of-band, so a node death,
/// agent disconnect, or crashed service is rescheduled immediately instead of
/// waiting for the next periodic tick. Cloneable; all clones share one wakeup.
#[derive(Clone, Default)]
pub struct ReconcileTrigger {
    notify: Arc<Notify>,
}

impl ReconcileTrigger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a reconciliation as soon as possible. If no waiter is currently
    /// parked, the request is coalesced into the next `notified()` call, so a
    /// trigger is never lost between reconcile cycles.
    pub fn trigger(&self) {
        self.notify.notify_one();
    }

    /// Wait until a reconciliation has been requested.
    pub async fn notified(&self) {
        self.notify.notified().await;
    }
}

/// Shared server state, accessible from gRPC handlers and background tasks.
#[derive(Clone)]
pub struct FleetState {
    inner: Arc<RwLock<FleetStateInner>>,
    /// Fired whenever fleet membership changes in a way that may require
    /// rescheduling (node eviction, agent disconnect, service crash).
    reconcile: ReconcileTrigger,
    /// Canary deployments that are healthy and awaiting manual promotion.
    pending_canaries: super::deployer::PendingCanaryStore,
    /// Node → assigned service names, consulted by the certificate issuer.
    /// Kept in sync with `FleetStateInner::assigned`.
    service_assignments: crate::ca::issuer::ServiceAssignments,
    /// Public key of the server's binary cache, stamped into every
    /// `DesiredState` so agents can verify fetched closures.
    cache_public_key: Arc<std::sync::OnceLock<String>>,
}

struct FleetStateInner {
    nodes: HashMap<NodeId, NodeInfo>,
    /// Pending request-response correlations for agent commands.
    pending_requests: HashMap<String, oneshot::Sender<crate::proto::AgentCommandResponse>>,
    /// Per-service declared resource requests, keyed by service name. Values are
    /// `(cpu_millicores, memory_mb)`, refreshed from the desired state on each
    /// reconcile so the `top` RPC can report requested capacity per service.
    service_requests: HashMap<String, (u64, u64)>,
    /// Monotonic counter identifying agent control-stream connections.
    next_connection_id: u64,
    /// The last full `DesiredState` assigned to each node, including nodes
    /// that are currently disconnected. Replayed when a node (re)connects and
    /// amended in place when a deployment updates a service's store path.
    assigned: HashMap<String, crate::proto::DesiredState>,
}

struct NodeInfo {
    /// Identifies the control stream this entry belongs to, so a stream that
    /// ends after its node has reconnected cannot deregister the new session.
    connection_id: u64,
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
    /// WireGuard mesh IP reported via heartbeat. Used by the reconciler to
    /// populate VXLAN tunnel endpoints for cross-node namespace networking.
    mesh_ip: Option<std::net::Ipv4Addr>,
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
                service_requests: HashMap::new(),
                next_connection_id: 0,
                assigned: HashMap::new(),
            })),
            reconcile: ReconcileTrigger::new(),
            pending_canaries: super::deployer::PendingCanaryStore::new(),
            service_assignments: crate::ca::issuer::ServiceAssignments::new(),
            cache_public_key: Arc::default(),
        }
    }

    /// Record the binary cache's public key (once, at startup).
    pub fn set_cache_public_key(&self, key: String) {
        let _ = self.cache_public_key.set(key);
    }

    /// Store paths assigned to `node_id` across its services, i.e. the roots
    /// of everything it may fetch from the binary cache. `None` covers
    /// every node (bearer-token agents in `ekafleet dev`).
    pub async fn assigned_store_paths(&self, node_id: Option<&str>) -> Vec<String> {
        let state = self.inner.read().await;
        let mut paths: Vec<String> = state
            .assigned
            .iter()
            .filter(|(node, _)| node_id.is_none_or(|n| n == node.as_str()))
            .flat_map(|(_, ds)| {
                ds.services
                    .iter()
                    .flat_map(|s| s.store_paths.iter().cloned())
            })
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// Shared node → service assignment table for the certificate issuer.
    pub fn service_assignments(&self) -> crate::ca::issuer::ServiceAssignments {
        self.service_assignments.clone()
    }

    /// Record `desired` as the complete set of services `node_id` should run
    /// and push it to the node if it is connected. The agent treats every
    /// `DesiredState` as authoritative, stopping anything not listed. Returns
    /// whether the message was delivered (disconnected nodes receive it when
    /// they reconnect).
    pub async fn assign_desired_state(
        &self,
        node_id: &str,
        mut desired: crate::proto::DesiredState,
    ) -> bool {
        if let Some(key) = self.cache_public_key.get() {
            desired.cache_public_key = key.clone();
        }
        let names = desired.services.iter().map(|s| s.name.clone()).collect();
        self.service_assignments.set(node_id, names).await;
        let tx = {
            let mut state = self.inner.write().await;
            state.assigned.insert(node_id.to_string(), desired.clone());
            state.nodes.get(node_id).map(|n| n.tx.clone())
        };
        let msg = ServerMessage {
            payload: Some(crate::proto::server_message::Payload::DesiredState(desired)),
        };
        match tx {
            Some(tx) => tx.send(msg).await.is_ok(),
            None => false,
        }
    }

    /// The last `DesiredState` assigned to a node, if any.
    pub async fn assigned_desired_state(
        &self,
        node_id: &str,
    ) -> Option<crate::proto::DesiredState> {
        self.inner.read().await.assigned.get(node_id).cloned()
    }

    /// Nodes that have ever been assigned a desired state.
    pub async fn assigned_nodes(&self) -> Vec<String> {
        self.inner.read().await.assigned.keys().cloned().collect()
    }

    /// The store path most recently deployed for `service_name` on `node_id`.
    pub async fn assigned_store_path(&self, node_id: &str, service_name: &str) -> Option<String> {
        let state = self.inner.read().await;
        state
            .assigned
            .get(node_id)?
            .services
            .iter()
            .find(|s| s.name == service_name)
            .map(|s| s.store_path.clone())
            .filter(|p| !p.is_empty())
    }

    /// Send a `DeployCommand` to a node, first recording the new store path in
    /// the node's assigned desired state so a reconnecting agent is replayed
    /// the deployed version rather than a stale one.
    pub async fn send_deploy_command(
        &self,
        node_id: &str,
        cmd: crate::proto::DeployCommand,
    ) -> bool {
        {
            let mut state = self.inner.write().await;
            if let Some(svc) = state
                .assigned
                .get_mut(node_id)
                .and_then(|ds| ds.services.iter_mut().find(|s| s.name == cmd.service_name))
            {
                svc.store_path = cmd.store_path.clone();
            }
        }
        let msg = ServerMessage {
            payload: Some(crate::proto::server_message::Payload::Deploy(cmd)),
        };
        self.send_to_agent(node_id, msg).await
    }

    /// Handle to the registry of canary deployments awaiting manual promotion.
    pub fn pending_canaries(&self) -> super::deployer::PendingCanaryStore {
        self.pending_canaries.clone()
    }

    /// Replace the per-service resource-request table. Called each reconcile with
    /// the desired-state requests so read paths like `top` can report requested
    /// CPU (millicores) and memory (MB) per service.
    pub async fn set_service_requests(&self, requests: HashMap<String, (u64, u64)>) {
        self.inner.write().await.service_requests = requests;
    }

    /// Look up the declared `(cpu_millicores, memory_mb)` request for a service.
    pub async fn service_request(&self, service_name: &str) -> Option<(u64, u64)> {
        self.inner
            .read()
            .await
            .service_requests
            .get(service_name)
            .copied()
    }

    /// Get a handle to the reconciliation trigger. Callers that observe a
    /// membership change fire it via [`ReconcileTrigger::trigger`]; the
    /// reconcile loop waits on it via [`ReconcileTrigger::notified`].
    pub fn reconcile_trigger(&self) -> ReconcileTrigger {
        self.reconcile.clone()
    }

    /// Register a newly connected agent. Returns a receiver for outbound messages.
    pub async fn register_agent(
        &self,
        node_id: &str,
        address: String,
        pool: String,
    ) -> mpsc::Receiver<ServerMessage> {
        self.register_agent_connection(node_id, address, pool)
            .await
            .1
    }

    /// Register a newly connected agent, replacing any previous session for
    /// the same node (whose outbound channel is dropped, ending that stream).
    /// Returns the connection id to pass to [`Self::deregister_agent`] and a
    /// receiver for outbound messages. A node's cordon state survives
    /// reconnects.
    pub async fn register_agent_connection(
        &self,
        node_id: &str,
        address: String,
        pool: String,
    ) -> (u64, mpsc::Receiver<ServerMessage>) {
        let (tx, rx) = mpsc::channel(64);
        let mut state = self.inner.write().await;
        state.next_connection_id += 1;
        let connection_id = state.next_connection_id;
        let schedulable = state
            .nodes
            .get(node_id)
            .is_none_or(|existing| existing.schedulable);

        state.nodes.insert(
            NodeId::new(node_id),
            NodeInfo {
                connection_id,
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
                schedulable,
                mesh_ip: None,
            },
        );

        tracing::info!(node_id, connection_id, "Agent registered");
        (connection_id, rx)
    }

    /// Remove an agent when its control stream (`connection_id`) ends. Does
    /// nothing if the node has since reconnected on a newer stream.
    pub async fn deregister_agent(&self, node_id: &str, connection_id: u64) {
        {
            let mut state = self.inner.write().await;
            if state
                .nodes
                .get(node_id)
                .is_none_or(|info| info.connection_id != connection_id)
            {
                tracing::debug!(node_id, connection_id, "Stale agent stream ended");
                return;
            }
            state.nodes.remove(node_id);
        }
        tracing::info!(node_id, connection_id, "Agent deregistered");
        // A disconnected node's services may need rescheduling — reconcile now
        // rather than waiting for the next periodic tick.
        self.reconcile.trigger();
    }

    /// Evict nodes whose last heartbeat exceeds the timeout.
    /// Returns the IDs of evicted nodes so the caller can trigger
    /// reconciliation to reschedule their services.
    pub async fn evict_dead_nodes(&self, timeout_secs: u64) -> Vec<String> {
        let mut state = self.inner.write().await;
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let evicted: Vec<String> = state
            .nodes
            .iter()
            .filter(|(_, info)| info.last_heartbeat.elapsed() > timeout)
            .map(|(id, _)| id.to_string())
            .collect();

        for id in &evicted {
            state.nodes.remove(id.as_str());
            tracing::warn!(
                node_id = %id,
                timeout_secs,
                "Evicted dead node (heartbeat timeout)"
            );
        }
        drop(state);

        if !evicted.is_empty() {
            // Evicted nodes' services must be rescheduled — reconcile now.
            self.reconcile.trigger();
        }

        evicted
    }

    /// Get the set of currently connected node IDs.
    pub async fn connected_node_ids(&self) -> std::collections::HashSet<String> {
        let state = self.inner.read().await;
        state.nodes.keys().map(|k| k.to_string()).collect()
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

    /// Record a node's mesh address once its peer advertisement is accepted.
    pub async fn update_mesh_ip(&self, node_id: &str, ip: std::net::Ipv4Addr) {
        let mut state = self.inner.write().await;
        if let Some(node) = state.nodes.get_mut(node_id) {
            node.mesh_ip = Some(ip);
        }
    }

    /// The mesh address of a connected node that joined the mesh.
    pub async fn mesh_ip_for_node(&self, node_id: &str) -> Option<std::net::Ipv4Addr> {
        let state = self.inner.read().await;
        state.nodes.get(node_id).and_then(|n| n.mesh_ip)
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
    ///
    /// If a service newly reports as failed (was not failed in the previous
    /// report), fire the reconcile trigger so the scheduler can reschedule it
    /// promptly instead of waiting for the next periodic tick.
    pub async fn update_status(&self, node_id: &str, services: Vec<crate::proto::ServiceInstance>) {
        let mut newly_failed = false;
        {
            let mut state = self.inner.write().await;
            if let Some(node) = state.nodes.get_mut(node_id) {
                let previously_failed: std::collections::HashSet<String> = node
                    .services
                    .iter()
                    .filter(|(_, info)| info.state == ServiceState::ServiceFailed)
                    .map(|(name, _)| name.clone())
                    .collect();

                node.services.clear();
                for svc in services {
                    let svc_state =
                        ServiceState::try_from(svc.state).unwrap_or(ServiceState::Unknown);
                    if svc_state == ServiceState::ServiceFailed
                        && !previously_failed.contains(&svc.service_name)
                    {
                        newly_failed = true;
                    }
                    node.services.insert(
                        svc.service_name.clone(),
                        AgentServiceInfo {
                            instance_id: svc.instance_id,
                            store_path: svc.store_path,
                            state: svc_state,
                            health: HealthStatus::HealthUnknown,
                        },
                    );
                }
            }
        }

        if newly_failed {
            self.reconcile.trigger();
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
        let senders: Vec<(NodeId, mpsc::Sender<ServerMessage>)> = {
            let state = self.inner.read().await;
            state
                .nodes
                .iter()
                .map(|(id, node)| (id.clone(), node.tx.clone()))
                .collect()
        };

        for (node_id, tx) in senders {
            if tx.send(msg.clone()).await.is_err() {
                tracing::warn!(%node_id, "Failed to send to agent");
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
            services: Vec<(String, String, String, ServiceState, HealthStatus)>,
        }

        let snapshots: Vec<NodeSnapshot> = {
            let state = self.inner.read().await;
            state
                .nodes
                .iter()
                .map(|(id, info)| NodeSnapshot {
                    node_id: id.to_string(),
                    address: info.address.clone(),
                    pool: info.pool.clone(),
                    total_resources: info.total_resources,
                    available_resources: info.available_resources,
                    heartbeat_elapsed_secs: info.last_heartbeat.elapsed().as_secs(),
                    services: info
                        .services
                        .iter()
                        .map(|(name, svc)| {
                            (
                                name.clone(),
                                svc.instance_id.clone(),
                                svc.store_path.clone(),
                                svc.state,
                                svc.health,
                            )
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
            for (svc_name, instance_id, _store_path, state, health) in &snap.services {
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

    /// Get the store path for a service running on a specific node.
    /// Used for drift detection: compare reported store_path against desired state.
    pub async fn service_store_path(&self, node_id: &str, service_name: &str) -> Option<String> {
        let state = self.inner.read().await;
        state
            .nodes
            .get(node_id)
            .and_then(|node| node.services.get(service_name))
            .map(|svc| svc.store_path.clone())
    }

    /// Count the number of services currently running on a node.
    pub async fn service_count_for_node(&self, node_id: &str) -> usize {
        let state = self.inner.read().await;
        state
            .nodes
            .get(node_id)
            .map(|node| node.services.len())
            .unwrap_or(0)
    }

    /// Get all service store paths for a node. Returns (service_name, store_path) pairs.
    pub async fn node_store_paths(&self, node_id: &str) -> Vec<(String, String)> {
        let state = self.inner.read().await;
        state
            .nodes
            .get(node_id)
            .map(|node| {
                node.services
                    .iter()
                    .map(|(name, svc)| (name.clone(), svc.store_path.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get list of connected node IDs.
    pub async fn connected_nodes(&self) -> Vec<String> {
        let state = self.inner.read().await;
        state.nodes.keys().map(|id| id.to_string()).collect()
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
    #[allow(clippy::result_large_err)]
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

    fn instance(name: &str, state: ServiceState) -> crate::proto::ServiceInstance {
        crate::proto::ServiceInstance {
            service_name: name.into(),
            instance_id: format!("{name}-inst"),
            store_path: "/nix/store/x".into(),
            state: state as i32,
        }
    }

    #[tokio::test]
    async fn service_requests_roundtrip() {
        let state = FleetState::new();
        assert_eq!(state.service_request("api").await, None);

        let mut requests = HashMap::new();
        requests.insert("api".to_string(), (500u64, 256u64));
        requests.insert("web".to_string(), (0u64, 0u64));
        state.set_service_requests(requests).await;

        assert_eq!(state.service_request("api").await, Some((500, 256)));
        assert_eq!(state.service_request("web").await, Some((0, 0)));
        assert_eq!(state.service_request("missing").await, None);

        // A subsequent publish fully replaces the table.
        let mut next = HashMap::new();
        next.insert("api".to_string(), (1000u64, 512u64));
        state.set_service_requests(next).await;
        assert_eq!(state.service_request("api").await, Some((1000, 512)));
        assert_eq!(state.service_request("web").await, None);
    }

    #[tokio::test]
    async fn trigger_coalesces_and_wakes_waiter() {
        let trigger = ReconcileTrigger::new();
        // A trigger fired before anyone waits is not lost.
        trigger.trigger();
        // notified() should return immediately without hanging.
        tokio::time::timeout(Duration::from_millis(100), trigger.notified())
            .await
            .expect("pending trigger should wake an immediate waiter");
    }

    #[tokio::test]
    async fn stale_stream_does_not_deregister_reconnected_node() {
        let state = FleetState::new();
        let (old_conn, mut old_rx) = state
            .register_agent_connection("node-1", "10.0.0.1:1".into(), "default".into())
            .await;
        state.set_schedulable("node-1", false).await;

        // The node reconnects before the old stream's task notices it ended.
        let (new_conn, _new_rx) = state
            .register_agent_connection("node-1", "10.0.0.1:2".into(), "default".into())
            .await;
        assert_ne!(old_conn, new_conn);
        // The old session's outbound channel was dropped.
        assert!(old_rx.recv().await.is_none());

        state.deregister_agent("node-1", old_conn).await;
        assert_eq!(state.connected_nodes().await, vec!["node-1".to_string()]);
        // Cordon survives the reconnect.
        assert!(!state.is_schedulable("node-1").await);

        state.deregister_agent("node-1", new_conn).await;
        assert!(state.connected_nodes().await.is_empty());
    }

    fn spec(name: &str) -> crate::proto::ServiceSpec {
        crate::proto::ServiceSpec {
            name: name.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn assigned_desired_state_tracks_assignments_and_deploys() {
        let state = FleetState::new();
        let assignments = state.service_assignments();
        let mut rx = state
            .register_agent("node-1", "127.0.0.1:1".into(), "default".into())
            .await;

        let delivered = state
            .assign_desired_state(
                "node-1",
                crate::proto::DesiredState {
                    services: vec![spec("web"), spec("api")],
                    ..Default::default()
                },
            )
            .await;
        assert!(delivered);
        assert!(matches!(
            rx.recv().await.unwrap().payload,
            Some(ServerPayload::DesiredState(ds)) if ds.services.len() == 2
        ));
        assert!(assignments.is_assigned("node-1", "web").await);
        assert!(!assignments.is_assigned("node-2", "web").await);

        // Deploying records the store path for replay.
        assert!(
            state
                .send_deploy_command(
                    "node-1",
                    crate::proto::DeployCommand {
                        service_name: "web".into(),
                        store_path: "/nix/store/abc-web".into(),
                        ..Default::default()
                    },
                )
                .await
        );
        assert_eq!(
            state.assigned_store_path("node-1", "web").await.as_deref(),
            Some("/nix/store/abc-web")
        );

        // A later assignment replaces the set entirely.
        state
            .assign_desired_state(
                "node-1",
                crate::proto::DesiredState {
                    services: vec![spec("api")],
                    ..Default::default()
                },
            )
            .await;
        assert!(!assignments.is_assigned("node-1", "web").await);
        assert!(assignments.is_assigned("node-1", "api").await);

        // Disconnected nodes keep their assignment for replay on reconnect.
        assert!(
            !state
                .assign_desired_state(
                    "node-2",
                    crate::proto::DesiredState {
                        services: vec![spec("db")],
                        ..Default::default()
                    },
                )
                .await
        );
        let replay = state.assigned_desired_state("node-2").await.unwrap();
        assert_eq!(replay.services[0].name, "db");
        assert!(assignments.is_assigned("node-2", "db").await);
    }

    #[tokio::test]
    async fn eviction_fires_reconcile_trigger() {
        let state = FleetState::new();
        let trigger = state.reconcile_trigger();
        state
            .register_agent("dead-node", "127.0.0.1:5000".into(), "default".into())
            .await;

        // Evict with a zero timeout so the just-registered node is reaped.
        let evicted = state.evict_dead_nodes(0).await;
        assert_eq!(evicted, vec!["dead-node".to_string()]);

        tokio::time::timeout(Duration::from_millis(100), trigger.notified())
            .await
            .expect("eviction should fire the reconcile trigger");
    }

    #[tokio::test]
    async fn newly_failed_service_fires_trigger() {
        let state = FleetState::new();
        let trigger = state.reconcile_trigger();
        state
            .register_agent("node-1", "127.0.0.1:5000".into(), "default".into())
            .await;

        // First report: running — must not fire.
        state
            .update_status(
                "node-1",
                vec![instance("web", ServiceState::ServiceRunning)],
            )
            .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), trigger.notified())
                .await
                .is_err(),
            "a healthy status report must not trigger reconcile"
        );

        // Second report: the same service now failed — must fire.
        state
            .update_status("node-1", vec![instance("web", ServiceState::ServiceFailed)])
            .await;
        tokio::time::timeout(Duration::from_millis(100), trigger.notified())
            .await
            .expect("a newly failed service should fire the reconcile trigger");
    }

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
            .send_command("node-1", msg, cid, Duration::from_secs(5))
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
            .send_command("node-1", msg, cid, Duration::from_millis(100))
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
            .send_command("nonexistent", msg, cid, Duration::from_secs(5))
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
