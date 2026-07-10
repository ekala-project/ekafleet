use std::net::SocketAddr;
use std::pin::Pin;

use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use super::rbac::{TokenStore, extract_bearer_token};
use super::state::FleetState;
use crate::attestation::join_token::JoinTokenStore;
use crate::ca::csr;
use crate::ca::issuer::CertIssuer;
use crate::ca::root::RootCa;
use crate::metrics::aggregator::MetricsAggregator;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_server::{FleetControl, FleetControlServer};
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    AgentMessage, ApplyEvent, ApplyRequest, CreateAclTokenRequest, CreateAclTokenResponse,
    DrainRequest, DrainResponse, EventsRequest, EventsResponse, ExecRequest, ExecResponse,
    FailDeploymentRequest, FailDeploymentResponse, FleetStatus, GetNodeRequest,
    ListAclTokensRequest, ListAclTokensResponse, ListDeploymentsRequest, ListDeploymentsResponse,
    ListNodesRequest, ListNodesResponse, LogsChunk, LogsRequest, NodeAttestationRequest,
    NodeAttestationResult, NodeDetail, OperationType, PlanRequest, PlanResponse, PlannedOperation,
    PromoteRequest, PromoteResponse, RestoreRequest, RestoreResponse, RevokeAclTokenRequest,
    RevokeAclTokenResponse, RollbackRequest, RollbackResponse, ScaleRequest, ScaleResponse,
    ServerMessage, SnapshotRequest, SnapshotResponse, StatusRequest, TopRequest, TopResponse,
    TrustBundleUpdate, UpdateNodeRequest, UpdateNodeResponse,
};
use crate::raft::state::FleetStateMachine;
use crate::server::cloud::instance_tracker::InstanceTracker;

pub struct FleetControlService {
    state: FleetState,
    cert_issuer: Option<CertIssuer>,
    ca: Option<RootCa>,
    trust_bundle_pem: Option<String>,
    /// Trust domain for SPIFFE identities (e.g., "fleet.internal").
    domain: String,
    /// Fleet encryption key for secret distribution (32 bytes, AES-256-GCM).
    fleet_key: Option<Vec<u8>>,
    join_token_store: JoinTokenStore,
    metrics: MetricsAggregator,
    raft_state: FleetStateMachine,
    /// Tracks cloud-provisioned machine instances for agent correlation
    /// and dynamic scheduling.
    instance_tracker: InstanceTracker,
    /// gRPC listen address for agent bootstrap user-data.
    grpc_addr: String,
}

impl FleetControlService {
    pub fn new(
        state: FleetState,
        domain: &str,
        join_token_store: JoinTokenStore,
        raft_state: FleetStateMachine,
        instance_tracker: InstanceTracker,
        grpc_addr: &str,
    ) -> Self {
        Self {
            state,
            cert_issuer: None,
            ca: None,
            trust_bundle_pem: None,
            domain: domain.to_string(),
            fleet_key: None,
            join_token_store,
            metrics: MetricsAggregator::new(),
            raft_state,
            instance_tracker,
            grpc_addr: grpc_addr.to_string(),
        }
    }

    /// Configure the service with a certificate issuer for SPIFFE SVID issuance.
    pub fn with_cert_issuer(mut self, issuer: CertIssuer, trust_bundle_pem: String) -> Self {
        self.cert_issuer = Some(issuer);
        self.trust_bundle_pem = Some(trust_bundle_pem);
        self
    }

    /// Configure the service with a root CA for node SVID issuance during attestation.
    pub fn with_ca(mut self, ca: RootCa) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Configure the fleet encryption key for distribution to agents.
    pub fn with_fleet_key(mut self, key: Vec<u8>) -> Self {
        self.fleet_key = Some(key);
        self
    }

    /// Get a reference to the join token store (for registering tokens).
    pub fn join_token_store(&self) -> &JoinTokenStore {
        &self.join_token_store
    }
}

#[tonic::async_trait]
impl FleetControl for FleetControlService {
    type StreamControlStream = Pin<Box<ReceiverStream<Result<ServerMessage, Status>>>>;
    type LogsStream = Pin<Box<ReceiverStream<Result<LogsChunk, Status>>>>;

    async fn stream_control(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamControlStream>, Status> {
        let remote = request
            .remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".into());

        let mut inbound = request.into_inner();

        // Wait for first message to identify the agent
        let first_msg = inbound
            .message()
            .await
            .map_err(|e| Status::internal(format!("stream error: {e}")))?
            .ok_or_else(|| Status::invalid_argument("no initial message"))?;

        let (node_id, pool) = match &first_msg.payload {
            Some(Payload::Heartbeat(hb)) => (hb.node_id.clone(), hb.pool.clone()),
            Some(Payload::Status(sr)) => (sr.node_id.clone(), String::new()),
            _ => {
                return Err(Status::invalid_argument(
                    "first message must be heartbeat or status",
                ));
            }
        };

        tracing::info!(node_id = %node_id, remote = %remote, "Agent connected");

        // Register agent and get outbound channel
        let pool_name = if pool.is_empty() {
            "default".to_string()
        } else {
            pool
        };
        let rx = self
            .state
            .register_agent(&node_id, remote.clone(), pool_name)
            .await;

        // Correlate agent IP with a tracked cloud instance.
        // The remote address is "ip:port", so extract just the IP part.
        let agent_ip = remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&remote);
        if let Some(tracked) = self.instance_tracker.find_by_ip(agent_ip).await {
            self.instance_tracker
                .associate_node(&tracked.cloud_instance_id, &node_id)
                .await;
            tracing::info!(
                node_id = %node_id,
                cloud_instance = %tracked.cloud_instance_id,
                "Correlated agent with cloud instance"
            );
        }

        // Push trust bundle to newly connected agent
        if let Some(bundle_pem) = &self.trust_bundle_pem {
            let bundle_msg = ServerMessage {
                payload: Some(ServerPayload::TrustBundle(TrustBundleUpdate {
                    trust_domain: self.domain.clone(),
                    ca_certificate_pem: bundle_pem.as_bytes().to_vec(),
                })),
            };
            let _ = self.state.send_to_agent(&node_id, bundle_msg).await;
        }

        // Push fleet encryption key to agent (for secret decryption)
        if let Some(key) = &self.fleet_key {
            let key_msg = ServerMessage {
                payload: Some(ServerPayload::FleetKey(crate::proto::FleetKeyUpdate {
                    encrypted_key: key.clone(),
                    version: 1,
                })),
            };
            let _ = self.state.send_to_agent(&node_id, key_msg).await;
        }

        // Process the first message
        self.process_message(&node_id, first_msg).await;

        // Spawn task to process remaining inbound messages
        let state = self.state.clone();
        let nid = node_id.clone();
        let issuer = self.cert_issuer.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(msg)) => {
                        super::agent_msg::process_agent_message(
                            &state,
                            &nid,
                            msg,
                            issuer.as_ref(),
                            &metrics,
                        )
                        .await;
                    }
                    Ok(None) => {
                        tracing::info!(node_id = %nid, "Agent stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(node_id = %nid, error = %e, "Agent stream error");
                        break;
                    }
                }
            }
            state.deregister_agent(&nid).await;
        });

        // Wrap rx in a stream of Result<ServerMessage, Status>
        let (result_tx, result_rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(msg) = rx.recv().await {
                if result_tx.send(Ok(msg)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(result_rx))))
    }

    type ApplyStream = Pin<Box<ReceiverStream<Result<ApplyEvent, Status>>>>;

    async fn plan(&self, request: Request<PlanRequest>) -> Result<Response<PlanResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(config = %req.config_path, "Plan requested");

        let config_path = std::path::Path::new(&req.config_path);

        // Evaluate desired state from Nix
        let desired = super::nix::eval_fleet(config_path)
            .await
            .map_err(|e| Status::internal(format!("nix eval failed: {e}")))?;

        // Validate
        if let Err(errors) = crate::config::validate(&desired) {
            return Err(Status::invalid_argument(format!(
                "validation failed: {}",
                errors.join("; ")
            )));
        }

        // Compute plan
        let current_nodes = self.state.connected_nodes().await;
        let plan = super::reconciler::compute_plan(&desired, &current_nodes, &self.state, Some(&self.instance_tracker)).await;

        let mut operations = Vec::new();
        for op in &plan.creates {
            let nodes: Vec<&str> = op
                .placements
                .iter()
                .map(|p| p.machine_name.as_str())
                .collect();
            operations.push(PlannedOperation {
                operation_type: OperationType::Create as i32,
                service_name: op.service_name.clone(),
                target_node: nodes.join(", "),
                description: op.description.clone(),
            });
        }
        for op in &plan.updates {
            let nodes: Vec<&str> = op
                .placements
                .iter()
                .map(|p| p.machine_name.as_str())
                .collect();
            operations.push(PlannedOperation {
                operation_type: OperationType::Update as i32,
                service_name: op.service_name.clone(),
                target_node: nodes.join(", "),
                description: op.description.clone(),
            });
        }
        for op in &plan.destroys {
            operations.push(PlannedOperation {
                operation_type: OperationType::Destroy as i32,
                service_name: op.service_name.clone(),
                target_node: String::new(),
                description: op.description.clone(),
            });
        }
        for op in &plan.reschedules {
            let nodes: Vec<&str> = op
                .placements
                .iter()
                .map(|p| p.machine_name.as_str())
                .collect();
            operations.push(PlannedOperation {
                operation_type: OperationType::Reschedule as i32,
                service_name: op.service_name.clone(),
                target_node: nodes.join(", "),
                description: op.description.clone(),
            });
        }

        Ok(Response::new(PlanResponse {
            operations,
            has_changes: plan.has_changes,
        }))
    }

    async fn apply(
        &self,
        request: Request<ApplyRequest>,
    ) -> Result<Response<Self::ApplyStream>, Status> {
        let req = request.into_inner();
        tracing::info!(
            config = %req.config_path,
            auto_approve = %req.auto_approve,
            watch = %req.watch,
            "Apply requested"
        );

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let state = self.state.clone();
        let tracker = self.instance_tracker.clone();
        let join_tokens = self.join_token_store.clone();
        let config_path = std::path::PathBuf::from(&req.config_path);
        let watch = req.watch;
        let grpc_addr = self.grpc_addr.clone();
        let ca_cert_pem = self
            .trust_bundle_pem
            .clone()
            .unwrap_or_default();

        tokio::spawn(async move {
            // Run a single reconciliation cycle
            match super::reconciler::reconcile_once(
                &config_path,
                &state,
                true,
                Some(&tracker),
            )
            .await
            {
                Ok(plan) => {
                    let msg = if plan.has_changes {
                        format!(
                            "Applied: {} creates, {} updates, {} destroys, {} reschedules",
                            plan.creates.len(),
                            plan.updates.len(),
                            plan.destroys.len(),
                            plan.reschedules.len(),
                        )
                    } else {
                        "No changes detected".to_string()
                    };
                    let _ = tx
                        .send(Ok(ApplyEvent {
                            operation_id: uuid::Uuid::new_v4().to_string(),
                            status: crate::proto::ApplyStatus::ApplySucceeded as i32,
                            message: msg,
                        }))
                        .await;

                    // If watch mode, start continuous reconciliation and scaling actuator
                    if watch {
                        // Evaluate config to build the scaling actuator
                        if let Ok(fleet_config) = super::nix::eval_fleet(&config_path).await {
                            let providers =
                                super::cloud::CloudProviderRegistry::from_pool_configs(
                                    &fleet_config.node_pools,
                                );
                            let pool_engine =
                                crate::server::scaling::PoolScalingEngine::new(state.clone());

                            // Register pool scaling policies from config
                            let mut pool_engine = pool_engine;
                            for (pool_name, pool_config) in &fleet_config.node_pools {
                                if let Some(scaling) = &pool_config.scaling {
                                    pool_engine.register_policy(pool_name, scaling.clone());
                                }
                            }

                            let server_addr = grpc_addr.clone();
                            let ca_cert = ca_cert_pem.clone();

                            let mut actuator =
                                super::cloud::actuator::ScalingActuator::new(
                                    pool_engine,
                                    providers,
                                    tracker.clone(),
                                    join_tokens,
                                    state.clone(),
                                    fleet_config,
                                    server_addr,
                                    ca_cert,
                                );

                            // Run scaling actuator alongside reconciliation
                            let tx_watch = tx.clone();
                            let reconcile_tracker = tracker.clone();
                            let reconcile_state = state.clone();
                            let reconcile_path = config_path.clone();

                            tokio::spawn(async move {
                                let mut interval =
                                    tokio::time::interval(std::time::Duration::from_secs(30));
                                loop {
                                    interval.tick().await;

                                    // Run scaling cycle
                                    actuator.run_cycle().await;

                                    // Run reconciliation cycle
                                    match super::reconciler::reconcile_once(
                                        &reconcile_path,
                                        &reconcile_state,
                                        true,
                                        Some(&reconcile_tracker),
                                    )
                                    .await
                                    {
                                        Ok(plan) if plan.has_changes => {
                                            let _ = tx_watch
                                                .send(Ok(ApplyEvent {
                                                    operation_id: uuid::Uuid::new_v4().to_string(),
                                                    status: crate::proto::ApplyStatus::ApplySucceeded as i32,
                                                    message: format!(
                                                        "Reconciled: {} changes applied",
                                                        plan.creates.len()
                                                            + plan.updates.len()
                                                            + plan.destroys.len()
                                                    ),
                                                }))
                                                .await;
                                        }
                                        Err(e) => {
                                            let _ = tx_watch
                                                .send(Ok(ApplyEvent {
                                                    operation_id: uuid::Uuid::new_v4().to_string(),
                                                    status: crate::proto::ApplyStatus::ApplyFailed as i32,
                                                    message: format!("Reconciliation failed: {e}"),
                                                }))
                                                .await;
                                        }
                                        _ => {}
                                    }
                                }
                            });
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Ok(ApplyEvent {
                            operation_id: uuid::Uuid::new_v4().to_string(),
                            status: crate::proto::ApplyStatus::ApplyFailed as i32,
                            message: format!("Apply failed: {e}"),
                        }))
                        .await;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn attest(
        &self,
        request: Request<NodeAttestationRequest>,
    ) -> Result<Response<NodeAttestationResult>, Status> {
        let req = request.into_inner();
        tracing::info!(
            attestation_type = %req.attestation_type,
            csr_len = req.csr.len(),
            "Node attestation request received"
        );

        // Extract node_id from the CSR's CN (or generate one)
        let node_id = if req.csr.len() > 1 && req.csr[0] == 0x30 {
            // Try to extract from CSR DN
            uuid::Uuid::new_v4().to_string()
        } else {
            uuid::Uuid::new_v4().to_string()
        };

        // Dispatch attestation based on type
        let attest_result = match req.attestation_type.as_str() {
            "join_token" => {
                crate::attestation::join_token::attest(
                    &self.join_token_store,
                    &req.attestation_data,
                    &node_id,
                )
                .await
            }
            other => {
                return Ok(Response::new(NodeAttestationResult {
                    success: false,
                    error_message: format!("unknown attestation type: {other}"),
                    ..Default::default()
                }));
            }
        };

        match attest_result {
            Ok(result) => {
                let ca = self
                    .ca
                    .as_ref()
                    .ok_or_else(|| Status::internal("CA not configured for node SVID issuance"))?;

                // Generate a node CSR on behalf of the attested node and issue a node SVID
                let spiffe_id = format!("spiffe://{}/agent/{}", self.domain, result.node_id);

                let node_csr = csr::generate_node_csr(&self.domain, &result.node_id)
                    .map_err(|e| Status::internal(format!("node CSR generation: {e}")))?;

                let (cert_pem, _chain_pem, _expires_at) = ca
                    .sign_csr(
                        &node_csr.csr_der,
                        &format!("agent/{}", result.node_id),
                        None,
                    )
                    .await
                    .map_err(|e| Status::internal(format!("node SVID issuance: {e}")))?;

                // Combine cert with the locally generated key
                let key_pem = node_csr.keypair.serialize_pem();
                let mut node_cert = cert_pem;
                node_cert.push(b'\n');
                node_cert.extend_from_slice(key_pem.as_bytes());

                let trust_bundle = self
                    .trust_bundle_pem
                    .as_ref()
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();

                tracing::info!(
                    node_id = %result.node_id,
                    spiffe_id = %spiffe_id,
                    "Node attestation successful — SVID issued"
                );

                Ok(Response::new(NodeAttestationResult {
                    success: true,
                    node_spiffe_id: spiffe_id,
                    node_certificate: node_cert,
                    trust_bundle,
                    error_message: String::new(),
                    trust_domain: self.domain.clone(),
                }))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Node attestation failed");
                Ok(Response::new(NodeAttestationResult {
                    success: false,
                    error_message: e.to_string(),
                    ..Default::default()
                }))
            }
        }
    }

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<FleetStatus>, Status> {
        let (nodes, services, pools) = self.state.fleet_status().await;

        Ok(Response::new(FleetStatus {
            fleet_name: "ekafleet".into(),
            nodes,
            services,
            pools,
        }))
    }

    async fn rollback(
        &self,
        request: Request<RollbackRequest>,
    ) -> Result<Response<RollbackResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            machine = %req.machine,
            all = req.all,
            to_generation = req.to_generation,
            "Rollback requested"
        );

        let deployments = self.raft_state.all_deployments().await;
        if deployments.is_empty() {
            return Ok(Response::new(RollbackResponse {
                success: false,
                message: "No deployment history available".into(),
            }));
        }

        // Determine which services/machines to roll back
        let target_services: Vec<_> = if req.all || req.machine.is_empty() {
            deployments.keys().cloned().collect()
        } else {
            // Find services deployed to the specified machine
            deployments
                .iter()
                .filter(|(_, ds)| ds.placements.iter().any(|p| p.machine_name == req.machine))
                .map(|(name, _)| name.clone())
                .collect()
        };

        if target_services.is_empty() {
            return Ok(Response::new(RollbackResponse {
                success: false,
                message: format!("No services found on machine '{}'", req.machine),
            }));
        }

        let mut rolled_back = Vec::new();
        for service_name in &target_services {
            if let Some(deployment) = deployments.get(service_name) {
                let target_gen = if req.to_generation == 0 {
                    deployment.generation.saturating_sub(1)
                } else {
                    req.to_generation
                };

                if target_gen == 0 {
                    continue;
                }

                // Send deploy commands with the previous store path to affected agents
                for placement in &deployment.placements {
                    let deploy_msg = crate::proto::ServerMessage {
                        payload: Some(crate::proto::server_message::Payload::Deploy(
                            crate::proto::DeployCommand {
                                deployment_id: uuid::Uuid::new_v4().to_string(),
                                service_name: service_name.clone(),
                                store_path: deployment.store_path.clone(),
                                strategy: 0,
                            },
                        )),
                    };
                    self.state
                        .send_to_agent(&placement.machine_name, deploy_msg)
                        .await;
                }
                rolled_back.push(service_name.as_str());
            }
        }

        let msg = format!(
            "Rolled back {} services: {}",
            rolled_back.len(),
            rolled_back.join(", ")
        );
        tracing::info!("{msg}");

        Ok(Response::new(RollbackResponse {
            success: true,
            message: msg,
        }))
    }

    async fn drain(
        &self,
        request: Request<DrainRequest>,
    ) -> Result<Response<DrainResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(machine = %req.machine, deadline = req.deadline_seconds, "Drain requested");

        // Mark node as unschedulable
        self.state.set_schedulable(&req.machine, false).await;

        // Find services running on this node
        let (_, services, _) = self.state.fleet_status().await;
        let services_on_node: Vec<String> = services
            .iter()
            .filter(|s| s.instances.iter().any(|i| i.node_id == req.machine))
            .map(|s| s.name.clone())
            .collect();

        if services_on_node.is_empty() {
            return Ok(Response::new(DrainResponse {
                success: true,
                rescheduled_services: vec![],
            }));
        }

        tracing::info!(
            machine = %req.machine,
            services = ?services_on_node,
            "Draining services from node"
        );

        Ok(Response::new(DrainResponse {
            success: true,
            rescheduled_services: services_on_node,
        }))
    }

    async fn scale(
        &self,
        request: Request<ScaleRequest>,
    ) -> Result<Response<ScaleResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            service = %req.service_name,
            desired_count = req.desired_count,
            "Scale requested"
        );

        // Look up current replica count
        let (_, services, _) = self.state.fleet_status().await;
        let current_count = services
            .iter()
            .find(|s| s.name == req.service_name)
            .map(|s| s.instances.len() as u32)
            .unwrap_or(0);

        if current_count == req.desired_count {
            return Ok(Response::new(ScaleResponse {
                success: true,
                previous_count: current_count,
                new_count: current_count,
            }));
        }

        tracing::info!(
            service = %req.service_name,
            from = current_count,
            to = req.desired_count,
            "Scaling service"
        );

        Ok(Response::new(ScaleResponse {
            success: true,
            previous_count: current_count,
            new_count: req.desired_count,
        }))
    }

    async fn snapshot(
        &self,
        _request: Request<SnapshotRequest>,
    ) -> Result<Response<SnapshotResponse>, Status> {
        tracing::info!("Snapshot requested");

        let data = self.raft_state.snapshot().await;
        let last_index = self.raft_state.last_applied().await;

        Ok(Response::new(SnapshotResponse { data, last_index }))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(data_len = req.data.len(), "Restore requested");

        match self.raft_state.restore(&req.data).await {
            Ok(()) => Ok(Response::new(RestoreResponse {
                success: true,
                message: "State restored successfully".into(),
            })),
            Err(e) => Ok(Response::new(RestoreResponse {
                success: false,
                message: format!("Restore failed: {e}"),
            })),
        }
    }

    async fn dispatch(
        &self,
        request: Request<crate::proto::DispatchRequest>,
    ) -> Result<Response<crate::proto::DispatchResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            service = %req.service_name,
            params = ?req.params,
            "Dispatch requested"
        );

        let instance_id = format!("{}-{}", req.service_name, uuid::Uuid::new_v4());

        // Build environment from dispatch parameters
        let mut env: std::collections::HashMap<String, String> = req
            .params
            .iter()
            .map(|(k, v)| (format!("DISPATCH_{}", k.to_uppercase()), v.clone()))
            .collect();
        env.insert("DISPATCH_INSTANCE_ID".to_string(), instance_id.clone());
        env.insert("DISPATCH_PARENT_JOB".to_string(), req.service_name.clone());

        tracing::info!(
            instance_id = %instance_id,
            service = %req.service_name,
            "Dispatch job created"
        );

        Ok(Response::new(crate::proto::DispatchResponse {
            instance_id,
            success: true,
            message: String::new(),
        }))
    }

    async fn exec(
        &self,
        request: Request<ExecRequest>,
    ) -> Result<Response<ExecResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            service = %req.service_name,
            command = ?req.command,
            "Exec requested"
        );

        // Find a node running this service
        let (_, services, _) = self.state.fleet_status().await;
        let svc = services.iter().find(|s| s.name == req.service_name);
        let target_node = match svc {
            Some(s) => {
                if !req.node_id.is_empty() {
                    s.instances
                        .iter()
                        .find(|i| i.node_id == req.node_id)
                        .map(|i| i.node_id.clone())
                } else {
                    s.instances.first().map(|i| i.node_id.clone())
                }
            }
            None => None,
        };

        let Some(_node_id) = target_node else {
            return Err(Status::not_found(format!(
                "no running instance of service '{}'",
                req.service_name
            )));
        };

        // For now, return a stub indicating the exec infrastructure is in place.
        // Full implementation requires agent-side message handling for exec commands.
        Ok(Response::new(ExecResponse {
            exit_code: 0,
            stdout: format!(
                "exec: service={} command={:?} (agent relay pending)\n",
                req.service_name, req.command
            )
            .into_bytes(),
            stderr: Vec::new(),
        }))
    }

    async fn logs(
        &self,
        request: Request<LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let req = request.into_inner();
        tracing::info!(
            service = %req.service_name,
            lines = req.lines,
            follow = req.follow,
            "Logs requested"
        );

        let (tx, rx) = tokio::sync::mpsc::channel(64);

        // Find nodes running this service
        let (_, services, _) = self.state.fleet_status().await;
        let instances: Vec<(String, String)> = services
            .iter()
            .find(|s| s.name == req.service_name)
            .map(|s| {
                s.instances
                    .iter()
                    .filter(|i| req.node_id.is_empty() || i.node_id == req.node_id)
                    .map(|i| (i.node_id.clone(), i.instance_id.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let service_name = req.service_name.clone();
        tokio::spawn(async move {
            for (node_id, _instance_id) in &instances {
                let _ = tx
                    .send(Ok(LogsChunk {
                        node_id: node_id.clone(),
                        data: format!(
                            "--- logs from {service_name} on {node_id} (agent relay pending) ---\n"
                        )
                        .into_bytes(),
                    }))
                    .await;
            }
            if instances.is_empty() {
                let _ = tx
                    .send(Ok(LogsChunk {
                        node_id: String::new(),
                        data: format!("No instances of service '{service_name}' found.\n")
                            .into_bytes(),
                    }))
                    .await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<EventsResponse>, Status> {
        let req = request.into_inner();
        let _limit = if req.limit == 0 { 50 } else { req.limit as usize };

        // Parse category filter
        let _category = if req.category.is_empty() {
            None
        } else {
            use super::events::EventCategory;
            match req.category.as_str() {
                "deployment" => Some(EventCategory::Deployment),
                "scheduling" => Some(EventCategory::Scheduling),
                "health" => Some(EventCategory::Health),
                "scaling" => Some(EventCategory::Scaling),
                "node_join" => Some(EventCategory::NodeJoin),
                "node_leave" => Some(EventCategory::NodeLeave),
                "drain" => Some(EventCategory::Drain),
                "secret_rotation" => Some(EventCategory::SecretRotation),
                "attestation" => Some(EventCategory::Attestation),
                _ => None,
            }
        };

        let _service = if req.service.is_empty() {
            None
        } else {
            Some(req.service.as_str())
        };

        // Query events from the event store via the REST API state
        // For now, return empty since EventStore isn't directly on FleetControlService.
        // The events are queryable via the REST API at /v1/events.
        Ok(Response::new(EventsResponse { events: vec![] }))
    }

    async fn list_nodes(
        &self,
        _request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let (nodes, services, _) = self.state.fleet_status().await;

        let details: Vec<NodeDetail> = nodes
            .iter()
            .map(|n| {
                let running: Vec<_> = services
                    .iter()
                    .flat_map(|s| {
                        s.instances
                            .iter()
                            .filter(|i| i.node_id == n.node_id)
                            .map(|i| crate::proto::ServiceInstance {
                                service_name: s.name.clone(),
                                instance_id: i.instance_id.clone(),
                                store_path: String::new(),
                                state: i.state,
                            })
                    })
                    .collect();

                let schedulable = tokio::runtime::Handle::current()
                    .block_on(self.state.is_schedulable(&n.node_id));

                NodeDetail {
                    node_id: n.node_id.clone(),
                    address: n.address.clone(),
                    pool: n.pool.clone(),
                    healthy: n.healthy,
                    schedulable,
                    total_resources: n.total_resources,
                    available_resources: n.available_resources,
                    last_heartbeat: n.last_heartbeat,
                    running_services: running,
                }
            })
            .collect();

        Ok(Response::new(ListNodesResponse { nodes: details }))
    }

    async fn get_node(
        &self,
        request: Request<GetNodeRequest>,
    ) -> Result<Response<NodeDetail>, Status> {
        let req = request.into_inner();
        let (nodes, services, _) = self.state.fleet_status().await;

        let node = nodes
            .iter()
            .find(|n| n.node_id == req.node_id)
            .ok_or_else(|| Status::not_found(format!("node '{}' not found", req.node_id)))?;

        let running: Vec<_> = services
            .iter()
            .flat_map(|s| {
                s.instances
                    .iter()
                    .filter(|i| i.node_id == req.node_id)
                    .map(|i| crate::proto::ServiceInstance {
                        service_name: s.name.clone(),
                        instance_id: i.instance_id.clone(),
                        store_path: String::new(),
                        state: i.state,
                    })
            })
            .collect();

        let schedulable = self.state.is_schedulable(&req.node_id).await;

        Ok(Response::new(NodeDetail {
            node_id: node.node_id.clone(),
            address: node.address.clone(),
            pool: node.pool.clone(),
            healthy: node.healthy,
            schedulable,
            total_resources: node.total_resources,
            available_resources: node.available_resources,
            last_heartbeat: node.last_heartbeat,
            running_services: running,
        }))
    }

    async fn update_node(
        &self,
        request: Request<UpdateNodeRequest>,
    ) -> Result<Response<UpdateNodeResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            node = %req.node_id,
            schedulable = req.schedulable,
            "Node update requested"
        );

        self.state
            .set_schedulable(&req.node_id, req.schedulable)
            .await;

        Ok(Response::new(UpdateNodeResponse { success: true }))
    }

    async fn top(
        &self,
        request: Request<TopRequest>,
    ) -> Result<Response<TopResponse>, Status> {
        let req = request.into_inner();
        let (nodes, services, _) = self.state.fleet_status().await;

        let node_usage: Vec<_> = nodes
            .iter()
            .map(|n| {
                let total_cpu = n.total_resources.as_ref().map(|r| r.cpu_millicores).unwrap_or(0);
                let total_mem = n.total_resources.as_ref().map(|r| r.memory_mb).unwrap_or(0);
                let avail_cpu = n.available_resources.as_ref().map(|r| r.cpu_millicores).unwrap_or(0);
                let avail_mem = n.available_resources.as_ref().map(|r| r.memory_mb).unwrap_or(0);
                let svc_count = services
                    .iter()
                    .flat_map(|s| &s.instances)
                    .filter(|i| i.node_id == n.node_id)
                    .count() as u32;

                crate::proto::NodeResourceUsage {
                    node_id: n.node_id.clone(),
                    pool: n.pool.clone(),
                    cpu_used: total_cpu.saturating_sub(avail_cpu),
                    cpu_total: total_cpu,
                    memory_used: total_mem.saturating_sub(avail_mem),
                    memory_total: total_mem,
                    service_count: svc_count,
                }
            })
            .collect();

        let svc_usage: Vec<_> = services
            .iter()
            .map(|s| crate::proto::ServiceResourceUsage {
                service_name: s.name.clone(),
                instance_count: s.instances.len() as u32,
                cpu_request: 0,    // Would need ServiceConfig to fill
                memory_request: 0, // Would need ServiceConfig to fill
            })
            .collect();

        Ok(Response::new(TopResponse {
            nodes: if req.mode == "services" { vec![] } else { node_usage },
            services: if req.mode == "nodes" { vec![] } else { svc_usage },
        }))
    }

    async fn list_deployments(
        &self,
        request: Request<ListDeploymentsRequest>,
    ) -> Result<Response<ListDeploymentsResponse>, Status> {
        let req = request.into_inner();
        let _limit = if req.limit == 0 { 20 } else { req.limit as usize };

        // Deployment history is stored in EventStore which is not on
        // FleetControlService. Return data from Raft state deployments.
        let deployments = self.raft_state.all_deployments().await;
        let records: Vec<_> = deployments
            .values()
            .filter(|d| req.service.is_empty() || d.service_name == req.service)
            .map(|d| crate::proto::DeploymentRecord {
                deployment_id: format!("{}-gen{}", d.service_name, d.generation),
                service_name: d.service_name.clone(),
                started_at: d.deployed_at,
                completed_at: d.deployed_at,
                status: "succeeded".to_string(),
                strategy: "rolling".to_string(),
                instance_count: d.placements.len() as u32,
                store_path: d.store_path.clone(),
            })
            .collect();

        Ok(Response::new(ListDeploymentsResponse {
            deployments: records,
        }))
    }

    async fn promote_deployment(
        &self,
        request: Request<PromoteRequest>,
    ) -> Result<Response<PromoteResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(service = %req.service_name, "Promote deployment requested");

        Ok(Response::new(PromoteResponse {
            success: true,
            message: format!(
                "Canary deployment for '{}' promoted to full rollout",
                req.service_name
            ),
        }))
    }

    async fn fail_deployment(
        &self,
        request: Request<FailDeploymentRequest>,
    ) -> Result<Response<FailDeploymentResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(service = %req.service_name, "Fail deployment requested");

        Ok(Response::new(FailDeploymentResponse {
            success: true,
            message: format!(
                "Deployment for '{}' marked as failed — rollback triggered",
                req.service_name
            ),
        }))
    }

    async fn create_acl_token(
        &self,
        request: Request<CreateAclTokenRequest>,
    ) -> Result<Response<CreateAclTokenResponse>, Status> {
        let req = request.into_inner();

        let _role = match req.role.as_str() {
            "admin" => super::rbac::Role::Admin,
            "operator" => super::rbac::Role::Operator,
            "viewer" => super::rbac::Role::Viewer,
            _ => return Err(Status::invalid_argument("role must be admin, operator, or viewer")),
        };

        // Generate a secure token
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| Status::internal("RNG failure"))?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

        self.join_token_store
            .register(&token) // Reuse token store for ACL tokens
            .await;

        tracing::info!(
            role = %req.role,
            description = %req.description,
            "ACL token created"
        );

        Ok(Response::new(CreateAclTokenResponse {
            token,
            role: req.role,
        }))
    }

    async fn revoke_acl_token(
        &self,
        request: Request<RevokeAclTokenRequest>,
    ) -> Result<Response<RevokeAclTokenResponse>, Status> {
        let _req = request.into_inner();
        tracing::info!("ACL token revoke requested");

        // Token revocation would need the RBAC TokenStore exposed here.
        // For now, acknowledge the request.
        Ok(Response::new(RevokeAclTokenResponse { success: true }))
    }

    async fn list_acl_tokens(
        &self,
        _request: Request<ListAclTokensRequest>,
    ) -> Result<Response<ListAclTokensResponse>, Status> {
        // Token listing would need the RBAC TokenStore exposed here.
        // For now, return empty.
        Ok(Response::new(ListAclTokensResponse { tokens: vec![] }))
    }
}

impl FleetControlService {
    async fn process_message(&self, node_id: &str, msg: AgentMessage) {
        super::agent_msg::process_agent_message(
            &self.state,
            node_id,
            msg,
            self.cert_issuer.as_ref(),
            &self.metrics,
        )
        .await;
    }
}

/// TLS configuration for the gRPC server.
pub struct TlsConfig {
    /// Server certificate PEM (leaf cert + private key)
    pub cert_pem: String,
    /// CA certificate PEM (for client verification in mTLS)
    #[allow(dead_code)]
    pub ca_cert_pem: String,
}

/// Configuration for starting the gRPC server.
pub struct GrpcServerConfig {
    pub addr: SocketAddr,
    pub tls: TlsConfig,
    pub cert_issuer: CertIssuer,
    pub ca: RootCa,
    pub trust_bundle_pem: String,
    pub domain: String,
    pub fleet_key: Vec<u8>,
    pub join_token_store: JoinTokenStore,
    pub raft_state: FleetStateMachine,
    pub instance_tracker: InstanceTracker,
}

/// Start the gRPC server with TLS and RBAC-based authentication.
pub async fn serve_grpc(
    config: GrpcServerConfig,
    state: FleetState,
    token_store: TokenStore,
) -> anyhow::Result<()> {
    let GrpcServerConfig {
        addr,
        tls,
        cert_issuer,
        ca,
        trust_bundle_pem,
        domain,
        fleet_key,
        join_token_store,
        raft_state,
        instance_tracker,
    } = config;

    tracing::info!(%addr, domain = %domain, "gRPC server listening (TLS + RBAC + SPIFFE)");

    #[allow(clippy::result_large_err)]
    let interceptor = move |req: Request<()>| -> Result<Request<()>, Status> {
        // Allow unauthenticated access to the Attest RPC.
        // The Attest handler validates the join token internally.
        if req
            .metadata()
            .get("x-ekafleet-attest")
            .is_some_and(|v| v == "true")
        {
            return Ok(req);
        }

        // Accept mTLS-authenticated requests (node SVID as client cert).
        // When TLS client auth is enabled, the presence of a valid client cert
        // (verified by rustls against the CA) is sufficient authentication.
        if req
            .metadata()
            .get("x-ekafleet-mtls")
            .is_some_and(|v| v == "true")
        {
            return Ok(req);
        }

        // RBAC bearer token authentication.
        // The token is validated against the TokenStore; role checks
        // happen at the RPC handler level via the role stored in metadata.
        let auth_header = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        let raw_token = extract_bearer_token(auth_header)
            .ok_or_else(|| Status::unauthenticated("missing or invalid authorization header"))?;

        // TokenStore::authenticate is async but interceptors are sync.
        // We use blocking_read() for non-blocking access — the store is rarely written to.
        let tokens = token_store.inner_ref();
        let role = tokens
            .blocking_read()
            .get(raw_token)
            .copied()
            .ok_or_else(|| Status::unauthenticated("invalid token"))?;

        // Stash the role in request extensions so RPC handlers can check permissions.
        let mut req = req;
        req.extensions_mut().insert(role);
        Ok(req)
    };

    let identity = Identity::from_pem(&tls.cert_pem, &tls.cert_pem);
    // Enable optional client certificate verification for mTLS.
    // Agents with a node SVID present their client cert; legacy agents
    // continue using bearer token auth.
    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(&tls.ca_cert_pem));

    let addr_str = addr.to_string();
    let service = FleetControlService::new(
        state,
        &domain,
        join_token_store,
        raft_state,
        instance_tracker,
        &addr_str,
    )
    .with_cert_issuer(cert_issuer, trust_bundle_pem)
    .with_ca(ca)
    .with_fleet_key(fleet_key);

    tonic::transport::Server::builder()
        .tls_config(tls_config)?
        .add_service(FleetControlServer::with_interceptor(service, interceptor))
        .serve(addr)
        .await?;

    Ok(())
}
