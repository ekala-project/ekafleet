use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use super::events::EventStore;
use super::rbac::{PeerIdentity, TokenStore, extract_bearer_token};
use super::state::FleetState;
use crate::attestation::join_token::JoinTokenStore;
use crate::ca::CaSigner;
use crate::ca::csr;
use crate::ca::issuer::CertIssuer;
use crate::metrics::aggregator::MetricsAggregator;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_server::{FleetControl, FleetControlServer};
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    AgentMessage, ApplyEvent, ApplyRequest, CreateAclTokenRequest, CreateAclTokenResponse,
    DiffGenerationsRequest, DiffGenerationsResponse, DrainRequest, DrainResponse, EventsRequest,
    EventsResponse, ExecRequest, ExecResponse, FailDeploymentRequest, FailDeploymentResponse,
    FleetStatus, GetNodeRequest, InspectServiceRequest, InspectServiceResponse,
    ListAclTokensRequest, ListAclTokensResponse, ListDeploymentsRequest, ListDeploymentsResponse,
    ListGenerationsRequest, ListGenerationsResponse, ListNodesRequest, ListNodesResponse,
    LogsChunk, LogsRequest, NodeAttestationRequest, NodeAttestationResult, NodeDetail,
    OperationType, PlanRequest, PlanResponse, PlannedOperation, PromoteRequest, PromoteResponse,
    RestoreRequest, RestoreResponse, RevokeAclTokenRequest, RevokeAclTokenResponse,
    RollbackRequest, RollbackResponse, RotateFleetKeyRequest, RotateFleetKeyResponse, ScaleRequest,
    ScaleResponse, ServerMessage, SnapshotRequest, SnapshotResponse, StatusRequest,
    SwitchGenerationRequest, SwitchGenerationResponse, SystemGcRequest, SystemGcResponse,
    SystemRebootRequest, SystemRebootResponse, SystemRebuildRequest, SystemRebuildResponse,
    TopRequest, TopResponse, TrustBundleUpdate, UpdateNodeRequest, UpdateNodeResponse,
};
use crate::raft::state::FleetStateMachine;
use crate::secrets::store::SecretStore;
use crate::server::cloud::instance_tracker::InstanceTracker;

/// Fleet encryption key with version tracking for rotation.
pub struct FleetKeyState {
    pub key: Vec<u8>,
    pub version: u64,
}

pub struct FleetControlService {
    pub(super) state: FleetState,
    pub(super) cert_issuer: Option<CertIssuer>,
    pub(super) ca: Option<Arc<dyn CaSigner>>,
    pub(super) trust_bundle_pem: Option<String>,
    /// Trust domain for SPIFFE identities (e.g., "fleet.internal").
    pub(super) domain: String,
    /// Fleet encryption key state — supports runtime rotation.
    pub(super) fleet_key: Arc<RwLock<FleetKeyState>>,
    /// Server-side encrypted secret storage (shared for rotation).
    pub(super) secret_store: Arc<RwLock<SecretStore>>,
    /// Path to persist the fleet key on disk.
    pub(super) data_dir: std::path::PathBuf,
    pub(super) join_token_store: JoinTokenStore,
    pub(super) metrics: MetricsAggregator,
    pub(super) raft_state: FleetStateMachine,
    /// Tracks cloud-provisioned machine instances for agent correlation
    /// and dynamic scheduling.
    pub(super) instance_tracker: InstanceTracker,
    /// gRPC listen address for agent bootstrap user-data.
    pub(super) grpc_addr: String,
    pub(super) event_store: EventStore,
    pub(super) token_store: TokenStore,
}

impl FleetControlService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: FleetState,
        domain: &str,
        join_token_store: JoinTokenStore,
        raft_state: FleetStateMachine,
        instance_tracker: InstanceTracker,
        grpc_addr: &str,
        event_store: EventStore,
        token_store: TokenStore,
        data_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            state,
            cert_issuer: None,
            ca: None,
            trust_bundle_pem: None,
            domain: domain.to_string(),
            fleet_key: Arc::new(RwLock::new(FleetKeyState {
                key: Vec::new(),
                version: 0,
            })),
            secret_store: Arc::new(RwLock::new(SecretStore::new(&[0u8; 32]))),
            data_dir,
            join_token_store,
            metrics: MetricsAggregator::new(),
            raft_state,
            instance_tracker,
            grpc_addr: grpc_addr.to_string(),
            event_store,
            token_store,
        }
    }

    /// Configure the service with a certificate issuer for SPIFFE SVID issuance.
    pub fn with_cert_issuer(mut self, issuer: CertIssuer, trust_bundle_pem: String) -> Self {
        self.cert_issuer = Some(issuer);
        self.trust_bundle_pem = Some(trust_bundle_pem);
        self
    }

    /// Configure the service with a CA signer for node SVID issuance during attestation.
    pub fn with_ca(mut self, ca: Arc<dyn CaSigner>) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Configure the fleet encryption key and secret store.
    pub fn with_fleet_key(self, key: Vec<u8>) -> Self {
        // Initialize the secret store with this key and set version 1
        let store = SecretStore::new(
            <&[u8; 32]>::try_from(key.as_slice()).expect("fleet key must be 32 bytes"),
        );
        *self.fleet_key.blocking_write() = FleetKeyState {
            key: key.clone(),
            version: 1,
        };
        *self.secret_store.blocking_write() = store;
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

        // Push per-agent derived encryption key (for secret decryption).
        // The fleet master key stays on the server; each agent receives a unique
        // key derived via HKDF so that compromising one agent does not expose
        // secrets encrypted for other agents.
        {
            let fk = self.fleet_key.read().await;
            if fk.version > 0 {
                let agent_spiffe_id = format!("spiffe://{}/agent/{}", self.domain, node_id);
                let derived =
                    crate::secrets::key_derivation::derive_agent_key(&fk.key, &agent_spiffe_id);
                let key_msg = ServerMessage {
                    payload: Some(ServerPayload::FleetKey(crate::proto::FleetKeyUpdate {
                        encrypted_key: derived.to_vec(),
                        version: fk.version,
                    })),
                };
                let _ = self.state.send_to_agent(&node_id, key_msg).await;
            }
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
        let plan = super::reconciler::compute_plan(
            &desired,
            &current_nodes,
            &self.state,
            Some(&self.instance_tracker),
            &self.raft_state,
        )
        .await;

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
        let ca_cert_pem = self.trust_bundle_pem.clone().unwrap_or_default();
        let raft_state = self.raft_state.clone();
        let event_store = self.event_store.clone();

        tokio::spawn(async move {
            // Run a single reconciliation cycle
            match super::reconciler::reconcile_once(
                &config_path,
                &state,
                true,
                Some(&tracker),
                &raft_state,
            )
            .await
            {
                Ok(plan) => {
                    // Emit events for policy-blocked services
                    for block in &plan.policy_blocked {
                        event_store
                            .emit_detail(
                                super::events::EventLevel::Error,
                                super::events::EventCategory::Scheduling,
                                Some(&block.service_name),
                                None,
                                &format!(
                                    "Deployment blocked by policy '{}': {}",
                                    block.rule_name, block.message
                                ),
                            )
                            .await;
                    }

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
                        if let Ok(mut fleet_config) = super::nix::eval_fleet(&config_path).await {
                            // Resolve managed cloud images: build and register
                            // any NixOS images whose store path has changed.
                            let image_tracker =
                                super::cloud::image_tracker::ImageTracker::new(raft_state.clone());
                            let mut image_managers: std::collections::HashMap<
                                String,
                                Box<dyn super::cloud::image::CloudImageManagerDyn>,
                            > = std::collections::HashMap::new();
                            let mut active_hashes: std::collections::HashMap<String, String> =
                                std::collections::HashMap::new();

                            for (pool_name, pool_config) in &mut fleet_config.node_pools {
                                let Some(cloud) = &mut pool_config.cloud else {
                                    continue;
                                };
                                let Some(image_config) = &cloud.image else {
                                    continue;
                                };

                                let manager =
                                    super::cloud::image::build_image_manager(cloud, image_config);
                                let manager_key = match cloud.provider {
                                    crate::config::CloudProviderType::Aws => "aws",
                                    crate::config::CloudProviderType::Azure => "azure",
                                    crate::config::CloudProviderType::Gcp => "gcp",
                                };

                                match super::cloud::image::ensure_image(
                                    pool_name,
                                    cloud,
                                    image_config,
                                    &fleet_config.name,
                                    &image_tracker,
                                    manager.as_ref(),
                                )
                                .await
                                {
                                    Ok(resolved_id) => {
                                        // Track the active hash for cleanup
                                        if let Ok(toplevel) = super::nix::build(&format!(
                                            "{}.config.system.build.toplevel",
                                            image_config.nixos_config
                                        ))
                                        .await
                                            && let Some(h) =
                                                super::cloud::image::extract_store_path_hash(
                                                    &toplevel,
                                                )
                                        {
                                            active_hashes.insert(pool_name.clone(), h.to_string());
                                        }

                                        cloud.image_id = Some(resolved_id);
                                        image_managers
                                            .entry(manager_key.to_string())
                                            .or_insert(manager);
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            pool = %pool_name,
                                            error = %e,
                                            "Failed to resolve managed cloud image"
                                        );
                                    }
                                }
                            }

                            // Clean up expired images
                            super::cloud::image::cleanup_expired_images(
                                &fleet_config,
                                &image_tracker,
                                &image_managers,
                                &active_hashes,
                            )
                            .await;

                            let providers = super::cloud::CloudProviderRegistry::from_pool_configs(
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

                            let mut actuator = super::cloud::actuator::ScalingActuator::new(
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
                            let reconcile_raft = raft_state.clone();
                            let reconcile_events = event_store.clone();

                            let reconcile_trigger = reconcile_state.reconcile_trigger();
                            tokio::spawn(async move {
                                let mut interval =
                                    tokio::time::interval(std::time::Duration::from_secs(30));
                                loop {
                                    // Reconcile on the periodic tick OR as soon as an
                                    // event (node eviction, agent disconnect, service
                                    // crash) requests it — whichever comes first.
                                    tokio::select! {
                                        _ = interval.tick() => {}
                                        _ = reconcile_trigger.notified() => {
                                            tracing::debug!(
                                                "Reconcile triggered by fleet event"
                                            );
                                        }
                                    }

                                    // Run scaling cycle
                                    actuator.run_cycle().await;

                                    // Run reconciliation cycle
                                    match super::reconciler::reconcile_once(
                                        &reconcile_path,
                                        &reconcile_state,
                                        true,
                                        Some(&reconcile_tracker),
                                        &reconcile_raft,
                                    )
                                    .await
                                    {
                                        Ok(plan) if plan.has_changes => {
                                            for block in &plan.policy_blocked {
                                                reconcile_events
                                                    .emit_detail(
                                                        super::events::EventLevel::Error,
                                                        super::events::EventCategory::Scheduling,
                                                        Some(&block.service_name),
                                                        None,
                                                        &format!(
                                                            "Deployment blocked by policy '{}': {}",
                                                            block.rule_name, block.message
                                                        ),
                                                    )
                                                    .await;
                                            }
                                            let _ = tx_watch
                                                .send(Ok(ApplyEvent {
                                                    operation_id: uuid::Uuid::new_v4().to_string(),
                                                    status:
                                                        crate::proto::ApplyStatus::ApplySucceeded
                                                            as i32,
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
                                                    status: crate::proto::ApplyStatus::ApplyFailed
                                                        as i32,
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
                                container_image: String::new(),
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

        // Mark node as unschedulable so no new services are placed here
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

        // Send an empty DesiredState to the agent so it stops all services
        // on the drained node. The next reconciliation cycle will reschedule
        // them onto healthy, schedulable nodes.
        let drain_msg = ServerMessage {
            payload: Some(ServerPayload::DesiredState(crate::proto::DesiredState {
                correlation_id: uuid::Uuid::new_v4().to_string(),
                services: vec![],
                system_path: String::new(),
            })),
        };

        if !self.state.send_to_agent(&req.machine, drain_msg).await {
            tracing::warn!(
                machine = %req.machine,
                "Could not send drain command to agent (node may already be disconnected)"
            );
        }

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

        // Update the desired replica count in Raft state so the next
        // reconciliation cycle picks up the change.
        self.raft_state
            .set_replica_override(&req.service_name, req.desired_count)
            .await;

        tracing::info!(
            service = %req.service_name,
            from = current_count,
            to = req.desired_count,
            "Service replica override recorded"
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

        if req.service_name.is_empty() {
            return Err(Status::invalid_argument("service_name is required"));
        }

        // Verify the service is deployed (exists in Raft state)
        if self
            .raft_state
            .get_deployment(&req.service_name)
            .await
            .is_none()
        {
            return Err(Status::not_found(format!(
                "service '{}' is not deployed",
                req.service_name
            )));
        }

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

    async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
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

        let Some(node_id) = target_node else {
            return Err(Status::not_found(format!(
                "no running instance of service '{}'",
                req.service_name
            )));
        };

        let correlation_id = uuid::Uuid::new_v4().to_string();
        let timeout_secs = if req.timeout_seconds == 0 {
            30
        } else {
            req.timeout_seconds
        };
        let msg = ServerMessage {
            payload: Some(ServerPayload::ExecCommand(crate::proto::ExecCommand {
                correlation_id: correlation_id.clone(),
                service_name: req.service_name.clone(),
                command: req.command.clone(),
                timeout_seconds: timeout_secs,
            })),
        };

        let resp = self
            .state
            .send_command(
                &node_id,
                msg,
                correlation_id,
                Duration::from_secs(timeout_secs as u64 + 5),
            )
            .await?;

        if !resp.success {
            return Err(Status::internal(resp.error_message));
        }

        match resp.result {
            Some(crate::proto::agent_command_response::Result::ExecResult(r)) => {
                Ok(Response::new(ExecResponse {
                    exit_code: r.exit_code,
                    stdout: r.stdout,
                    stderr: r.stderr,
                }))
            }
            _ => Err(Status::internal("unexpected response type from agent")),
        }
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
        let lines = if req.lines == 0 { 100 } else { req.lines };
        let follow = req.follow;
        let state = self.state.clone();

        tokio::spawn(async move {
            if instances.is_empty() {
                let _ = tx
                    .send(Ok(LogsChunk {
                        node_id: String::new(),
                        data: format!("No instances of service '{service_name}' found.\n")
                            .into_bytes(),
                    }))
                    .await;
                return;
            }

            for (node_id, _instance_id) in &instances {
                let correlation_id = uuid::Uuid::new_v4().to_string();
                let msg = ServerMessage {
                    payload: Some(ServerPayload::LogsCommand(crate::proto::LogsCommand {
                        correlation_id: correlation_id.clone(),
                        service_name: service_name.clone(),
                        lines,
                        follow,
                    })),
                };

                match state
                    .send_command(node_id, msg, correlation_id, Duration::from_secs(30))
                    .await
                {
                    Ok(resp) if resp.success => {
                        if let Some(crate::proto::agent_command_response::Result::LogsResult(r)) =
                            resp.result
                        {
                            let _ = tx
                                .send(Ok(LogsChunk {
                                    node_id: node_id.clone(),
                                    data: r.data,
                                }))
                                .await;
                        }
                    }
                    Ok(resp) => {
                        let _ = tx
                            .send(Ok(LogsChunk {
                                node_id: node_id.clone(),
                                data: format!("Error from {node_id}: {}\n", resp.error_message)
                                    .into_bytes(),
                            }))
                            .await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Ok(LogsChunk {
                                node_id: node_id.clone(),
                                data: format!("Error reaching {node_id}: {e}\n").into_bytes(),
                            }))
                            .await;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<EventsResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit == 0 {
            50
        } else {
            req.limit as usize
        };

        // Parse category filter
        let category = if req.category.is_empty() {
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

        let service = if req.service.is_empty() {
            None
        } else {
            Some(req.service.as_str())
        };

        let events = self.event_store.query(category, service, limit).await;
        let proto_events = events
            .iter()
            .map(|e| crate::proto::FleetEventProto {
                timestamp: e.timestamp,
                level: format!("{:?}", e.level).to_lowercase(),
                category: format!("{:?}", e.category),
                service: e.service.clone().unwrap_or_default(),
                node: e.node.clone().unwrap_or_default(),
                message: e.message.clone(),
            })
            .collect();

        Ok(Response::new(EventsResponse {
            events: proto_events,
        }))
    }

    async fn list_nodes(
        &self,
        _request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let (nodes, services, _) = self.state.fleet_status().await;

        let mut details: Vec<NodeDetail> = Vec::with_capacity(nodes.len());
        for n in &nodes {
            let store_paths = self.state.node_store_paths(&n.node_id).await;
            let running: Vec<_> = services
                .iter()
                .flat_map(|s| {
                    s.instances
                        .iter()
                        .filter(|i| i.node_id == n.node_id)
                        .map(|i| {
                            let store_path = store_paths
                                .iter()
                                .find(|(name, _)| name == &s.name)
                                .map(|(_, p)| p.clone())
                                .unwrap_or_default();
                            crate::proto::ServiceInstance {
                                service_name: s.name.clone(),
                                instance_id: i.instance_id.clone(),
                                store_path,
                                state: i.state,
                            }
                        })
                })
                .collect();

            let schedulable = self.state.is_schedulable(&n.node_id).await;

            details.push(NodeDetail {
                node_id: n.node_id.clone(),
                address: n.address.clone(),
                pool: n.pool.clone(),
                healthy: n.healthy,
                schedulable,
                total_resources: n.total_resources,
                available_resources: n.available_resources,
                last_heartbeat: n.last_heartbeat,
                running_services: running,
            });
        }

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

        let store_paths = self.state.node_store_paths(&req.node_id).await;
        let running: Vec<_> = services
            .iter()
            .flat_map(|s| {
                s.instances
                    .iter()
                    .filter(|i| i.node_id == req.node_id)
                    .map(|i| {
                        let store_path = store_paths
                            .iter()
                            .find(|(name, _)| name == &s.name)
                            .map(|(_, p)| p.clone())
                            .unwrap_or_default();
                        crate::proto::ServiceInstance {
                            service_name: s.name.clone(),
                            instance_id: i.instance_id.clone(),
                            store_path,
                            state: i.state,
                        }
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

    async fn top(&self, request: Request<TopRequest>) -> Result<Response<TopResponse>, Status> {
        let req = request.into_inner();
        let (nodes, services, _) = self.state.fleet_status().await;

        let node_usage: Vec<_> = nodes
            .iter()
            .map(|n| {
                let total_cpu = n
                    .total_resources
                    .as_ref()
                    .map(|r| r.cpu_millicores)
                    .unwrap_or(0);
                let total_mem = n.total_resources.as_ref().map(|r| r.memory_mb).unwrap_or(0);
                let avail_cpu = n
                    .available_resources
                    .as_ref()
                    .map(|r| r.cpu_millicores)
                    .unwrap_or(0);
                let avail_mem = n
                    .available_resources
                    .as_ref()
                    .map(|r| r.memory_mb)
                    .unwrap_or(0);
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
            nodes: if req.mode == "services" {
                vec![]
            } else {
                node_usage
            },
            services: if req.mode == "nodes" {
                vec![]
            } else {
                svc_usage
            },
        }))
    }

    async fn list_deployments(
        &self,
        request: Request<ListDeploymentsRequest>,
    ) -> Result<Response<ListDeploymentsResponse>, Status> {
        let req = request.into_inner();
        let _limit = if req.limit == 0 {
            20
        } else {
            req.limit as usize
        };

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

        let pending = match self.state.pending_canaries().take(&req.service_name).await {
            Some(p) => p,
            None => {
                return Ok(Response::new(PromoteResponse {
                    success: false,
                    message: format!(
                        "No canary deployment awaiting promotion for '{}'",
                        req.service_name
                    ),
                }));
            }
        };

        match crate::server::deployer::promote_canary(
            &self.state,
            &pending,
            Some(&self.event_store),
        )
        .await
        {
            Ok(()) => Ok(Response::new(PromoteResponse {
                success: true,
                message: format!(
                    "Canary deployment for '{}' promoted to full rollout",
                    req.service_name
                ),
            })),
            Err(e) => {
                // Re-register the pending canary so the operator can retry or
                // fail it, rather than silently losing the deployment.
                self.state.pending_canaries().insert(pending).await;
                Ok(Response::new(PromoteResponse {
                    success: false,
                    message: format!("Promotion of '{}' failed: {e}", req.service_name),
                }))
            }
        }
    }

    async fn fail_deployment(
        &self,
        request: Request<FailDeploymentRequest>,
    ) -> Result<Response<FailDeploymentResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(service = %req.service_name, "Fail deployment requested");

        let pending = match self.state.pending_canaries().take(&req.service_name).await {
            Some(p) => p,
            None => {
                return Ok(Response::new(FailDeploymentResponse {
                    success: false,
                    message: format!(
                        "No canary deployment awaiting promotion for '{}'",
                        req.service_name
                    ),
                }));
            }
        };

        crate::server::deployer::fail_canary(&self.state, &pending, Some(&self.event_store)).await;

        Ok(Response::new(FailDeploymentResponse {
            success: true,
            message: format!(
                "Deployment for '{}' marked as failed — canary rolled back",
                req.service_name
            ),
        }))
    }

    async fn create_acl_token(
        &self,
        request: Request<CreateAclTokenRequest>,
    ) -> Result<Response<CreateAclTokenResponse>, Status> {
        let req = request.into_inner();

        let role = match req.role.as_str() {
            "admin" => super::rbac::Role::Admin,
            "operator" => super::rbac::Role::Operator,
            "viewer" => super::rbac::Role::Viewer,
            _ => {
                return Err(Status::invalid_argument(
                    "role must be admin, operator, or viewer",
                ));
            }
        };

        // Generate a secure token
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| Status::internal("RNG failure"))?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

        self.token_store
            .register(&token, role, &req.description)
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
        let req = request.into_inner();
        tracing::info!(token_prefix = %&req.token[..8.min(req.token.len())], "ACL token revoke requested");

        let revoked = self.token_store.revoke(&req.token).await;
        Ok(Response::new(RevokeAclTokenResponse { success: revoked }))
    }

    async fn list_acl_tokens(
        &self,
        _request: Request<ListAclTokensRequest>,
    ) -> Result<Response<ListAclTokensResponse>, Status> {
        let tokens = self.token_store.list().await;
        let infos = tokens
            .into_iter()
            .map(|(description, role)| crate::proto::AclTokenInfo {
                description,
                role: format!("{role:?}").to_lowercase(),
            })
            .collect();
        Ok(Response::new(ListAclTokensResponse { tokens: infos }))
    }

    async fn list_generations(
        &self,
        request: Request<ListGenerationsRequest>,
    ) -> Result<Response<ListGenerationsResponse>, Status> {
        self.handle_list_generations(request.into_inner()).await
    }

    async fn switch_generation(
        &self,
        request: Request<SwitchGenerationRequest>,
    ) -> Result<Response<SwitchGenerationResponse>, Status> {
        self.handle_switch_generation(request.into_inner()).await
    }

    async fn diff_generations(
        &self,
        request: Request<DiffGenerationsRequest>,
    ) -> Result<Response<DiffGenerationsResponse>, Status> {
        self.handle_diff_generations(request.into_inner()).await
    }

    async fn system_gc(
        &self,
        request: Request<SystemGcRequest>,
    ) -> Result<Response<SystemGcResponse>, Status> {
        self.handle_system_gc(request.into_inner()).await
    }

    async fn system_reboot(
        &self,
        request: Request<SystemRebootRequest>,
    ) -> Result<Response<SystemRebootResponse>, Status> {
        self.handle_system_reboot(request.into_inner()).await
    }

    async fn system_rebuild(
        &self,
        request: Request<SystemRebuildRequest>,
    ) -> Result<Response<SystemRebuildResponse>, Status> {
        self.handle_system_rebuild(request.into_inner()).await
    }

    async fn inspect_service(
        &self,
        request: Request<InspectServiceRequest>,
    ) -> Result<Response<InspectServiceResponse>, Status> {
        self.handle_inspect_service(request.into_inner()).await
    }

    async fn rotate_fleet_key(
        &self,
        _request: Request<RotateFleetKeyRequest>,
    ) -> Result<Response<RotateFleetKeyResponse>, Status> {
        tracing::info!("Fleet key rotation requested");

        // Generate a new 256-bit key
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut new_key = [0u8; 32];
        rng.fill(&mut new_key)
            .map_err(|_| Status::internal("RNG failure during key generation"))?;

        // Re-encrypt all secrets in the store with the new key
        {
            let mut store = self.secret_store.write().await;
            store
                .rekey(&new_key)
                .await
                .map_err(|e| Status::internal(format!("failed to re-encrypt secrets: {e}")))?;
        }

        // Update the fleet key state and bump the version
        let (prev_version, new_version) = {
            let mut fk = self.fleet_key.write().await;
            let prev = fk.version;
            fk.version += 1;
            fk.key = new_key.to_vec();
            (prev, fk.version)
        };

        // Persist the new key to disk, sealed at rest when configured.
        let key_path = self.data_dir.join("fleet-key");
        let hex: String = new_key.iter().map(|b| format!("{b:02x}")).collect();
        super::seal::write_maybe_sealed(&key_path, hex.as_bytes(), "fleet encryption key")
            .await
            .map_err(|e| Status::internal(format!("failed to persist rotated key: {e}")))?;

        // Push the new per-agent derived key to all connected agents
        let node_ids = self.state.connected_nodes().await;
        let mut notified: u32 = 0;
        for nid in &node_ids {
            let agent_spiffe_id = format!("spiffe://{}/agent/{}", self.domain, nid);
            let derived =
                crate::secrets::key_derivation::derive_agent_key(&new_key, &agent_spiffe_id);
            let key_msg = ServerMessage {
                payload: Some(ServerPayload::FleetKey(crate::proto::FleetKeyUpdate {
                    encrypted_key: derived.to_vec(),
                    version: new_version,
                })),
            };
            if self.state.send_to_agent(nid, key_msg).await {
                notified += 1;
            }
        }

        tracing::info!(
            prev_version,
            new_version,
            notified,
            total_agents = node_ids.len(),
            "Fleet key rotated successfully"
        );

        Ok(Response::new(RotateFleetKeyResponse {
            success: true,
            previous_version: prev_version,
            new_version,
            agents_notified: notified,
            message: format!(
                "Fleet key rotated from v{prev_version} to v{new_version}, {notified}/{} agents notified",
                node_ids.len()
            ),
        }))
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
    pub ca: Arc<dyn CaSigner>,
    pub trust_bundle_pem: String,
    pub domain: String,
    pub fleet_key: Vec<u8>,
    pub join_token_store: JoinTokenStore,
    pub raft_state: FleetStateMachine,
    pub instance_tracker: InstanceTracker,
    pub event_store: EventStore,
    pub data_dir: std::path::PathBuf,
}

/// Start the gRPC server with TLS and RBAC-based authentication.
pub async fn serve_grpc(
    config: GrpcServerConfig,
    state: FleetState,
    token_store: TokenStore,
    shutdown: tokio_util::sync::CancellationToken,
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
        event_store,
        data_dir,
    } = config;

    tracing::info!(%addr, domain = %domain, "gRPC server listening (TLS + RBAC + SPIFFE)");

    let service_token_store = token_store.clone();
    #[allow(clippy::result_large_err)]
    let interceptor = move |mut req: Request<()>| -> Result<Request<()>, Status> {
        // Strip any client-supplied authentication markers. These are internal
        // signals derived by the server from the verified TLS peer certificate;
        // a client must never be able to assert them itself. Removing them here
        // closes the metadata-spoofing auth bypass.
        req.metadata_mut().remove("x-ekafleet-mtls");
        req.metadata_mut().remove("x-ekafleet-attest");

        // Extract the request namespace (CLI `--namespace`) and stash it in
        // extensions so handlers can scope operations. Absent/invalid markers
        // fall back to the default namespace.
        let namespace = req
            .metadata()
            .get(super::rbac::NAMESPACE_METADATA_KEY)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .map(|v| super::rbac::RequestNamespace(v.to_string()))
            .unwrap_or_default();
        req.extensions_mut().insert(namespace);

        // Accept mTLS-authenticated requests. Authentication is established by
        // the presence of a client certificate that rustls has *already verified*
        // against the configured CA (client_ca_root below). `peer_certs()` only
        // returns certificates for a genuinely completed, verified mTLS handshake,
        // so this cannot be forged by setting a header.
        if let Some(certs) = req.peer_certs()
            && !certs.is_empty()
        {
            // A verified node SVID grants the AgentConnect/operator surface.
            // Record the identity marker for handler-level checks.
            req.extensions_mut().insert(PeerIdentity::Mtls);
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
        let guard = tokens.blocking_read();
        let role = super::rbac::TokenStore::authenticate_sync(&guard, raw_token)
            .ok_or_else(|| Status::unauthenticated("invalid or expired token"))?;

        // Stash the role in request extensions so RPC handlers can check permissions.
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
        event_store,
        service_token_store,
        data_dir,
    )
    .with_cert_issuer(cert_issuer, trust_bundle_pem)
    .with_ca(ca)
    .with_fleet_key(fleet_key);

    tonic::transport::Server::builder()
        .tls_config(tls_config)?
        .http2_keepalive_interval(Some(Duration::from_secs(20)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .add_service(FleetControlServer::with_interceptor(service, interceptor))
        .serve_with_shutdown(addr, shutdown.cancelled())
        .await?;

    Ok(())
}
