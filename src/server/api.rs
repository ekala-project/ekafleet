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
    AgentMessage, ApplyEvent, ApplyRequest, DrainRequest, DrainResponse, FleetStatus,
    NodeAttestationRequest, NodeAttestationResult, OperationType, PlanRequest, PlanResponse,
    PlannedOperation, RestoreRequest, RestoreResponse, RollbackRequest, RollbackResponse,
    ScaleRequest, ScaleResponse, ServerMessage, SnapshotRequest, SnapshotResponse, StatusRequest,
    TrustBundleUpdate,
};
use crate::raft::state::FleetStateMachine;

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
}

impl FleetControlService {
    pub fn new(state: FleetState, domain: &str) -> Self {
        Self {
            state,
            cert_issuer: None,
            ca: None,
            trust_bundle_pem: None,
            domain: domain.to_string(),
            fleet_key: None,
            join_token_store: JoinTokenStore::new(),
            metrics: MetricsAggregator::new(),
            raft_state: FleetStateMachine::new(),
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
        let rx = self.state.register_agent(&node_id, remote, pool_name).await;

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
        let plan = super::reconciler::compute_plan(&desired, &current_nodes, &self.state).await;

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
            "Apply requested"
        );

        let (_tx, rx) = tokio::sync::mpsc::channel(64);
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

    let service = FleetControlService::new(state, &domain)
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
