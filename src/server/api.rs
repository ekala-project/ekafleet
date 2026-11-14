use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use super::events::EventStore;
use super::rbac::{PeerIdentity, Permission, TokenStore, extract_bearer_token, require_permission};
use super::state::FleetState;
use crate::attestation::join_token::JoinTokenStore;
use crate::ca::CaSigner;
use crate::ca::issuer::CertIssuer;
use crate::metrics::aggregator::MetricsAggregator;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_bootstrap_server::FleetBootstrapServer;
use crate::proto::fleet_control_server::{FleetControl, FleetControlServer};
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    AgentMessage, ApplyEvent, ApplyRequest, CreateAclTokenRequest, CreateAclTokenResponse,
    CreateJoinTokenRequest, CreateJoinTokenResponse, DiffGenerationsRequest,
    DiffGenerationsResponse, DrainRequest, DrainResponse, EventsRequest, EventsResponse,
    ExecRequest, ExecResponse, FailDeploymentRequest, FailDeploymentResponse, FleetStatus,
    GetNodeRequest, InspectServiceRequest, InspectServiceResponse, ListAclTokensRequest,
    ListAclTokensResponse, ListDeploymentsRequest, ListDeploymentsResponse, ListGenerationsRequest,
    ListGenerationsResponse, ListNodesRequest, ListNodesResponse, LogsChunk, LogsRequest,
    NodeDetail, OperationType, PlanRequest, PlanResponse, PlannedOperation, PromoteRequest,
    PromoteResponse, RestoreRequest, RestoreResponse, RevokeAclTokenRequest,
    RevokeAclTokenResponse, RollbackRequest, RollbackResponse, RotateFleetKeyRequest,
    RotateFleetKeyResponse, ScaleRequest, ScaleResponse, ServerMessage, SnapshotRequest,
    SnapshotResponse, StatusRequest, SwitchGenerationRequest, SwitchGenerationResponse,
    SystemGcRequest, SystemGcResponse, SystemRebootRequest, SystemRebootResponse,
    SystemRebuildRequest, SystemRebuildResponse, TopRequest, TopResponse, TrustBundleUpdate,
    UpdateNodeRequest, UpdateNodeResponse,
};
use crate::raft::state::FleetStateMachine;
use crate::secrets::store::SecretStore;
use crate::server::cloud::instance_tracker::InstanceTracker;

/// Fleet encryption key with version tracking for rotation.
pub struct FleetKeyState {
    pub key: zeroize::Zeroizing<Vec<u8>>,
    pub version: u64,
}

pub struct FleetControlService {
    pub(super) state: FleetState,
    pub(super) cert_issuer: Option<CertIssuer>,
    pub(super) ca: Option<Arc<dyn CaSigner>>,
    pub(super) trust_bundle_pem: Option<String>,
    /// The JWT bundle (JWKS) pushed to agents with the X.509 bundle.
    pub(super) jwt_bundle: Option<String>,
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
    pub(super) event_store: EventStore,
    pub(super) token_store: TokenStore,
    /// Append-only audit log recording which principal performed each action.
    pub(super) audit_log: super::audit::AuditLog,
    /// Accept agent streams authenticated by a bearer token instead of a
    /// node SVID. Only `ekafleet dev` enables this.
    pub(super) allow_bearer_agents: bool,
    /// Server-owned reconcile loop (spawned by `serve_grpc`).
    pub(super) controller: super::controller::Controller,
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
        let controller = super::controller::Controller::new(
            state.clone(),
            raft_state.clone(),
            instance_tracker.clone(),
            join_token_store.clone(),
            event_store.clone(),
            grpc_addr,
        );
        Self {
            controller,
            state,
            cert_issuer: None,
            ca: None,
            trust_bundle_pem: None,
            jwt_bundle: None,
            domain: domain.to_string(),
            fleet_key: Arc::new(RwLock::new(FleetKeyState {
                key: zeroize::Zeroizing::new(Vec::new()),
                version: 0,
            })),
            secret_store: Arc::new(RwLock::new(SecretStore::new(&[0u8; 32]))),
            data_dir,
            join_token_store,
            metrics: MetricsAggregator::new(),
            raft_state,
            instance_tracker,
            event_store,
            token_store,
            audit_log: super::audit::AuditLog::new(),
            allow_bearer_agents: false,
        }
    }

    /// Accept bearer-token agent streams (development only).
    pub fn with_bearer_agents(mut self, allow: bool) -> Self {
        self.allow_bearer_agents = allow;
        self
    }

    /// Record an audit-log entry, attributing it to the principal that issued
    /// `request`. Bearer-token principals are identified by their non-secret
    /// token id; verified mTLS peers are recorded as `mtls-peer`.
    pub(super) async fn audit<T>(
        &self,
        request: &Request<T>,
        action: super::audit::AuditAction,
        resource: &str,
        detail: &str,
        outcome: super::audit::AuditOutcome,
    ) {
        let actor = Self::actor(request);
        self.audit_log
            .record(&actor, action, resource, detail, outcome)
            .await;
    }

    /// The principal that issued `request`, as recorded in the audit log.
    fn actor<T>(request: &Request<T>) -> String {
        request
            .extensions()
            .get::<super::rbac::TokenIdentity>()
            .map(|id| id.actor())
            .or_else(|| {
                request
                    .extensions()
                    .get::<super::rbac::PeerIdentity>()
                    .map(|peer| peer.actor())
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// The server-owned reconcile loop. `serve_grpc` spawns it; embedders
    /// that build the service themselves spawn it with
    /// [`super::controller::Controller::spawn`].
    pub fn controller(&self) -> super::controller::Controller {
        self.controller.clone()
    }

    /// Configure the service with a certificate issuer for SPIFFE SVID issuance.
    pub fn with_cert_issuer(
        mut self,
        issuer: CertIssuer,
        trust_bundle_pem: String,
        jwt_bundle: String,
    ) -> Self {
        self.cert_issuer = Some(issuer);
        self.trust_bundle_pem = Some(trust_bundle_pem);
        self.jwt_bundle = Some(jwt_bundle);
        self
    }

    /// Configure the service with a CA signer for node SVID issuance during attestation.
    pub fn with_ca(mut self, ca: Arc<dyn CaSigner>) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Configure the fleet encryption key and secret store.
    ///
    /// Called while building the service, before its state is shared, so the
    /// locks are replaced rather than locked (this runs inside the runtime,
    /// where blocking on a tokio lock would panic).
    pub fn with_fleet_key(mut self, key: zeroize::Zeroizing<Vec<u8>>) -> Self {
        // Initialize the secret store with this key and set version 1
        let store = SecretStore::new(
            <&[u8; 32]>::try_from(key.as_slice()).expect("fleet key must be 32 bytes"),
        );
        self.fleet_key = Arc::new(RwLock::new(FleetKeyState { key, version: 1 }));
        self.secret_store = Arc::new(RwLock::new(store));
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
        require_permission(&request, Permission::AgentConnect)?;
        // An mTLS session's node identity is the node SVID's SPIFFE ID; any
        // node_id the agent puts in its messages is only checked against it.
        let authenticated_node = match request.extensions().get::<PeerIdentity>() {
            Some(peer) => Some(
                peer.agent_name(&self.domain)
                    .ok_or_else(|| {
                        Status::permission_denied(format!(
                            "{} is not an agent identity",
                            peer.spiffe_id
                        ))
                    })?
                    .to_string(),
            ),
            None if self.allow_bearer_agents => None,
            None => {
                return Err(Status::permission_denied(
                    "agents must authenticate with a node SVID; \
                     join with `ekafleet agent --join-token-file` \
                     (bearer-token agents are only accepted by `ekafleet dev`)",
                ));
            }
        };
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

        let (claimed_node_id, pool) = match &first_msg.payload {
            Some(Payload::Heartbeat(hb)) => (hb.node_id.clone(), hb.pool.clone()),
            Some(Payload::Status(sr)) => (sr.node_id.clone(), String::new()),
            _ => {
                return Err(Status::invalid_argument(
                    "first message must be heartbeat or status",
                ));
            }
        };
        let node_id = resolve_stream_node_id(authenticated_node.as_deref(), &claimed_node_id)?;

        tracing::info!(
            node_id = %node_id,
            remote = %remote,
            mtls = authenticated_node.is_some(),
            "Agent connected"
        );

        // Register agent and get outbound channel
        let pool_name = if pool.is_empty() {
            "default".to_string()
        } else {
            pool
        };
        let (connection_id, rx) = self
            .state
            .register_agent_connection(&node_id, remote.clone(), pool_name)
            .await;

        // Correlate agent IP with a tracked cloud instance.
        // The remote address is "ip:port", so extract just the IP part.
        let agent_ip = remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&remote);
        if let Some(tracked) = self.instance_tracker.find_by_ip(agent_ip).await {
            if let Err(e) = self
                .instance_tracker
                .associate_node(&tracked.cloud_instance_id, &node_id)
                .await
            {
                tracing::error!(
                    node_id = %node_id,
                    cloud_instance = %tracked.cloud_instance_id,
                    error = %e,
                    "Failed to record cloud instance correlation"
                );
            }
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
                    jwt_bundle_jwks: self
                        .jwt_bundle
                        .as_deref()
                        .unwrap_or_default()
                        .as_bytes()
                        .to_vec(),
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

        // Replay the node's assigned desired state so a reconnecting agent
        // converges immediately instead of waiting for the next reconcile.
        // Sent after the trust bundle, which the agent needs to request SVIDs.
        if let Some(desired) = self.state.assigned_desired_state(&node_id).await {
            let msg = ServerMessage {
                payload: Some(ServerPayload::DesiredState(desired)),
            };
            let _ = self.state.send_to_agent(&node_id, msg).await;
        }

        // Process the first message
        let mtls = authenticated_node.is_some();
        self.process_message(&node_id, first_msg, mtls).await;

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
                            mtls,
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
            state.deregister_agent(&nid, connection_id).await;
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
        require_permission(&request, Permission::Read)?;
        let req = request.into_inner();
        tracing::info!(flake_ref = %req.flake_ref, "Plan requested");

        let desired = super::nix::eval_flake(&req.flake_ref)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?
            .config;

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
        require_permission(&request, Permission::Deploy)?;
        let actor = Self::actor(&request);
        let flake_ref = request.get_ref().flake_ref.clone();
        if flake_ref.is_empty() {
            return Err(Status::invalid_argument("flake_ref is required"));
        }
        self.audit(
            &request,
            super::audit::AuditAction::Apply,
            &flake_ref,
            "apply requested",
            super::audit::AuditOutcome::Success,
        )
        .await;
        let follow = request.get_ref().follow;
        tracing::info!(%flake_ref, follow, "Apply requested");

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let raft_state = self.raft_state.clone();
        let controller = self.controller.clone();
        tokio::spawn(async move {
            let send = |revision: u64, status: crate::proto::ApplyStatus, message: String| {
                let tx = tx.clone();
                async move {
                    tx.send(Ok(ApplyEvent {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        status: status as i32,
                        message,
                        revision,
                    }))
                    .await
                    .is_ok()
                }
            };
            use crate::proto::ApplyStatus::{ApplyFailed, ApplyInProgress};

            send(0, ApplyInProgress, format!("Evaluating {flake_ref}")).await;
            let evaluated = match super::nix::eval_flake(&flake_ref).await {
                Ok(evaluated) => evaluated,
                Err(e) => {
                    send(0, ApplyFailed, format!("Apply failed: {e}")).await;
                    return;
                }
            };
            if let Err(errors) = crate::config::validate(&evaluated.config) {
                send(
                    0,
                    ApplyFailed,
                    format!("Apply failed: validation failed: {}", errors.join("; ")),
                )
                .await;
                return;
            }

            let mut updates = controller.subscribe();
            let revision = match raft_state
                .apply_config(crate::raft::state::Command::ApplyConfig {
                    flake_ref: evaluated.locked_ref.clone(),
                    config_json: evaluated.json,
                    applied_at: unix_now(),
                    applied_by: actor,
                    rollback_of: None,
                })
                .await
            {
                Ok(revision) => revision,
                Err(e) => {
                    send(
                        0,
                        ApplyFailed,
                        format!("Apply failed: cannot record configuration: {e}"),
                    )
                    .await;
                    return;
                }
            };
            controller.trigger();
            if !send(
                revision,
                ApplyInProgress,
                format!("Recorded revision {revision} ({})", evaluated.locked_ref),
            )
            .await
            {
                return;
            }

            let Some(first) = super::controller::Controller::wait_for(&mut updates, revision).await
            else {
                return;
            };
            if !send(first.revision, first.status, first.message).await || !follow {
                return;
            }
            loop {
                match updates.recv().await {
                    Ok(update) if update.changed => {
                        if !send(update.revision, update.status, update.message).await {
                            return;
                        }
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn create_join_token(
        &self,
        request: Request<CreateJoinTokenRequest>,
    ) -> Result<Response<CreateJoinTokenResponse>, Status> {
        require_permission(&request, Permission::ManageTokens)?;
        let req = request.get_ref();
        let ttl = (req.ttl_secs > 0).then(|| Duration::from_secs(req.ttl_secs));
        let (token, expires_at) = self
            .join_token_store
            .create(&req.node_name, ttl)
            .await
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        self.audit(
            &request,
            super::audit::AuditAction::TokenCreate,
            &format!("join-token/{}", req.node_name),
            &format!(
                "join token for node {} (expires {expires_at})",
                req.node_name
            ),
            super::audit::AuditOutcome::Success,
        )
        .await;
        Ok(Response::new(CreateJoinTokenResponse { token, expires_at }))
    }

    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<FleetStatus>, Status> {
        require_permission(&request, Permission::Read)?;
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
        require_permission(&request, Permission::Deploy)?;
        let actor = Self::actor(&request);
        let revisions = self.raft_state.config_revisions().await;
        let Some(current) = revisions.last() else {
            return Err(Status::failed_precondition(
                "no configuration has been applied yet",
            ));
        };
        let wanted = match request.get_ref().to_revision {
            0 => current.revision.saturating_sub(1),
            n => n,
        };
        if wanted == current.revision {
            return Err(Status::invalid_argument(format!(
                "revision {wanted} is already the current revision"
            )));
        }
        let Some(target) = revisions.iter().find(|r| r.revision == wanted) else {
            let oldest = revisions.first().map_or(0, |r| r.revision);
            return Err(Status::not_found(format!(
                "revision {wanted} is not retained (available: {oldest}..={})",
                current.revision
            )));
        };
        self.audit(
            &request,
            super::audit::AuditAction::Rollback,
            &target.flake_ref,
            &format!("rollback to revision {wanted}"),
            super::audit::AuditOutcome::Success,
        )
        .await;

        let mut updates = self.controller.subscribe();
        let revision = self
            .raft_state
            .apply_config(crate::raft::state::Command::ApplyConfig {
                flake_ref: target.flake_ref.clone(),
                config_json: target.config_json.clone(),
                applied_at: unix_now(),
                applied_by: actor,
                rollback_of: Some(wanted),
            })
            .await
            .map_err(|e| Status::internal(format!("cannot record configuration: {e}")))?;
        self.controller.trigger();
        tracing::info!(revision, rollback_of = wanted, "Rollback recorded");

        let update = super::controller::Controller::wait_for(&mut updates, revision)
            .await
            .ok_or_else(|| Status::unavailable("reconcile loop stopped"))?;
        Ok(Response::new(RollbackResponse {
            success: update.status == crate::proto::ApplyStatus::ApplySucceeded,
            message: format!(
                "Rolled back to revision {wanted} as revision {revision}. {}",
                update.message
            ),
            revision,
        }))
    }

    async fn list_config_revisions(
        &self,
        request: Request<crate::proto::ListConfigRevisionsRequest>,
    ) -> Result<Response<crate::proto::ListConfigRevisionsResponse>, Status> {
        require_permission(&request, Permission::Read)?;
        let revisions = self.raft_state.config_revisions().await;
        let current = revisions.last().map(|r| r.revision);
        let revisions = revisions
            .into_iter()
            .map(|r| crate::proto::ConfigRevisionInfo {
                current: Some(r.revision) == current,
                revision: r.revision,
                flake_ref: r.flake_ref,
                applied_at: r.applied_at,
                applied_by: r.applied_by,
                rollback_of: r.rollback_of.unwrap_or(0),
            })
            .collect();
        Ok(Response::new(crate::proto::ListConfigRevisionsResponse {
            revisions,
        }))
    }

    async fn drain(
        &self,
        request: Request<DrainRequest>,
    ) -> Result<Response<DrainResponse>, Status> {
        require_permission(&request, Permission::Drain)?;
        self.audit(
            &request,
            super::audit::AuditAction::Drain,
            &request.get_ref().machine,
            &format!("drain deadline {}s", request.get_ref().deadline_seconds),
            super::audit::AuditOutcome::Success,
        )
        .await;
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
                namespace_networks: vec![],
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
        require_permission(&request, Permission::Scale)?;
        self.audit(
            &request,
            super::audit::AuditAction::Scale,
            &request.get_ref().service_name,
            &format!("scale to {}", request.get_ref().desired_count),
            super::audit::AuditOutcome::Success,
        )
        .await;
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
            .await
            .map_err(|e| Status::internal(format!("failed to record replica count: {e}")))?;

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
        request: Request<SnapshotRequest>,
    ) -> Result<Response<SnapshotResponse>, Status> {
        require_permission(&request, Permission::Read)?;
        tracing::info!("Snapshot requested");

        let data = self.raft_state.snapshot().await;
        let last_index = self.raft_state.last_applied().await;

        Ok(Response::new(SnapshotResponse { data, last_index }))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        require_permission(&request, Permission::Deploy)?;
        let req = request.into_inner();
        tracing::info!(data_len = req.data.len(), "Restore requested");

        match self.raft_state.install_snapshot(&req.data).await {
            Ok(index) => Ok(Response::new(RestoreResponse {
                success: true,
                message: format!("State restored successfully (index {index})"),
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
        require_permission(&request, Permission::Deploy)?;
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
        require_permission(&request, Permission::Deploy)?;
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
        require_permission(&request, Permission::Read)?;
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
        require_permission(&request, Permission::Read)?;
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
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        require_permission(&request, Permission::Read)?;
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
        require_permission(&request, Permission::Read)?;
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
        require_permission(&request, Permission::Deploy)?;
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
        require_permission(&request, Permission::Read)?;
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

        let mut svc_usage = Vec::with_capacity(services.len());
        for s in &services {
            // Per-instance requests are multiplied by the running instance count
            // to report the total requested capacity for the service.
            let (cpu_req, mem_req) = self.state.service_request(&s.name).await.unwrap_or((0, 0));
            let instances = s.instances.len() as u64;
            svc_usage.push(crate::proto::ServiceResourceUsage {
                service_name: s.name.clone(),
                instance_count: s.instances.len() as u32,
                cpu_request: cpu_req.saturating_mul(instances),
                memory_request: mem_req.saturating_mul(instances),
            });
        }

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
        require_permission(&request, Permission::Read)?;
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
        require_permission(&request, Permission::Deploy)?;
        self.audit(
            &request,
            super::audit::AuditAction::Apply,
            &request.get_ref().service_name,
            "promote canary deployment",
            super::audit::AuditOutcome::Success,
        )
        .await;
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
        require_permission(&request, Permission::Deploy)?;
        self.audit(
            &request,
            super::audit::AuditAction::Rollback,
            &request.get_ref().service_name,
            "fail canary deployment",
            super::audit::AuditOutcome::Success,
        )
        .await;
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
        require_permission(&request, Permission::ManageTokens)?;
        let req = request.get_ref().clone();

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

        let namespace = if req.namespace.is_empty() {
            None
        } else {
            Some(req.namespace.clone())
        };

        self.token_store
            .register_with_opts(&token, role, &req.description, None, namespace)
            .await;

        tracing::info!(
            role = %req.role,
            description = %req.description,
            namespace = %req.namespace,
            "ACL token created"
        );

        self.audit(
            &request,
            super::audit::AuditAction::TokenCreate,
            &super::rbac::token_id(&token),
            &format!("create {} token: {}", req.role, req.description),
            super::audit::AuditOutcome::Success,
        )
        .await;

        Ok(Response::new(CreateAclTokenResponse {
            token,
            role: req.role,
            namespace: req.namespace,
        }))
    }

    async fn revoke_acl_token(
        &self,
        request: Request<RevokeAclTokenRequest>,
    ) -> Result<Response<RevokeAclTokenResponse>, Status> {
        require_permission(&request, Permission::ManageTokens)?;
        let token = request.get_ref().token.clone();
        tracing::info!(token_prefix = %&token[..8.min(token.len())], "ACL token revoke requested");

        let revoked = self.token_store.revoke(&token).await;
        self.audit(
            &request,
            super::audit::AuditAction::TokenRevoke,
            &super::rbac::token_id(&token),
            "revoke ACL token",
            if revoked {
                super::audit::AuditOutcome::Success
            } else {
                super::audit::AuditOutcome::Failed
            },
        )
        .await;
        Ok(Response::new(RevokeAclTokenResponse { success: revoked }))
    }

    async fn list_acl_tokens(
        &self,
        request: Request<ListAclTokensRequest>,
    ) -> Result<Response<ListAclTokensResponse>, Status> {
        require_permission(&request, Permission::ManageTokens)?;
        let tokens = self.token_store.list().await;
        let infos = tokens
            .into_iter()
            .map(
                |(description, role, namespace)| crate::proto::AclTokenInfo {
                    description,
                    role: format!("{role:?}").to_lowercase(),
                    namespace: namespace.unwrap_or_default(),
                },
            )
            .collect();
        Ok(Response::new(ListAclTokensResponse { tokens: infos }))
    }

    async fn list_generations(
        &self,
        request: Request<ListGenerationsRequest>,
    ) -> Result<Response<ListGenerationsResponse>, Status> {
        require_permission(&request, Permission::Read)?;
        self.handle_list_generations(request.into_inner()).await
    }

    async fn switch_generation(
        &self,
        request: Request<SwitchGenerationRequest>,
    ) -> Result<Response<SwitchGenerationResponse>, Status> {
        require_permission(&request, Permission::Deploy)?;
        self.handle_switch_generation(request.into_inner()).await
    }

    async fn diff_generations(
        &self,
        request: Request<DiffGenerationsRequest>,
    ) -> Result<Response<DiffGenerationsResponse>, Status> {
        require_permission(&request, Permission::Read)?;
        self.handle_diff_generations(request.into_inner()).await
    }

    async fn system_gc(
        &self,
        request: Request<SystemGcRequest>,
    ) -> Result<Response<SystemGcResponse>, Status> {
        require_permission(&request, Permission::Deploy)?;
        self.handle_system_gc(request.into_inner()).await
    }

    async fn system_reboot(
        &self,
        request: Request<SystemRebootRequest>,
    ) -> Result<Response<SystemRebootResponse>, Status> {
        require_permission(&request, Permission::Deploy)?;
        self.handle_system_reboot(request.into_inner()).await
    }

    async fn system_rebuild(
        &self,
        request: Request<SystemRebuildRequest>,
    ) -> Result<Response<SystemRebuildResponse>, Status> {
        require_permission(&request, Permission::Deploy)?;
        self.handle_system_rebuild(request.into_inner()).await
    }

    async fn inspect_service(
        &self,
        request: Request<InspectServiceRequest>,
    ) -> Result<Response<InspectServiceResponse>, Status> {
        require_permission(&request, Permission::Read)?;
        self.handle_inspect_service(request.into_inner()).await
    }

    async fn rotate_fleet_key(
        &self,
        request: Request<RotateFleetKeyRequest>,
    ) -> Result<Response<RotateFleetKeyResponse>, Status> {
        require_permission(&request, Permission::ManageTokens)?;
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
            fk.key = zeroize::Zeroizing::new(new_key.to_vec());
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
    async fn process_message(&self, node_id: &str, msg: AgentMessage, mtls: bool) {
        super::agent_msg::process_agent_message(
            &self.state,
            node_id,
            msg,
            self.cert_issuer.as_ref(),
            &self.metrics,
            mtls,
        )
        .await;
    }
}

/// Decide which node a control stream speaks for.
///
/// With an mTLS node SVID the node is the one named by the certificate, and a
/// different self-asserted `node_id` is refused. Without one (bearer-token
/// sessions in dev mode) the agent's claimed name is used after validation.
#[allow(clippy::result_large_err)]
fn resolve_stream_node_id(authenticated: Option<&str>, claimed: &str) -> Result<String, Status> {
    match authenticated {
        Some(name) => {
            if !claimed.is_empty() && claimed != name {
                return Err(Status::permission_denied(format!(
                    "node SVID identifies '{name}' but the agent claimed to be '{claimed}'"
                )));
            }
            Ok(name.to_string())
        }
        None => {
            crate::ca::validate_identity_name(claimed)
                .map_err(|e| Status::invalid_argument(format!("invalid node name: {e}")))?;
            Ok(claimed.to_string())
        }
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
    pub jwt_bundle: String,
    pub domain: String,
    pub fleet_key: zeroize::Zeroizing<Vec<u8>>,
    pub join_token_store: JoinTokenStore,
    pub raft_state: FleetStateMachine,
    pub instance_tracker: InstanceTracker,
    pub event_store: EventStore,
    pub data_dir: std::path::PathBuf,
    /// Accept bearer-token agent streams (`ekafleet dev` only).
    pub allow_bearer_agents: bool,
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
        jwt_bundle,
        domain,
        fleet_key,
        join_token_store,
        raft_state,
        instance_tracker,
        event_store,
        data_dir,
        allow_bearer_agents,
    } = config;

    tracing::info!(%addr, domain = %domain, "gRPC server listening (TLS + RBAC + SPIFFE)");

    let service_token_store = token_store.clone();
    let interceptor_domain = domain.clone();
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
        //
        // Extract the SPIFFE ID from the leaf certificate's SAN URI and derive
        // a role from the path structure (/server/* → Admin, /agent/* → Agent).
        // Any other CA-verified identity (e.g. a workload's service SVID) is
        // refused outright rather than granted a fallback role.
        if let Some(certs) = req.peer_certs()
            && let Some(leaf) = certs.first()
        {
            let spiffe_id = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_der(leaf)
                .ok_or_else(|| Status::permission_denied("client certificate has no SPIFFE ID"))?;
            let peer = PeerIdentity::from_spiffe_id(&interceptor_domain, spiffe_id.clone())
                .ok_or_else(|| {
                    Status::permission_denied(format!(
                        "SPIFFE ID {spiffe_id} is not authorized for the control plane"
                    ))
                })?;
            let role = peer.role;
            req.extensions_mut().insert(role);
            req.extensions_mut().insert(peer);
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

        let (role, identity) = token_store
            .authenticate_identity(raw_token)
            .ok_or_else(|| Status::unauthenticated("invalid or expired token"))?;

        // Stash the role in request extensions so RPC handlers can check permissions,
        // and the token identity so handlers can attribute audit-log entries.
        req.extensions_mut().insert(role);
        req.extensions_mut().insert(identity);
        Ok(req)
    };

    let identity = Identity::from_pem(&tls.cert_pem, &tls.cert_pem);
    // Client certificates are optional at the TLS layer: agents present
    // their node SVID, while the CLI (bearer token) and joining agents
    // (FleetBootstrap.Attest) have none. A certificate that is presented
    // must chain to the fleet CA; authorization is per RPC.
    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(&tls.ca_cert_pem))
        .client_auth_optional(true);

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
    .with_cert_issuer(cert_issuer, trust_bundle_pem.clone(), jwt_bundle)
    .with_ca(ca.clone())
    .with_fleet_key(fleet_key)
    .with_bearer_agents(allow_bearer_agents);
    service.controller().spawn(
        trust_bundle_pem.clone(),
        super::controller::RECONCILE_INTERVAL,
        shutdown.clone(),
    );
    if allow_bearer_agents {
        tracing::warn!("Accepting bearer-token agents (development mode)");
    }
    let bootstrap = super::bootstrap::FleetBootstrapService::new(
        service.join_token_store.clone(),
        ca,
        &domain,
        trust_bundle_pem,
        service.audit_log.clone(),
    );

    tonic::transport::Server::builder()
        .tls_config(tls_config)?
        .http2_keepalive_interval(Some(Duration::from_secs(20)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .add_service(FleetBootstrapServer::new(bootstrap))
        .add_service(FleetControlServer::with_interceptor(service, interceptor))
        .serve_with_shutdown(addr, shutdown.cancelled())
        .await?;

    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::resolve_stream_node_id;

    #[test]
    fn mtls_identity_wins_over_claim() {
        assert_eq!(resolve_stream_node_id(Some("n1"), "n1").unwrap(), "n1");
        assert_eq!(resolve_stream_node_id(Some("n1"), "").unwrap(), "n1");
        let err = resolve_stream_node_id(Some("n1"), "n2").unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn bearer_claim_must_be_valid_name() {
        assert_eq!(resolve_stream_node_id(None, "web-1").unwrap(), "web-1");
        for bad in ["", "../server/x", "a/b", "-x"] {
            let err = resolve_stream_node_id(None, bad).unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{bad:?}");
        }
    }
}
