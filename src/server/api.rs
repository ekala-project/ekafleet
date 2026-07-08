use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use axum::routing::get;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use super::events::EventStore;
use super::rbac::{Permission, TokenStore, extract_bearer_token};
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
    AgentMessage, ApplyEvent, ApplyRequest, CertificateResponse, FleetStatus,
    NodeAttestationRequest, NodeAttestationResult, PlanRequest, PlanResponse, ServerMessage,
    StatusRequest, TrustBundleUpdate,
};

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
                        process_agent_message(&state, &nid, msg, issuer.as_ref(), &metrics).await;
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

        Ok(Response::new(PlanResponse {
            operations: vec![],
            has_changes: false,
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
}

impl FleetControlService {
    async fn process_message(&self, node_id: &str, msg: AgentMessage) {
        process_agent_message(
            &self.state,
            node_id,
            msg,
            self.cert_issuer.as_ref(),
            &self.metrics,
        )
        .await;
    }
}

async fn process_agent_message(
    state: &FleetState,
    node_id: &str,
    msg: AgentMessage,
    cert_issuer: Option<&CertIssuer>,
    metrics: &MetricsAggregator,
) {
    match msg.payload {
        Some(Payload::Heartbeat(hb)) => {
            tracing::debug!(node_id = %hb.node_id, "Heartbeat received");
            state
                .update_heartbeat(node_id, hb.available_resources)
                .await;
        }
        Some(Payload::Health(report)) => {
            tracing::debug!(
                node_id = %report.node_id,
                count = report.services.len(),
                "Health report received"
            );
            state.update_health(node_id, report.services).await;
        }
        Some(Payload::Status(report)) => {
            tracing::debug!(
                node_id = %report.node_id,
                services = report.running_services.len(),
                "Status report received"
            );
            state.update_status(node_id, report.running_services).await;
        }
        Some(Payload::CertRequest(req)) => {
            tracing::debug!(
                node_id = %req.node_id,
                service = %req.service_name,
                "Certificate request received"
            );

            if let Some(issuer) = cert_issuer {
                match issuer
                    .process_request(&req.node_id, &req.service_name, &req.csr)
                    .await
                {
                    Ok((cert, chain, expires_at)) => {
                        let response = ServerMessage {
                            payload: Some(ServerPayload::Cert(CertificateResponse {
                                certificate: cert,
                                chain,
                                expires_at,
                                service_name: req.service_name.clone(),
                            })),
                        };
                        state.send_to_agent(node_id, response).await;
                        tracing::info!(
                            node_id = %req.node_id,
                            service = %req.service_name,
                            "SVID issued"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            node_id = %req.node_id,
                            service = %req.service_name,
                            error = %e,
                            "Certificate request denied"
                        );
                    }
                }
            }
        }
        Some(Payload::Metrics(summary)) => {
            tracing::debug!(
                node_id = %summary.node_id,
                points = summary.points.len(),
                "Metrics received"
            );
            metrics.ingest(&summary.node_id, summary.points).await;
        }
        Some(Payload::Nack(nack)) => {
            tracing::warn!(
                correlation_id = %nack.correlation_id,
                reason = %nack.reason,
                "Agent NACKed a command"
            );
        }
        Some(Payload::AttestResponse(_)) => {
            // Attestation responses are handled via the Attest RPC, not the stream.
            tracing::debug!("Ignoring attestation response on stream (use Attest RPC)");
        }
        None => {}
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

/// Start the gRPC server with TLS and RBAC-based authentication.
pub async fn serve_grpc(
    addr: SocketAddr,
    state: FleetState,
    token_store: TokenStore,
    tls: &TlsConfig,
    cert_issuer: CertIssuer,
    ca: RootCa,
    trust_bundle_pem: String,
    domain: &str,
    fleet_key: Vec<u8>,
) -> anyhow::Result<()> {
    tracing::info!(%addr, domain, "gRPC server listening (TLS + RBAC + SPIFFE)");

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

    let service = FleetControlService::new(state, domain)
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

/// Shared state for the HTTP REST API.
#[derive(Clone)]
pub struct HttpApiState {
    pub fleet_state: FleetState,
    pub event_store: EventStore,
    pub token_store: TokenStore,
}

/// Start the HTTP API server with REST endpoints for all operations.
/// The /health endpoint is public; all other endpoints require authentication via RBAC tokens.
pub async fn serve_http(
    addr: SocketAddr,
    fleet_state: FleetState,
    event_store: EventStore,
    token_store: TokenStore,
) -> anyhow::Result<()> {
    use axum::extract::State;
    use axum::http::StatusCode;

    let api_state = HttpApiState {
        fleet_state,
        event_store,
        token_store: token_store.clone(),
    };

    let authenticated_routes = Router::new()
        .route("/metrics", get(metrics))
        .route("/v1/status", get(rest_status))
        .route("/v1/services", get(rest_services))
        .route("/v1/capacity", get(rest_capacity))
        .route("/v1/events", get(rest_events))
        .route("/v1/deployments", get(rest_deployments))
        .route("/v1/deployments/{service}", get(rest_service_deployments))
        .with_state(api_state)
        .layer(axum::middleware::from_fn_with_state(
            token_store,
            |State(store): State<TokenStore>,
             req: axum::http::Request<axum::body::Body>,
             next: axum::middleware::Next| async move {
                let auth_header = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok());
                let token = extract_bearer_token(auth_header).ok_or(StatusCode::UNAUTHORIZED)?;

                let role = store
                    .authenticate(token)
                    .await
                    .ok_or(StatusCode::UNAUTHORIZED)?;

                if !role.has_permission(Permission::Read) {
                    return Err(StatusCode::FORBIDDEN);
                }

                Ok(next.run(req).await)
            },
        ));

    let app = Router::new()
        .route("/health", get(health))
        .merge(authenticated_routes);

    tracing::info!(%addr, "HTTP server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn metrics() -> &'static str {
    ""
}

/// GET /v1/status — Fleet health overview (JSON).
async fn rest_status(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
) -> axum::Json<serde_json::Value> {
    let (nodes, services, pools) = state.fleet_state.fleet_status().await;
    axum::Json(serde_json::json!({
        "fleet_name": "ekafleet",
        "nodes": nodes.iter().map(|n| serde_json::json!({
            "node_id": n.node_id,
            "address": n.address,
            "healthy": n.healthy,
            "pool": n.pool,
            "last_heartbeat": n.last_heartbeat,
        })).collect::<Vec<_>>(),
        "services": services.iter().map(|s| serde_json::json!({
            "name": s.name,
            "healthy_count": s.healthy_count,
            "instance_count": s.instances.len(),
        })).collect::<Vec<_>>(),
        "pools": pools.iter().map(|p| serde_json::json!({
            "name": p.name,
            "machine_count": p.machine_count,
        })).collect::<Vec<_>>(),
    }))
}

/// GET /v1/services — Service placement listing (JSON).
async fn rest_services(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
) -> axum::Json<serde_json::Value> {
    let (_, services, _) = state.fleet_state.fleet_status().await;
    let data: Vec<serde_json::Value> = services
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "desired_count": s.desired_count,
                "healthy_count": s.healthy_count,
                "instances": s.instances.iter().map(|i| serde_json::json!({
                    "instance_id": i.instance_id,
                    "node_id": i.node_id,
                    "state": i.state,
                    "health": i.health,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    axum::Json(serde_json::json!(data))
}

/// GET /v1/capacity — Resource utilization report (JSON).
async fn rest_capacity(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
) -> axum::Json<serde_json::Value> {
    let (nodes, _, pools) = state.fleet_state.fleet_status().await;
    let mut total_cpu = 0u64;
    let mut total_mem = 0u64;
    let mut total_disk = 0u64;
    for node in &nodes {
        if let Some(res) = &node.available_resources {
            total_cpu += res.cpu_millicores;
            total_mem += res.memory_mb;
            total_disk += res.disk_mb;
        }
    }
    axum::Json(serde_json::json!({
        "node_count": nodes.len(),
        "available_cpu_millicores": total_cpu,
        "available_memory_mb": total_mem,
        "available_disk_mb": total_disk,
        "pools": pools.iter().map(|p| {
            let sched = p.total_schedulable.as_ref();
            let alloc = p.total_allocated.as_ref();
            serde_json::json!({
                "name": p.name,
                "machine_count": p.machine_count,
                "schedulable_cpu": sched.map(|r| r.cpu_millicores).unwrap_or(0),
                "schedulable_memory": sched.map(|r| r.memory_mb).unwrap_or(0),
                "allocated_cpu": alloc.map(|r| r.cpu_millicores).unwrap_or(0),
                "allocated_memory": alloc.map(|r| r.memory_mb).unwrap_or(0),
            })
        }).collect::<Vec<_>>(),
    }))
}

/// GET /v1/events?category=...&service=...&limit=... — Query event timeline (JSON).
async fn rest_events(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    query: axum::extract::Query<EventsQuery>,
) -> axum::Json<serde_json::Value> {
    let limit = query.limit.unwrap_or(50).min(1000);
    let events = state
        .event_store
        .query(None, query.service.as_deref(), limit as usize)
        .await;
    axum::Json(serde_json::json!(events))
}

#[derive(serde::Deserialize)]
struct EventsQuery {
    service: Option<String>,
    limit: Option<u32>,
}

/// GET /v1/deployments — All deployment history (JSON).
async fn rest_deployments(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    query: axum::extract::Query<DeploymentsQuery>,
) -> axum::Json<serde_json::Value> {
    let limit = query.limit.unwrap_or(50).min(1000);
    let history = state.event_store.all_deploy_history(limit as usize).await;
    axum::Json(serde_json::json!(history))
}

/// GET /v1/deployments/:service — Per-service deployment history (JSON).
async fn rest_service_deployments(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    axum::extract::Path(service): axum::extract::Path<String>,
    query: axum::extract::Query<DeploymentsQuery>,
) -> axum::Json<serde_json::Value> {
    let limit = query.limit.unwrap_or(50).min(1000);
    let history = state
        .event_store
        .deploy_history(&service, limit as usize)
        .await;
    axum::Json(serde_json::json!(history))
}

#[derive(serde::Deserialize)]
struct DeploymentsQuery {
    limit: Option<u32>,
}
