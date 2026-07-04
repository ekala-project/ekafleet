use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use axum::routing::get;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Identity, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use super::state::FleetState;
use crate::ca::issuer::CertIssuer;
use crate::metrics::aggregator::MetricsAggregator;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_server::{FleetControl, FleetControlServer};
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    AgentMessage, ApplyEvent, ApplyRequest, CertificateResponse, FleetStatus, PlanRequest,
    PlanResponse, ServerMessage, StatusRequest, TrustBundleUpdate,
};

pub struct FleetControlService {
    state: FleetState,
    cert_issuer: Option<CertIssuer>,
    trust_bundle_pem: Option<String>,
    metrics: MetricsAggregator,
}

impl FleetControlService {
    pub fn new(state: FleetState) -> Self {
        Self {
            state,
            cert_issuer: None,
            trust_bundle_pem: None,
            metrics: MetricsAggregator::new(),
        }
    }

    /// Configure the service with a certificate issuer for SPIFFE SVID issuance.
    pub fn with_cert_issuer(mut self, issuer: CertIssuer, trust_bundle_pem: String) -> Self {
        self.cert_issuer = Some(issuer);
        self.trust_bundle_pem = Some(trust_bundle_pem);
        self
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

        let node_id = match &first_msg.payload {
            Some(Payload::Heartbeat(hb)) => hb.node_id.clone(),
            Some(Payload::Status(sr)) => sr.node_id.clone(),
            _ => {
                return Err(Status::invalid_argument(
                    "first message must be heartbeat or status",
                ));
            }
        };

        tracing::info!(node_id = %node_id, remote = %remote, "Agent connected");

        // Register agent and get outbound channel
        let rx = self.state.register_agent(&node_id, remote).await;

        // Push trust bundle to newly connected agent
        if let Some(bundle_pem) = &self.trust_bundle_pem {
            let bundle_msg = ServerMessage {
                payload: Some(ServerPayload::TrustBundle(TrustBundleUpdate {
                    trust_domain: "fleet.internal".into(),
                    ca_certificate_pem: bundle_pem.as_bytes().to_vec(),
                })),
            };
            let _ = self.state.send_to_agent(&node_id, bundle_msg).await;
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

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<FleetStatus>, Status> {
        let (nodes, services) = self.state.fleet_status().await;

        Ok(Response::new(FleetStatus {
            fleet_name: "ekafleet".into(),
            nodes,
            services,
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

/// Start the gRPC server with TLS and bearer token authentication.
pub async fn serve_grpc(
    addr: SocketAddr,
    state: FleetState,
    token: &str,
    tls: &TlsConfig,
    cert_issuer: CertIssuer,
    trust_bundle_pem: String,
) -> anyhow::Result<()> {
    tracing::info!(%addr, "gRPC server listening (TLS + token-authenticated + SPIFFE)");

    let expected_token = format!("Bearer {token}");
    #[allow(clippy::result_large_err)]
    let interceptor = move |req: Request<()>| -> Result<Request<()>, Status> {
        match req.metadata().get("authorization") {
            Some(val) if val == expected_token.as_str() => Ok(req),
            Some(_) => Err(Status::unauthenticated("invalid token")),
            None => Err(Status::unauthenticated("missing authorization header")),
        }
    };

    let identity = Identity::from_pem(&tls.cert_pem, &tls.cert_pem);
    let tls_config = ServerTlsConfig::new().identity(identity);

    let service = FleetControlService::new(state).with_cert_issuer(cert_issuer, trust_bundle_pem);

    tonic::transport::Server::builder()
        .tls_config(tls_config)?
        .add_service(FleetControlServer::with_interceptor(service, interceptor))
        .serve(addr)
        .await?;

    Ok(())
}

/// Start the HTTP API server (health, metrics, status endpoints).
/// The /health endpoint is public; /metrics requires bearer token.
pub async fn serve_http(addr: SocketAddr, token: String) -> anyhow::Result<()> {
    use axum::extract::State;
    use axum::http::StatusCode;

    let authenticated_routes =
        Router::new()
            .route("/metrics", get(metrics))
            .layer(axum::middleware::from_fn_with_state(
                token.clone(),
                |State(expected): State<String>,
                 req: axum::http::Request<axum::body::Body>,
                 next: axum::middleware::Next| async move {
                    let expected_header = format!("Bearer {expected}");
                    match req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                    {
                        Some(val) if val == expected_header => Ok(next.run(req).await),
                        _ => Err(StatusCode::UNAUTHORIZED),
                    }
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
