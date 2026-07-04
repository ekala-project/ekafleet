use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use axum::routing::get;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use super::state::FleetState;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_server::{FleetControl, FleetControlServer};
use crate::proto::{
    AgentMessage, ApplyEvent, ApplyRequest, FleetStatus, PlanRequest, PlanResponse, ServerMessage,
    StatusRequest,
};

pub struct FleetControlService {
    state: FleetState,
}

impl FleetControlService {
    pub fn new(state: FleetState) -> Self {
        Self { state }
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

        // Process the first message
        self.process_message(&node_id, first_msg).await;

        // Spawn task to process remaining inbound messages
        let state = self.state.clone();
        let nid = node_id.clone();
        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(msg)) => {
                        process_agent_message(&state, &nid, msg).await;
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
        process_agent_message(&self.state, node_id, msg).await;
    }
}

async fn process_agent_message(state: &FleetState, node_id: &str, msg: AgentMessage) {
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
            // TODO: issue certificate
        }
        Some(Payload::Metrics(summary)) => {
            tracing::debug!(
                node_id = %summary.node_id,
                points = summary.points.len(),
                "Metrics received"
            );
            // TODO: store/aggregate metrics
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

/// Start the gRPC server (FleetControl service) with bearer token authentication.
pub async fn serve_grpc(addr: SocketAddr, state: FleetState, token: &str) -> anyhow::Result<()> {
    tracing::info!(%addr, "gRPC server listening (token-authenticated)");

    let expected_token = format!("Bearer {token}");
    #[allow(clippy::result_large_err)]
    let interceptor = move |req: Request<()>| -> Result<Request<()>, Status> {
        match req.metadata().get("authorization") {
            Some(val) if val == expected_token.as_str() => Ok(req),
            Some(_) => Err(Status::unauthenticated("invalid token")),
            None => Err(Status::unauthenticated("missing authorization header")),
        }
    };

    tonic::transport::Server::builder()
        .add_service(FleetControlServer::with_interceptor(
            FleetControlService::new(state),
            interceptor,
        ))
        .serve(addr)
        .await?;

    Ok(())
}

/// Start the HTTP API server (health, metrics, status endpoints).
pub async fn serve_http(addr: SocketAddr) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics));

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
