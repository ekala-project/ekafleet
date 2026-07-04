use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use axum::routing::get;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::proto::fleet_control_server::{FleetControl, FleetControlServer};
use crate::proto::{
    AgentMessage, ApplyEvent, ApplyRequest, FleetStatus, PlanRequest, PlanResponse, ServerMessage,
    StatusRequest,
};

pub struct FleetControlService;

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

        tracing::info!(remote = %remote, "Agent connected");

        let (_tx, rx) = mpsc::channel(64);

        // TODO: spawn task to process incoming agent messages from request.into_inner()
        // and send ServerMessage responses via tx

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
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

        let (_tx, rx) = mpsc::channel(64);

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<FleetStatus>, Status> {
        Ok(Response::new(FleetStatus {
            fleet_name: "ekafleet".into(),
            nodes: vec![],
            services: vec![],
        }))
    }
}

/// Start the gRPC server (FleetControl service).
pub async fn serve_grpc(addr: SocketAddr) -> anyhow::Result<()> {
    tracing::info!(%addr, "gRPC server listening");

    tonic::transport::Server::builder()
        .add_service(FleetControlServer::new(FleetControlService))
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
    // TODO: expose prometheus metrics
    ""
}
