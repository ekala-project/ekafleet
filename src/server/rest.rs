use std::net::SocketAddr;

use axum::Router;
use axum::routing::get;

use super::events::EventStore;
use super::rbac::{Permission, TokenStore, extract_bearer_token};
use super::state::FleetState;

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
        .route("/v1/watch", get(rest_watch))
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

/// GET /v1/watch — Server-Sent Events stream of fleet events.
/// Polls the event store every 2 seconds and sends new events as SSE.
async fn rest_watch(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
) -> axum::response::Sse<
    impl futures_core::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse;

    let mut last_count = 0usize;
    let stream = async_stream::stream! {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let events = state.event_store.query(None, None, 100).await;
            let current_count = events.len();
            if current_count > last_count {
                let new_events = &events[..current_count - last_count];
                for event in new_events {
                    let data = serde_json::to_string(event).unwrap_or_default();
                    yield Ok(sse::Event::default().data(data));
                }
                last_count = current_count;
            }
        }
    };

    axum::response::Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    )
}
