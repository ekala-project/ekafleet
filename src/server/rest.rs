use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::response::IntoResponse;
use axum::routing::{delete, get};

use super::events::EventStore;
use super::rbac::{Permission, TokenStore, extract_bearer_token};
use super::state::FleetState;
use crate::metrics::aggregator::MetricsAggregator;
use crate::metrics::alerting::{AlertEvaluator, AlertSilence};

/// Embedded single-page application HTML/JS/CSS for the fleet dashboard.
const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ekafleet Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;
 background:#0d1117;color:#c9d1d9;min-height:100vh;display:flex}
a{color:#58a6ff;text-decoration:none}
nav{width:200px;background:#161b22;padding:16px;border-right:1px solid #30363d;
 display:flex;flex-direction:column;gap:4px;position:fixed;height:100vh}
nav h1{font-size:16px;color:#58a6ff;margin-bottom:12px;padding-bottom:8px;
 border-bottom:1px solid #30363d}
nav a{display:block;padding:8px 12px;border-radius:6px;color:#c9d1d9;font-size:14px}
nav a:hover,nav a.active{background:#21262d;color:#f0f6fc}
main{margin-left:200px;padding:24px;flex:1;width:calc(100% - 200px)}
h2{font-size:20px;margin-bottom:16px;color:#f0f6fc}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;
 margin-bottom:16px}
.card h3{font-size:14px;color:#8b949e;margin-bottom:8px;text-transform:uppercase;
 letter-spacing:0.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.stat{text-align:center;padding:12px}
.stat .value{font-size:28px;font-weight:bold;color:#58a6ff}
.stat .label{font-size:12px;color:#8b949e;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;padding:8px 12px;border-bottom:2px solid #30363d;color:#8b949e;
 font-weight:600}
td{padding:8px 12px;border-bottom:1px solid #21262d}
tr:hover td{background:#161b22}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;
 font-weight:600}
.badge-green{background:#238636;color:#fff}
.badge-red{background:#da3633;color:#fff}
.badge-yellow{background:#9e6a03;color:#fff}
.badge-blue{background:#1f6feb;color:#fff}
.error{color:#f85149;padding:16px;text-align:center}
.loading{color:#8b949e;padding:24px;text-align:center}
.empty{color:#8b949e;padding:24px;text-align:center;font-style:italic}
.event-time{color:#8b949e;font-size:12px;white-space:nowrap}
</style>
</head>
<body>
<nav>
<h1>ekafleet</h1>
<a href="#overview" onclick="navigate('overview')" id="nav-overview">Overview</a>
<a href="#nodes" onclick="navigate('nodes')" id="nav-nodes">Nodes</a>
<a href="#services" onclick="navigate('services')" id="nav-services">Services</a>
<a href="#events" onclick="navigate('events')" id="nav-events">Events</a>
<a href="#deployments" onclick="navigate('deployments')" id="nav-deployments">Deployments</a>
</nav>
<main id="content">
<div class="loading">Loading...</div>
</main>
<script>
let statusData=null,servicesData=null,eventsData=null,deploymentsData=null;
const $=id=>document.getElementById(id);
async function api(path){
 const r=await fetch(path);
 if(!r.ok)throw new Error(r.status+' '+r.statusText);
 return r.json();
}
async function loadAll(){
 try{
  [statusData,servicesData,eventsData,deploymentsData]=await Promise.all([
   api('/v1/status'),api('/v1/services'),api('/v1/events'),api('/v1/deployments')
  ]);
 }catch(e){$('content').innerHTML='<div class="error">Failed to load data: '+e.message+'</div>';}
}
function badge(ok,yes,no){return '<span class="badge badge-'+(ok?'green':'red')+'">'+(ok?yes:no)+'</span>';}
function renderOverview(){
 if(!statusData)return '<div class="loading">Loading...</div>';
 const nodes=statusData.nodes||[];
 const svcs=statusData.services||[];
 const healthy=nodes.filter(n=>n.healthy).length;
 const svcHealthy=svcs.reduce((a,s)=>a+s.healthy_count,0);
 const svcTotal=svcs.reduce((a,s)=>a+s.instance_count,0);
 return '<h2>Fleet Overview</h2><div class="card"><div class="grid">'+
  '<div class="stat"><div class="value">'+nodes.length+'</div><div class="label">Total Nodes</div></div>'+
  '<div class="stat"><div class="value">'+healthy+'</div><div class="label">Healthy Nodes</div></div>'+
  '<div class="stat"><div class="value">'+svcs.length+'</div><div class="label">Services</div></div>'+
  '<div class="stat"><div class="value">'+svcHealthy+'/'+svcTotal+'</div><div class="label">Healthy Instances</div></div>'+
  '</div></div>'+
  '<div class="card"><h3>Nodes</h3><table><tr><th>Node</th><th>Address</th><th>Pool</th><th>Status</th></tr>'+
  nodes.map(n=>'<tr><td>'+n.node_id+'</td><td>'+n.address+'</td><td>'+(n.pool||'-')+'</td><td>'+badge(n.healthy,'healthy','unhealthy')+'</td></tr>').join('')+
  '</table></div>'+
  '<div class="card"><h3>Services</h3><table><tr><th>Service</th><th>Instances</th><th>Healthy</th></tr>'+
  svcs.map(s=>'<tr><td>'+s.name+'</td><td>'+s.instance_count+'</td><td>'+s.healthy_count+'</td></tr>').join('')+
  '</table></div>';
}
function renderNodes(){
 if(!statusData)return '<div class="loading">Loading...</div>';
 const nodes=statusData.nodes||[];
 if(!nodes.length)return '<h2>Nodes</h2><div class="empty">No nodes registered.</div>';
 return '<h2>Nodes</h2><div class="card"><table><tr><th>Node ID</th><th>Address</th><th>Pool</th><th>Last Heartbeat</th><th>Status</th></tr>'+
  nodes.map(n=>'<tr><td>'+n.node_id+'</td><td>'+n.address+'</td><td>'+(n.pool||'-')+'</td><td>'+n.last_heartbeat+'s ago</td><td>'+badge(n.healthy,'healthy','unhealthy')+'</td></tr>').join('')+
  '</table></div>';
}
function renderServices(){
 if(!servicesData)return '<div class="loading">Loading...</div>';
 const svcs=Array.isArray(servicesData)?servicesData:[];
 if(!svcs.length)return '<h2>Services</h2><div class="empty">No services deployed.</div>';
 return '<h2>Services</h2>'+svcs.map(s=>{
  const insts=s.instances||[];
  return '<div class="card"><h3>'+s.name+' ('+s.healthy_count+'/'+s.desired_count+' healthy)</h3>'+
   '<table><tr><th>Instance</th><th>Node</th><th>State</th><th>Health</th></tr>'+
   insts.map(i=>'<tr><td>'+i.instance_id+'</td><td>'+i.node_id+'</td><td><span class="badge badge-blue">'+i.state+'</span></td><td>'+badge(i.health==='healthy'||i.health===1,'healthy','unhealthy')+'</td></tr>').join('')+
   '</table></div>';
 }).join('');
}
function renderEvents(){
 if(!eventsData)return '<div class="loading">Loading...</div>';
 const evts=Array.isArray(eventsData)?eventsData:[];
 if(!evts.length)return '<h2>Events</h2><div class="empty">No events recorded.</div>';
 return '<h2>Events</h2><div class="card"><table><tr><th>Time</th><th>Category</th><th>Service</th><th>Message</th></tr>'+
  evts.map(e=>'<tr><td class="event-time">'+(e.timestamp||'')+'</td><td><span class="badge badge-yellow">'+(e.category||'')+'</span></td><td>'+(e.service||'-')+'</td><td>'+(e.message||'')+'</td></tr>').join('')+
  '</table></div>';
}
function renderDeployments(){
 if(!deploymentsData)return '<div class="loading">Loading...</div>';
 const deps=Array.isArray(deploymentsData)?deploymentsData:[];
 if(!deps.length)return '<h2>Deployments</h2><div class="empty">No deployment history.</div>';
 return '<h2>Deployments</h2><div class="card"><table><tr><th>ID</th><th>Service</th><th>Status</th><th>Time</th></tr>'+
  deps.map(d=>'<tr><td>'+(d.deployment_id||d.id||'-')+'</td><td>'+(d.service_name||d.service||'-')+'</td><td><span class="badge badge-blue">'+(d.status||'-')+'</span></td><td class="event-time">'+(d.timestamp||d.deployed_at||'')+'</td></tr>').join('')+
  '</table></div>';
}
const pages={overview:renderOverview,nodes:renderNodes,services:renderServices,events:renderEvents,deployments:renderDeployments};
let currentPage='overview';
function navigate(page){
 currentPage=page;
 document.querySelectorAll('nav a').forEach(a=>a.classList.remove('active'));
 const el=$('nav-'+page);if(el)el.classList.add('active');
 render();
}
function render(){
 const fn=pages[currentPage]||renderOverview;
 $('content').innerHTML=fn();
}
async function init(){
 await loadAll();render();
 const hash=location.hash.replace('#','');if(hash&&pages[hash])navigate(hash);
 else navigate('overview');
 setInterval(async()=>{await loadAll();render();},10000);
}
init();
</script>
</body>
</html>"##;

/// Shared state for the HTTP REST API.
#[derive(Clone)]
pub struct HttpApiState {
    pub fleet_state: FleetState,
    pub event_store: EventStore,
    pub token_store: TokenStore,
    pub metrics: MetricsAggregator,
    pub alert_evaluator: AlertEvaluator,
    pub kv_store: Arc<tokio::sync::RwLock<HashMap<String, Vec<u8>>>>,
    pub instance_tracker: Option<super::cloud::instance_tracker::InstanceTracker>,
}

/// Start the HTTP API server with REST endpoints for all operations.
/// The /health endpoint is public; all other endpoints require authentication via RBAC tokens.
pub async fn serve_http(
    addr: SocketAddr,
    fleet_state: FleetState,
    event_store: EventStore,
    token_store: TokenStore,
    metrics: MetricsAggregator,
    alert_evaluator: AlertEvaluator,
    instance_tracker: Option<super::cloud::instance_tracker::InstanceTracker>,
    shutdown: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    use axum::extract::State;
    use axum::http::StatusCode;

    let api_state = HttpApiState {
        fleet_state,
        event_store,
        token_store: token_store.clone(),
        metrics,
        alert_evaluator,
        kv_store: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        instance_tracker,
    };

    let authenticated_routes = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/v1/status", get(rest_status))
        .route("/v1/services", get(rest_services))
        .route("/v1/capacity", get(rest_capacity))
        .route("/v1/events", get(rest_events))
        .route("/v1/deployments", get(rest_deployments))
        .route("/v1/deployments/{service}", get(rest_service_deployments))
        .route("/v1/watch", get(rest_watch))
        .route("/v1/query", get(rest_query))
        .route(
            "/v1/alerts/silences",
            get(rest_list_silences).post(rest_create_silence),
        )
        .route("/v1/alerts/silences/{id}", delete(rest_delete_silence))
        .route(
            "/v1/kv/{*key}",
            get(rest_kv_get).put(rest_kv_put).delete(rest_kv_delete),
        )
        .route("/v1/kv", get(rest_kv_list))
        .route("/v1/metrics/services/{name}", get(rest_service_metrics))
        .route("/v1/cloud/instances", get(rest_cloud_instances))
        .route("/ui/", get(ui_handler))
        .route("/ui/{*path}", get(ui_handler))
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
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

/// GET /ui/ — Serve the embedded single-page dashboard application.
async fn ui_handler() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD_HTML,
    )
}

/// GET /metrics — Prometheus exposition format metrics.
async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
) -> impl IntoResponse {
    let body = state.metrics.export_prometheus().await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
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

// --- Feature 20: PromQL / Metric Query API ---

#[derive(serde::Deserialize)]
struct MetricQuery {
    metric: String,
    service: Option<String>,
    node: Option<String>,
}

/// GET /v1/query?metric=<name>&service=<name> or &node=<id>
/// Returns current metric value from MetricsAggregator.
async fn rest_query(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    query: axum::extract::Query<MetricQuery>,
) -> axum::Json<serde_json::Value> {
    if let Some(ref service) = query.service {
        // Service metric query
        let avg = state
            .metrics
            .service_metric_avg(service, &query.metric)
            .await;
        match avg {
            Some(value) => axum::Json(serde_json::json!({
                "metric": query.metric,
                "value": value,
                "labels": { "service": service },
            })),
            None => axum::Json(serde_json::json!({
                "metric": query.metric,
                "value": null,
                "labels": { "service": service },
            })),
        }
    } else if let Some(ref node) = query.node {
        // Node metric query
        let value = state.metrics.node_metric(node, &query.metric).await;
        match value {
            Some(v) => axum::Json(serde_json::json!({
                "metric": query.metric,
                "value": v,
                "labels": { "node": node },
            })),
            None => axum::Json(serde_json::json!({
                "metric": query.metric,
                "value": null,
                "labels": { "node": node },
            })),
        }
    } else {
        // Fleet-wide metric query
        let avg = state.metrics.fleet_metric_avg(&query.metric).await;
        match avg {
            Some(value) => axum::Json(serde_json::json!({
                "metric": query.metric,
                "value": value,
                "labels": {},
            })),
            None => axum::Json(serde_json::json!({
                "metric": query.metric,
                "value": null,
                "labels": {},
            })),
        }
    }
}

// --- Feature 21: Alerting Pipeline REST endpoints ---

/// GET /v1/alerts/silences — List all active silences.
async fn rest_list_silences(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
) -> axum::Json<serde_json::Value> {
    let silences = state.alert_evaluator.list_silences().await;
    axum::Json(serde_json::json!(silences))
}

/// POST /v1/alerts/silences — Create a silence (JSON body).
async fn rest_create_silence(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    axum::Json(silence): axum::Json<AlertSilence>,
) -> axum::Json<serde_json::Value> {
    state.alert_evaluator.add_silence(silence).await;
    let silences = state.alert_evaluator.list_silences().await;
    axum::Json(serde_json::json!({
        "status": "created",
        "count": silences.len(),
    }))
}

/// DELETE /v1/alerts/silences/:id — Remove a silence by index.
async fn rest_delete_silence(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    axum::extract::Path(id): axum::extract::Path<usize>,
) -> axum::Json<serde_json::Value> {
    state.alert_evaluator.remove_silence(id).await;
    axum::Json(serde_json::json!({
        "status": "deleted",
    }))
}

// --- Feature 23: Consul KV API ---

/// GET /v1/kv/:key — Read a key from the in-memory KV store.
/// Returns the value as a UTF-8 string. Non-UTF-8 bytes are replaced with U+FFFD.
async fn rest_kv_get(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> impl IntoResponse {
    let store = state.kv_store.read().await;
    match store.get(&key) {
        Some(value) => {
            let value_str = String::from_utf8_lossy(value).into_owned();
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!([{
                    "Key": key,
                    "Value": value_str,
                }])),
            )
        }
        None => (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "key not found"})),
        ),
    }
}

/// PUT /v1/kv/:key — Write a key to the in-memory KV store.
async fn rest_kv_put(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    axum::extract::Path(key): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> axum::Json<serde_json::Value> {
    let mut store = state.kv_store.write().await;
    store.insert(key, body.to_vec());
    axum::Json(serde_json::json!(true))
}

/// DELETE /v1/kv/:key — Delete a key from the in-memory KV store.
async fn rest_kv_delete(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let mut store = state.kv_store.write().await;
    let existed = store.remove(&key).is_some();
    axum::Json(serde_json::json!(existed))
}

#[derive(serde::Deserialize)]
struct KvListQuery {
    prefix: Option<String>,
}

/// GET /v1/kv?prefix=... — List keys by prefix.
async fn rest_kv_list(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    query: axum::extract::Query<KvListQuery>,
) -> axum::Json<serde_json::Value> {
    let store = state.kv_store.read().await;
    let prefix = query.prefix.as_deref().unwrap_or("");
    let keys: Vec<&String> = store.keys().filter(|k| k.starts_with(prefix)).collect();
    axum::Json(serde_json::json!(keys))
}

// --- Feature 24: HPA Metrics API ---

/// GET /v1/metrics/services/:name — Current metrics for a service.
async fn rest_service_metrics(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let metrics = state.metrics.service_metrics(&name).await;
    axum::Json(serde_json::json!({
        "service": name,
        "metrics": metrics,
    }))
}

/// GET /v1/cloud/instances — List all tracked cloud-provisioned machine instances.
async fn rest_cloud_instances(
    axum::extract::State(state): axum::extract::State<HttpApiState>,
) -> axum::Json<serde_json::Value> {
    let instances = if let Some(tracker) = &state.instance_tracker {
        let all = tracker.all().await;
        all.values()
            .map(|i| {
                serde_json::json!({
                    "instance_id": i.cloud_instance_id,
                    "provider": i.provider,
                    "pool": i.pool,
                    "private_ip": i.private_ip,
                    "fleet_node_id": i.fleet_node_id,
                    "created_at": i.created_at,
                    "joined_at": i.joined_at,
                })
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    axum::Json(serde_json::json!({
        "cloud_instances": instances,
        "count": instances.len(),
    }))
}
