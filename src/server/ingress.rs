//! Per-node ingress routes.
//!
//! Every [`PUBLISH_INTERVAL`] the server works out, for each connected node,
//! the routes of the fleet configuration's `ingress` that the node serves
//! (by `pools` / `nodes`), each with the mesh addresses of the replicas
//! currently serving its service. The node's agent hands them to its
//! ingress proxy (see [`crate::proxy::routes`]). Like DNS records, a set
//! is sent when it changes and re-sent periodically for agents that
//! restarted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::dns::DnsInputs;
use super::state::FleetState;
use crate::config::FleetConfig;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{IngressRoute, IngressUpdate, ServerMessage};
use crate::raft::state::FleetStateMachine;

/// How often routes are recomputed.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);

/// Unchanged route sets are re-sent this often.
const RESEND_INTERVAL: Duration = Duration::from_secs(30);

/// The routes each of `nodes` (node → pool) serves. Every listed node gets
/// an entry, empty when it serves none.
pub fn build_routes(
    config: &FleetConfig,
    nodes: &BTreeMap<String, String>,
    inputs: &DnsInputs,
) -> BTreeMap<String, Vec<IngressRoute>> {
    // service → port name → serving backends.
    let mut backends: HashMap<&str, HashMap<&str, BTreeSet<String>>> = HashMap::new();
    for (node, specs) in &inputs.assignments {
        let Some(ip) = inputs.mesh_ips.get(node) else {
            continue;
        };
        for spec in specs {
            if !crate::agent::netns::is_default_namespace(&spec.namespace)
                || !inputs.serving.contains(&(node.clone(), spec.name.clone()))
            {
                continue;
            }
            let ports = backends.entry(spec.name.as_str()).or_default();
            for port in spec.ports.iter().filter(|p| p.port != 0) {
                ports
                    .entry(port.name.as_str())
                    .or_default()
                    .insert(format!("{ip}:{}", port.port));
            }
        }
    }

    let mut names: Vec<&String> = config.ingress.keys().collect();
    names.sort();
    nodes
        .iter()
        .map(|(node, pool)| {
            let routes = names
                .iter()
                .filter_map(|name| {
                    let route = &config.ingress[*name];
                    route.served_by(node, pool).then(|| IngressRoute {
                        name: name.to_string(),
                        host: route.host.clone(),
                        path_prefix: route.path.clone(),
                        backends: backends
                            .get(route.service.as_str())
                            .and_then(|ports| ports.get(route.port.as_str()))
                            .map(|b| b.iter().cloned().collect())
                            .unwrap_or_default(),
                    })
                })
                .collect();
            (node.clone(), routes)
        })
        .collect()
}

/// Pushes route sets to connected agents when they change.
pub struct IngressPublisher {
    state: FleetState,
    raft_state: FleetStateMachine,
    sent: Mutex<HashMap<String, (Vec<IngressRoute>, Instant)>>,
}

impl IngressPublisher {
    pub fn new(state: FleetState, raft_state: FleetStateMachine) -> Self {
        Self {
            state,
            raft_state,
            sent: Mutex::default(),
        }
    }

    /// Send each connected agent its routes if they changed (or have not
    /// been sent for a while). Returns how many agents were sent routes.
    pub async fn publish(&self) -> usize {
        let config = match self.raft_state.current_config().await {
            Some(revision) => match revision.config() {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!(error = %e, "Cannot read ingress routes");
                    return 0;
                }
            },
            // Nothing applied yet, so nothing to serve or withdraw.
            None => return 0,
        };
        let connected = self.state.connected_nodes().await;
        let (statuses, _, _) = self.state.fleet_status().await;
        let nodes: BTreeMap<String, String> = statuses
            .into_iter()
            .filter(|n| connected.contains(&n.node_id))
            .map(|n| (n.node_id, n.pool))
            .collect();
        let mut routes = build_routes(&config, &nodes, &DnsInputs::gather(&self.state).await);

        let mut sent = self.sent.lock().await;
        sent.retain(|node, _| connected.contains(node));
        let mut count = 0;
        for node in connected {
            let set = routes.remove(&node).unwrap_or_default();
            if let Some((previous, at)) = sent.get(&node)
                && *previous == set
                && at.elapsed() < RESEND_INTERVAL
            {
                continue;
            }
            let msg = ServerMessage {
                payload: Some(ServerPayload::Ingress(IngressUpdate {
                    routes: set.clone(),
                })),
            };
            if self.state.send_to_agent(&node, msg).await {
                sent.insert(node, (set, Instant::now()));
                count += 1;
            }
        }
        count
    }

    /// Publish every [`PUBLISH_INTERVAL`] until `shutdown`.
    pub fn spawn(self, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PUBLISH_INTERVAL);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => {
                        self.publish().await;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{PortSpec, ServiceSpec};
    use std::net::Ipv4Addr;

    fn spec(name: &str, namespace: &str) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            namespace: namespace.into(),
            ports: vec![
                PortSpec {
                    name: "http".into(),
                    port: 8080,
                    protocol: "tcp".into(),
                    hostname: String::new(),
                },
                PortSpec {
                    name: "admin".into(),
                    port: 9000,
                    protocol: "tcp".into(),
                    hostname: String::new(),
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn nodes_get_their_routes_with_serving_backends() {
        let config: FleetConfig = serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "services": {"web": {"command": "/bin/web", "ports": {"http": {"port": 8080}}}},
            "ingress": {
                "site": {"host": "www.example.com", "service": "web", "port": "http", "pools": ["edge"]},
                "admin": {"host": "admin.example.com", "service": "web", "port": "admin", "nodes": ["b"]},
            },
        }))
        .unwrap();
        // a and b run web; c's replica is not serving; d is unaddressed.
        let inputs = DnsInputs {
            assignments: BTreeMap::from([
                ("a".into(), vec![spec("web", "")]),
                ("b".into(), vec![spec("web", "default")]),
                ("c".into(), vec![spec("web", "")]),
                ("d".into(), vec![spec("web", "")]),
            ]),
            mesh_ips: BTreeMap::from([
                ("a".into(), Ipv4Addr::new(10, 100, 0, 1)),
                ("b".into(), Ipv4Addr::new(10, 100, 0, 2)),
                ("c".into(), Ipv4Addr::new(10, 100, 0, 3)),
            ]),
            serving: [("a", "web"), ("b", "web"), ("d", "web")]
                .into_iter()
                .map(|(n, s)| (n.to_string(), s.to_string()))
                .collect(),
            ..Default::default()
        };
        let nodes = BTreeMap::from([
            ("a".to_string(), "edge".to_string()),
            ("b".to_string(), "default".to_string()),
            ("e".to_string(), "default".to_string()),
        ]);
        let routes = build_routes(&config, &nodes, &inputs);

        assert_eq!(
            routes["a"],
            vec![IngressRoute {
                name: "site".into(),
                host: "www.example.com".into(),
                path_prefix: "/".into(),
                backends: vec!["10.100.0.1:8080".into(), "10.100.0.2:8080".into()],
            }]
        );
        assert_eq!(routes["b"].len(), 1);
        assert_eq!(routes["b"][0].name, "admin");
        assert_eq!(
            routes["b"][0].backends,
            ["10.100.0.1:9000", "10.100.0.2:9000"]
        );
        assert!(routes["e"].is_empty());
    }

    #[test]
    fn a_route_without_serving_replicas_has_no_backends() {
        let config: FleetConfig = serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "services": {"web": {"command": "/bin/web", "ports": {"http": {"port": 8080}}}},
            "ingress": {"site": {"host": "*", "service": "web", "port": "http"}},
        }))
        .unwrap();
        let nodes = BTreeMap::from([("a".to_string(), "default".to_string())]);
        let routes = build_routes(&config, &nodes, &DnsInputs::default());
        assert_eq!(routes["a"].len(), 1);
        assert!(routes["a"][0].backends.is_empty());
    }
}
