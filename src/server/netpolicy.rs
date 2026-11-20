//! Per-node network policy.
//!
//! Policy is opt-in per service. A service that declares
//! `identity.allowedCallers` is reachable from other nodes only from the
//! nodes running one of those callers, or serving an ingress route to it.
//! A namespaced service is reachable only from its callers' replicas, by
//! their namespace IPs, and from the ingress proxies routing to it. A service that declares `identity.egressRules` may
//! send only what they allow. Every [`PUBLISH_INTERVAL`] the server works out
//! each connected node's policy for the replicas it runs, and the agent
//! enforces it with nftables (see [`crate::policy::nftables`]). As with
//! ingress routes, a policy is sent when it changes and re-sent
//! periodically.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::dns::DnsInputs;
use super::state::FleetState;
use crate::agent::netns::is_default_namespace;
use crate::config::{EgressAction, FleetConfig};
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{EgressPolicy, EgressRuleSpec, IngressPolicy, PolicyUpdate, ServerMessage};
use crate::raft::state::FleetStateMachine;

/// How often policies are recomputed.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);

/// Unchanged policies are re-sent this often.
const RESEND_INTERVAL: Duration = Duration::from_secs(30);

/// The policy of each of `nodes` (node → pool). Every listed node gets an
/// entry, empty when none of its replicas declares a policy.
pub fn build_policies(
    config: &FleetConfig,
    nodes: &BTreeMap<String, String>,
    inputs: &DnsInputs,
) -> BTreeMap<String, PolicyUpdate> {
    // Where each service runs: host-networked replicas by their node's mesh
    // IP, namespaced ones by namespace IP (within their namespace).
    let mut hosts: HashMap<&str, BTreeSet<String>> = HashMap::new();
    let mut replicas: HashMap<(&str, &str), BTreeSet<String>> = HashMap::new();
    for (node, specs) in &inputs.assignments {
        for spec in specs {
            if is_default_namespace(&spec.namespace) {
                if let Some(ip) = inputs.mesh_ips.get(node) {
                    hosts.entry(&spec.name).or_default().insert(ip.to_string());
                }
            } else if !spec.namespace_ip.is_empty() {
                replicas
                    .entry((&spec.namespace, &spec.name))
                    .or_default()
                    .insert(spec.namespace_ip.clone());
            }
        }
    }
    // Nodes whose ingress proxy forwards to each service.
    let mut proxies: HashMap<&str, BTreeSet<String>> = HashMap::new();
    for route in config.ingress.values() {
        for (node, pool) in nodes {
            if route.served_by(node, pool)
                && let Some(ip) = inputs.mesh_ips.get(node)
            {
                for service in route.services() {
                    proxies.entry(service).or_default().insert(ip.to_string());
                }
            }
        }
    }

    nodes
        .keys()
        .map(|node| {
            let mut update = PolicyUpdate::default();
            let specs = inputs.assignments.get(node).map_or(&[][..], Vec::as_slice);
            for spec in specs {
                let Some(service) = config.services.get(&spec.name) else {
                    continue;
                };
                let identity = &service.identity;
                let namespaced = !is_default_namespace(&spec.namespace);
                let ports: Vec<u32> = spec
                    .ports
                    .iter()
                    .map(|p| p.port)
                    .filter(|p| *p != 0)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                if !identity.allowed_callers.is_empty()
                    && !ports.is_empty()
                    && (!namespaced || !spec.namespace_ip.is_empty())
                {
                    let mut sources = BTreeSet::new();
                    for caller in &identity.allowed_callers {
                        let found = if namespaced {
                            replicas.get(&(spec.namespace.as_str(), caller.as_str()))
                        } else {
                            hosts.get(caller.as_str())
                        };
                        sources.extend(found.into_iter().flatten().cloned());
                    }
                    // Proxies reach namespaced replicas from their mesh
                    // address too, through the namespace's uplink.
                    sources.extend(
                        proxies
                            .get(spec.name.as_str())
                            .into_iter()
                            .flatten()
                            .cloned(),
                    );
                    update.ingress.push(IngressPolicy {
                        service: spec.name.clone(),
                        namespace: if namespaced {
                            spec.namespace.clone()
                        } else {
                            String::new()
                        },
                        dest_ip: if namespaced {
                            spec.namespace_ip.clone()
                        } else {
                            String::new()
                        },
                        ports,
                        allowed_sources: sources.into_iter().collect(),
                    });
                }
                if !identity.egress_rules.is_empty() {
                    update.egress.push(EgressPolicy {
                        service: spec.name.clone(),
                        namespace: if namespaced {
                            spec.namespace.clone()
                        } else {
                            String::new()
                        },
                        rules: identity
                            .egress_rules
                            .iter()
                            .map(|r| EgressRuleSpec {
                                dest_cidr: r.dest_cidr.clone(),
                                dest_ports: r.dest_ports.iter().map(|p| u32::from(*p)).collect(),
                                allow: r.action == EgressAction::Allow,
                            })
                            .collect(),
                    });
                }
            }
            update.ingress.sort_by(|a, b| a.service.cmp(&b.service));
            update.egress.sort_by(|a, b| a.service.cmp(&b.service));
            (node.clone(), update)
        })
        .collect()
}

/// Pushes policies to connected agents when they change.
pub struct PolicyPublisher {
    state: FleetState,
    raft_state: FleetStateMachine,
    sent: Mutex<HashMap<String, (PolicyUpdate, Instant)>>,
}

impl PolicyPublisher {
    pub fn new(state: FleetState, raft_state: FleetStateMachine) -> Self {
        Self {
            state,
            raft_state,
            sent: Mutex::default(),
        }
    }

    /// Send each connected agent its policy if it changed (or has not been
    /// sent for a while). Returns how many agents were sent one.
    pub async fn publish(&self) -> usize {
        let config = match self.raft_state.current_config().await {
            Some(revision) => match revision.config() {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!(error = %e, "Cannot read network policy");
                    return 0;
                }
            },
            None => return 0,
        };
        let connected = self.state.connected_nodes().await;
        let (statuses, _, _) = self.state.fleet_status().await;
        let nodes: BTreeMap<String, String> = statuses
            .into_iter()
            .filter(|n| connected.contains(&n.node_id))
            .map(|n| (n.node_id, n.pool))
            .collect();
        let mut policies = build_policies(&config, &nodes, &DnsInputs::gather(&self.state).await);

        let mut sent = self.sent.lock().await;
        sent.retain(|node, _| connected.contains(node));
        let mut count = 0;
        for node in connected {
            let policy = policies.remove(&node).unwrap_or_default();
            if let Some((previous, at)) = sent.get(&node)
                && *previous == policy
                && at.elapsed() < RESEND_INTERVAL
            {
                continue;
            }
            let msg = ServerMessage {
                payload: Some(ServerPayload::Policy(policy.clone())),
            };
            if self.state.send_to_agent(&node, msg).await {
                sent.insert(node, (policy, Instant::now()));
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

    fn spec(name: &str, namespace: &str, namespace_ip: &str, ports: &[u32]) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            namespace: namespace.into(),
            namespace_ip: namespace_ip.into(),
            ports: ports
                .iter()
                .map(|p| PortSpec {
                    name: format!("p{p}"),
                    port: *p,
                    protocol: "tcp".into(),
                    hostname: String::new(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn callers_proxies_and_egress_make_each_nodes_policy() {
        let config: FleetConfig = serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "services": {
                "db": {"command": "/bin/db", "ports": {"pg": {"port": 5432}},
                       "identity": {"allowedCallers": ["api"],
                                    "egressRules": [{"destCidr": "10.0.0.0/8", "destPorts": [443]},
                                                    {"destCidr": "10.9.9.9", "action": "deny"}]}},
                "api": {"command": "/bin/api", "ports": {"http": {"port": 8080}},
                        "identity": {"allowedCallers": ["web"]}},
                "web": {"command": "/bin/web", "ports": {"http": {"port": 80}}},
                "cache": {"command": "/bin/cache", "namespace": "acme", "ports": {"r": {"port": 6379}},
                          "identity": {"allowedCallers": ["app"]}},
                "app": {"command": "/bin/app", "namespace": "acme"},
            },
            "ingress": {
                "site": {"host": "*", "service": "api", "port": "http", "pools": ["edge"]},
                "store": {"host": "s.test", "service": "cache", "port": "r", "nodes": ["d"]},
            },
        }))
        .unwrap();
        let inputs = DnsInputs {
            assignments: BTreeMap::from([
                (
                    "a".into(),
                    vec![
                        spec("db", "", "", &[5432]),
                        spec("cache", "acme", "10.200.0.2", &[6379]),
                    ],
                ),
                (
                    "b".into(),
                    vec![
                        spec("api", "default", "", &[8080]),
                        spec("app", "acme", "10.200.0.3", &[]),
                    ],
                ),
                (
                    "c".into(),
                    vec![
                        spec("web", "", "", &[80]),
                        spec("app", "acme", "10.200.0.4", &[]),
                    ],
                ),
                ("d".into(), vec![spec("api", "", "", &[8080])]),
            ]),
            mesh_ips: BTreeMap::from([
                ("a".into(), Ipv4Addr::new(10, 100, 0, 1)),
                ("b".into(), Ipv4Addr::new(10, 100, 0, 2)),
                ("c".into(), Ipv4Addr::new(10, 100, 0, 3)),
                ("d".into(), Ipv4Addr::new(10, 100, 0, 4)),
                ("e".into(), Ipv4Addr::new(10, 100, 0, 5)),
            ]),
            ..Default::default()
        };
        let nodes: BTreeMap<String, String> = [
            ("a", "default"),
            ("b", "default"),
            ("c", "default"),
            ("d", "default"),
            ("e", "edge"),
        ]
        .into_iter()
        .map(|(n, p)| (n.to_string(), p.to_string()))
        .collect();
        let policies = build_policies(&config, &nodes, &inputs);

        let a = &policies["a"];
        assert_eq!(
            a.ingress,
            vec![
                IngressPolicy {
                    service: "cache".into(),
                    namespace: "acme".into(),
                    dest_ip: "10.200.0.2".into(),
                    ports: vec![6379],
                    // app's replicas, and d's ingress proxy.
                    allowed_sources: vec![
                        "10.100.0.4".into(),
                        "10.200.0.3".into(),
                        "10.200.0.4".into()
                    ],
                },
                IngressPolicy {
                    service: "db".into(),
                    namespace: String::new(),
                    dest_ip: String::new(),
                    ports: vec![5432],
                    // api runs on b and d.
                    allowed_sources: vec!["10.100.0.2".into(), "10.100.0.4".into()],
                },
            ]
        );
        assert_eq!(
            a.egress,
            vec![EgressPolicy {
                service: "db".into(),
                namespace: String::new(),
                rules: vec![
                    EgressRuleSpec {
                        dest_cidr: "10.0.0.0/8".into(),
                        dest_ports: vec![443],
                        allow: true
                    },
                    EgressRuleSpec {
                        dest_cidr: "10.9.9.9".into(),
                        dest_ports: vec![],
                        allow: false
                    },
                ],
            }]
        );
        // api accepts web (on c) and the edge node's ingress proxy (e).
        assert_eq!(
            policies["b"].ingress[0].allowed_sources,
            ["10.100.0.3", "10.100.0.5"]
        );
        assert_eq!(policies["b"].ingress, policies["d"].ingress);
        // Services without a policy add nothing.
        assert_eq!(policies["c"], PolicyUpdate::default());
        assert_eq!(policies["e"], PolicyUpdate::default());
    }

    #[test]
    fn a_service_whose_callers_run_nowhere_accepts_no_one() {
        let config: FleetConfig = serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "services": {
                "db": {"command": "/bin/db", "ports": {"pg": {"port": 5432}},
                       "identity": {"allowedCallers": ["api"]}},
            },
        }))
        .unwrap();
        let inputs = DnsInputs {
            assignments: BTreeMap::from([("a".into(), vec![spec("db", "", "", &[5432])])]),
            ..Default::default()
        };
        let nodes = BTreeMap::from([("a".to_string(), "default".to_string())]);
        let policy = &build_policies(&config, &nodes, &inputs)["a"];
        assert_eq!(policy.ingress.len(), 1);
        assert!(policy.ingress[0].allowed_sources.is_empty());
    }
}
