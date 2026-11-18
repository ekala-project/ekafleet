//! Fleet DNS records, published to agents.
//!
//! The server is the authority for `<domain>`: from the desired state it
//! assigned each node, the mesh addresses nodes advertised, and replica
//! health, it builds every node's complete record set and pushes it as a
//! `DnsUpdate` snapshot, which replaces the agent's cache. Agents answer
//! queries locally, so name resolution survives a server outage with the
//! last records it saw.
//!
//! Names are relative to the fleet domain:
//!
//! - `<node>.node`: the node's mesh address.
//! - `<svc>.service` (fleet-wide): the mesh addresses of the nodes running a
//!   serving replica of a default-namespace (host-networked) service, plus
//!   SRV records `<port> <node>.node` for its declared ports.
//! - `<svc>.service` in namespace `ns`: the overlay addresses of serving
//!   replicas, plus SRV records `<port> <svc>.service`, sent only to nodes
//!   that run something in `ns`.
//! - `<name>.external`: the addresses of an `externalServices` entry that
//!   pass its health check (see `server::external`), plus SRV records
//!   `<port> <name>.external`.
//!
//! A replica is serving when its node reports it running and not unhealthy.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::external::ExternalHealth;
use super::state::FleetState;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    DnsRecord, DnsRecordType, DnsUpdate, HealthStatus, ServerMessage, ServiceSpec, ServiceState,
};
use crate::raft::state::FleetStateMachine;

/// TTL of every answer: short, so clients notice failover quickly.
pub const RECORD_TTL: u32 = 10;

/// How often records are recomputed.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);

/// Unchanged snapshots are re-sent this often, for agents that restarted.
const RESEND_INTERVAL: Duration = Duration::from_secs(30);

/// Inputs to [`build_records`], gathered from the fleet state.
#[derive(Debug, Default)]
pub struct DnsInputs {
    /// The services assigned to each node.
    pub assignments: BTreeMap<String, Vec<ServiceSpec>>,
    /// Advertised mesh addresses, by node.
    pub mesh_ips: BTreeMap<String, Ipv4Addr>,
    /// (node, service) pairs whose replica is serving.
    pub serving: HashSet<(String, String)>,
    /// Serving addresses of each external service.
    pub external: BTreeMap<String, Vec<SocketAddrV4>>,
}

impl DnsInputs {
    pub async fn gather(state: &FleetState) -> Self {
        let mut nodes: BTreeSet<String> = state.assigned_nodes().await.into_iter().collect();
        nodes.extend(state.connected_nodes().await);
        let mut inputs = Self::default();
        for node in nodes {
            if let Some(ip) = state.mesh_ip_for_node(&node).await {
                inputs.mesh_ips.insert(node.clone(), ip);
            }
            if let Some(desired) = state.assigned_desired_state(&node).await {
                inputs.assignments.insert(node, desired.services);
            }
        }
        let (_, services, _) = state.fleet_status().await;
        for service in services {
            for instance in service.instances {
                let running = instance.state == ServiceState::ServiceRunning as i32;
                let unhealthy = instance.health == HealthStatus::Unhealthy as i32;
                if running && !unhealthy {
                    inputs
                        .serving
                        .insert((instance.node_id, service.name.clone()));
                }
            }
        }
        inputs
    }
}

/// Every node's record set, sorted so equal inputs give equal snapshots.
pub fn build_records(inputs: &DnsInputs) -> BTreeMap<String, Vec<DnsRecord>> {
    let record = |name: String, kind: DnsRecordType, values: Vec<String>, ns: &str| DnsRecord {
        name,
        record_type: kind as i32,
        values,
        ttl: RECORD_TTL,
        namespace: ns.to_string(),
    };

    let mut fleet = Vec::new();
    for (node, ip) in &inputs.mesh_ips {
        fleet.push(record(
            format!("{node}.node"),
            DnsRecordType::A,
            vec![ip.to_string()],
            "",
        ));
    }

    // (addresses, SRV values) of a service.
    type Addresses = (BTreeSet<String>, BTreeSet<String>);
    // Fleet-wide (host-networked) services by name.
    let mut hosted: BTreeMap<&str, Addresses> = BTreeMap::new();
    // Namespaced services by (namespace, name).
    let mut namespaced: BTreeMap<(&str, &str), Addresses> = BTreeMap::new();
    // Namespaces each node takes part in.
    let mut node_namespaces: HashMap<&str, BTreeSet<&str>> = HashMap::new();

    for (node, specs) in &inputs.assignments {
        for spec in specs {
            let serving = inputs.serving.contains(&(node.clone(), spec.name.clone()));
            if crate::agent::netns::is_default_namespace(&spec.namespace) {
                let entry = hosted.entry(spec.name.as_str()).or_default();
                if serving && let Some(ip) = inputs.mesh_ips.get(node) {
                    entry.0.insert(ip.to_string());
                    for port in spec.ports.iter().filter(|p| p.port != 0) {
                        entry.1.insert(format!("{} {node}.node", port.port));
                    }
                }
            } else {
                node_namespaces
                    .entry(node.as_str())
                    .or_default()
                    .insert(spec.namespace.as_str());
                let entry = namespaced
                    .entry((spec.namespace.as_str(), spec.name.as_str()))
                    .or_default();
                if serving && !spec.namespace_ip.is_empty() {
                    entry.0.insert(spec.namespace_ip.clone());
                    for port in spec.ports.iter().filter(|p| p.port != 0) {
                        entry
                            .1
                            .insert(format!("{} {}.service", port.port, spec.name));
                    }
                }
            }
        }
    }
    for (name, endpoints) in &inputs.external {
        let ips: BTreeSet<String> = endpoints.iter().map(|a| a.ip().to_string()).collect();
        if ips.is_empty() {
            continue;
        }
        let name = format!("{name}.external");
        let srv: BTreeSet<String> = endpoints
            .iter()
            .map(|a| format!("{} {name}", a.port()))
            .collect();
        fleet.push(record(
            name.clone(),
            DnsRecordType::A,
            ips.into_iter().collect(),
            "",
        ));
        fleet.push(record(
            name,
            DnsRecordType::Srv,
            srv.into_iter().collect(),
            "",
        ));
    }
    for (name, (ips, srv)) in hosted {
        if !ips.is_empty() {
            let name = format!("{name}.service");
            fleet.push(record(
                name.clone(),
                DnsRecordType::A,
                ips.into_iter().collect(),
                "",
            ));
            if !srv.is_empty() {
                fleet.push(record(
                    name,
                    DnsRecordType::Srv,
                    srv.into_iter().collect(),
                    "",
                ));
            }
        }
    }

    let mut nodes: BTreeSet<&str> = inputs.mesh_ips.keys().map(String::as_str).collect();
    nodes.extend(inputs.assignments.keys().map(String::as_str));
    nodes
        .into_iter()
        .map(|node| {
            let mut records = fleet.clone();
            let member_of = node_namespaces.get(node);
            for ((ns, name), (ips, srv)) in &namespaced {
                if !ips.is_empty() && member_of.is_some_and(|m| m.contains(ns)) {
                    records.push(record(
                        format!("{name}.service"),
                        DnsRecordType::A,
                        ips.iter().cloned().collect(),
                        ns,
                    ));
                    if !srv.is_empty() {
                        records.push(record(
                            format!("{name}.service"),
                            DnsRecordType::Srv,
                            srv.iter().cloned().collect(),
                            ns,
                        ));
                    }
                }
            }
            (node.to_string(), records)
        })
        .collect()
}

/// Pushes record snapshots to connected agents when they change.
pub struct DnsPublisher {
    state: FleetState,
    external: Option<(FleetStateMachine, ExternalHealth)>,
    sent: Mutex<HashMap<String, (Vec<DnsRecord>, Instant)>>,
}

impl DnsPublisher {
    pub fn new(state: FleetState) -> Self {
        Self {
            state,
            external: None,
            sent: Mutex::default(),
        }
    }

    /// Also publish the external services of the current configuration.
    pub fn with_external(mut self, raft_state: FleetStateMachine, health: ExternalHealth) -> Self {
        self.external = Some((raft_state, health));
        self
    }

    async fn inputs(&self) -> DnsInputs {
        let mut inputs = DnsInputs::gather(&self.state).await;
        if let Some((raft_state, health)) = &self.external
            && let Some(revision) = raft_state.current_config().await
        {
            match revision.config() {
                Ok(config) => inputs.external = health.serving(&config).await,
                Err(e) => tracing::error!(error = %e, "Cannot read external services"),
            }
        }
        inputs
    }

    /// Send each connected agent its records if they changed (or have not
    /// been sent for a while). Returns how many agents were sent records.
    pub async fn publish(&self) -> usize {
        let mut records = build_records(&self.inputs().await);
        let connected = self.state.connected_nodes().await;
        let mut sent = self.sent.lock().await;
        sent.retain(|node, _| connected.contains(node));
        let mut count = 0;
        for node in connected {
            let snapshot = records.remove(&node).unwrap_or_default();
            if let Some((previous, at)) = sent.get(&node)
                && *previous == snapshot
                && at.elapsed() < RESEND_INTERVAL
            {
                continue;
            }
            let msg = ServerMessage {
                payload: Some(ServerPayload::Dns(DnsUpdate {
                    records: snapshot.clone(),
                })),
            };
            if self.state.send_to_agent(&node, msg).await {
                sent.insert(node, (snapshot, Instant::now()));
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
    use crate::proto::PortSpec;

    fn spec(name: &str, namespace: &str, namespace_ip: &str, port: u32) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            namespace: namespace.into(),
            namespace_ip: namespace_ip.into(),
            ports: vec![PortSpec {
                name: "http".into(),
                port,
                protocol: "tcp".into(),
                hostname: String::new(),
            }],
            ..Default::default()
        }
    }

    fn find<'a>(
        records: &'a [DnsRecord],
        name: &str,
        kind: DnsRecordType,
    ) -> Option<&'a DnsRecord> {
        records
            .iter()
            .find(|r| r.name == name && r.record_type == kind as i32)
    }

    #[test]
    fn external_services_are_fleet_wide() {
        let inputs = DnsInputs {
            mesh_ips: BTreeMap::from([("a".into(), Ipv4Addr::new(10, 100, 0, 1))]),
            external: BTreeMap::from([
                (
                    "db".into(),
                    vec![
                        "10.0.0.2:5432".parse().unwrap(),
                        "10.0.0.1:5432".parse().unwrap(),
                    ],
                ),
                // Every address failing: no records at all.
                ("down".into(), Vec::new()),
            ]),
            ..Default::default()
        };
        let records = build_records(&inputs);
        let a = &records["a"];
        let db = find(a, "db.external", DnsRecordType::A).unwrap();
        assert_eq!(db.values, ["10.0.0.1", "10.0.0.2"]);
        assert!(db.namespace.is_empty());
        assert_eq!(
            find(a, "db.external", DnsRecordType::Srv).unwrap().values,
            ["5432 db.external"]
        );
        assert!(!a.iter().any(|r| r.name == "down.external"));
    }

    #[test]
    fn records_follow_serving_replicas_and_namespace_membership() {
        let mut inputs = DnsInputs {
            mesh_ips: BTreeMap::from([
                ("a".into(), Ipv4Addr::new(10, 100, 0, 1)),
                ("b".into(), Ipv4Addr::new(10, 100, 0, 2)),
                ("c".into(), Ipv4Addr::new(10, 100, 0, 3)),
            ]),
            ..Default::default()
        };
        inputs.assignments = BTreeMap::from([
            (
                "a".into(),
                vec![
                    spec("web", "", "", 8080),
                    spec("db", "acme", "10.200.1.2", 5432),
                ],
            ),
            (
                "b".into(),
                vec![
                    spec("web", "default", "", 8080),
                    spec("db", "acme", "10.200.1.3", 5432),
                ],
            ),
            ("c".into(), vec![spec("web", "", "", 8080)]),
        ]);
        // c's web replica is unhealthy; b's db is not running yet.
        inputs.serving = [("a", "web"), ("b", "web"), ("a", "db")]
            .into_iter()
            .map(|(n, s)| (n.to_string(), s.to_string()))
            .collect();

        let records = build_records(&inputs);
        assert_eq!(records.keys().collect::<Vec<_>>(), ["a", "b", "c"]);

        let a = &records["a"];
        let web = find(a, "web.service", DnsRecordType::A).unwrap();
        assert_eq!(web.values, ["10.100.0.1", "10.100.0.2"]);
        assert!(web.namespace.is_empty());
        assert_eq!(web.ttl, RECORD_TTL);
        let srv = find(a, "web.service", DnsRecordType::Srv).unwrap();
        assert_eq!(srv.values, ["8080 a.node", "8080 b.node"]);
        assert_eq!(
            find(a, "c.node", DnsRecordType::A).unwrap().values,
            ["10.100.0.3"]
        );

        let db = find(a, "db.service", DnsRecordType::A).unwrap();
        assert_eq!(db.namespace, "acme");
        assert_eq!(db.values, ["10.200.1.2"]);
        let db_srv = find(a, "db.service", DnsRecordType::Srv).unwrap();
        assert_eq!(
            (db_srv.namespace.as_str(), &db_srv.values[..]),
            ("acme", &["5432 db.service".to_string()][..])
        );
        // Only members of the namespace learn its records.
        assert!(find(&records["b"], "db.service", DnsRecordType::A).is_some());
        assert!(find(&records["c"], "db.service", DnsRecordType::A).is_none());
        // Fleet-wide records go everywhere.
        assert_eq!(
            find(&records["c"], "web.service", DnsRecordType::A),
            Some(web)
        );
    }

    #[test]
    fn services_without_serving_replicas_have_no_records() {
        let mut inputs = DnsInputs {
            mesh_ips: BTreeMap::from([("a".into(), Ipv4Addr::new(10, 100, 0, 1))]),
            assignments: BTreeMap::from([("a".into(), vec![spec("web", "", "", 0)])]),
            ..Default::default()
        };
        let records = build_records(&inputs);
        assert!(find(&records["a"], "web.service", DnsRecordType::A).is_none());
        inputs.serving.insert(("a".into(), "web".into()));
        let records = build_records(&inputs);
        assert!(find(&records["a"], "web.service", DnsRecordType::A).is_some());
        // No declared port: no SRV record.
        assert!(find(&records["a"], "web.service", DnsRecordType::Srv).is_none());
    }

    #[tokio::test]
    async fn publisher_sends_changed_snapshots_only() {
        let state = FleetState::new();
        let mut rx = state
            .register_agent("a", "127.0.0.1:1".into(), "default".into())
            .await;
        state
            .update_mesh_ip("a", Ipv4Addr::new(10, 100, 0, 1))
            .await;
        let publisher = DnsPublisher::new(state.clone());
        assert_eq!(publisher.publish().await, 1);
        let Some(ServerPayload::Dns(update)) = rx.try_recv().unwrap().payload else {
            panic!("expected a DnsUpdate");
        };
        assert_eq!(update.records[0].name, "a.node");
        assert_eq!(publisher.publish().await, 0, "unchanged snapshot re-sent");
        state
            .update_mesh_ip("a", Ipv4Addr::new(10, 100, 0, 9))
            .await;
        assert_eq!(publisher.publish().await, 1);
    }
}
