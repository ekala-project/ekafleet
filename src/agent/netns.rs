//! Network namespace lifecycle management for per-namespace isolation.
//!
//! Each non-default namespace gets its own Linux network namespace with a bridge
//! and per-service veth pairs. Services in the same namespace can reach each other
//! via the bridge; services in different namespaces are isolated by default (no
//! routes exist between namespace bridges). The `default` namespace retains host
//! networking for backward compatibility and infrastructure services.
//!
//! Each namespace network also has an uplink to the host: a veth pair
//! (`nu-<hash>` on the host, `uplink0` inside) with the namespace's default
//! route. The host masquerades the namespace's outbound traffic and routes
//! its subnet back in, and the `inet ekafleet-uplink` table confines it:
//! namespaced services reach outside networks only, never the host itself,
//! the mesh, or another namespace. Traffic into a namespace comes from the
//! host (its ingress proxy, probes) or from other nodes over the mesh, to
//! which the server routes each replica's address.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum NetnsError {
    #[error("netns command failed: {0}")]
    Command(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("subnet exhausted for namespace {0}")]
    SubnetExhausted(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Run `f` inside the network namespace at `netns_path` (e.g.
/// `/run/netns/ekafleet-acme`), on a thread of its own. Sockets `f` makes
/// stay in that namespace.
///
/// setns moves only the calling thread, so never on a pooled thread: a tokio
/// blocking-pool thread is reused, and work scheduled on it later (`tokio::fs`,
/// `lookup_host`, ...) would silently run in the namespace. This thread exits
/// once `f` returns.
pub async fn run_in_netns<T, F>(netns_path: &std::path::Path, f: F) -> std::io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
{
    let netns_path = netns_path.to_path_buf();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ekafleet-netns".into())
        .spawn(move || {
            let _ = tx.send(enter_netns(&netns_path).and_then(|()| f()));
        })?;
    rx.await
        .map_err(|_| std::io::Error::other("network namespace thread panicked"))?
}

/// Move the calling thread into the network namespace at `netns_path`.
fn enter_netns(netns_path: &std::path::Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let ns = std::fs::File::open(netns_path)?;
    // SAFETY: `ns` is an open namespace file descriptor; setns only changes
    // the calling thread's network namespace.
    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Information about a remote node hosting services in the same namespace.
pub struct RemotePeerInfo {
    pub node_id: String,
    pub tunnel_endpoint: Ipv4Addr,
    pub services: Vec<(String, Ipv4Addr)>,
}

/// Per-namespace network state.
#[allow(dead_code)]
struct NamespaceNetwork {
    namespace: String,
    /// Linux netns name: "ekafleet-{namespace}"
    netns_name: String,
    /// Bridge device name: "br-{short_hash}" (max 15 chars for IFNAMSIZ)
    bridge_name: String,
    /// Subnet for this namespace: 10.200.{index}.0/24
    subnet: String,
    /// Gateway IP on the bridge: 10.200.{index}.1
    gateway: Ipv4Addr,
    /// VXLAN Network Identifier for cross-node tunneling.
    vni: u32,
    /// VXLAN interface name inside the netns, if created.
    vxlan_iface: Option<String>,
    /// Currently configured remote peers (node_id → state) for diffing.
    remote_peers: HashMap<String, RemotePeerState>,
    /// Service name → assigned IP
    service_ips: HashMap<String, Ipv4Addr>,
    /// Service name → veth host-side name
    service_veths: HashMap<String, String>,
}

#[allow(dead_code)]
struct RemotePeerState {
    tunnel_endpoint: Ipv4Addr,
    services: Vec<(String, Ipv4Addr)>,
}

/// Manages network namespaces across all active namespaces on this agent.
pub struct NamespaceNetworkManager {
    inner: Arc<RwLock<ManagerInner>>,
}

struct ManagerInner {
    namespaces: HashMap<String, NamespaceNetwork>,
    /// The uplink ruleset last loaded on the host.
    uplink_rules: Option<String>,
}

/// Name of the namespace side of the uplink.
const UPLINK: &str = "uplink0";

/// Next hop of a namespace's default route: link-local, resolved to the
/// host side's MAC by a permanent neighbor entry, so the host needs no
/// address on the link.
const UPLINK_GATEWAY: &str = "169.254.1.1";

/// Prefix of the host side of every uplink.
const UPLINK_PREFIX: &str = "nu-";

/// The network namespace subnets are allocated from (`10.200.0.0/16`).
const NAMESPACE_NETWORK: &str = "10.200.0.0/16";

/// Whether `ip` lies in the network namespace subnets are allocated from.
pub fn in_namespace_network(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    (a, b) == (10, 200)
}

impl Default for NamespaceNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceNetworkManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ManagerInner {
                namespaces: HashMap::new(),
                uplink_rules: None,
            })),
        }
    }

    /// Ensure a namespace network exists with the given subnet/gateway.
    /// Called when DesiredState arrives with NamespaceNetworkConfig entries.
    /// Idempotent: does nothing if the namespace is already set up.
    pub async fn ensure_namespace(
        &self,
        namespace: &str,
        subnet: &str,
        gateway: &str,
        vni: u32,
    ) -> Result<(), NetnsError> {
        if is_default_namespace(namespace) {
            return Ok(());
        }

        let mut inner = self.inner.write().await;
        if inner.namespaces.contains_key(namespace) {
            return Ok(());
        }

        let gateway_ip: Ipv4Addr = gateway
            .parse()
            .map_err(|e| NetnsError::Config(format!("invalid gateway IP '{gateway}': {e}")))?;

        let netns_name = format!("ekafleet-{namespace}");
        let bridge_name = bridge_name_for(namespace);

        // Each step tolerates leftovers of a previous agent run: services
        // that kept running are attached to the existing namespace.

        // 1. Create network namespace
        if !std::path::Path::new("/run/netns")
            .join(&netns_name)
            .exists()
        {
            run_ip(&["netns", "add", &netns_name]).await?;
        }

        // 2. Create the bridge inside the namespace (bridges cannot be moved
        // between network namespaces)
        if run_ip_netns(&netns_name, &["link", "show", &bridge_name])
            .await
            .is_err()
        {
            run_ip_netns(
                &netns_name,
                &["link", "add", &bridge_name, "type", "bridge"],
            )
            .await?;
        }

        // 3. Configure the bridge
        let cidr = format!("{gateway}/{}", subnet_prefix_len(subnet));
        run_ip_netns(
            &netns_name,
            &["addr", "replace", &cidr, "dev", &bridge_name],
        )
        .await?;
        run_ip_netns(&netns_name, &["link", "set", &bridge_name, "up"]).await?;
        run_ip_netns(&netns_name, &["link", "set", "lo", "up"]).await?;

        // 4. Uplink to the host
        ensure_uplink(&netns_name, &uplink_name_for(namespace), gateway_ip).await?;

        tracing::info!(
            namespace = %namespace,
            netns = %netns_name,
            bridge = %bridge_name,
            subnet = %subnet,
            gateway = %gateway,
            "Created namespace network"
        );

        inner.namespaces.insert(
            namespace.to_string(),
            NamespaceNetwork {
                namespace: namespace.to_string(),
                netns_name,
                bridge_name,
                subnet: subnet.to_string(),
                gateway: gateway_ip,
                vni,
                vxlan_iface: None,
                remote_peers: HashMap::new(),
                service_ips: HashMap::new(),
                service_veths: HashMap::new(),
            },
        );

        Ok(())
    }

    /// Add a service to a namespace network. Creates a veth pair and attaches
    /// the host side to the namespace bridge. Returns the container-side veth
    /// name that should be assigned the service's IP.
    ///
    /// `assigned_ip` is the server-assigned IP from `ServiceSpec.namespace_ip`.
    pub async fn add_service(
        &self,
        namespace: &str,
        service_name: &str,
        assigned_ip: Ipv4Addr,
    ) -> Result<String, NetnsError> {
        if is_default_namespace(namespace) {
            return Err(NetnsError::Config(
                "cannot add services to default namespace network".into(),
            ));
        }

        let mut inner = self.inner.write().await;
        let ns = inner.namespaces.get_mut(namespace).ok_or_else(|| {
            NetnsError::Config(format!("namespace '{namespace}' network not initialized"))
        })?;

        // If service already has a veth, it's already set up
        if ns.service_veths.contains_key(service_name) {
            return Ok(veth_container_name(service_name));
        }

        let veth_host = veth_host_name(service_name);
        let veth_container = veth_container_name(service_name);

        // Drop a pair left by a previous agent run (deleting one end
        // deletes both).
        let _ = run_ip_netns(&ns.netns_name, &["link", "del", &veth_host]).await;
        let _ = run_ip(&["link", "del", &veth_host]).await;

        // 1. Create veth pair in the host namespace
        run_ip(&[
            "link",
            "add",
            &veth_host,
            "type",
            "veth",
            "peer",
            "name",
            &veth_container,
        ])
        .await?;

        // 2. Move host-side veth into the namespace and attach to bridge
        run_ip(&["link", "set", &veth_host, "netns", &ns.netns_name]).await?;
        run_ip_netns(
            &ns.netns_name,
            &["link", "set", &veth_host, "master", &ns.bridge_name],
        )
        .await?;
        run_ip_netns(&ns.netns_name, &["link", "set", &veth_host, "up"]).await?;

        // 3. Configure container-side veth with the assigned IP
        // The container-side stays in the namespace (it will be passed to the
        // service via NetworkNamespacePath — it's already in the right netns
        // because we move it there next).
        run_ip(&["link", "set", &veth_container, "netns", &ns.netns_name]).await?;
        let cidr = format!("{assigned_ip}/24");
        run_ip_netns(
            &ns.netns_name,
            &["addr", "replace", &cidr, "dev", &veth_container],
        )
        .await?;
        run_ip_netns(&ns.netns_name, &["link", "set", &veth_container, "up"]).await?;

        // Set deterministic MAC so remote FDB entries can address this service
        let mac = mac_for_namespace_ip(assigned_ip);
        run_ip_netns(
            &ns.netns_name,
            &["link", "set", &veth_container, "address", &mac],
        )
        .await?;

        ns.service_ips.insert(service_name.to_string(), assigned_ip);
        ns.service_veths
            .insert(service_name.to_string(), veth_host.clone());

        tracing::info!(
            namespace = %namespace,
            service = %service_name,
            ip = %assigned_ip,
            veth = %veth_container,
            "Added service to namespace network"
        );

        Ok(veth_container)
    }

    /// Remove a service's veth pair from the namespace network.
    pub async fn remove_service(
        &self,
        namespace: &str,
        service_name: &str,
    ) -> Result<(), NetnsError> {
        if is_default_namespace(namespace) {
            return Ok(());
        }

        let mut inner = self.inner.write().await;
        let Some(ns) = inner.namespaces.get_mut(namespace) else {
            return Ok(());
        };

        if ns.service_veths.remove(service_name).is_some() {
            ns.service_ips.remove(service_name);

            // Deleting either end of a veth pair removes both
            let veth_host = veth_host_name(service_name);
            // Ignore errors — the veth may already be gone if the service crashed
            let _ = run_ip_netns(&ns.netns_name, &["link", "del", &veth_host]).await;

            tracing::info!(
                namespace = %namespace,
                service = %service_name,
                "Removed service from namespace network"
            );
        }

        Ok(())
    }

    /// Tear down a namespace network entirely (remove bridge, delete netns).
    pub async fn destroy_namespace(&self, namespace: &str) -> Result<(), NetnsError> {
        if is_default_namespace(namespace) {
            return Ok(());
        }

        let mut inner = self.inner.write().await;
        let Some(ns) = inner.namespaces.remove(namespace) else {
            return Ok(());
        };

        // Delete the network namespace (also removes all interfaces within
        // it, and with uplink0 its host side).
        let _ = run_ip(&["netns", "del", &ns.netns_name]).await;
        let _ = run_ip(&["link", "del", &uplink_name_for(namespace)]).await;

        tracing::info!(
            namespace = %namespace,
            netns = %ns.netns_name,
            "Destroyed namespace network"
        );

        Ok(())
    }

    /// Get the netns path for a namespace (e.g. "/run/netns/ekafleet-customer-a").
    /// Returns None for the default namespace (which uses host networking).
    pub async fn netns_path(&self, namespace: &str) -> Option<String> {
        if is_default_namespace(namespace) {
            return None;
        }
        let inner = self.inner.read().await;
        inner
            .namespaces
            .get(namespace)
            .map(|ns| format!("/run/netns/{}", ns.netns_name))
    }

    /// Set up or update VXLAN tunnels for cross-node namespace networking.
    /// Creates a VXLAN interface attached to the namespace bridge and configures
    /// FDB/neighbor entries so traffic to remote namespace IPs is encapsulated
    /// and sent through the WireGuard mesh.
    pub async fn ensure_vxlan_tunnel(
        &self,
        namespace: &str,
        vni: u32,
        local_mesh_ip: Ipv4Addr,
        remote_peers: &[RemotePeerInfo],
    ) -> Result<(), NetnsError> {
        if is_default_namespace(namespace) {
            return Ok(());
        }

        let mut inner = self.inner.write().await;
        let ns = inner.namespaces.get_mut(namespace).ok_or_else(|| {
            NetnsError::Config(format!("namespace '{namespace}' network not initialized"))
        })?;

        let vxlan_name = vxlan_iface_name(namespace);

        // Create VXLAN interface if it doesn't exist yet
        if ns.vxlan_iface.is_none() {
            let vni_str = vni.to_string();
            let local_ip = local_mesh_ip.to_string();
            run_ip(&[
                "link",
                "add",
                &vxlan_name,
                "type",
                "vxlan",
                "id",
                &vni_str,
                "local",
                &local_ip,
                "dstport",
                "4789",
                "nolearning",
            ])
            .await?;
            run_ip(&["link", "set", &vxlan_name, "netns", &ns.netns_name]).await?;
            run_ip_netns(
                &ns.netns_name,
                &["link", "set", &vxlan_name, "master", &ns.bridge_name],
            )
            .await?;
            run_ip_netns(&ns.netns_name, &["link", "set", &vxlan_name, "up"]).await?;
            ns.vxlan_iface = Some(vxlan_name.clone());

            tracing::info!(
                namespace = %namespace,
                vni = vni,
                vxlan = %vxlan_name,
                "Created VXLAN interface"
            );
        }

        // Remove FDB/neigh entries for peers that are no longer present
        let current_peer_ids: Vec<String> = ns.remote_peers.keys().cloned().collect();
        for old_id in &current_peer_ids {
            if !remote_peers.iter().any(|rp| rp.node_id == *old_id)
                && let Some(old_peer) = ns.remote_peers.remove(old_id)
            {
                let ep = old_peer.tunnel_endpoint.to_string();
                // Remove headend replication entry
                let _ = run_bridge_fdb_netns(
                    &ns.netns_name,
                    &["del", "00:00:00:00:00:00", "dev", &vxlan_name, "dst", &ep],
                )
                .await;
                // Remove per-service entries
                for (_, ip) in &old_peer.services {
                    let mac = mac_for_namespace_ip(*ip);
                    let _ = run_bridge_fdb_netns(
                        &ns.netns_name,
                        &["del", &mac, "dev", &vxlan_name, "dst", &ep],
                    )
                    .await;
                    let ip_str = ip.to_string();
                    let _ = run_ip_netns(
                        &ns.netns_name,
                        &["neigh", "del", &ip_str, "dev", &vxlan_name],
                    )
                    .await;
                }
                tracing::info!(
                    namespace = %namespace,
                    peer = %old_id,
                    "Removed VXLAN remote peer"
                );
            }
        }

        // Add/update FDB and neighbor entries for current peers
        for peer in remote_peers {
            let ep = peer.tunnel_endpoint.to_string();

            // Add headend replication entry (BUM traffic)
            let _ = run_bridge_fdb_netns(
                &ns.netns_name,
                &[
                    "append",
                    "00:00:00:00:00:00",
                    "dev",
                    &vxlan_name,
                    "dst",
                    &ep,
                ],
            )
            .await;

            // Add per-service FDB and ARP neighbor entries
            for (_, ip) in &peer.services {
                let mac = mac_for_namespace_ip(*ip);
                let ip_str = ip.to_string();
                let _ = run_bridge_fdb_netns(
                    &ns.netns_name,
                    &["append", &mac, "dev", &vxlan_name, "dst", &ep],
                )
                .await;
                let _ = run_ip_netns(
                    &ns.netns_name,
                    &[
                        "neigh",
                        "replace",
                        &ip_str,
                        "lladdr",
                        &mac,
                        "dev",
                        &vxlan_name,
                        "nud",
                        "permanent",
                    ],
                )
                .await;
            }

            ns.remote_peers.insert(
                peer.node_id.clone(),
                RemotePeerState {
                    tunnel_endpoint: peer.tunnel_endpoint,
                    services: peer.services.clone(),
                },
            );

            tracing::info!(
                namespace = %namespace,
                peer = %peer.node_id,
                endpoint = %peer.tunnel_endpoint,
                services = peer.services.len(),
                "Configured VXLAN remote peer"
            );
        }

        Ok(())
    }

    /// Remove the VXLAN tunnel for a namespace (when remote_peers becomes empty).
    pub async fn remove_vxlan_tunnel(&self, namespace: &str) -> Result<(), NetnsError> {
        if is_default_namespace(namespace) {
            return Ok(());
        }

        let mut inner = self.inner.write().await;
        let Some(ns) = inner.namespaces.get_mut(namespace) else {
            return Ok(());
        };

        if let Some(vxlan_name) = ns.vxlan_iface.take() {
            let _ = run_ip_netns(&ns.netns_name, &["link", "del", &vxlan_name]).await;
            ns.remote_peers.clear();
            tracing::info!(
                namespace = %namespace,
                vxlan = %vxlan_name,
                "Removed VXLAN interface"
            );
        }

        Ok(())
    }

    /// Bring the host side of every uplink in line: the route to each
    /// namespace subnet (from `mesh`'s address, when the mesh is up, so
    /// network policy sees proxies by their mesh address), IP forwarding,
    /// and the `inet ekafleet-uplink` table. `mesh` is the mesh interface
    /// and this node's address on it.
    pub async fn sync_host(&self, mesh_iface: &str, mesh_ip: Option<Ipv4Addr>) {
        let mut inner = self.inner.write().await;
        let mut subnets: Vec<String> = Vec::new();
        for (name, ns) in &inner.namespaces {
            let uplink = uplink_name_for(name);
            let src = mesh_ip.map(|ip| ip.to_string());
            let mut args = vec!["route", "replace", &ns.subnet, "dev", &uplink];
            if let Some(src) = &src {
                args.extend(["src", src]);
            }
            match run_ip(&args).await {
                Ok(()) => subnets.push(ns.subnet.clone()),
                Err(e) => {
                    tracing::warn!(namespace = %name, error = %e, "Cannot route the namespace subnet")
                }
            }
        }
        subnets.sort();
        if subnets.is_empty() && inner.uplink_rules.is_none() {
            // Never loaded: nothing to remove.
            return;
        }
        if !subnets.is_empty() {
            enable_forwarding().await;
        }
        let rules = uplink_ruleset(&subnets, mesh_iface);
        if inner.uplink_rules.as_deref() == Some(rules.as_str()) {
            return;
        }
        match crate::policy::nftables::apply_ruleset(None, &rules).await {
            Ok(()) => {
                tracing::info!(namespaces = subnets.len(), "Namespace uplink rules loaded");
                inner.uplink_rules = Some(rules);
            }
            Err(e) => tracing::error!(error = %e, "Cannot load the namespace uplink rules"),
        }
    }

    /// Remove namespaces that are no longer needed (not in the provided set).
    pub async fn gc_namespaces(&self, active: &[String]) -> Result<(), NetnsError> {
        let to_remove: Vec<String> = {
            let inner = self.inner.read().await;
            inner
                .namespaces
                .keys()
                .filter(|ns| !active.contains(ns))
                .cloned()
                .collect()
        };

        for ns in to_remove {
            self.destroy_namespace(&ns).await?;
        }
        Ok(())
    }
}

/// Whether a namespace name represents the default (host-networking) namespace.
pub fn is_default_namespace(namespace: &str) -> bool {
    namespace.is_empty() || namespace == "default"
}

/// Generate a bridge name that fits within IFNAMSIZ (15 chars).
/// Format: "br-" + 12 hex chars from a simple hash = 15 chars total.
fn bridge_name_for(namespace: &str) -> String {
    // Simple hash to keep the name short and deterministic
    let mut hash: u64 = 0;
    for b in namespace.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as u64);
    }
    // Truncate to 48 bits (12 hex chars) so "br-" + hash = 15 chars
    let truncated = hash & 0xFFFF_FFFF_FFFF;
    format!("br-{truncated:012x}")
}

/// The host side of a namespace's uplink: "nu-" + 12 hex chars.
fn uplink_name_for(namespace: &str) -> String {
    format!(
        "{UPLINK_PREFIX}{}",
        bridge_name_for(namespace).trim_start_matches("br-")
    )
}

/// Create (or adopt, after an agent restart) the uplink of the network
/// namespace `netns`, and point its default route at the host. Outbound
/// traffic leaves from the namespace's `gateway` address.
async fn ensure_uplink(netns: &str, host_side: &str, gateway: Ipv4Addr) -> Result<(), NetnsError> {
    if run_ip(&["link", "show", host_side]).await.is_err() {
        // Drop a namespace side left without its peer.
        let _ = run_ip_netns(netns, &["link", "del", UPLINK]).await;
        run_ip(&[
            "link", "add", host_side, "type", "veth", "peer", "name", UPLINK, "netns", netns,
        ])
        .await?;
    }
    run_ip(&["link", "set", host_side, "up"]).await?;
    run_ip_netns(netns, &["link", "set", UPLINK, "up"]).await?;
    let mac = tokio::fs::read_to_string(format!("/sys/class/net/{host_side}/address")).await?;
    run_ip_netns(
        netns,
        &[
            "neigh",
            "replace",
            UPLINK_GATEWAY,
            "lladdr",
            mac.trim(),
            "dev",
            UPLINK,
            "nud",
            "permanent",
        ],
    )
    .await?;
    let src = gateway.to_string();
    run_ip_netns(
        netns,
        &[
            "route",
            "replace",
            "default",
            "via",
            UPLINK_GATEWAY,
            "dev",
            UPLINK,
            "onlink",
            "src",
            &src,
        ],
    )
    .await
}

/// Let the host forward between uplinks and its other interfaces.
async fn enable_forwarding() {
    const PATH: &str = "/proc/sys/net/ipv4/ip_forward";
    if tokio::fs::read_to_string(PATH)
        .await
        .is_ok_and(|v| v.trim() == "1")
    {
        return;
    }
    match tokio::fs::write(PATH, "1\n").await {
        Ok(()) => tracing::info!("Enabled IPv4 forwarding for namespace uplinks"),
        Err(e) => {
            tracing::warn!(error = %e, "Cannot enable IPv4 forwarding; namespaces have no uplink")
        }
    }
}

/// The host's `inet ekafleet-uplink` table for namespace `subnets`, or its
/// removal when there are none. A drop in any table is final, so these
/// hold whatever the host firewall accepts:
///
/// - from an uplink, only replies reach the host itself;
/// - an uplink never forwards to another uplink or to the mesh, except
///   replies (to ingress proxies on other nodes);
/// - only the mesh forwards into an uplink (the host's own traffic is not
///   forwarded), and nothing forwards to other nodes' namespaces;
/// - outbound namespace traffic is masqueraded.
fn uplink_ruleset(subnets: &[String], mesh_iface: &str) -> String {
    let mut out =
        String::from("table inet ekafleet-uplink {}\ndelete table inet ekafleet-uplink\n");
    if subnets.is_empty() {
        return out;
    }
    let up = format!("{UPLINK_PREFIX}*");
    out.push_str(&format!(
        "table inet ekafleet-uplink {{
    set namespaces {{
        type ipv4_addr
        flags interval
        elements = {{ {subnets} }}
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname \"{up}\" ct state established,related accept
        iifname \"{up}\" drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        ct state established,related accept
        iifname \"{up}\" oifname \"{up}\" drop
        iifname \"{up}\" oifname \"{mesh_iface}\" drop
        oifname \"{up}\" iifname != \"{mesh_iface}\" drop
        oifname \"{mesh_iface}\" ip daddr {NAMESPACE_NETWORK} drop
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname != \"{up}\" ip saddr @namespaces masquerade
    }}
}}
",
        subnets = subnets.join(", ")
    ));
    out
}

/// Generate the host-side veth name for a service. Must fit IFNAMSIZ.
fn veth_host_name(service_name: &str) -> String {
    let short = if service_name.len() > 8 {
        &service_name[..8]
    } else {
        service_name
    };
    format!("vh-{short}")
}

/// Generate the container-side veth name for a service. Must fit IFNAMSIZ.
fn veth_container_name(service_name: &str) -> String {
    let short = if service_name.len() > 8 {
        &service_name[..8]
    } else {
        service_name
    };
    format!("vc-{short}")
}

/// Generate a VXLAN interface name that fits within IFNAMSIZ (15 chars).
/// Format: "vx-" + 12 hex chars from hash = 15 chars total.
fn vxlan_iface_name(namespace: &str) -> String {
    let mut hash: u64 = 0;
    for b in namespace.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as u64);
    }
    let truncated = hash & 0xFFFF_FFFF_FFFF;
    format!("vx-{truncated:012x}")
}

/// Deterministic locally-administered MAC address derived from a namespace IP.
/// Format: 02:00:aa:bb:cc:dd where aa.bb.cc.dd are the IP octets.
/// The 02 prefix marks it as locally administered. Must be consistent across
/// all nodes so FDB entries match.
pub fn mac_for_namespace_ip(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
}

/// Extract prefix length from a subnet string like "10.200.1.0/24".
fn subnet_prefix_len(subnet: &str) -> &str {
    subnet.rsplit('/').next().unwrap_or("24")
}

/// Run an `ip` command.
async fn run_ip(args: &[&str]) -> Result<(), NetnsError> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetnsError::Command(format!(
            "ip {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Run a `bridge fdb` command inside a network namespace.
async fn run_bridge_fdb_netns(netns: &str, args: &[&str]) -> Result<(), NetnsError> {
    let mut full_args = vec!["netns", "exec", netns, "bridge", "fdb"];
    full_args.extend_from_slice(args);

    let output = tokio::process::Command::new("ip")
        .args(&full_args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetnsError::Command(format!(
            "ip netns exec {} bridge fdb {} failed: {}",
            netns,
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Run an `ip` command inside a network namespace.
async fn run_ip_netns(netns: &str, args: &[&str]) -> Result<(), NetnsError> {
    let mut full_args = vec!["netns", "exec", netns, "ip"];
    full_args.extend_from_slice(args);

    let output = tokio::process::Command::new("ip")
        .args(&full_args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetnsError::Command(format!(
            "ip netns exec {} ip {} failed: {}",
            netns,
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_in_netns_does_not_run_outside_its_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let result = run_in_netns(&dir.path().join("missing"), move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn default_namespace_detection() {
        assert!(is_default_namespace(""));
        assert!(is_default_namespace("default"));
        assert!(!is_default_namespace("customer-a"));
        assert!(!is_default_namespace("production"));
    }

    #[test]
    fn bridge_name_fits_ifnamsiz() {
        let name = bridge_name_for("customer-a");
        assert!(name.len() <= 15, "bridge name too long: {name}");
        assert!(name.starts_with("br-"));
    }

    #[test]
    fn bridge_name_is_deterministic() {
        let a = bridge_name_for("customer-a");
        let b = bridge_name_for("customer-a");
        assert_eq!(a, b);
    }

    #[test]
    fn bridge_name_differs_for_different_namespaces() {
        let a = bridge_name_for("customer-a");
        let b = bridge_name_for("customer-b");
        assert_ne!(a, b);
    }

    #[test]
    fn veth_names_fit_ifnamsiz() {
        let host = veth_host_name("my-very-long-service-name");
        let container = veth_container_name("my-very-long-service-name");
        assert!(host.len() <= 15, "veth host name too long: {host}");
        assert!(
            container.len() <= 15,
            "veth container name too long: {container}"
        );
    }

    #[test]
    fn uplink_name_fits_ifnamsiz_and_differs_per_namespace() {
        let name = uplink_name_for("customer-a");
        assert_eq!(name.len(), 15);
        assert!(name.starts_with(UPLINK_PREFIX));
        assert_ne!(name, uplink_name_for("customer-b"));
    }

    #[test]
    fn namespace_network_membership() {
        assert!(in_namespace_network(Ipv4Addr::new(10, 200, 3, 7)));
        assert!(!in_namespace_network(Ipv4Addr::new(10, 100, 0, 1)));
        assert!(!in_namespace_network(Ipv4Addr::new(10, 201, 0, 1)));
    }

    #[test]
    fn uplink_rules_confine_namespaces() {
        let rules = uplink_ruleset(
            &["10.200.1.0/24".into(), "10.200.2.0/24".into()],
            "wg-fleet",
        );
        assert!(
            rules.starts_with("table inet ekafleet-uplink {}\ndelete table inet ekafleet-uplink\n")
        );
        assert!(rules.contains("elements = { 10.200.1.0/24, 10.200.2.0/24 }"));
        // No new connections from a namespace to the host, the mesh or
        // another namespace; only the mesh forwards in.
        assert!(rules.contains("iifname \"nu-*\" drop"));
        assert!(rules.contains("iifname \"nu-*\" oifname \"nu-*\" drop"));
        assert!(rules.contains("iifname \"nu-*\" oifname \"wg-fleet\" drop"));
        assert!(rules.contains("oifname \"nu-*\" iifname != \"wg-fleet\" drop"));
        assert!(rules.contains("oifname != \"nu-*\" ip saddr @namespaces masquerade"));
        // Replies are accepted before the drops.
        let replies = rules.find("ct state established,related accept").unwrap();
        assert!(replies < rules.find("iifname \"nu-*\" drop").unwrap());

        // Without namespaces the table is removed.
        assert_eq!(
            uplink_ruleset(&[], "wg-fleet"),
            "table inet ekafleet-uplink {}\ndelete table inet ekafleet-uplink\n"
        );
    }

    #[test]
    fn subnet_prefix_len_parsing() {
        assert_eq!(subnet_prefix_len("10.200.1.0/24"), "24");
        assert_eq!(subnet_prefix_len("10.0.0.0/16"), "16");
        assert_eq!(subnet_prefix_len("no-slash"), "no-slash");
    }

    #[test]
    fn vxlan_iface_name_fits_ifnamsiz() {
        let name = vxlan_iface_name("customer-a");
        assert!(name.len() <= 15, "vxlan name too long: {name}");
        assert!(name.starts_with("vx-"));
    }

    #[test]
    fn vxlan_iface_name_is_deterministic() {
        let a = vxlan_iface_name("customer-a");
        let b = vxlan_iface_name("customer-a");
        assert_eq!(a, b);
    }

    #[test]
    fn mac_for_namespace_ip_is_deterministic() {
        let ip = Ipv4Addr::new(10, 200, 1, 2);
        assert_eq!(mac_for_namespace_ip(ip), mac_for_namespace_ip(ip));
    }

    #[test]
    fn mac_for_namespace_ip_locally_administered() {
        let mac = mac_for_namespace_ip(Ipv4Addr::new(10, 200, 1, 2));
        assert!(
            mac.starts_with("02:00:"),
            "must be locally administered: {mac}"
        );
    }

    #[test]
    fn mac_for_namespace_ip_encodes_octets() {
        let mac = mac_for_namespace_ip(Ipv4Addr::new(10, 200, 1, 42));
        assert_eq!(mac, "02:00:0a:c8:01:2a");
    }

    #[tokio::test]
    async fn ensure_default_namespace_is_noop() {
        let mgr = NamespaceNetworkManager::new();
        assert!(
            mgr.ensure_namespace("", "10.200.1.0/24", "10.200.1.1", 1)
                .await
                .is_ok()
        );
        assert!(
            mgr.ensure_namespace("default", "10.200.1.0/24", "10.200.1.1", 1)
                .await
                .is_ok()
        );
        // No namespace should have been created
        let inner = mgr.inner.read().await;
        assert!(inner.namespaces.is_empty());
    }

    #[tokio::test]
    async fn remove_service_noop_for_default() {
        let mgr = NamespaceNetworkManager::new();
        assert!(mgr.remove_service("default", "web").await.is_ok());
    }

    #[tokio::test]
    async fn destroy_noop_for_default() {
        let mgr = NamespaceNetworkManager::new();
        assert!(mgr.destroy_namespace("default").await.is_ok());
    }

    #[tokio::test]
    async fn netns_path_none_for_default() {
        let mgr = NamespaceNetworkManager::new();
        assert!(mgr.netns_path("").await.is_none());
        assert!(mgr.netns_path("default").await.is_none());
    }

    #[tokio::test]
    async fn remove_vxlan_tunnel_noop_for_default() {
        let mgr = NamespaceNetworkManager::new();
        assert!(mgr.remove_vxlan_tunnel("default").await.is_ok());
    }

    #[tokio::test]
    async fn ensure_vxlan_tunnel_noop_for_default() {
        let mgr = NamespaceNetworkManager::new();
        let ip = Ipv4Addr::new(10, 100, 0, 1);
        assert!(mgr.ensure_vxlan_tunnel("default", 1, ip, &[]).await.is_ok());
    }
}
