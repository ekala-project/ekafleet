//! Network namespace lifecycle management for per-namespace isolation.
//!
//! Each non-default namespace gets its own Linux network namespace with a bridge
//! and per-service veth pairs. Services in the same namespace can reach each other
//! via the bridge; services in different namespaces are isolated by default (no
//! routes exist between namespace bridges). The `default` namespace retains host
//! networking for backward compatibility and infrastructure services.

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
    /// Service name → assigned IP
    service_ips: HashMap<String, Ipv4Addr>,
    /// Service name → veth host-side name
    service_veths: HashMap<String, String>,
}

/// Manages network namespaces across all active namespaces on this agent.
pub struct NamespaceNetworkManager {
    inner: Arc<RwLock<ManagerInner>>,
}

struct ManagerInner {
    namespaces: HashMap<String, NamespaceNetwork>,
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

        // 1. Create network namespace
        run_ip(&["netns", "add", &netns_name]).await?;

        // 2. Create bridge and move it into the namespace
        run_ip(&["link", "add", &bridge_name, "type", "bridge"]).await?;
        run_ip(&["link", "set", &bridge_name, "netns", &netns_name]).await?;

        // 3. Configure bridge inside the namespace
        let cidr = format!("{gateway}/{}", subnet_prefix_len(subnet));
        run_ip_netns(&netns_name, &["addr", "add", &cidr, "dev", &bridge_name]).await?;
        run_ip_netns(&netns_name, &["link", "set", &bridge_name, "up"]).await?;
        run_ip_netns(&netns_name, &["link", "set", "lo", "up"]).await?;

        // 4. Add default route via the gateway for outbound traffic
        // The host-side veth peer + NAT handles actual routing
        run_ip_netns(&netns_name, &["route", "add", "default", "via", gateway]).await?;

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
            &["addr", "add", &cidr, "dev", &veth_container],
        )
        .await?;
        run_ip_netns(&ns.netns_name, &["link", "set", &veth_container, "up"]).await?;

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

        // Delete the network namespace (also removes all interfaces within it)
        let _ = run_ip(&["netns", "del", &ns.netns_name]).await;

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
    fn subnet_prefix_len_parsing() {
        assert_eq!(subnet_prefix_len("10.200.1.0/24"), "24");
        assert_eq!(subnet_prefix_len("10.0.0.0/16"), "16");
        assert_eq!(subnet_prefix_len("no-slash"), "no-slash");
    }

    #[tokio::test]
    async fn ensure_default_namespace_is_noop() {
        let mgr = NamespaceNetworkManager::new();
        assert!(
            mgr.ensure_namespace("", "10.200.1.0/24", "10.200.1.1")
                .await
                .is_ok()
        );
        assert!(
            mgr.ensure_namespace("default", "10.200.1.0/24", "10.200.1.1")
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
}
