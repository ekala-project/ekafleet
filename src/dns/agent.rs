//! The agent's DNS servers: one on the host and one per namespace network.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::listener;
use super::resolver::DnsResolver;

/// Where the resolv.conf for services in namespace `ns` lives; units of
/// those services bind it over `/etc/resolv.conf`.
pub fn namespace_resolv_conf(ns: &str) -> PathBuf {
    PathBuf::from(format!("/run/ekafleet/netns/{ns}/resolv.conf"))
}

/// Agent DNS settings.
#[derive(Debug, Clone)]
pub struct DnsSettings {
    /// Host listener address; `None` disables the agent's DNS entirely.
    pub listen: Option<SocketAddr>,
    /// Upstream resolvers for non-fleet names; empty = the host's
    /// `/etc/resolv.conf` nameservers (except our own listener).
    pub upstream: Vec<SocketAddr>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            listen: Some(SocketAddr::from(([127, 0, 0, 1], 53))),
            upstream: Vec::new(),
        }
    }
}

impl DnsSettings {
    pub fn disabled() -> Self {
        Self {
            listen: None,
            upstream: Vec::new(),
        }
    }
}

pub struct AgentDns {
    resolver: DnsResolver,
    enabled: bool,
    shutdown: CancellationToken,
    /// Running namespace listeners: namespace → (gateway, stop).
    namespaces: Mutex<HashMap<String, (Ipv4Addr, CancellationToken)>>,
}

impl AgentDns {
    /// Start the host listener (if enabled). A listener that cannot bind
    /// (port taken, not root) is logged and skipped: fleet DNS is then
    /// unavailable on this host, nothing else is affected.
    pub async fn start(settings: &DnsSettings, shutdown: CancellationToken) -> Self {
        let upstream = if settings.upstream.is_empty() {
            std::fs::read_to_string("/etc/resolv.conf")
                .map(|conf| super::resolver::upstream_from_resolv_conf(&conf, settings.listen))
                .unwrap_or_default()
        } else {
            settings.upstream.clone()
        };
        let resolver = DnsResolver::new("fleet.internal", upstream);
        if let Some(addr) = settings.listen {
            match tokio::net::UdpSocket::bind(addr).await {
                Ok(socket) => {
                    tracing::info!(%addr, "DNS listener started");
                    tokio::spawn(listener::serve(
                        socket,
                        resolver.clone(),
                        None,
                        shutdown.child_token(),
                    ));
                }
                Err(e) => tracing::warn!(%addr, error = %e, "Cannot start the DNS listener"),
            }
        }
        Self {
            resolver,
            enabled: settings.listen.is_some(),
            shutdown,
            namespaces: Mutex::default(),
        }
    }

    pub fn resolver(&self) -> &DnsResolver {
        &self.resolver
    }

    /// Serve namespace `ns` on its bridge gateway inside its network
    /// namespace, and point its services' resolv.conf there.
    pub async fn ensure_namespace(&self, ns: &str, gateway: Ipv4Addr) {
        if !self.enabled {
            return;
        }
        // The name becomes part of filesystem paths.
        if let Err(e) = crate::ca::validate_identity_name(ns) {
            tracing::warn!(namespace = ns, error = %e, "Invalid namespace name; no DNS for it");
            return;
        }
        let mut namespaces = self.namespaces.lock().await;
        if namespaces.get(ns).is_some_and(|(gw, _)| *gw == gateway) {
            return;
        }
        if let Some((_, stop)) = namespaces.remove(ns) {
            stop.cancel();
        }
        let netns = PathBuf::from(format!("/run/netns/ekafleet-{ns}"));
        let addr = SocketAddr::from((gateway, 53));
        let socket = match listener::bind_in_netns(&netns, addr).await {
            Ok(socket) => socket,
            Err(e) => {
                tracing::warn!(namespace = ns, %addr, error = %e, "Cannot start the namespace DNS listener");
                return;
            }
        };
        let resolv_conf = namespace_resolv_conf(ns);
        let written = async {
            if let Some(dir) = resolv_conf.parent() {
                tokio::fs::create_dir_all(dir).await?;
            }
            tokio::fs::write(&resolv_conf, format!("nameserver {gateway}\n")).await
        }
        .await;
        if let Err(e) = written {
            tracing::warn!(namespace = ns, error = %e, "Cannot write the namespace resolv.conf");
        }
        let stop = self.shutdown.child_token();
        tokio::spawn(listener::serve(
            socket,
            self.resolver.clone(),
            Some(ns.to_string()),
            stop.clone(),
        ));
        tracing::info!(namespace = ns, %addr, "Namespace DNS listener started");
        namespaces.insert(ns.to_string(), (gateway, stop));
    }

    /// Stop the listeners of namespaces not in `active`.
    pub async fn retain(&self, active: &[String]) {
        let mut namespaces = self.namespaces.lock().await;
        let gone: Vec<String> = namespaces
            .keys()
            .filter(|ns| !active.contains(ns))
            .cloned()
            .collect();
        for ns in gone {
            if let Some((_, stop)) = namespaces.remove(&ns) {
                stop.cancel();
            }
            if let Some(dir) = namespace_resolv_conf(&ns).parent() {
                let _ = tokio::fs::remove_dir_all(dir).await;
            }
        }
    }
}
