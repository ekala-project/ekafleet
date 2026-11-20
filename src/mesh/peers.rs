use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use zeroize::Zeroizing;

use super::wireguard::{WgError, WireguardManager};
use crate::proto::{MeshAssignment, WireguardPeer};

/// How this agent takes part in the WireGuard mesh.
#[derive(Debug, Clone)]
pub struct MeshSettings {
    pub enabled: bool,
    /// Address peers reach this node on; detected from the route to the
    /// server when unset.
    pub advertise_addr: Option<IpAddr>,
    pub listen_port: u16,
}

impl Default for MeshSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            advertise_addr: None,
            listen_port: 51820,
        }
    }
}

/// Manages the peer configuration for the WireGuard mesh.
/// Tracks known peers and applies updates from the server.
pub struct PeerManager {
    wg: WireguardManager,
    settings: MeshSettings,
    peers: HashMap<String, PeerInfo>,
    /// Namespace addresses routed over the mesh (the peers' `routed`).
    routes: BTreeSet<Ipv4Addr>,
    /// Trust domain used to verify that a peer advertisement's signing
    /// certificate matches the advertised node identity. Taken from this
    /// node's SVID on activation.
    trust_domain: String,
    /// Peers received before the interface was up.
    pending: Option<Vec<WireguardPeer>>,
    /// The control-plane address (`ip:port`), used to pick the advertised
    /// address when none is configured.
    server_addr: String,
}

#[derive(Debug, Clone)]
struct PeerInfo {
    public_key: String,
    endpoint: String,
    allowed_ip: String,
    /// Namespace addresses of the peer's replicas, routed to it.
    routed: Vec<Ipv4Addr>,
}

impl PeerManager {
    pub fn new(wg: WireguardManager, settings: MeshSettings, server_addr: &str) -> Self {
        Self {
            wg,
            settings,
            peers: HashMap::new(),
            routes: BTreeSet::new(),
            trust_domain: String::new(),
            pending: None,
            server_addr: server_addr.to_string(),
        }
    }

    /// Bring the mesh interface up for the server's `assignment` and return
    /// this node's advertisement, signed with its node SVID (`cert_pem`,
    /// leaf first, and the PKCS#8 `key_pem`), for the server to distribute.
    /// `Ok(None)` means the mesh is disabled on this node.
    pub async fn activate(
        &mut self,
        node_id: &str,
        assignment: &MeshAssignment,
        identity: Option<(&str, &str)>,
    ) -> Result<Option<WireguardPeer>, WgError> {
        if !self.settings.enabled {
            tracing::debug!("WireGuard mesh disabled by configuration");
            return Ok(None);
        }
        if let Some(reason) = WireguardManager::unavailable_reason() {
            tracing::warn!(reason = %reason, "WireGuard mesh disabled on this node");
            return Ok(None);
        }
        let Some((cert_pem, key_pem)) = identity else {
            tracing::warn!("WireGuard mesh disabled: no node SVID to sign the advertisement");
            return Ok(None);
        };

        let ip: Ipv4Addr = assignment
            .mesh_ip
            .parse()
            .map_err(|_| WgError::Assignment(format!("bad address {:?}", assignment.mesh_ip)))?;
        let prefix_len = u8::try_from(assignment.prefix_len)
            .ok()
            .filter(|p| (8..=30).contains(p))
            .ok_or_else(|| {
                WgError::Assignment(format!("bad prefix length {}", assignment.prefix_len))
            })?;

        let leaf_pem = leaf_certificate_pem(cert_pem)
            .ok_or_else(|| WgError::Identity("node certificate is not PEM".into()))?;
        let spiffe_id = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&leaf_pem)
            .ok_or_else(|| WgError::Identity("node certificate has no SPIFFE ID".into()))?;
        let trust_domain = spiffe_id
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.strip_suffix(&format!("/agent/{node_id}")))
            .filter(|domain| !domain.is_empty() && !domain.contains('/'))
            .ok_or_else(|| {
                WgError::Identity(format!("{spiffe_id} is not this node's agent identity"))
            })?;
        self.trust_domain = trust_domain.to_string();
        let key_der = pkcs8_der(key_pem)
            .ok_or_else(|| WgError::Identity("node key is not PKCS#8 PEM".into()))?;

        let endpoint_ip = match self.settings.advertise_addr {
            Some(addr) => addr,
            None => default_advertise_addr(&self.server_addr)?,
        };
        let endpoint = SocketAddr::new(endpoint_ip, self.wg.listen_port()).to_string();

        if self.wg.initialize(ip, prefix_len).await? {
            // A new interface has no peers (nor routes over it).
            self.peers.clear();
            self.routes.clear();
        }
        let public_key = self.wg.public_key().to_string();
        let allowed_ip = format!("{ip}/32");
        let signature =
            super::advert::sign_advert(node_id, &public_key, &endpoint, &allowed_ip, &key_der)?;

        if let Some(pending) = self.pending.take() {
            self.apply_update(pending).await?;
        }

        Ok(Some(WireguardPeer {
            node_id: node_id.to_string(),
            public_key,
            endpoint,
            allowed_ip,
            signature,
            signing_cert_pem: leaf_pem,
            routed_ips: Vec::new(),
        }))
    }

    /// Apply a peer update from the server.
    /// Adds new peers, updates changed peers, removes stale peers. Before
    /// the interface is up the update is kept and applied on activation.
    pub async fn apply_update(&mut self, updates: Vec<WireguardPeer>) -> Result<(), WgError> {
        if self.wg.mesh_ip().is_none() {
            self.pending = Some(updates);
            return Ok(());
        }
        // Only accept advertisements whose WireGuard key is cryptographically
        // bound to the advertising node's SVID identity, and that route only
        // that node's own mesh address. Unsigned, forged, or over-broad
        // advertisements are dropped so a substituted key or a wide
        // allowed-ips range cannot capture another node's traffic.
        let updates: Vec<WireguardPeer> = updates
            .into_iter()
            .filter(|peer| {
                let verified = super::advert::verify_advert(peer, &self.trust_domain)
                    .map_err(|e| e.to_string())
                    .and_then(|()| self.check_allowed_ip(&peer.allowed_ip));
                match verified {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(
                            node_id = %peer.node_id,
                            error = %e,
                            "Rejected unverified WireGuard peer advertisement"
                        );
                        false
                    }
                }
            })
            .collect();

        let new_ids: Vec<String> = updates.iter().map(|p| p.node_id.clone()).collect();

        // The namespace addresses each peer's replicas hold. An address is
        // routed to one peer only.
        let mut claimed = HashSet::new();
        let routed: Vec<Vec<Ipv4Addr>> = updates
            .iter()
            .map(|peer| {
                peer.routed_ips
                    .iter()
                    .filter_map(|ip| match self.check_routed_ip(ip) {
                        Ok(ip) if claimed.insert(ip) => Some(ip),
                        Ok(ip) => {
                            tracing::warn!(node_id = %peer.node_id, %ip, "Namespace address routed to two peers; ignored");
                            None
                        }
                        Err(e) => {
                            tracing::warn!(node_id = %peer.node_id, error = %e, "Rejected routed namespace address");
                            None
                        }
                    })
                    .collect()
            })
            .collect();

        // Add/update peers
        for (peer, routed) in updates.iter().zip(routed) {
            let existing = self.peers.get(&peer.node_id);
            let changed = existing.is_none_or(|existing| {
                existing.public_key != peer.public_key
                    || existing.endpoint != peer.endpoint
                    || existing.allowed_ip != peer.allowed_ip
                    || existing.routed != routed
            });
            if !changed {
                continue;
            }
            // A node that re-keyed (restarted) leaves its old key behind.
            if let Some(old) = existing
                && old.public_key != peer.public_key
            {
                self.wg.remove_peer(&old.public_key).await?;
            }
            let allowed_ips: Vec<String> = std::iter::once(peer.allowed_ip.clone())
                .chain(routed.iter().map(|ip| format!("{ip}/32")))
                .collect();
            self.wg
                .set_peer(&peer.public_key, &peer.endpoint, &allowed_ips.join(","))
                .await?;
            tracing::info!(
                node_id = %peer.node_id,
                endpoint = %peer.endpoint,
                allowed_ip = %peer.allowed_ip,
                routed = routed.len(),
                "WireGuard peer configured"
            );
            self.peers.insert(
                peer.node_id.clone(),
                PeerInfo {
                    public_key: peer.public_key.clone(),
                    endpoint: peer.endpoint.clone(),
                    allowed_ip: peer.allowed_ip.clone(),
                    routed,
                },
            );
        }

        // Remove peers no longer in the update
        let stale: Vec<String> = self
            .peers
            .keys()
            .filter(|id| !new_ids.contains(id))
            .cloned()
            .collect();

        for id in stale {
            if let Some(peer) = self.peers.remove(&id) {
                self.wg.remove_peer(&peer.public_key).await?;
                tracing::info!(node_id = %id, "Stale peer removed");
            }
        }

        self.sync_routes().await;
        Ok(())
    }

    /// Route the peers' namespace addresses over the mesh. A failed route
    /// is retried with the next update.
    async fn sync_routes(&mut self) {
        let wanted: BTreeSet<Ipv4Addr> = self
            .peers
            .values()
            .flat_map(|p| p.routed.iter().copied())
            .collect();
        for ip in self.routes.difference(&wanted).copied().collect::<Vec<_>>() {
            if let Err(e) = self.wg.remove_route(ip).await {
                tracing::debug!(%ip, error = %e, "Namespace route already gone");
            }
            self.routes.remove(&ip);
        }
        for ip in wanted.difference(&self.routes).copied().collect::<Vec<_>>() {
            match self.wg.add_route(ip).await {
                Ok(()) => {
                    self.routes.insert(ip);
                }
                Err(e) => tracing::warn!(%ip, error = %e, "Cannot route a namespace address"),
            }
        }
    }

    /// A routed address must be a single namespace-network address.
    fn check_routed_ip(&self, ip: &str) -> Result<Ipv4Addr, String> {
        let parsed: Ipv4Addr = ip
            .parse()
            .map_err(|_| format!("routed address {ip:?} is not a single IPv4 address"))?;
        if !crate::agent::netns::in_namespace_network(parsed) || self.wg.in_mesh_network(parsed) {
            return Err(format!(
                "routed address {ip} is outside the namespace network"
            ));
        }
        Ok(parsed)
    }

    /// A peer may route exactly one address, inside the mesh network.
    fn check_allowed_ip(&self, allowed_ip: &str) -> Result<(), String> {
        let ip = allowed_ip
            .strip_suffix("/32")
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| format!("allowed-ips {allowed_ip} is not a single address"))?;
        if !self.wg.in_mesh_network(ip) || Some(ip) == self.wg.mesh_ip() {
            return Err(format!("allowed-ips {allowed_ip} is outside the mesh"));
        }
        Ok(())
    }

    /// Look up which peer node owns the given mesh IP address.
    /// Used for route table management to determine next-hop peer.
    pub fn route_to_peer(&self, ip: Ipv4Addr) -> Option<&str> {
        let wanted = format!("{ip}/32");
        self.peers
            .iter()
            .find(|(_, info)| info.allowed_ip == wanted)
            .map(|(node_id, _)| node_id.as_str())
    }

    /// Get the WireGuard manager reference.
    pub fn wireguard(&self) -> &WireguardManager {
        &self.wg
    }
}

/// The first certificate in `pem`, re-encoded alone.
fn leaf_certificate_pem(pem: &str) -> Option<String> {
    let end_marker = "-----END CERTIFICATE-----";
    let start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let end = pem[start..].find(end_marker)? + start + end_marker.len();
    Some(format!("{}\n", &pem[start..end]))
}

/// The PKCS#8 DER inside a `PRIVATE KEY` PEM block.
fn pkcs8_der(pem: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    match crate::ca::pki::pem_private_key(&mut reader).ok()?? {
        rustls_pki_types::PrivateKeyDer::Pkcs8(key) => {
            Some(Zeroizing::new(key.secret_pkcs8_der().to_vec()))
        }
        _ => None,
    }
}

/// The address to advertise when none is configured: the local address on
/// the route to the server, or, when that is loopback (an agent embedded in
/// its server), the source address of the default route.
fn default_advertise_addr(server_addr: &str) -> Result<IpAddr, WgError> {
    let ip = local_addr_towards(server_addr)?;
    if !ip.is_loopback() {
        return Ok(ip);
    }
    // Documentation addresses: only a route lookup, nothing is sent.
    let probe = if ip.is_ipv4() {
        "192.0.2.1:9"
    } else {
        "[2001:db8::1]:9"
    };
    local_addr_towards(probe).map_err(|_| {
        WgError::Assignment("no default route; set --advertise-addr for the mesh".into())
    })
}

/// The local address the kernel would use to reach `server_addr` (no
/// packet is sent: connecting a UDP socket only selects a route).
fn local_addr_towards(server_addr: &str) -> Result<IpAddr, WgError> {
    let server: SocketAddr = server_addr.parse().map_err(|_| {
        WgError::Assignment(format!("server address {server_addr:?} is not ip:port"))
    })?;
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(server)?;
    Ok(socket.local_addr()?.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_is_the_first_certificate() {
        let chain = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\
                     -----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        assert_eq!(
            leaf_certificate_pem(chain).unwrap(),
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
        );
        assert!(leaf_certificate_pem("nothing").is_none());
    }

    #[test]
    fn advertised_address_follows_the_route_to_the_server() {
        assert_eq!(
            local_addr_towards("127.0.0.1:7400").unwrap(),
            IpAddr::from(Ipv4Addr::LOCALHOST)
        );
        assert!(local_addr_towards("not-an-address").is_err());
    }

    #[test]
    fn node_keys_are_read_as_pkcs8() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        assert_eq!(
            pkcs8_der(&key.serialize_pem()).unwrap().as_slice(),
            key.serialize_der().as_slice()
        );
        assert!(pkcs8_der("garbage").is_none());
    }

    #[tokio::test]
    async fn updates_before_activation_are_kept() {
        let mut pm = PeerManager::new(
            WireguardManager::new("wg-test", 51820),
            MeshSettings::default(),
            "127.0.0.1:7400",
        );
        pm.apply_update(vec![WireguardPeer::default()])
            .await
            .unwrap();
        assert_eq!(pm.pending.as_ref().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn disabled_mesh_does_nothing() {
        let mut pm = PeerManager::new(
            WireguardManager::new("wg-test", 51820),
            MeshSettings {
                enabled: false,
                ..MeshSettings::default()
            },
            "127.0.0.1:7400",
        );
        let assignment = MeshAssignment {
            mesh_ip: "10.100.0.1".into(),
            prefix_len: 16,
        };
        assert!(pm.activate("a", &assignment, None).await.unwrap().is_none());
        assert!(pm.wireguard().mesh_ip().is_none());
    }
}
