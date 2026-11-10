use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use super::advert::{AdvertVerifier, advert_mesh_ip};
use super::wireguard::WireguardManager;
use crate::proto::WireguardPeer;

/// Manages the peer configuration for the WireGuard mesh.
///
/// The server relays every node's signed advert; this re-verifies each one
/// itself (it does not trust the server to have done so) before installing
/// it, so a compromised server or relay cannot substitute a peer's key.
pub struct PeerManager {
    wg: WireguardManager,
    peers: HashMap<String, PeerInfo>,
    /// Verifies adverts against the fleet CA and trust domain. `None` (no CA
    /// certificate or no node SVID) rejects every advert.
    verifier: Option<AdvertVerifier>,
    local_node_id: String,
    /// Whether the local WireGuard interface is up. Updates are verified but
    /// not applied until it is.
    enabled: bool,
    /// Highest `issued_at` seen per node, so an older advert (for example a
    /// retired WireGuard key) cannot be reinstalled.
    newest: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct PeerInfo {
    public_key: String,
    endpoint: String,
    allowed_ip: Ipv4Addr,
}

impl PeerManager {
    pub fn new(
        wg: WireguardManager,
        local_node_id: impl Into<String>,
        verifier: Option<AdvertVerifier>,
    ) -> Self {
        Self {
            wg,
            peers: HashMap::new(),
            verifier,
            local_node_id: local_node_id.into(),
            enabled: false,
            newest: HashMap::new(),
        }
    }

    /// Bring up the local WireGuard interface at `mesh_index`.
    pub async fn enable(&mut self, mesh_index: u16) -> Result<(), super::wireguard::WgError> {
        self.wg.initialize(mesh_index).await?;
        self.enabled = true;
        Ok(())
    }

    /// Keep only adverts that verify and are safe to install together.
    ///
    /// Drops: unverified adverts, this node's own advert, adverts older than
    /// one already seen for that node, and adverts whose key or address is
    /// this node's or another accepted peer's (first by node ID wins).
    fn select(&mut self, updates: Vec<WireguardPeer>, own_key: Option<&str>) -> Vec<WireguardPeer> {
        let own_ip = self.wg.mesh_ip();
        let mut keys: HashSet<String> = own_key.into_iter().map(str::to_string).collect();
        let mut ips: HashSet<Ipv4Addr> = self.enabled.then_some(own_ip).into_iter().collect();
        let mut seen_nodes = HashSet::new();

        let mut updates = updates;
        updates.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let mut accepted = Vec::new();
        for peer in updates {
            let reject = |reason: &str| {
                tracing::warn!(
                    node_id = %peer.node_id,
                    reason,
                    "Rejected WireGuard peer advertisement"
                );
            };
            if peer.node_id == self.local_node_id {
                continue;
            }
            let Some(verifier) = &self.verifier else {
                reject("no trust bundle or node SVID to verify adverts");
                continue;
            };
            if let Err(e) = verifier.verify(&peer) {
                reject(&e.to_string());
                continue;
            }
            if !seen_nodes.insert(peer.node_id.clone()) {
                reject("duplicate advert for node");
                continue;
            }
            if self
                .newest
                .get(&peer.node_id)
                .is_some_and(|&newest| peer.issued_at < newest)
            {
                reject("older than an advert already seen");
                continue;
            }
            let ip = advert_mesh_ip(&peer.allowed_ip).expect("verified adverts have a /32");
            if keys.contains(&peer.public_key) {
                reject("WireGuard key already in use");
                continue;
            }
            if !ips.insert(ip) {
                reject("mesh address already in use");
                continue;
            }
            keys.insert(peer.public_key.clone());
            self.newest.insert(peer.node_id.clone(), peer.issued_at);
            accepted.push(peer);
        }
        accepted
    }

    /// Apply a peer update from the server: the full set of peers.
    /// Adds new peers, updates changed peers, removes stale peers.
    pub async fn apply_update(
        &mut self,
        updates: Vec<WireguardPeer>,
    ) -> Result<(), super::wireguard::WgError> {
        if !self.enabled {
            tracing::debug!(
                peers = updates.len(),
                "WireGuard not enabled; ignoring peer update"
            );
            return Ok(());
        }
        let own_key = self.wg.public_key().await.ok();
        let updates = self.select(updates, own_key.as_deref());
        let new_ids: HashSet<String> = updates.iter().map(|p| p.node_id.clone()).collect();

        // Add/update peers
        for peer in &updates {
            let existing = self.peers.get(&peer.node_id);
            let changed = existing.is_none_or(|existing| {
                existing.public_key != peer.public_key || existing.endpoint != peer.endpoint
            });
            if !changed {
                continue;
            }
            // A node that rotated its key leaves a stale peer behind otherwise.
            if let Some(old) = existing
                && old.public_key != peer.public_key
            {
                self.wg.remove_peer(&old.public_key).await?;
            }
            self.wg
                .set_peer(&peer.public_key, &peer.endpoint, &peer.allowed_ip)
                .await?;
            tracing::info!(node_id = %peer.node_id, endpoint = %peer.endpoint, "WireGuard peer installed");
            self.peers.insert(
                peer.node_id.clone(),
                PeerInfo {
                    public_key: peer.public_key.clone(),
                    endpoint: peer.endpoint.clone(),
                    allowed_ip: advert_mesh_ip(&peer.allowed_ip).unwrap_or(Ipv4Addr::UNSPECIFIED),
                },
            );
        }

        // Remove peers no longer in the update
        let stale: Vec<String> = self
            .peers
            .keys()
            .filter(|id| !new_ids.contains(*id))
            .cloned()
            .collect();
        for id in stale {
            if let Some(peer) = self.peers.remove(&id) {
                self.wg.remove_peer(&peer.public_key).await?;
                tracing::info!(node_id = %id, "Stale peer removed");
            }
        }

        Ok(())
    }

    /// Look up which peer node owns the given mesh IP address.
    /// Used for route table management to determine next-hop peer.
    pub fn route_to_peer(&self, ip: Ipv4Addr) -> Option<&str> {
        self.peers
            .iter()
            .find(|(_, info)| info.allowed_ip == ip)
            .map(|(node_id, _)| node_id.as_str())
    }

    /// Get the WireGuard manager reference.
    pub fn wireguard(&self) -> &WireguardManager {
        &self.wg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::advert::tests::{TestCa, WG_KEY_A, WG_KEY_B, signed_peer, unsigned_peer};

    const WG_KEY_C: &str = "8BBn8Z7ZgCeTnyCBU2ErXyvp5s4y4LuKOFnEqDPYNnY=";

    fn manager(ca: &TestCa) -> PeerManager {
        PeerManager::new(
            WireguardManager::new("wg-test", 51820),
            "node-self",
            Some(ca.verifier()),
        )
    }

    fn ids(peers: &[WireguardPeer]) -> Vec<&str> {
        peers.iter().map(|p| p.node_id.as_str()).collect()
    }

    #[test]
    fn keeps_valid_adverts_and_skips_own() {
        let ca = TestCa::new();
        let mut pm = manager(&ca);
        let got = pm.select(
            vec![
                signed_peer(&ca, "node-b", WG_KEY_B, "10.100.0.2"),
                signed_peer(&ca, "node-self", WG_KEY_C, "10.100.0.3"),
                signed_peer(&ca, "node-a", WG_KEY_A, "10.100.0.4"),
            ],
            None,
        );
        assert_eq!(ids(&got), ["node-a", "node-b"]);
    }

    #[test]
    fn rejects_unsigned_and_wrongly_signed_adverts() {
        let ca = TestCa::new();
        let rogue = TestCa::new();
        let mut pm = manager(&ca);
        let mut impersonated = unsigned_peer("node-c", WG_KEY_C, "10.100.0.5");
        let (cert, key) = ca.issue("spiffe://fleet.internal/agent/node-evil");
        crate::mesh::advert::sign_advert(&mut impersonated, &cert, &key).unwrap();
        let got = pm.select(
            vec![
                unsigned_peer("node-a", WG_KEY_A, "10.100.0.2"),
                signed_peer(&rogue, "node-b", WG_KEY_B, "10.100.0.3"),
                impersonated,
            ],
            None,
        );
        assert!(got.is_empty());
    }

    #[test]
    fn without_verifier_everything_is_rejected() {
        let ca = TestCa::new();
        let mut pm = PeerManager::new(WireguardManager::new("wg-test", 51820), "node-self", None);
        assert!(
            pm.select(
                vec![signed_peer(&ca, "node-a", WG_KEY_A, "10.100.0.2")],
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn rejects_rollback_to_an_older_advert() {
        let ca = TestCa::new();
        let mut pm = manager(&ca);
        let mut newer = unsigned_peer("node-a", WG_KEY_A, "10.100.0.2");
        newer.issued_at = 2_000;
        let (cert, key) = ca.issue("spiffe://fleet.internal/agent/node-a");
        crate::mesh::advert::sign_advert(&mut newer, &cert, &key).unwrap();
        assert_eq!(pm.select(vec![newer.clone()], None).len(), 1);
        // The same advert again is fine (a snapshot repeats it)...
        assert_eq!(pm.select(vec![newer], None).len(), 1);
        // ...but an older one (issued_at 1000) with a different key is not.
        assert!(
            pm.select(
                vec![signed_peer(&ca, "node-a", WG_KEY_B, "10.100.0.2")],
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn rejects_duplicate_keys_and_addresses() {
        let ca = TestCa::new();
        let mut pm = manager(&ca);
        let got = pm.select(
            vec![
                signed_peer(&ca, "node-a", WG_KEY_A, "10.100.0.2"),
                // Same WireGuard key as node-a: would replace its peer.
                signed_peer(&ca, "node-b", WG_KEY_A, "10.100.0.3"),
                // Same mesh address as node-a: would steal its route.
                signed_peer(&ca, "node-c", WG_KEY_B, "10.100.0.2"),
                // Our own key.
                signed_peer(&ca, "node-d", WG_KEY_C, "10.100.0.4"),
            ],
            Some(WG_KEY_C),
        );
        assert_eq!(ids(&got), ["node-a"]);
    }
}
