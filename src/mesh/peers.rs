use std::collections::HashMap;
use std::net::Ipv4Addr;

use super::wireguard::WireguardManager;

/// Manages the peer configuration for the WireGuard mesh.
/// Tracks known peers and applies updates from the server.
pub struct PeerManager {
    wg: WireguardManager,
    peers: HashMap<String, PeerInfo>,
    /// Trust domain used to verify that a peer advertisement's signing
    /// certificate matches the advertised node identity.
    trust_domain: String,
}

#[derive(Debug, Clone)]
struct PeerInfo {
    public_key: String,
    endpoint: String,
    allowed_ip: Ipv4Addr,
}

impl PeerManager {
    pub fn new(wg: WireguardManager, trust_domain: impl Into<String>) -> Self {
        Self {
            wg,
            peers: HashMap::new(),
            trust_domain: trust_domain.into(),
        }
    }

    /// Apply a peer update from the server.
    /// Adds new peers, updates changed peers, removes stale peers.
    pub async fn apply_update(
        &mut self,
        updates: Vec<crate::proto::WireguardPeer>,
    ) -> Result<(), super::wireguard::WgError> {
        // Only accept advertisements whose WireGuard key is cryptographically
        // bound to the advertising node's SVID identity. Unsigned or forged
        // advertisements are dropped so a leaked/substituted public key cannot
        // be installed as another node's peer.
        let updates: Vec<crate::proto::WireguardPeer> = updates
            .into_iter()
            .filter(
                |peer| match super::advert::verify_advert(peer, &self.trust_domain) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(
                            node_id = %peer.node_id,
                            error = %e,
                            "Rejected unverified WireGuard peer advertisement"
                        );
                        false
                    }
                },
            )
            .collect();

        let new_ids: Vec<String> = updates.iter().map(|p| p.node_id.clone()).collect();

        // Add/update peers
        for peer in &updates {
            let changed = self.peers.get(&peer.node_id).is_none_or(|existing| {
                existing.public_key != peer.public_key || existing.endpoint != peer.endpoint
            });

            if changed {
                self.wg
                    .set_peer(&peer.public_key, &peer.endpoint, &peer.allowed_ip)
                    .await?;

                let ip: Ipv4Addr = peer
                    .allowed_ip
                    .split('/')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);

                self.peers.insert(
                    peer.node_id.clone(),
                    PeerInfo {
                        public_key: peer.public_key.clone(),
                        endpoint: peer.endpoint.clone(),
                        allowed_ip: ip,
                    },
                );
            }
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
