use std::collections::HashMap;
use std::net::Ipv4Addr;

use super::wireguard::WireguardManager;

/// Manages the peer configuration for the WireGuard mesh.
/// Tracks known peers and applies updates from the server.
pub struct PeerManager {
    wg: WireguardManager,
    peers: HashMap<String, PeerInfo>,
}

#[derive(Debug, Clone)]
struct PeerInfo {
    public_key: String,
    endpoint: String,
    #[allow(dead_code)] // TODO: needed for route table management once mesh routing is wired
    allowed_ip: Ipv4Addr,
}

impl PeerManager {
    pub fn new(wg: WireguardManager) -> Self {
        Self {
            wg,
            peers: HashMap::new(),
        }
    }

    /// Apply a peer update from the server.
    /// Adds new peers, updates changed peers, removes stale peers.
    pub async fn apply_update(
        &mut self,
        updates: Vec<crate::proto::WireguardPeer>,
    ) -> Result<(), super::wireguard::WgError> {
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

    /// Get the WireGuard manager reference.
    pub fn wireguard(&self) -> &WireguardManager {
        &self.wg
    }
}
