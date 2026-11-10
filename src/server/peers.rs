//! Server-side registry of verified WireGuard peer adverts.
//!
//! Agents send their signed advert over the control stream
//! (`AgentMessage::PeerAdvert`). The server accepts it only from an mTLS
//! stream authenticated by that node's SVID, verifies the advert itself
//! (chain, identity, signature; see [`crate::mesh::advert`]), and then checks
//! state: the advert must be recent and newer than the node's last one, and
//! its WireGuard key and mesh address must not belong to another node.
//! Accepted adverts are relayed unchanged to every agent, which verifies them
//! again, so a compromised server cannot forge a peer key.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use crate::mesh::advert::{AdvertError, AdvertVerifier, advert_mesh_ip};
use crate::proto::WireguardPeer;

/// How far in the past an advert's `issued_at` may be when it arrives. The
/// agent signs immediately before sending, so this only absorbs clock skew.
const MAX_ADVERT_AGE_MS: u64 = 5 * 60 * 1000;
/// How far in the future `issued_at` may be.
const MAX_FUTURE_SKEW_MS: u64 = 30 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum AdvertRejection {
    #[error("peer adverts require an mTLS stream authenticated with a node SVID")]
    NotSvidAuthenticated,
    #[error("stream is authenticated as '{stream}' but the advert is for '{advert}'")]
    WrongNode { stream: String, advert: String },
    #[error(transparent)]
    Invalid(#[from] AdvertError),
    #[error("advert issued_at is outside the accepted window")]
    NotFresh,
    #[error("advert is not newer than the node's current advert")]
    Replayed,
    #[error("{what} is already advertised by node '{owner}'")]
    Conflict { what: &'static str, owner: String },
}

struct Entry {
    advert: WireguardPeer,
    /// Control-stream connection that installed the advert, so a stale
    /// stream ending does not remove the advert of a newer one.
    conn: u64,
}

pub struct PeerRegistry {
    verifier: AdvertVerifier,
    adverts: Mutex<HashMap<String, Entry>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl PeerRegistry {
    pub fn new(verifier: AdvertVerifier) -> Self {
        Self {
            verifier,
            adverts: Mutex::new(HashMap::new()),
        }
    }

    /// Accept `advert` from connection `conn`, whose SVID names
    /// `stream_node` (`None` for bearer-token streams).
    pub async fn accept(
        &self,
        stream_node: Option<&str>,
        conn: u64,
        advert: WireguardPeer,
    ) -> Result<(), AdvertRejection> {
        self.accept_at(stream_node, conn, advert, now_ms()).await
    }

    async fn accept_at(
        &self,
        stream_node: Option<&str>,
        conn: u64,
        advert: WireguardPeer,
        now_ms: u64,
    ) -> Result<(), AdvertRejection> {
        // A bearer token is shared and does not name a node, so it cannot
        // vouch for a node's WireGuard key.
        let stream_node = stream_node.ok_or(AdvertRejection::NotSvidAuthenticated)?;
        if advert.node_id != stream_node {
            return Err(AdvertRejection::WrongNode {
                stream: stream_node.to_string(),
                advert: advert.node_id,
            });
        }
        self.verifier.verify(&advert)?;
        if advert.issued_at > now_ms.saturating_add(MAX_FUTURE_SKEW_MS)
            || advert.issued_at < now_ms.saturating_sub(MAX_ADVERT_AGE_MS)
        {
            return Err(AdvertRejection::NotFresh);
        }

        let mut adverts = self.adverts.lock().await;
        if let Some(current) = adverts.get(&advert.node_id)
            && advert.issued_at <= current.advert.issued_at
        {
            return Err(AdvertRejection::Replayed);
        }
        let mesh_ip = advert_mesh_ip(&advert.allowed_ip);
        for (owner, entry) in adverts.iter() {
            if *owner == advert.node_id {
                continue;
            }
            // WireGuard peers are keyed by public key, and routes by address:
            // reusing either would let this node displace another's peer.
            if entry.advert.public_key == advert.public_key {
                return Err(AdvertRejection::Conflict {
                    what: "WireGuard public key",
                    owner: owner.clone(),
                });
            }
            if advert_mesh_ip(&entry.advert.allowed_ip) == mesh_ip {
                return Err(AdvertRejection::Conflict {
                    what: "mesh address",
                    owner: owner.clone(),
                });
            }
        }
        adverts.insert(advert.node_id.clone(), Entry { advert, conn });
        Ok(())
    }

    /// Remove `node_id`'s advert if connection `conn` installed it. Returns
    /// whether anything was removed.
    pub async fn remove(&self, node_id: &str, conn: u64) -> bool {
        let mut adverts = self.adverts.lock().await;
        if adverts.get(node_id).is_some_and(|e| e.conn == conn) {
            adverts.remove(node_id);
            true
        } else {
            false
        }
    }

    /// All current adverts, ordered by node ID.
    pub async fn snapshot(&self) -> Vec<WireguardPeer> {
        let adverts = self.adverts.lock().await;
        let mut peers: Vec<WireguardPeer> = adverts.values().map(|e| e.advert.clone()).collect();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::advert::sign_advert;
    use crate::mesh::advert::tests::{TestCa, WG_KEY_A, WG_KEY_B, signed_peer, unsigned_peer};

    const NOW: u64 = 1_700_000_000_000;

    fn at(mut peer: WireguardPeer, ca: &TestCa, issued_at: u64) -> WireguardPeer {
        let (cert, key) = ca.issue(&format!("spiffe://fleet.internal/agent/{}", peer.node_id));
        peer.issued_at = issued_at;
        sign_advert(&mut peer, &cert, &key).unwrap();
        peer
    }

    fn advert(ca: &TestCa, node: &str, key: &str, ip: &str, issued_at: u64) -> WireguardPeer {
        at(unsigned_peer(node, key, ip), ca, issued_at)
    }

    #[tokio::test]
    async fn accepts_valid_advert_from_its_own_svid_stream() {
        let ca = TestCa::new();
        let reg = PeerRegistry::new(ca.verifier());
        let a = advert(&ca, "node-a", WG_KEY_A, "10.100.0.1", NOW);
        reg.accept_at(Some("node-a"), 1, a.clone(), NOW)
            .await
            .unwrap();
        assert_eq!(reg.snapshot().await, vec![a]);
    }

    #[tokio::test]
    async fn rejects_unsigned_and_bearer_and_other_node_adverts() {
        let ca = TestCa::new();
        let reg = PeerRegistry::new(ca.verifier());
        let mut unsigned = unsigned_peer("node-a", WG_KEY_A, "10.100.0.1");
        unsigned.issued_at = NOW;
        assert!(matches!(
            reg.accept_at(Some("node-a"), 1, unsigned, NOW).await,
            Err(AdvertRejection::Invalid(AdvertError::MissingSignature))
        ));

        let a = advert(&ca, "node-a", WG_KEY_A, "10.100.0.1", NOW);
        assert!(matches!(
            reg.accept_at(None, 1, a.clone(), NOW).await,
            Err(AdvertRejection::NotSvidAuthenticated)
        ));
        // node-b's stream relaying node-a's (validly signed) advert.
        assert!(matches!(
            reg.accept_at(Some("node-b"), 1, a, NOW).await,
            Err(AdvertRejection::WrongNode { .. })
        ));
        assert!(reg.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn rejects_wrongly_signed_advert() {
        let ca = TestCa::new();
        let rogue = TestCa::new();
        let reg = PeerRegistry::new(ca.verifier());
        let mut forged = signed_peer(&rogue, "node-a", WG_KEY_A, "10.100.0.1");
        forged = at(forged, &rogue, NOW);
        assert!(matches!(
            reg.accept_at(Some("node-a"), 1, forged, NOW).await,
            Err(AdvertRejection::Invalid(AdvertError::UntrustedCert(_)))
        ));
    }

    #[tokio::test]
    async fn rejects_stale_future_and_replayed_adverts() {
        let ca = TestCa::new();
        let reg = PeerRegistry::new(ca.verifier());
        let old = advert(
            &ca,
            "node-a",
            WG_KEY_A,
            "10.100.0.1",
            NOW - MAX_ADVERT_AGE_MS - 1,
        );
        let future = advert(
            &ca,
            "node-a",
            WG_KEY_A,
            "10.100.0.1",
            NOW + MAX_FUTURE_SKEW_MS + 1,
        );
        for p in [old, future] {
            assert!(matches!(
                reg.accept_at(Some("node-a"), 1, p, NOW).await,
                Err(AdvertRejection::NotFresh)
            ));
        }

        let first = advert(&ca, "node-a", WG_KEY_A, "10.100.0.1", NOW);
        reg.accept_at(Some("node-a"), 1, first.clone(), NOW)
            .await
            .unwrap();
        // The same advert again, or an older one, cannot replace it.
        assert!(matches!(
            reg.accept_at(Some("node-a"), 1, first.clone(), NOW).await,
            Err(AdvertRejection::Replayed)
        ));
        let older = advert(&ca, "node-a", WG_KEY_B, "10.100.0.1", NOW - 1);
        assert!(matches!(
            reg.accept_at(Some("node-a"), 1, older, NOW).await,
            Err(AdvertRejection::Replayed)
        ));
        // A newer one (key rotation) does.
        let newer = advert(&ca, "node-a", WG_KEY_B, "10.100.0.1", NOW + 1);
        reg.accept_at(Some("node-a"), 2, newer.clone(), NOW)
            .await
            .unwrap();
        assert_eq!(reg.snapshot().await, vec![newer]);
    }

    #[tokio::test]
    async fn rejects_another_nodes_key_or_address() {
        let ca = TestCa::new();
        let reg = PeerRegistry::new(ca.verifier());
        reg.accept_at(
            Some("node-a"),
            1,
            advert(&ca, "node-a", WG_KEY_A, "10.100.0.1", NOW),
            NOW,
        )
        .await
        .unwrap();
        let same_key = advert(&ca, "node-b", WG_KEY_A, "10.100.0.2", NOW);
        let same_ip = advert(&ca, "node-b", WG_KEY_B, "10.100.0.1", NOW);
        for p in [same_key, same_ip] {
            assert!(matches!(
                reg.accept_at(Some("node-b"), 2, p, NOW).await,
                Err(AdvertRejection::Conflict { .. })
            ));
        }
        reg.accept_at(
            Some("node-b"),
            2,
            advert(&ca, "node-b", WG_KEY_B, "10.100.0.2", NOW),
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(reg.snapshot().await.len(), 2);
    }

    #[tokio::test]
    async fn only_the_installing_connection_removes_an_advert() {
        let ca = TestCa::new();
        let reg = PeerRegistry::new(ca.verifier());
        reg.accept_at(
            Some("node-a"),
            1,
            advert(&ca, "node-a", WG_KEY_A, "10.100.0.1", NOW),
            NOW,
        )
        .await
        .unwrap();
        reg.accept_at(
            Some("node-a"),
            2,
            advert(&ca, "node-a", WG_KEY_A, "10.100.0.1", NOW + 1),
            NOW,
        )
        .await
        .unwrap();
        // The old stream ending after the reconnect must not drop the advert.
        assert!(!reg.remove("node-a", 1).await);
        assert_eq!(reg.snapshot().await.len(), 1);
        assert!(reg.remove("node-a", 2).await);
        assert!(reg.snapshot().await.is_empty());
    }
}
