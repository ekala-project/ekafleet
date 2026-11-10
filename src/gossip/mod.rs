//! Gossip: SWIM membership and failure detection between fleet nodes.
//!
//! The server and every agent run a [`swim::SwimMembership`] on UDP
//! (default port [`swim::DEFAULT_GOSSIP_PORT`]). The server derives the cluster
//! key from the fleet key ([`derive_cluster_key`]) and hands it, with the
//! current member list, to each agent over the mTLS control stream
//! (`ServerMessage::GossipConfig`), so only attested or token-authenticated
//! agents can join.

pub mod catalog;
pub mod swim;

use ring::hkdf::{self, HKDF_SHA256};

/// Derive the gossip HMAC key from the fleet master key.
///
/// HKDF-SHA256 with a gossip-specific salt, so the gossip key reveals nothing
/// about the fleet key or the per-agent secret keys derived from it. It
/// changes whenever the fleet key is rotated.
pub fn derive_cluster_key(fleet_master_key: &[u8]) -> [u8; 32] {
    let salt = hkdf::Salt::new(HKDF_SHA256, b"ekafleet-gossip-hmac-v1");
    let prk = salt.extract(fleet_master_key);
    let okm = prk
        .expand(&[b"swim"], HKDF_SHA256)
        .expect("HKDF expand with valid length");
    let mut key = [0u8; 32];
    okm.fill(&mut key).expect("32-byte output fits SHA-256");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_key_is_deterministic_and_distinct() {
        let fleet_key = [3u8; 32];
        let key = derive_cluster_key(&fleet_key);
        assert_eq!(key, derive_cluster_key(&fleet_key));
        assert_ne!(key, derive_cluster_key(&[4u8; 32]));
        assert_ne!(&key[..], &fleet_key[..]);
        let agent_key = crate::secrets::key_derivation::derive_agent_key(
            &fleet_key,
            "spiffe://fleet.internal/agent/swim",
        );
        assert_ne!(key, agent_key);
    }
}
