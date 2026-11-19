//! Keeping every server's fleet key current.
//!
//! Secrets and transit keys in the replicated state are sealed under the
//! fleet key, which each server keeps on its own disk (first from the key
//! bundle, see [`super::keybundle`]). A rotation happens on the leader, so
//! the other servers learn of it through Raft: the state records a check
//! value of the current key ([`key_check`]), and a server whose key does
//! not match fetches the current key from a peer over `RaftInternal`
//! (server SVIDs only), verifies it against the check value, and adopts it.
//! Until then it refuses to seal anything new under its stale key.

#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tonic::Status;
use zeroize::Zeroizing;

use super::api::FleetKeyState;
use super::raft_rpc::GrpcNetwork;
use super::state::FleetState;
use crate::proto::FleetKeyUpdate;
use crate::proto::server_message::Payload as ServerPayload;
use crate::raft::state::{Command, FleetStateMachine};
use crate::secrets::key_derivation::derive_agent_key;
use crate::secrets::store::SecretStore;

/// How often a server compares its fleet key with the replicated check.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(5);

/// A value identifying `key` without revealing it: HMAC-SHA256 under the
/// key of a fixed label.
pub fn key_check(key: &[u8]) -> Vec<u8> {
    let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&mac, CHECK_LABEL).as_ref().to_vec()
}

const CHECK_LABEL: &[u8] = b"ekafleet fleet key check v1";

/// Whether `check` is the check value of `key` (compared in constant time).
pub fn has_check(key: &[u8], check: &[u8]) -> bool {
    let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::verify(&mac, CHECK_LABEL, check).is_ok()
}

/// Whether `key` is the fleet key the replicated state was sealed under
/// (any key is, before a check value is recorded).
pub async fn is_current(raft_state: &FleetStateMachine, key: &[u8]) -> bool {
    match raft_state.fleet_key_check().await {
        Some(check) => has_check(key, &check),
        None => true,
    }
}

/// Refuse to seal under a fleet key that a rotation on another server has
/// replaced; [`FleetKeySync`] fetches the new one shortly.
pub async fn ensure_current(
    raft_state: &FleetStateMachine,
    fleet_key: &FleetKeyState,
) -> Result<(), Status> {
    if is_current(raft_state, &fleet_key.key).await {
        Ok(())
    } else {
        Err(Status::unavailable(
            "this server's fleet key is out of date after a rotation; retry shortly",
        ))
    }
}

/// Send each connected agent its key derived from `key`. Returns how many
/// were sent one, and how many are connected.
pub async fn notify_agents(
    state: &FleetState,
    domain: &str,
    key: &[u8],
    version: u64,
) -> (u32, usize) {
    let node_ids = state.connected_nodes().await;
    let mut notified = 0;
    for node in &node_ids {
        let agent_id = format!("spiffe://{domain}/agent/{node}");
        let derived = Zeroizing::new(derive_agent_key(key, &agent_id));
        let msg = crate::proto::ServerMessage {
            payload: Some(ServerPayload::FleetKey(FleetKeyUpdate {
                encrypted_key: derived.to_vec(),
                version,
            })),
        };
        if state.send_to_agent(node, msg).await {
            notified += 1;
        }
    }
    (notified, node_ids.len())
}

/// Runs on every server: records the key's check value when none is (on
/// the leader), and replaces a stale key with the current one.
pub struct FleetKeySync {
    pub raft_state: FleetStateMachine,
    pub fleet_key: Arc<RwLock<FleetKeyState>>,
    pub secret_store: Arc<RwLock<SecretStore>>,
    pub network: GrpcNetwork,
    pub state: FleetState,
    pub data_dir: std::path::PathBuf,
    pub domain: String,
}

impl FleetKeySync {
    pub fn spawn(self, stop: CancellationToken) {
        tokio::spawn(async move {
            loop {
                self.sync().await;
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = tokio::time::sleep(SYNC_INTERVAL) => {}
                }
            }
        });
    }

    /// One comparison, and whatever it calls for. Returns whether this
    /// server's key is current afterwards.
    pub async fn sync(&self) -> bool {
        let own = key_check(&self.fleet_key.read().await.key);
        let Some(expected) = self.raft_state.fleet_key_check().await else {
            // Clusters from before check values: the leader records its own.
            return match self
                .raft_state
                .apply_next(Command::SetFleetKeyCheck { check: own })
                .await
            {
                Ok(_) => true,
                Err(crate::raft::RaftError::NotLeader { .. }) => true,
                Err(e) => {
                    tracing::warn!(error = %e, "Could not record the fleet key check");
                    false
                }
            };
        };
        if has_check(&self.fleet_key.read().await.key, &expected) {
            return true;
        }
        for addr in self.peers() {
            match self.network.fleet_key(&addr, &expected).await {
                Ok(key) if key.len() == 32 && has_check(&key, &expected) => {
                    match self.adopt(key).await {
                        Ok(()) => return true,
                        Err(e) => {
                            tracing::error!(error = %e, "Could not install the rotated fleet key");
                            return false;
                        }
                    }
                }
                Ok(_) => tracing::warn!(peer = %addr, "Peer sent a fleet key that does not match"),
                Err(e) => {
                    tracing::debug!(peer = %addr, error = %e, "Peer has no current fleet key")
                }
            }
        }
        tracing::warn!("This server's fleet key is out of date and no peer had the current one");
        false
    }

    /// The other servers, the leader first.
    fn peers(&self) -> Vec<String> {
        let Some(raft) = self.raft_state.raft() else {
            return Vec::new();
        };
        let metrics = raft.metrics().borrow().clone();
        let mut peers: Vec<(bool, String)> = metrics
            .membership_config
            .membership()
            .nodes()
            .filter(|(id, _)| **id != metrics.id)
            .map(|(id, node)| (Some(*id) != metrics.current_leader, node.addr.clone()))
            .collect();
        peers.sort();
        peers.into_iter().map(|(_, addr)| addr).collect()
    }

    async fn adopt(&self, key: Zeroizing<Vec<u8>>) -> anyhow::Result<()> {
        let array: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("fleet key must be 32 bytes"))?;
        let hex: Zeroizing<String> =
            Zeroizing::new(key.iter().map(|b| format!("{b:02x}")).collect());
        let mut fleet_key = self.fleet_key.write().await;
        let mut store = self.secret_store.write().await;
        super::seal::write_maybe_sealed(
            &self.data_dir.join("fleet-key"),
            hex.as_bytes(),
            "fleet encryption key",
        )
        .await?;
        *store = SecretStore::new(array);
        fleet_key.version += 1;
        fleet_key.key = key;
        let version = fleet_key.version;
        let (notified, total) =
            notify_agents(&self.state, &self.domain, &fleet_key.key, version).await;
        tracing::info!(
            version,
            notified,
            total,
            "Adopted the rotated fleet key from a peer"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_identify_keys_without_revealing_them() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(key_check(&a), key_check(&a));
        assert_ne!(key_check(&a), key_check(&b));
        assert_eq!(key_check(&a).len(), 32);
        assert!(!key_check(&a).windows(4).any(|w| w == [1, 1, 1, 1]));
    }

    #[tokio::test]
    async fn sealing_waits_for_the_current_key() {
        let raft = FleetStateMachine::new();
        let stale = FleetKeyState {
            key: Zeroizing::new(vec![1; 32]),
            version: 1,
        };
        // Nothing recorded yet: any key seals.
        assert!(ensure_current(&raft, &stale).await.is_ok());
        raft.apply_next(Command::SetFleetKeyCheck {
            check: key_check(&[2; 32]),
        })
        .await
        .unwrap();
        let refused = ensure_current(&raft, &stale).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Unavailable);
        let current = FleetKeyState {
            key: Zeroizing::new(vec![2; 32]),
            version: 2,
        };
        assert!(ensure_current(&raft, &current).await.is_ok());
    }
}
