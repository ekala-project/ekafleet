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
//!
//! So that a rotation never leaves the key on the leader alone, the leader
//! first stages the new key on a majority of the voting servers
//! ([`stage_on_peers`]); they adopt their staged copy once the rotation is
//! committed, and serve it to the others.

#![allow(clippy::result_large_err)]

use std::path::Path;
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

/// How long a staged key may wait for its rotation to commit before it is
/// taken to be abandoned.
const ABANDONED_STAGE: Duration = Duration::from_secs(600);

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

fn to_hex(key: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(key.iter().map(|b| format!("{b:02x}")).collect())
}

fn from_hex(hex: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let hex = std::str::from_utf8(hex).ok()?.trim();
    if hex.len() != 64 {
        return None;
    }
    let key: Option<Vec<u8>> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect();
    key.map(Zeroizing::new)
}

fn staged_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(super::secrets::NEXT_FLEET_KEY_FILE)
}

/// Hold `key` as this server's staged fleet key (see [`stage_on_peers`]).
pub async fn write_staged(data_dir: &Path, key: &[u8]) -> anyhow::Result<()> {
    super::seal::write_maybe_sealed(
        &staged_path(data_dir),
        to_hex(key).as_bytes(),
        "staged fleet encryption key",
    )
    .await
}

/// This server's staged fleet key, if any.
pub async fn read_staged(data_dir: &Path) -> Option<Zeroizing<Vec<u8>>> {
    let path = staged_path(data_dir);
    if !path.exists() {
        return None;
    }
    let hex = super::seal::read_maybe_sealed(&path).await.ok()?;
    from_hex(&hex)
}

/// Stage `key` on the other servers before a rotation to it is
/// committed. Succeeds once a majority of the voters, this server
/// included, hold it, so the key outlives the loss of any minority.
pub async fn stage_on_peers(
    raft_state: &FleetStateMachine,
    network: &GrpcNetwork,
    key: &[u8],
) -> Result<(), String> {
    let Some(raft) = raft_state.raft() else {
        return Ok(());
    };
    let metrics = raft.metrics().borrow().clone();
    let membership = metrics.membership_config.membership().clone();
    let voters: std::collections::BTreeSet<_> = membership.voter_ids().collect();
    let mut holders = usize::from(voters.contains(&metrics.id));
    for (id, node) in membership.nodes() {
        if *id == metrics.id {
            continue;
        }
        match network.stage_fleet_key(&node.addr, key).await {
            Ok(()) if voters.contains(id) => holders += 1,
            Ok(()) => {}
            Err(e) => tracing::warn!(peer = id, error = %e, "Could not stage the new fleet key"),
        }
    }
    let needed = voters.len() / 2 + 1;
    if holders < needed {
        return Err(format!(
            "only {holders} of the {needed} servers needed hold the new fleet key"
        ));
    }
    Ok(())
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
            self.drop_abandoned_stage().await;
            // The version agents are sent follows the replicated one.
            let version = self.raft_state.fleet_key_version().await;
            if version > self.fleet_key.read().await.version {
                self.fleet_key.write().await.version = version;
            }
            return true;
        }
        if let Some(staged) = read_staged(&self.data_dir).await
            && has_check(&staged, &expected)
        {
            return match self.adopt(staged).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!(error = %e, "Could not install the staged fleet key");
                    false
                }
            };
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

    /// Remove a staged key a rotation never committed: the leader stages
    /// the key on the servers before it commits, and gives up if too few
    /// hold it.
    async fn drop_abandoned_stage(&self) {
        let path = staged_path(&self.data_dir);
        let abandoned = tokio::fs::metadata(&path)
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|at| at.elapsed().ok())
            .is_some_and(|age| age > ABANDONED_STAGE);
        if abandoned && tokio::fs::remove_file(&path).await.is_ok() {
            tracing::info!("Removed a staged fleet key whose rotation never committed");
        }
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
        let mut fleet_key = self.fleet_key.write().await;
        let mut store = self.secret_store.write().await;
        super::seal::write_maybe_sealed(
            &self.data_dir.join("fleet-key"),
            to_hex(&key).as_bytes(),
            "fleet encryption key",
        )
        .await?;
        if read_staged(&self.data_dir)
            .await
            .is_some_and(|staged| *staged == *key)
        {
            let _ = tokio::fs::remove_file(staged_path(&self.data_dir)).await;
        }
        *store = SecretStore::new(array);
        fleet_key.version = (fleet_key.version + 1).max(self.raft_state.fleet_key_version().await);
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
    async fn rotations_count_the_version_in_the_replicated_state() {
        let raft = FleetStateMachine::new();
        assert_eq!(raft.fleet_key_version().await, 0);
        raft.apply_next(Command::SetFleetKeyCheck {
            check: key_check(&[1; 32]),
        })
        .await
        .unwrap();
        assert_eq!(raft.fleet_key_version().await, 1);
        let reseal = |check: Option<Vec<u8>>| {
            let raft = raft.clone();
            async move {
                raft.reseal_under(
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    check,
                )
                .await
                .unwrap()
            }
        };
        reseal(Some(key_check(&[2; 32]))).await;
        assert_eq!(raft.fleet_key_version().await, 2);
        // Resealing without a new key, or recording the same one again,
        // is no rotation.
        reseal(None).await;
        reseal(Some(key_check(&[2; 32]))).await;
        raft.apply_next(Command::SetFleetKeyCheck {
            check: key_check(&[2; 32]),
        })
        .await
        .unwrap();
        assert_eq!(raft.fleet_key_version().await, 2);
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
