//! Raft consensus (openraft) over the encrypted Raft storage.
//!
//! [`LogStore`] keeps the replicated log, the vote and the commit index,
//! and [`StateMachineStore`] applies committed entries to the
//! [`FleetStateMachine`] and keeps its snapshots. Everything goes through
//! [`RaftStorage`], so it is sealed at rest with AES-256-GCM under the Raft
//! storage key, each record bound to its kind and index.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use openraft::{
    AnyError, BasicNode, Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
    Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::RaftError;
use super::state::{Command, FleetStateMachine, StateMachineInner, unix_now};
use super::storage::RaftStorage;

/// A command as proposed to the cluster, stamped with the proposer's clock
/// so every replica (and every replay) applies the same timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub command: Command,
    /// Unix seconds at proposal.
    pub at: u64,
}

impl Proposal {
    pub fn new(command: Command) -> Self {
        Self {
            command,
            at: unix_now(),
        }
    }
}

openraft::declare_raft_types!(
    /// ekafleet's Raft types: fleet commands keyed by numeric server ids,
    /// each server known by its Raft address.
    pub TypeConfig:
        D = Proposal,
        R = (),
);

pub type NodeId = u64;
pub type Raft = openraft::Raft<TypeConfig>;
type StorageResult<T> = Result<T, StorageError<NodeId>>;

const ENTRIES: &str = "entries";
const ENTRY_EXT: &str = "entry";
const ENTRY_KIND: &str = "raft-entry";

/// Log metadata records, one per index below.
const META: &str = "meta";
const META_EXT: &str = "meta";
const META_KIND: &str = "raft-meta";
const VOTE: u64 = 0;
const COMMITTED: u64 = 1;
const PURGED: u64 = 2;

const SNAPSHOTS: &str = "consensus-snapshots";
const SNAPSHOT_EXT: &str = "snap";
const SNAPSHOT_KIND: &str = "raft-consensus-snapshot";

fn storage_err(
    make: impl FnOnce(AnyError) -> StorageIOError<NodeId>,
    e: RaftError,
) -> StorageError<NodeId> {
    make(AnyError::new(&e)).into()
}

async fn read_meta<T: for<'de> Deserialize<'de>>(
    storage: &RaftStorage,
    index: u64,
) -> Result<Option<T>, RaftError> {
    match storage.get_record(META, META_EXT, META_KIND, index).await? {
        Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
        None => Ok(None),
    }
}

async fn write_meta<T: Serialize>(
    storage: &RaftStorage,
    index: u64,
    value: &T,
) -> Result<(), RaftError> {
    let data = serde_json::to_vec(value)?;
    storage
        .put_record(META, META_EXT, META_KIND, index, &data)
        .await?;
    storage.sync_dir(META).await
}

/// The replicated log, the vote and the commit index, durable on return
/// from every write. Entries are cached in memory between purges.
#[derive(Clone)]
pub struct LogStore {
    inner: Arc<Mutex<LogInner>>,
}

struct LogInner {
    storage: Arc<RaftStorage>,
    entries: BTreeMap<u64, Entry<TypeConfig>>,
    vote: Option<Vote<NodeId>>,
    committed: Option<LogId<NodeId>>,
    purged: Option<LogId<NodeId>>,
}

impl LogStore {
    /// Open the log in `storage`. Any unreadable record is an error.
    pub async fn open(storage: Arc<RaftStorage>) -> Result<Self, RaftError> {
        storage.ensure_dir(ENTRIES).await?;
        storage.ensure_dir(META).await?;
        let vote = read_meta(&storage, VOTE).await?;
        let committed = read_meta(&storage, COMMITTED).await?;
        let purged: Option<LogId<NodeId>> = read_meta(&storage, PURGED).await?;
        let mut entries = BTreeMap::new();
        for index in storage.record_indices(ENTRIES, ENTRY_EXT).await? {
            // Left over from a purge interrupted after recording it.
            if purged.is_some_and(|p| index <= p.index) {
                storage.remove_record(ENTRIES, ENTRY_EXT, index).await?;
                continue;
            }
            let data = storage
                .get_record(ENTRIES, ENTRY_EXT, ENTRY_KIND, index)
                .await?
                .ok_or_else(|| RaftError::Inconsistent(format!("log entry {index} vanished")))?;
            let entry: Entry<TypeConfig> = serde_json::from_slice(&data)?;
            if entry.log_id.index != index {
                return Err(RaftError::Inconsistent(format!(
                    "log record {index} holds entry {}",
                    entry.log_id.index
                )));
            }
            entries.insert(index, entry);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(LogInner {
                storage,
                entries,
                vote,
                committed,
                purged,
            })),
        })
    }

    /// Start the log after a migrated snapshot at `log_id`: everything up
    /// to it counts as purged.
    pub(super) async fn seed_purged(&self, log_id: LogId<NodeId>) -> Result<(), RaftError> {
        let mut inner = self.inner.lock().await;
        write_meta(&inner.storage, PURGED, &log_id).await?;
        write_meta(&inner.storage, COMMITTED, &log_id).await?;
        inner.purged = Some(log_id);
        inner.committed = Some(log_id);
        Ok(())
    }

    /// Whether nothing was ever recorded (fresh or pre-consensus storage).
    pub async fn is_empty(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.entries.is_empty() && inner.vote.is_none() && inner.purged.is_none()
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> StorageResult<Vec<Entry<TypeConfig>>> {
        let inner = self.inner.lock().await;
        Ok(inner.entries.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> StorageResult<LogState<TypeConfig>> {
        let inner = self.inner.lock().await;
        let last = inner.entries.values().next_back().map(|e| e.log_id);
        Ok(LogState {
            last_purged_log_id: inner.purged,
            last_log_id: last.or(inner.purged),
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> StorageResult<()> {
        let mut inner = self.inner.lock().await;
        write_meta(&inner.storage, VOTE, vote)
            .await
            .map_err(|e| storage_err(StorageIOError::write_vote, e))?;
        inner.vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> StorageResult<Option<Vote<NodeId>>> {
        Ok(self.inner.lock().await.vote)
    }

    async fn save_committed(&mut self, committed: Option<LogId<NodeId>>) -> StorageResult<()> {
        let mut inner = self.inner.lock().await;
        write_meta(&inner.storage, COMMITTED, &committed)
            .await
            .map_err(|e| storage_err(StorageIOError::write, e))?;
        inner.committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> StorageResult<Option<LogId<NodeId>>> {
        Ok(self.inner.lock().await.committed)
    }

    async fn append<I>(&mut self, entries: I, callback: LogFlushed<TypeConfig>) -> StorageResult<()>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut inner = self.inner.lock().await;
        for entry in entries {
            let index = entry.log_id.index;
            let data = serde_json::to_vec(&entry)
                .map_err(|e| storage_err(StorageIOError::write_logs, e.into()))?;
            inner
                .storage
                .put_record(ENTRIES, ENTRY_EXT, ENTRY_KIND, index, &data)
                .await
                .map_err(|e| storage_err(StorageIOError::write_logs, e))?;
            inner.entries.insert(index, entry);
        }
        inner
            .storage
            .sync_dir(ENTRIES)
            .await
            .map_err(|e| storage_err(StorageIOError::write_logs, e))?;
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> StorageResult<()> {
        let mut inner = self.inner.lock().await;
        let doomed: Vec<u64> = inner
            .entries
            .range(log_id.index..)
            .map(|(i, _)| *i)
            .collect();
        // Highest first: a crash midway leaves a contiguous log.
        for index in doomed.into_iter().rev() {
            inner
                .storage
                .remove_record(ENTRIES, ENTRY_EXT, index)
                .await
                .map_err(|e| storage_err(StorageIOError::write_logs, e))?;
            inner.entries.remove(&index);
        }
        inner
            .storage
            .sync_dir(ENTRIES)
            .await
            .map_err(|e| storage_err(StorageIOError::write_logs, e))
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> StorageResult<()> {
        let mut inner = self.inner.lock().await;
        // Record the purge first; `open` finishes an interrupted one.
        write_meta(&inner.storage, PURGED, &log_id)
            .await
            .map_err(|e| storage_err(StorageIOError::write_logs, e))?;
        inner.purged = Some(log_id);
        let doomed: Vec<u64> = inner
            .entries
            .range(..=log_id.index)
            .map(|(i, _)| *i)
            .collect();
        for index in doomed {
            inner
                .storage
                .remove_record(ENTRIES, ENTRY_EXT, index)
                .await
                .map_err(|e| storage_err(StorageIOError::write_logs, e))?;
            inner.entries.remove(&index);
        }
        inner
            .storage
            .sync_dir(ENTRIES)
            .await
            .map_err(|e| storage_err(StorageIOError::write_logs, e))
    }
}

/// Applies committed entries to the fleet state and keeps its snapshots.
/// The state itself is in memory: it is rebuilt at boot from the latest
/// snapshot plus the committed log after it.
#[derive(Clone)]
pub struct StateMachineStore {
    state: FleetStateMachine,
    storage: Arc<RaftStorage>,
}

/// Snapshot file: big-endian u32 metadata length, metadata JSON, state.
fn encode_snapshot(
    meta: &SnapshotMeta<NodeId, BasicNode>,
    data: &[u8],
) -> Result<Vec<u8>, RaftError> {
    let meta = serde_json::to_vec(meta)?;
    let len = u32::try_from(meta.len())
        .map_err(|_| RaftError::Inconsistent("snapshot metadata too large".into()))?;
    let mut out = Vec::with_capacity(4 + meta.len() + data.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(data);
    Ok(out)
}

type DecodedSnapshot = (SnapshotMeta<NodeId, BasicNode>, Vec<u8>);

fn decode_snapshot(file: &[u8]) -> Result<DecodedSnapshot, RaftError> {
    let bad = || RaftError::Inconsistent("truncated snapshot".into());
    let len = u32::from_be_bytes(
        file.get(..4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    );
    let end = 4usize.checked_add(len as usize).ok_or_else(bad)?;
    let meta = serde_json::from_slice(file.get(4..end).ok_or_else(bad)?)?;
    Ok((meta, file[end..].to_vec()))
}

impl StateMachineStore {
    /// Attach `state` to the snapshots in `storage`, loading the latest.
    pub async fn open(
        state: FleetStateMachine,
        storage: Arc<RaftStorage>,
    ) -> Result<Self, RaftError> {
        storage.ensure_dir(SNAPSHOTS).await?;
        let store = Self { state, storage };
        if let Some((meta, data)) = store.latest_snapshot().await? {
            store.replace_state(&meta, &data).await?;
            tracing::info!(
                index = meta.last_log_id.map_or(0, |l| l.index),
                "Restored fleet state from snapshot"
            );
        }
        Ok(store)
    }

    async fn latest_snapshot(&self) -> Result<Option<DecodedSnapshot>, RaftError> {
        let Some(index) = self
            .storage
            .record_indices(SNAPSHOTS, SNAPSHOT_EXT)
            .await?
            .pop()
        else {
            return Ok(None);
        };
        let file = self
            .storage
            .get_record(SNAPSHOTS, SNAPSHOT_EXT, SNAPSHOT_KIND, index)
            .await?
            .ok_or_else(|| RaftError::Inconsistent(format!("snapshot {index} vanished")))?;
        decode_snapshot(&file).map(Some)
    }

    /// Persist a snapshot, then drop every older one.
    pub(super) async fn persist_snapshot(
        &self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        data: &[u8],
    ) -> Result<(), RaftError> {
        let index = meta.last_log_id.map_or(0, |l| l.index);
        let file = encode_snapshot(meta, data)?;
        self.storage
            .put_record(SNAPSHOTS, SNAPSHOT_EXT, SNAPSHOT_KIND, index, &file)
            .await?;
        self.storage.sync_dir(SNAPSHOTS).await?;
        for other in self.storage.record_indices(SNAPSHOTS, SNAPSHOT_EXT).await? {
            if other != index {
                self.storage
                    .remove_record(SNAPSHOTS, SNAPSHOT_EXT, other)
                    .await?;
            }
        }
        self.storage.sync_dir(SNAPSHOTS).await?;
        tracing::info!(index, size = data.len(), "Raft snapshot saved (encrypted)");
        Ok(())
    }

    /// Replace the in-memory state with snapshot `data` described by `meta`.
    async fn replace_state(
        &self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        data: &[u8],
    ) -> Result<(), RaftError> {
        let mut restored: StateMachineInner = serde_json::from_slice(data)?;
        restored.last_applied_log = meta.last_log_id;
        restored.last_applied = meta.last_log_id.map_or(0, |l| l.index);
        restored.last_membership = meta.last_membership.clone();
        *self.state.inner.write().await = restored;
        Ok(())
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
    async fn build_snapshot(&mut self) -> StorageResult<Snapshot<TypeConfig>> {
        let (data, last_log_id, last_membership) = {
            let state = self.state.inner.read().await;
            let data = serde_json::to_vec(&*state)
                .map_err(|e| storage_err(StorageIOError::read_state_machine, e.into()))?;
            (data, state.last_applied_log, state.last_membership.clone())
        };
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: format!(
                "{}-{}",
                last_log_id.map_or(0, |l| l.index),
                uuid::Uuid::new_v4().simple()
            ),
        };
        self.persist_snapshot(&meta, &data)
            .await
            .map_err(|e| storage_err(|a| StorageIOError::write_snapshot(None, a), e))?;
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> StorageResult<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>)> {
        let state = self.state.inner.read().await;
        Ok((state.last_applied_log, state.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> StorageResult<Vec<()>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut state = self.state.inner.write().await;
        let mut applied = Vec::new();
        for entry in entries {
            let index = entry.log_id.index;
            match entry.payload {
                EntryPayload::Blank => {}
                EntryPayload::Normal(proposal) => {
                    FleetStateMachine::apply_locked(
                        &mut state,
                        index,
                        proposal.command,
                        proposal.at,
                    );
                }
                EntryPayload::Membership(membership) => {
                    state.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                }
            }
            state.last_applied = index;
            state.last_applied_log = Some(entry.log_id);
            applied.push(());
        }
        Ok(applied)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(&mut self) -> StorageResult<Box<Cursor<Vec<u8>>>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> StorageResult<()> {
        let data = snapshot.into_inner();
        let sig = || Some(meta.signature());
        // Check it parses before it replaces anything on disk.
        serde_json::from_slice::<StateMachineInner>(&data)
            .map_err(|e| storage_err(|a| StorageIOError::read_snapshot(sig(), a), e.into()))?;
        self.persist_snapshot(meta, &data)
            .await
            .map_err(|e| storage_err(|a| StorageIOError::write_snapshot(sig(), a), e))?;
        self.replace_state(meta, &data)
            .await
            .map_err(|e| storage_err(|a| StorageIOError::read_snapshot(sig(), a), e))
    }

    async fn get_current_snapshot(&mut self) -> StorageResult<Option<Snapshot<TypeConfig>>> {
        let latest = self
            .latest_snapshot()
            .await
            .map_err(|e| storage_err(|a| StorageIOError::read_snapshot(None, a), e))?;
        Ok(latest.map(|(meta, data)| Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        }))
    }
}

/// Raft timing for a fleet control plane: heartbeats every 250ms, a new
/// election after 1–2s without one, and a snapshot every 1000 entries.
pub fn raft_config(cluster: &str) -> Result<openraft::Config, RaftError> {
    openraft::Config {
        cluster_name: cluster.to_string(),
        heartbeat_interval: 250,
        election_timeout_min: 1000,
        election_timeout_max: 2000,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(1000),
        max_in_snapshot_log_to_keep: 100,
        // JSON-encoded, a chunk stays well inside a gRPC message.
        snapshot_max_chunk_size: 1024 * 1024,
        ..Default::default()
    }
    .validate()
    .map_err(|e| RaftError::Inconsistent(format!("raft config: {e}")))
}

/// Move state kept by the pre-consensus single-node log (`raft/log`,
/// `raft/snapshots`) into the consensus store as a snapshot whose
/// membership is just this server, then drop the old layout. Does nothing
/// unless the consensus log is empty and old state exists. Returns whether
/// it migrated.
pub async fn migrate_legacy(
    storage: &Arc<RaftStorage>,
    log: &LogStore,
    machine: &StateMachineStore,
    node_id: NodeId,
    addr: &str,
) -> Result<bool, RaftError> {
    if !log.is_empty().await || storage.is_empty().await? {
        return Ok(false);
    }
    let legacy = FleetStateMachine::with_log(storage.clone());
    legacy.load().await?;
    let index = legacy.last_applied().await;
    // The old log wrote every entry at term 1.
    let log_id = LogId::new(openraft::CommittedLeaderId::new(1, node_id), index);
    let membership = openraft::Membership::new(
        vec![[node_id].into_iter().collect()],
        [(node_id, BasicNode::new(addr))]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
    );
    let meta = SnapshotMeta {
        last_log_id: Some(log_id),
        last_membership: StoredMembership::new(Some(log_id), membership),
        snapshot_id: format!("{index}-migrated"),
    };
    let data = legacy.snapshot().await;
    // Snapshot first, then the log position: a crash in between leaves the
    // old layout in place and the migration runs again.
    machine.persist_snapshot(&meta, &data).await?;
    log.seed_purged(log_id).await?;
    machine.replace_state(&meta, &data).await?;
    storage.remove_legacy_layout().await?;
    tracing::info!(index, "Migrated single-node Raft storage to consensus");
    Ok(true)
}

/// Start this server's Raft node over `storage` and route `state`'s
/// writes through it. Migrates pre-consensus storage first. A node that
/// was never initialized forms a cluster of `members` when it is the only
/// one; otherwise it waits to be joined (see `ekafleet raft`).
pub async fn boot<N: openraft::RaftNetworkFactory<TypeConfig>>(
    state: &FleetStateMachine,
    storage: Arc<RaftStorage>,
    node_id: NodeId,
    addr: &str,
    members: BTreeMap<NodeId, BasicNode>,
    network: N,
    config: openraft::Config,
) -> Result<Raft, RaftError> {
    let log = LogStore::open(storage.clone()).await?;
    let machine = StateMachineStore::open(state.clone(), storage.clone()).await?;
    migrate_legacy(&storage, &log, &machine, node_id, addr).await?;
    let raft = Raft::new(node_id, Arc::new(config), network, log, machine)
        .await
        .map_err(|e| RaftError::Consensus(e.to_string()))?;
    let initialized = raft
        .is_initialized()
        .await
        .map_err(|e| RaftError::Consensus(e.to_string()))?;
    if !initialized && members.len() == 1 && members.contains_key(&node_id) {
        raft.initialize(members)
            .await
            .map_err(|e| RaftError::Consensus(e.to_string()))?;
        tracing::info!(node_id, "Formed a single-server Raft cluster");
    }
    state.attach(raft.clone());
    Ok(raft)
}

/// Wait until this node leads and has applied every committed entry, so
/// state reads are current. Gives up after `timeout`.
pub async fn wait_leading(raft: &Raft, timeout: std::time::Duration) -> Result<(), RaftError> {
    let id = raft.metrics().borrow().id;
    raft.wait(Some(timeout))
        .metrics(|m| m.current_leader == Some(id), "this node leads")
        .await
        .map_err(|e| RaftError::Consensus(e.to_string()))?;
    raft.ensure_linearizable()
        .await
        .map_err(|e| RaftError::Consensus(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod testing {
    //! An in-process network joining [`Raft`] nodes for tests.

    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable};
    use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
    use openraft::raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    };

    use super::{BasicNode, NodeId, Raft, TypeConfig};

    /// Routes RPCs to the registered nodes; an absent node is unreachable.
    #[derive(Clone, Default)]
    pub struct Router {
        nodes: Arc<Mutex<BTreeMap<NodeId, Raft>>>,
    }

    impl Router {
        pub fn add(&self, id: NodeId, raft: Raft) {
            self.nodes.lock().unwrap().insert(id, raft);
        }

        pub fn remove(&self, id: NodeId) -> Option<Raft> {
            self.nodes.lock().unwrap().remove(&id)
        }

        // The network trait's error type, as is.
        #[allow(clippy::result_large_err)]
        fn get<E: std::error::Error>(
            &self,
            id: NodeId,
        ) -> Result<Raft, RPCError<NodeId, BasicNode, E>> {
            self.nodes.lock().unwrap().get(&id).cloned().ok_or_else(|| {
                RPCError::Unreachable(Unreachable::new(&std::io::Error::other("down")))
            })
        }
    }

    pub struct Connection {
        router: Router,
        target: NodeId,
    }

    impl RaftNetworkFactory<TypeConfig> for Router {
        type Network = Connection;

        async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Connection {
            Connection {
                router: self.clone(),
                target,
            }
        }
    }

    impl RaftNetwork<TypeConfig> for Connection {
        async fn append_entries(
            &mut self,
            rpc: AppendEntriesRequest<TypeConfig>,
            _option: RPCOption,
        ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>>
        {
            let raft = self.router.get(self.target)?;
            raft.append_entries(rpc)
                .await
                .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
        }

        async fn install_snapshot(
            &mut self,
            rpc: InstallSnapshotRequest<TypeConfig>,
            _option: RPCOption,
        ) -> Result<
            InstallSnapshotResponse<NodeId>,
            RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
        > {
            let raft = self.router.get(self.target)?;
            raft.install_snapshot(rpc)
                .await
                .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
        }

        async fn vote(
            &mut self,
            rpc: VoteRequest<NodeId>,
            _option: RPCOption,
        ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
            let raft = self.router.get(self.target)?;
            raft.vote(rpc)
                .await
                .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
        }
    }

    /// Election timings for tests: leaders emerge in well under a second.
    pub fn fast_config() -> std::sync::Arc<openraft::Config> {
        std::sync::Arc::new(
            openraft::Config {
                heartbeat_interval: 50,
                election_timeout_min: 200,
                election_timeout_max: 400,
                snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(5),
                max_in_snapshot_log_to_keep: 0,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        )
    }

    /// An uninitialized node stored in `dir`, reachable through `router`.
    pub async fn node(
        router: &Router,
        id: NodeId,
        dir: &std::path::Path,
    ) -> (Raft, crate::raft::state::FleetStateMachine) {
        let storage = Arc::new(crate::raft::storage::RaftStorage::new(dir, &[7u8; 32]));
        storage.initialize().await.unwrap();
        let log = super::LogStore::open(storage.clone()).await.unwrap();
        let state = crate::raft::state::FleetStateMachine::new();
        let machine = super::StateMachineStore::open(state.clone(), storage)
            .await
            .unwrap();
        let raft = Raft::new(id, fast_config(), router.clone(), log, machine)
            .await
            .unwrap();
        router.add(id, raft.clone());
        (raft, state)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::testing::{Router, fast_config};
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    async fn stores(dir: &std::path::Path) -> (Arc<RaftStorage>, LogStore, StateMachineStore) {
        let storage = Arc::new(RaftStorage::new(dir, &key()));
        storage.initialize().await.unwrap();
        let log = LogStore::open(storage.clone()).await.unwrap();
        let machine = StateMachineStore::open(FleetStateMachine::new(), storage.clone())
            .await
            .unwrap();
        (storage, log, machine)
    }

    struct Builder;

    impl openraft::testing::StoreBuilder<TypeConfig, LogStore, StateMachineStore, tempfile::TempDir>
        for Builder
    {
        async fn build(&self) -> StorageResult<(tempfile::TempDir, LogStore, StateMachineStore)> {
            let dir = tempfile::tempdir().unwrap();
            let (_, log, machine) = stores(dir.path()).await;
            Ok((dir, log, machine))
        }
    }

    #[test]
    fn storage_passes_the_openraft_suite() {
        openraft::testing::Suite::test_all(Builder).unwrap();
    }

    struct Node {
        raft: Raft,
        state: FleetStateMachine,
    }

    async fn start(router: &Router, id: NodeId, dir: &std::path::Path) -> Node {
        let (_, log, machine) = stores(dir).await;
        let state = machine.state.clone();
        let raft = Raft::new(id, fast_config(), router.clone(), log, machine)
            .await
            .unwrap();
        router.add(id, raft.clone());
        Node { raft, state }
    }

    fn put(key: &str, value: &str) -> Proposal {
        Proposal::new(Command::KvPut {
            key: key.into(),
            value: value.as_bytes().to_vec(),
        })
    }

    async fn leader(nodes: &BTreeMap<NodeId, Node>) -> NodeId {
        let any = nodes.values().next().unwrap();
        any.raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |m| m.current_leader.is_some_and(|l| nodes.contains_key(&l)),
                "leader",
            )
            .await
            .unwrap()
            .current_leader
            .unwrap()
    }

    async fn wait_leader(raft: &Raft, id: NodeId) {
        raft.wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader == Some(id), "leader")
            .await
            .unwrap();
    }

    async fn wait_value(node: &Node, key: &str, value: &str) {
        for _ in 0..100 {
            if node.state.kv_get(key).await.as_deref() == Some(value.as_bytes()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{key} never became {value}");
    }

    #[tokio::test]
    async fn a_cluster_replicates_fails_over_and_recovers_from_disk() {
        let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
        let router = Router::default();
        let mut nodes = BTreeMap::new();
        for (i, dir) in dirs.iter().enumerate() {
            let id = i as NodeId + 1;
            nodes.insert(id, start(&router, id, dir.path()).await);
        }
        let members: BTreeMap<NodeId, BasicNode> = (1..=3)
            .map(|id| (id, BasicNode::new(format!("node-{id}"))))
            .collect();
        nodes[&1].raft.initialize(members).await.unwrap();

        // Writes through the leader reach every replica, past snapshots.
        let first = leader(&nodes).await;
        for i in 0..12 {
            nodes[&first]
                .raft
                .client_write(put(&format!("k{i}"), "v"))
                .await
                .unwrap();
        }
        for node in nodes.values() {
            wait_value(node, "k11", "v").await;
        }

        // A follower refuses writes and names the leader.
        let follower = *nodes.keys().find(|id| **id != first).unwrap();
        let err = nodes[&follower]
            .raft
            .client_write(put("x", "y"))
            .await
            .unwrap_err();
        assert_eq!(
            err.forward_to_leader().and_then(|f| f.leader_id),
            Some(first)
        );

        // The leader goes away; the others elect a new one and carry on.
        router.remove(first);
        let old = nodes.remove(&first).unwrap();
        old.raft.shutdown().await.unwrap();
        drop(old);
        let second = leader(&nodes).await;
        assert_ne!(second, first);
        nodes[&second]
            .raft
            .client_write(put("after", "failover"))
            .await
            .unwrap();

        // The old leader restarts from its disk and catches up.
        let dir = &dirs[(first - 1) as usize];
        let back = start(&router, first, dir.path()).await;
        wait_value(&back, "k11", "v").await;
        wait_value(&back, "after", "failover").await;
        nodes.insert(first, back);
        for node in nodes.values() {
            node.raft.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn applied_state_is_rebuilt_on_restart_with_proposal_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let router = Router::default();
        let node = start(&router, 1, dir.path()).await;
        node.raft
            .initialize(BTreeMap::from([(1, BasicNode::new("solo"))]))
            .await
            .unwrap();
        wait_leader(&node.raft, 1).await;
        let node = node.raft;
        let proposal = Proposal {
            command: Command::TrackCloudInstance {
                instance_id: "i-1".into(),
                provider: "aws".into(),
                pool: "p".into(),
                private_ip: None,
                created_at: 1,
            },
            at: 1,
        };
        node.client_write(proposal).await.unwrap();
        node.client_write(Proposal {
            command: Command::UpdateCloudInstance {
                instance_id: "i-1".into(),
                fleet_node_id: "n".into(),
            },
            at: 42,
        })
        .await
        .unwrap();
        node.client_write(put("k", "v")).await.unwrap();
        router.remove(1);
        node.shutdown().await.unwrap();
        drop(node);

        let again = start(&router, 1, dir.path()).await;
        wait_value(&again, "k", "v").await;
        let instance = again.state.cloud_instances().await.remove("i-1").unwrap();
        assert_eq!(instance.joined_at, Some(42));
        again.raft.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn legacy_single_node_storage_migrates_into_consensus() {
        let dir = tempfile::tempdir().unwrap();
        {
            let storage = Arc::new(RaftStorage::new(dir.path(), &key()));
            storage.initialize().await.unwrap();
            let legacy = FleetStateMachine::with_log(storage);
            legacy
                .apply_next(Command::KvPut {
                    key: "old".into(),
                    value: b"state".to_vec(),
                })
                .await
                .unwrap();
            legacy.checkpoint().await.unwrap();
            legacy
                .apply_next(Command::KvPut {
                    key: "later".into(),
                    value: b"entry".to_vec(),
                })
                .await
                .unwrap();
        }

        let (storage, log, machine) = stores(dir.path()).await;
        assert!(
            migrate_legacy(&storage, &log, &machine, 1, "solo")
                .await
                .unwrap()
        );
        assert!(!dir.path().join("raft/log").exists());
        assert!(
            !migrate_legacy(&storage, &log, &machine, 1, "solo")
                .await
                .unwrap()
        );

        // The migrated server leads its one-member cluster without being
        // initialized again, and keeps both the snapshot and the later entry.
        let router = Router::default();
        let state = machine.state.clone();
        let raft = Raft::new(1, fast_config(), router.clone(), log, machine)
            .await
            .unwrap();
        router.add(1, raft.clone());
        wait_leader(&raft, 1).await;
        assert_eq!(state.kv_get("old").await.as_deref(), Some(&b"state"[..]));
        assert_eq!(state.kv_get("later").await.as_deref(), Some(&b"entry"[..]));
        raft.client_write(put("new", "write")).await.unwrap();
        assert_eq!(state.kv_get("new").await.as_deref(), Some(&b"write"[..]));
        raft.shutdown().await.unwrap();
    }
}
