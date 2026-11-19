use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::RaftError;
use super::consensus::{Proposal, Raft};
use super::storage::{LogEntry, RaftStorage};

/// Term recorded in log entries. Single-node until consensus lands.
const TERM: u64 = 1;

/// Fleet state machine for Raft consensus.
/// Earlier versions kept per static secret, for `ekafleet secret rollback`.
pub const SECRET_HISTORY: usize = 9;

/// service → name → earlier (version, sealed value), oldest first.
pub type SecretHistory = HashMap<String, HashMap<String, Vec<(u64, Vec<u8>)>>>;

/// Stores all persistent fleet state: deployments, secrets, DNS, scheduling plans.
#[derive(Clone)]
pub struct FleetStateMachine {
    pub(super) inner: Arc<RwLock<StateMachineInner>>,
    /// Durable log. When set, every command is persisted before it is
    /// applied, so an acknowledged write survives a crash.
    log: Option<Arc<RaftStorage>>,
    /// Consensus. Once attached, commands are proposed to the cluster and
    /// applied by [`super::consensus::StateMachineStore`] when committed;
    /// `log` is then unused.
    raft: Arc<std::sync::OnceLock<Raft>>,
    /// Serializes proposals, so a helper's check and its write see no
    /// other write from this server in between.
    propose: Arc<Mutex<()>>,
    /// The ACL tokens as of the latest write, readable without awaiting
    /// (the gRPC interceptor authenticates synchronously).
    acl: AclView,
}

/// ACL token digest → entry; see [`crate::server::rbac::TokenStore`].
pub type AclTokens = BTreeMap<String, crate::server::rbac::TokenEntry>;

/// A synchronously readable copy of the state's ACL tokens.
pub type AclView = Arc<std::sync::RwLock<Arc<AclTokens>>>;

/// A join token, by the hex SHA-256 of the token (never the token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinTokenRecord {
    /// The only node name it attests.
    pub node_name: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// When it was used; consumed tokens are kept until they would have
    /// expired, so replays are reported as such.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<u64>,
}

/// Write access to the state; refreshes the [`AclView`] when dropped.
pub(super) struct StateWrite<'a> {
    guard: RwLockWriteGuard<'a, StateMachineInner>,
    acl: &'a AclView,
}

impl std::ops::Deref for StateWrite<'_> {
    type Target = StateMachineInner;
    fn deref(&self) -> &StateMachineInner {
        &self.guard
    }
}

impl std::ops::DerefMut for StateWrite<'_> {
    fn deref_mut(&mut self) -> &mut StateMachineInner {
        &mut self.guard
    }
}

impl Drop for StateWrite<'_> {
    fn drop(&mut self) {
        let mut view = self.acl.write().unwrap_or_else(|e| e.into_inner());
        if **view != self.guard.acl_tokens {
            *view = Arc::new(self.guard.acl_tokens.clone());
        }
    }
}

/// One proposer's exclusive turn: read state, then commit. `commit` takes
/// `&mut self`, so the borrow checker rejects holding a read guard across
/// it (applying needs the write lock).
struct Turn<'a> {
    machine: &'a FleetStateMachine,
    _turn: MutexGuard<'a, ()>,
}

impl Turn<'_> {
    async fn read(&self) -> RwLockReadGuard<'_, StateMachineInner> {
        self.machine.inner.read().await
    }

    async fn commit(&mut self, command: Command) -> Result<u64, RaftError> {
        self.machine.commit(command).await
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct StateMachineInner {
    /// Current deployed services and their placements
    deployments: HashMap<String, DeploymentState>,
    /// Static secrets: service → name → value sealed under the fleet key
    /// (AAD bound to service and name).
    secrets: HashMap<String, HashMap<String, Vec<u8>>>,
    /// service → name → last version stored. Kept after a delete so a value
    /// set again gets a higher version than any agent has seen.
    #[serde(default)]
    secret_versions: HashMap<String, HashMap<String, u64>>,
    /// service → name → earlier (version, sealed value), oldest first; at
    /// most [`SECRET_HISTORY`] per secret. Dropped with the secret.
    #[serde(default)]
    secret_history: SecretHistory,
    /// Transit keys by name; each version's key is sealed under the fleet
    /// key (scope [`crate::secrets::transit::SEAL_SCOPE`]).
    #[serde(default)]
    transit_keys: BTreeMap<String, TransitKey>,
    /// Dynamic secrets' current users: service → name → lease. Their
    /// credentials are stored (sealed) in `secrets` like a static value.
    #[serde(default)]
    dynamic_leases: BTreeMap<String, BTreeMap<String, DynamicLease>>,
    /// Database users still to drop.
    #[serde(default)]
    retired_users: Vec<RetiredUser>,
    /// DNS zone data
    dns_zones: HashMap<String, Vec<DnsEntry>>,
    /// General-purpose key-value store (used for volume tracking, etc.)
    #[serde(default)]
    kv: HashMap<String, Vec<u8>>,
    /// Cloud-provisioned machine instances tracked across the fleet.
    #[serde(default)]
    cloud_instances: HashMap<String, TrackedCloudInstance>,
    /// Per-namespace IP allocations: namespace → (holder → assigned IP),
    /// where the holder is one replica (see [`namespace_ip_holder`]).
    /// Server-assigned so IPs are unique within a namespace across all nodes.
    #[serde(default)]
    namespace_ips: HashMap<String, HashMap<String, Ipv4Addr>>,
    /// Per-namespace subnets: namespace → third octet of `10.200.X.0/24`,
    /// also used as the VXLAN VNI. Unique across namespaces so tenants never
    /// share a subnet or an overlay segment.
    #[serde(default)]
    namespace_subnets: HashMap<String, u8>,
    /// WireGuard mesh addresses: node → address in [`MESH_NETWORK`]/16.
    #[serde(default)]
    mesh_ips: HashMap<String, Ipv4Addr>,
    /// Applied fleet configurations, oldest first; the last one is what the
    /// server reconciles toward. At most [`MAX_CONFIG_REVISIONS`].
    #[serde(default)]
    config_revisions: Vec<ConfigRevision>,
    /// Last applied log index
    pub(super) last_applied: u64,
    /// Consensus position of `last_applied` (absent before consensus).
    #[serde(default)]
    pub(super) last_applied_log: Option<openraft::LogId<u64>>,
    /// Cluster membership as of the last applied membership entry.
    #[serde(default)]
    pub(super) last_membership: openraft::StoredMembership<u64, openraft::BasicNode>,
    /// API-created ACL tokens, by digest.
    #[serde(default)]
    acl_tokens: AclTokens,
    /// Join tokens, by digest.
    #[serde(default)]
    join_tokens: BTreeMap<String, JoinTokenRecord>,
    /// Identifies the current fleet key without revealing it (see
    /// `server::secrets::key_check`), so a server can tell its own copy
    /// is out of date.
    #[serde(default)]
    fleet_key_check: Option<Vec<u8>>,
    /// The current fleet key's version: 1 when its check was first
    /// recorded, one more with each rotation.
    #[serde(default)]
    fleet_key_version: u64,
}

/// A transit encryption key: its namespace and every version, oldest
/// first (version N at index N-1), each sealed under the fleet key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitKey {
    pub namespace: String,
    pub versions: Vec<Vec<u8>>,
}

/// The database user currently backing a dynamic secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicLease {
    pub engine: String,
    pub role: String,
    pub username: String,
    pub issued_at: u64,
    /// When the database stops accepting the user's password.
    pub expires_at: u64,
}

impl DynamicLease {
    /// When to issue a replacement: two thirds of the way through, leaving
    /// the last third for services to pick it up before this one expires.
    pub fn renew_at(&self) -> u64 {
        self.issued_at + self.expires_at.saturating_sub(self.issued_at) * 2 / 3
    }
}

/// A database user replaced or no longer declared, to drop at `drop_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredUser {
    pub engine: String,
    pub username: String,
    pub drop_at: u64,
}

/// A cloud-provisioned machine instance tracked in Raft state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedCloudInstance {
    pub cloud_instance_id: String,
    pub provider: String,
    pub pool: String,
    pub private_ip: Option<String>,
    pub created_at: u64,
    /// Set when the agent running on this instance joins the fleet.
    pub fleet_node_id: Option<String>,
    /// Set when the agent joins.
    pub joined_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentState {
    pub service_name: String,
    pub store_path: String,
    pub placements: Vec<PlacementRecord>,
    /// Bumped each time `store_path` changes (placement-only changes keep it).
    pub generation: u64,
    pub deployed_at: u64,
    /// Earlier revisions, oldest first, at most [`MAX_DEPLOYMENT_HISTORY`].
    #[serde(default)]
    pub history: Vec<DeploymentRevision>,
}

/// A previously deployed revision of a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRevision {
    pub generation: u64,
    pub store_path: String,
    pub deployed_at: u64,
}

/// Revisions kept per service for rollback.
pub const MAX_DEPLOYMENT_HISTORY: usize = 10;

/// Number of applied fleet configurations kept for `ekafleet rollback`.
pub const MAX_CONFIG_REVISIONS: usize = 10;

/// One applied fleet configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRevision {
    /// Starts at 1 and increases with every apply or rollback.
    pub revision: u64,
    /// The flake reference the configuration was evaluated from.
    pub flake_ref: String,
    /// The evaluated configuration, exactly as `nix eval --json` printed it.
    pub config_json: String,
    pub applied_at: u64,
    /// Principal that applied it, as recorded in the audit log.
    pub applied_by: String,
    /// Set when this revision re-applies an earlier one.
    pub rollback_of: Option<u64>,
    /// Store paths each service needs, built by the server at apply time.
    #[serde(default)]
    pub closures: BTreeMap<String, Vec<String>>,
    /// Container image of each service, pinned to a digest at apply time.
    #[serde(default)]
    pub images: BTreeMap<String, String>,
}

impl ConfigRevision {
    /// The recorded configuration with each service's built store paths.
    pub fn config(&self) -> Result<crate::config::FleetConfig, serde_json::Error> {
        let mut config: crate::config::FleetConfig = serde_json::from_str(&self.config_json)?;
        for (name, service) in &mut config.services {
            if let Some(paths) = self.closures.get(name) {
                service.store_paths = paths.clone();
            }
            if let (Some(image), Some(container)) =
                (self.images.get(name), service.container.as_mut())
            {
                container.image = image.clone();
            }
        }
        Ok(config)
    }
}

impl DeploymentState {
    /// The revision recorded as `generation`, current or historical.
    pub fn revision(&self, generation: u64) -> Option<DeploymentRevision> {
        if generation == self.generation {
            return Some(DeploymentRevision {
                generation,
                store_path: self.store_path.clone(),
                deployed_at: self.deployed_at,
            });
        }
        self.history
            .iter()
            .find(|r| r.generation == generation)
            .cloned()
    }

    /// Whether recording `store_path` on `placements` would change anything.
    pub fn differs_from(&self, store_path: &str, placements: &[PlacementRecord]) -> bool {
        let mut current = self.placements.clone();
        let mut new = placements.to_vec();
        current.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
        new.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
        self.store_path != store_path || current != new
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRecord {
    pub instance_id: String,
    pub machine_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsEntry {
    name: String,
    record_type: String,
    values: Vec<String>,
    ttl: u32,
}

/// Commands that can be applied to the state machine via Raft log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// Record a new desired fleet configuration (apply or rollback).
    ApplyConfig {
        flake_ref: String,
        config_json: String,
        applied_at: u64,
        applied_by: String,
        rollback_of: Option<u64>,
        #[serde(default)]
        closures: BTreeMap<String, Vec<String>>,
        #[serde(default)]
        images: BTreeMap<String, String>,
    },
    Deploy {
        service_name: String,
        store_path: String,
        placements: Vec<PlacementRecord>,
    },
    Undeploy {
        service_name: String,
    },
    PutSecret {
        service_name: String,
        secret_name: String,
        encrypted_value: Vec<u8>,
    },
    DeleteSecret {
        service_name: String,
        secret_name: String,
    },
    /// Swap every sealed value for one re-encrypted under a new fleet key,
    /// keeping versions (fleet key rotation).
    ResealSecrets {
        secrets: HashMap<String, HashMap<String, Vec<u8>>>,
        /// Earlier versions, resealed too: service → name → version → value.
        #[serde(default)]
        history: HashMap<String, HashMap<String, HashMap<u64, Vec<u8>>>>,
        /// Transit keys, resealed: name → every version.
        #[serde(default)]
        transit: HashMap<String, Vec<Vec<u8>>>,
        /// The check value of the key they are now sealed under.
        #[serde(default)]
        key_check: Option<Vec<u8>>,
    },
    /// Record the check value of the fleet key (first set by a leader that
    /// finds none).
    SetFleetKeyCheck {
        check: Vec<u8>,
    },
    /// Create, rotate (a version added) or replace a transit key.
    PutTransitKey {
        name: String,
        key: TransitKey,
    },
    DeleteTransitKey {
        name: String,
    },
    /// Store new credentials for a dynamic secret (a new version, without
    /// history); the user they replace is retired at its expiry.
    IssueDynamicSecret {
        service_name: String,
        secret_name: String,
        encrypted_value: Vec<u8>,
        lease: DynamicLease,
    },
    /// Remove a dynamic secret's value and lease, retiring its user at
    /// `drop_at`.
    RetireDynamicSecret {
        service_name: String,
        secret_name: String,
        drop_at: u64,
    },
    /// A retired database user was dropped (or can never be).
    ForgetRetiredUser {
        engine: String,
        username: String,
    },
    UpdateDns {
        zone: String,
        entries: Vec<(String, String, Vec<String>, u32)>,
    },
    KvPut {
        key: String,
        value: Vec<u8>,
    },
    KvDelete {
        key: String,
    },
    TrackCloudInstance {
        instance_id: String,
        provider: String,
        pool: String,
        private_ip: Option<String>,
        created_at: u64,
    },
    UpdateCloudInstance {
        instance_id: String,
        fleet_node_id: String,
    },
    UntrackCloudInstance {
        instance_id: String,
    },
    AllocateNamespaceSubnet {
        namespace: String,
        octet: u8,
    },
    AllocateNamespaceIp {
        namespace: String,
        #[serde(alias = "service_name")]
        holder: String,
        ip: Ipv4Addr,
    },
    /// Releases the namespace subnet too once its last IP is released.
    ReleaseNamespaceIp {
        namespace: String,
        #[serde(alias = "service_name")]
        holder: String,
    },
    AllocateMeshIp {
        node_id: String,
        ip: Ipv4Addr,
    },
    ReleaseMeshIp {
        node_id: String,
    },
    /// Replace the fleet state with an operator backup (JSON of the whole
    /// state, as `Snapshot` returns it). Consensus bookkeeping is kept.
    RestoreState {
        data: Vec<u8>,
    },
    /// Register (or replace) the ACL token with digest `key`.
    AclTokenPut {
        key: String,
        entry: crate::server::rbac::TokenEntry,
    },
    AclTokenRevoke {
        key: String,
    },
    /// A join token for `node_name`, created when proposed.
    JoinTokenPut {
        hash: String,
        node_name: String,
        expires_at: u64,
    },
    /// Mark a join token used, when proposed.
    JoinTokenConsume {
        hash: String,
    },
    /// Undo [`Command::JoinTokenConsume`].
    JoinTokenRelease {
        hash: String,
    },
    /// Drop join tokens and ACL tokens expired when proposed.
    ExpireTokens,
}

/// The WireGuard mesh network, `10.100.0.0/16`.
pub const MESH_NETWORK: Ipv4Addr = Ipv4Addr::new(10, 100, 0, 0);
pub const MESH_PREFIX_LEN: u8 = 16;

/// Seconds since the Unix epoch.
pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Allocation key for one replica of a service in a namespace network.
pub fn namespace_ip_holder(service_name: &str, node: &str) -> String {
    format!("{service_name}@{node}")
}

impl Default for FleetStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl FleetStateMachine {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StateMachineInner::default())),
            log: None,
            raft: Default::default(),
            propose: Default::default(),
            acl: Default::default(),
        }
    }

    /// A state machine that persists every command to `storage` before
    /// applying it. Load existing state first with [`Self::load`].
    pub fn with_log(storage: Arc<RaftStorage>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StateMachineInner::default())),
            log: Some(storage),
            raft: Default::default(),
            propose: Default::default(),
            acl: Default::default(),
        }
    }

    /// Restore the persisted state: the latest snapshot, then every log
    /// entry after it. Any unreadable file is an error; callers must not
    /// carry on with partial state. Storage written under the legacy key is
    /// rewritten under the current one.
    pub async fn load(&self) -> Result<(), RaftError> {
        let Some(storage) = &self.log else {
            return Ok(());
        };
        let snapshot_index = match storage.load_latest_snapshot().await? {
            Some((index, data)) => {
                self.restore(&data).await?;
                tracing::info!(snapshot_index = index, "Restored Raft state from snapshot");
                index
            }
            None => 0,
        };
        let entries = storage.read_log_from(snapshot_index + 1).await?;
        let replayed = entries.len();
        for entry in entries {
            self.apply(entry.index, entry.command).await;
        }
        if replayed > 0 {
            tracing::info!(
                replayed,
                from_index = snapshot_index + 1,
                "Replayed Raft log entries"
            );
        }
        if storage.used_legacy_key() {
            let state = self.inner.read().await;
            let data = serde_json::to_vec(&*state)?;
            storage.rewrite(state.last_applied, &data).await?;
            tracing::warn!(
                index = state.last_applied,
                "Re-encrypted Raft storage from the fleet key to the dedicated Raft key"
            );
        }
        Ok(())
    }

    /// Apply a command to the state machine, allocating the next log index
    /// atomically under the state lock. This keeps indices globally monotonic
    /// across all callers (deployments, secrets, cloud/image trackers) so the
    /// `last_applied` dedup guard cannot silently drop a write from one caller
    /// because another caller advanced the index first. Returns the index used.
    ///
    /// After a snapshot restore, `last_applied` already reflects the restored
    /// state, so newly allocated indices naturally continue past it.
    ///
    /// With a log attached the command is persisted first; if that fails
    /// nothing is applied and the error is returned.
    pub async fn apply_next(&self, command: Command) -> Result<u64, RaftError> {
        self.turn().await.commit(command).await
    }

    /// Route every later write through consensus. The state is then
    /// applied by the Raft state machine store sharing this state.
    pub fn attach(&self, raft: Raft) {
        if self.raft.set(raft).is_err() {
            tracing::warn!("Raft already attached to the fleet state");
        }
    }

    /// The attached consensus, if any.
    pub fn raft(&self) -> Option<&Raft> {
        self.raft.get()
    }

    /// Exclusive write access to the state.
    pub(super) async fn write(&self) -> StateWrite<'_> {
        StateWrite {
            guard: self.inner.write().await,
            acl: &self.acl,
        }
    }

    /// The ACL tokens, read without awaiting.
    pub fn acl_tokens(&self) -> Arc<AclTokens> {
        self.acl.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn turn(&self) -> Turn<'_> {
        Turn {
            machine: self,
            _turn: self.propose.lock().await,
        }
    }

    /// Propose `command` (or, without consensus, persist and apply it) and
    /// return its index once it is applied here.
    async fn commit(&self, command: Command) -> Result<u64, RaftError> {
        if let Some(raft) = self.raft.get() {
            let response = raft
                .client_write(Proposal::new(command))
                .await
                .map_err(RaftError::from_client_write)?;
            return Ok(response.log_id.index);
        }
        let mut state = self.write().await;
        self.commit_locked(&mut state, command).await
    }

    /// Persist (when a log is attached) and apply `command` at the next
    /// index while the caller holds the write lock.
    async fn commit_locked(
        &self,
        state: &mut StateMachineInner,
        command: Command,
    ) -> Result<u64, RaftError> {
        let index = state.last_applied + 1;
        if let Some(log) = &self.log {
            log.append_log(&LogEntry {
                index,
                term: TERM,
                command: command.clone(),
            })
            .await?;
        }
        Self::apply_locked(state, index, command, unix_now());
        Ok(index)
    }

    /// Apply a command to the state machine at an explicit index (used when
    /// replaying a persisted log at boot).
    pub async fn apply(&self, index: u64, command: Command) {
        let mut state = self.write().await;
        if index <= state.last_applied {
            return; // Already applied
        }
        Self::apply_locked(&mut state, index, command, unix_now());
    }

    /// Apply `command` as entry `index`, proposed at `now` (Unix seconds).
    /// Deterministic, so every replica and every replay agrees.
    pub(super) fn apply_locked(
        state: &mut StateMachineInner,
        index: u64,
        command: Command,
        now: u64,
    ) {
        match command {
            Command::Deploy {
                service_name,
                store_path,
                placements,
            } => {
                match state.deployments.get_mut(&service_name) {
                    // Same revision, new placements (scale, reschedule).
                    Some(current) if current.store_path == store_path => {
                        current.placements = placements;
                    }
                    Some(current) => {
                        current.history.push(DeploymentRevision {
                            generation: current.generation,
                            store_path: std::mem::replace(&mut current.store_path, store_path),
                            deployed_at: current.deployed_at,
                        });
                        let excess = current.history.len().saturating_sub(MAX_DEPLOYMENT_HISTORY);
                        current.history.drain(..excess);
                        current.generation += 1;
                        current.deployed_at = now;
                        current.placements = placements;
                    }
                    None => {
                        state.deployments.insert(
                            service_name.clone(),
                            DeploymentState {
                                service_name,
                                store_path,
                                placements,
                                generation: 1,
                                deployed_at: now,
                                history: Vec::new(),
                            },
                        );
                    }
                }
            }
            Command::Undeploy { service_name } => {
                state.deployments.remove(&service_name);
            }
            Command::PutSecret {
                service_name,
                secret_name,
                encrypted_value,
            } => {
                let version = state
                    .secret_versions
                    .entry(service_name.clone())
                    .or_default()
                    .entry(secret_name.clone())
                    .or_default();
                let previous_version = *version;
                *version += 1;
                let previous = state
                    .secrets
                    .entry(service_name.clone())
                    .or_default()
                    .insert(secret_name.clone(), encrypted_value);
                if let Some(previous) = previous {
                    let history = state
                        .secret_history
                        .entry(service_name)
                        .or_default()
                        .entry(secret_name)
                        .or_default();
                    history.push((previous_version, previous));
                    let excess = history.len().saturating_sub(SECRET_HISTORY);
                    history.drain(..excess);
                }
            }
            Command::DeleteSecret {
                service_name,
                secret_name,
            } => {
                if let Some(svc) = state.secrets.get_mut(&service_name) {
                    svc.remove(&secret_name);
                    if svc.is_empty() {
                        state.secrets.remove(&service_name);
                    }
                }
                if let Some(svc) = state.secret_history.get_mut(&service_name) {
                    svc.remove(&secret_name);
                    if svc.is_empty() {
                        state.secret_history.remove(&service_name);
                    }
                }
            }
            Command::SetFleetKeyCheck { check } => {
                if state.fleet_key_check.as_ref() != Some(&check) {
                    state.fleet_key_version = state.fleet_key_version.max(1);
                }
                state.fleet_key_check = Some(check);
            }
            Command::ResealSecrets {
                secrets,
                history,
                transit,
                key_check,
            } => {
                if key_check.is_some() && key_check != state.fleet_key_check {
                    state.fleet_key_version = state.fleet_key_version.max(1) + 1;
                    state.fleet_key_check = key_check;
                }
                for (name, versions) in transit {
                    if let Some(key) = state.transit_keys.get_mut(&name)
                        && key.versions.len() == versions.len()
                    {
                        key.versions = versions;
                    }
                }
                for (service, values) in secrets {
                    if let Some(stored) = state.secrets.get_mut(&service) {
                        for (name, sealed) in values {
                            if let Some(slot) = stored.get_mut(&name) {
                                *slot = sealed;
                            }
                        }
                    }
                }
                for (service, values) in history {
                    let Some(stored) = state.secret_history.get_mut(&service) else {
                        continue;
                    };
                    for (name, mut versions) in values {
                        for (version, sealed) in stored.get_mut(&name).into_iter().flatten() {
                            if let Some(resealed) = versions.remove(version) {
                                *sealed = resealed;
                            }
                        }
                    }
                }
            }
            Command::PutTransitKey { name, key } => {
                state.transit_keys.insert(name, key);
            }
            Command::DeleteTransitKey { name } => {
                state.transit_keys.remove(&name);
            }
            Command::IssueDynamicSecret {
                service_name,
                secret_name,
                encrypted_value,
                lease,
            } => {
                *state
                    .secret_versions
                    .entry(service_name.clone())
                    .or_default()
                    .entry(secret_name.clone())
                    .or_default() += 1;
                state
                    .secrets
                    .entry(service_name.clone())
                    .or_default()
                    .insert(secret_name.clone(), encrypted_value);
                let previous = state
                    .dynamic_leases
                    .entry(service_name)
                    .or_default()
                    .insert(secret_name, lease);
                if let Some(previous) = previous {
                    state.retired_users.push(RetiredUser {
                        engine: previous.engine,
                        username: previous.username,
                        drop_at: previous.expires_at,
                    });
                }
            }
            Command::RetireDynamicSecret {
                service_name,
                secret_name,
                drop_at,
            } => {
                if let Some(svc) = state.secrets.get_mut(&service_name) {
                    svc.remove(&secret_name);
                    if svc.is_empty() {
                        state.secrets.remove(&service_name);
                    }
                }
                let lease = state
                    .dynamic_leases
                    .get_mut(&service_name)
                    .and_then(|svc| svc.remove(&secret_name));
                if state
                    .dynamic_leases
                    .get(&service_name)
                    .is_some_and(BTreeMap::is_empty)
                {
                    state.dynamic_leases.remove(&service_name);
                }
                if let Some(lease) = lease {
                    state.retired_users.push(RetiredUser {
                        engine: lease.engine,
                        username: lease.username,
                        drop_at,
                    });
                }
            }
            Command::ForgetRetiredUser { engine, username } => {
                state
                    .retired_users
                    .retain(|u| !(u.engine == engine && u.username == username));
            }
            Command::UpdateDns { zone, entries } => {
                let dns_entries: Vec<DnsEntry> = entries
                    .into_iter()
                    .map(|(name, record_type, values, ttl)| DnsEntry {
                        name,
                        record_type,
                        values,
                        ttl,
                    })
                    .collect();
                state.dns_zones.insert(zone, dns_entries);
            }
            Command::KvPut { key, value } => {
                state.kv.insert(key, value);
            }
            Command::KvDelete { key } => {
                state.kv.remove(&key);
            }
            Command::TrackCloudInstance {
                instance_id,
                provider,
                pool,
                private_ip,
                created_at,
            } => {
                state.cloud_instances.insert(
                    instance_id.clone(),
                    TrackedCloudInstance {
                        cloud_instance_id: instance_id,
                        provider,
                        pool,
                        private_ip,
                        created_at,
                        fleet_node_id: None,
                        joined_at: None,
                    },
                );
            }
            Command::UpdateCloudInstance {
                instance_id,
                fleet_node_id,
            } => {
                if let Some(inst) = state.cloud_instances.get_mut(&instance_id) {
                    inst.fleet_node_id = Some(fleet_node_id);
                    inst.joined_at = Some(now);
                }
            }
            Command::UntrackCloudInstance { instance_id } => {
                state.cloud_instances.remove(&instance_id);
            }
            Command::ApplyConfig {
                flake_ref,
                config_json,
                applied_at,
                applied_by,
                rollback_of,
                closures,
                images,
            } => {
                let revision = state.config_revisions.last().map_or(1, |r| r.revision + 1);
                state.config_revisions.push(ConfigRevision {
                    revision,
                    flake_ref,
                    config_json,
                    applied_at,
                    applied_by,
                    rollback_of,
                    closures,
                    images,
                });
                let excess = state
                    .config_revisions
                    .len()
                    .saturating_sub(MAX_CONFIG_REVISIONS);
                state.config_revisions.drain(..excess);
            }
            Command::AllocateNamespaceSubnet { namespace, octet } => {
                state.namespace_subnets.insert(namespace, octet);
            }
            Command::AllocateNamespaceIp {
                namespace,
                holder,
                ip,
            } => {
                state
                    .namespace_ips
                    .entry(namespace)
                    .or_default()
                    .insert(holder, ip);
            }
            Command::ReleaseNamespaceIp { namespace, holder } => {
                if let Some(ns_ips) = state.namespace_ips.get_mut(&namespace) {
                    ns_ips.remove(&holder);
                }
                if state
                    .namespace_ips
                    .get(&namespace)
                    .is_none_or(HashMap::is_empty)
                {
                    state.namespace_ips.remove(&namespace);
                    state.namespace_subnets.remove(&namespace);
                }
            }
            Command::AllocateMeshIp { node_id, ip } => {
                state.mesh_ips.insert(node_id, ip);
            }
            Command::ReleaseMeshIp { node_id } => {
                state.mesh_ips.remove(&node_id);
            }
            Command::AclTokenPut { key, entry } => {
                state.acl_tokens.insert(key, entry);
            }
            Command::AclTokenRevoke { key } => {
                state.acl_tokens.remove(&key);
            }
            Command::JoinTokenPut {
                hash,
                node_name,
                expires_at,
            } => {
                state.join_tokens.insert(
                    hash,
                    JoinTokenRecord {
                        node_name,
                        created_at: now,
                        expires_at,
                        consumed_at: None,
                    },
                );
            }
            Command::JoinTokenConsume { hash } => {
                if let Some(token) = state.join_tokens.get_mut(&hash) {
                    token.consumed_at.get_or_insert(now);
                }
            }
            Command::JoinTokenRelease { hash } => {
                if let Some(token) = state.join_tokens.get_mut(&hash) {
                    token.consumed_at = None;
                }
            }
            Command::ExpireTokens => {
                state.join_tokens.retain(|_, t| t.expires_at > now);
                state.acl_tokens.retain(|_, t| !t.expired_at(now));
            }
            Command::RestoreState { data } => {
                match serde_json::from_slice::<StateMachineInner>(&data) {
                    Ok(mut restored) => {
                        restored.last_applied_log = state.last_applied_log;
                        restored.last_membership = std::mem::take(&mut state.last_membership);
                        *state = restored;
                    }
                    // Checked before proposing, so only a corrupt entry lands here.
                    Err(e) => {
                        tracing::error!(index, error = %e, "Ignoring unreadable state restore")
                    }
                }
            }
        }

        state.last_applied = index;
    }

    /// The join token with digest `hash`.
    pub async fn join_token(&self, hash: &str) -> Option<JoinTokenRecord> {
        self.inner.read().await.join_tokens.get(hash).cloned()
    }

    /// Every join token, by digest.
    pub async fn join_tokens(&self) -> BTreeMap<String, JoinTokenRecord> {
        self.inner.read().await.join_tokens.clone()
    }

    /// Mark the join token `hash` used if `usable` accepts it as it stands,
    /// in one turn so no other use of it can come in between. Returns what
    /// `usable` decided.
    pub async fn consume_join_token<E>(
        &self,
        hash: &str,
        usable: impl FnOnce(Option<&JoinTokenRecord>) -> Result<(), E>,
    ) -> Result<Result<(), E>, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        let verdict = usable(state.join_tokens.get(hash));
        drop(state);
        if verdict.is_ok() {
            turn.commit(Command::JoinTokenConsume {
                hash: hash.to_string(),
            })
            .await?;
        }
        Ok(verdict)
    }

    /// Get the current deployment state for a service.
    pub async fn get_deployment(&self, service_name: &str) -> Option<DeploymentState> {
        let state = self.inner.read().await;
        state.deployments.get(service_name).cloned()
    }

    /// Get all current deployments.
    /// Record `command` (an [`Command::ApplyConfig`]) and return the
    /// revision it created.
    pub async fn apply_config(&self, command: Command) -> Result<u64, RaftError> {
        debug_assert!(matches!(command, Command::ApplyConfig { .. }));
        let mut turn = self.turn().await;
        turn.commit(command).await?;
        Ok(turn
            .read()
            .await
            .config_revisions
            .last()
            .map_or(0, |r| r.revision))
    }

    /// The configuration the server currently reconciles toward.
    pub async fn current_config(&self) -> Option<ConfigRevision> {
        self.inner.read().await.config_revisions.last().cloned()
    }

    /// Retained configuration revisions, oldest first.
    pub async fn config_revisions(&self) -> Vec<ConfigRevision> {
        self.inner.read().await.config_revisions.clone()
    }

    pub async fn all_deployments(&self) -> HashMap<String, DeploymentState> {
        let state = self.inner.read().await;
        state.deployments.clone()
    }

    /// Serialize the state machine for snapshotting.
    pub async fn snapshot(&self) -> Vec<u8> {
        let state = self.inner.read().await;
        serde_json::to_vec(&*state).unwrap_or_default()
    }

    /// Replace the whole state with an operator-supplied snapshot (the
    /// `Restore` RPC). The result takes a fresh index past both the current
    /// and the snapshot's, and with a log attached it replaces the persisted
    /// state, so it survives restarts and later writes build on it.
    pub async fn install_snapshot(&self, data: &[u8]) -> Result<u64, RaftError> {
        // Reject a bad backup before it reaches the log.
        serde_json::from_slice::<StateMachineInner>(data)?;
        self.apply_next(Command::RestoreState {
            data: data.to_vec(),
        })
        .await
    }

    /// Persist a snapshot of the current state and drop the log entries it
    /// subsumes. Returns the snapshot index, or `None` when there is nothing
    /// to snapshot or no log is attached.
    pub async fn checkpoint(&self) -> Result<Option<u64>, RaftError> {
        if let Some(raft) = self.raft.get() {
            raft.trigger()
                .snapshot()
                .await
                .map_err(|e| RaftError::Consensus(e.to_string()))?;
            return Ok(Some(self.last_applied().await));
        }
        let Some(log) = &self.log else {
            return Ok(None);
        };
        // Hold the read lock so no entry is appended between serializing
        // and compacting.
        let state = self.inner.read().await;
        if state.last_applied == 0 {
            return Ok(None);
        }
        let data = serde_json::to_vec(&*state)?;
        log.save_snapshot(state.last_applied, &data).await?;
        log.compact_log(state.last_applied).await?;
        Ok(Some(state.last_applied))
    }

    /// Restore from a snapshot as-is (boot-time load).
    pub async fn restore(&self, data: &[u8]) -> Result<(), serde_json::Error> {
        let restored: StateMachineInner = serde_json::from_slice(data)?;
        let mut state = self.write().await;
        *state = restored;
        Ok(())
    }

    /// Get the last applied log index.
    pub async fn last_applied(&self) -> u64 {
        let state = self.inner.read().await;
        state.last_applied
    }

    /// Store a sealed secret value; returns its new version.
    pub async fn put_secret(
        &self,
        service_name: &str,
        secret_name: &str,
        sealed: Vec<u8>,
    ) -> Result<u64, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        drop(state);
        turn.commit(Command::PutSecret {
            service_name: service_name.to_string(),
            secret_name: secret_name.to_string(),
            encrypted_value: sealed,
        })
        .await?;
        Ok(turn.read().await.secret_versions[service_name][secret_name])
    }

    /// Make an earlier version of a secret current again, as a new version.
    /// Returns that version, or `None` if `version` isn't kept.
    pub async fn rollback_secret(
        &self,
        service_name: &str,
        secret_name: &str,
        version: u64,
    ) -> Result<Option<u64>, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        let Some(sealed) = state
            .secret_history
            .get(service_name)
            .and_then(|s| s.get(secret_name))
            .and_then(|h| h.iter().find(|(v, _)| *v == version))
            .map(|(_, sealed)| sealed.clone())
        else {
            return Ok(None);
        };
        drop(state);
        turn.commit(Command::PutSecret {
            service_name: service_name.to_string(),
            secret_name: secret_name.to_string(),
            encrypted_value: sealed,
        })
        .await?;
        Ok(Some(
            turn.read().await.secret_versions[service_name][secret_name],
        ))
    }

    /// Delete a secret's value. Returns whether it had one.
    pub async fn delete_secret(
        &self,
        service_name: &str,
        secret_name: &str,
    ) -> Result<bool, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        if !state
            .secrets
            .get(service_name)
            .is_some_and(|svc| svc.contains_key(secret_name))
        {
            return Ok(false);
        }
        drop(state);
        turn.commit(Command::DeleteSecret {
            service_name: service_name.to_string(),
            secret_name: secret_name.to_string(),
        })
        .await?;
        Ok(true)
    }

    /// Every stored secret: service → name → (sealed value, version).
    pub async fn secrets(&self) -> HashMap<String, HashMap<String, (Vec<u8>, u64)>> {
        let state = self.inner.read().await;
        state
            .secrets
            .iter()
            .map(|(service, values)| {
                let versions = state.secret_versions.get(service);
                let values = values
                    .iter()
                    .map(|(name, sealed)| {
                        let version = versions.and_then(|v| v.get(name)).copied().unwrap_or(1);
                        (name.clone(), (sealed.clone(), version))
                    })
                    .collect();
                (service.clone(), values)
            })
            .collect()
    }

    /// Earlier versions of every secret: service → name → [(version,
    /// sealed value)], oldest first.
    pub async fn secret_history(&self) -> SecretHistory {
        self.inner.read().await.secret_history.clone()
    }

    /// Replace sealed values, current and earlier, after a fleet key
    /// rotation (versions kept).
    pub async fn reseal_secrets(
        &self,
        secrets: HashMap<String, HashMap<String, Vec<u8>>>,
        history: HashMap<String, HashMap<String, HashMap<u64, Vec<u8>>>>,
        transit: HashMap<String, Vec<Vec<u8>>>,
    ) -> Result<(), RaftError> {
        self.reseal_under(secrets, history, transit, None).await
    }

    /// [`Self::reseal_secrets`] under a new fleet key with check value
    /// `key_check`, recorded in the same entry.
    pub async fn reseal_under(
        &self,
        secrets: HashMap<String, HashMap<String, Vec<u8>>>,
        history: HashMap<String, HashMap<String, HashMap<u64, Vec<u8>>>>,
        transit: HashMap<String, Vec<Vec<u8>>>,
        key_check: Option<Vec<u8>>,
    ) -> Result<(), RaftError> {
        self.apply_next(Command::ResealSecrets {
            secrets,
            history,
            transit,
            key_check,
        })
        .await
        .map(drop)
    }

    /// The current fleet key's version (0 before its check is recorded).
    pub async fn fleet_key_version(&self) -> u64 {
        self.inner.read().await.fleet_key_version
    }

    /// The check value of the current fleet key, once recorded.
    pub async fn fleet_key_check(&self) -> Option<Vec<u8>> {
        self.inner.read().await.fleet_key_check.clone()
    }

    /// Every transit key, by name.
    pub async fn transit_keys(&self) -> BTreeMap<String, TransitKey> {
        self.inner.read().await.transit_keys.clone()
    }

    pub async fn transit_key(&self, name: &str) -> Option<TransitKey> {
        self.inner.read().await.transit_keys.get(name).cloned()
    }

    /// Store a new transit key; false if one with that name exists.
    pub async fn create_transit_key(&self, name: &str, key: TransitKey) -> Result<bool, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        if state.transit_keys.contains_key(name) {
            return Ok(false);
        }
        drop(state);
        turn.commit(Command::PutTransitKey {
            name: name.to_string(),
            key,
        })
        .await
        .map(|_| true)
    }

    /// Add a version (sealed) to a transit key; returns the new version,
    /// or `None` if there is no such key.
    pub async fn add_transit_key_version(
        &self,
        name: &str,
        sealed: Vec<u8>,
    ) -> Result<Option<u32>, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        let Some(mut key) = state.transit_keys.get(name).cloned() else {
            return Ok(None);
        };
        key.versions.push(sealed);
        let version = key.versions.len() as u32;
        drop(state);
        turn.commit(Command::PutTransitKey {
            name: name.to_string(),
            key,
        })
        .await?;
        Ok(Some(version))
    }

    /// Delete a transit key; false if there was none.
    pub async fn delete_transit_key(&self, name: &str) -> Result<bool, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        if !state.transit_keys.contains_key(name) {
            return Ok(false);
        }
        drop(state);
        turn.commit(Command::DeleteTransitKey {
            name: name.to_string(),
        })
        .await
        .map(|_| true)
    }

    /// Every dynamic secret's lease: service → name → lease.
    pub async fn dynamic_leases(&self) -> BTreeMap<String, BTreeMap<String, DynamicLease>> {
        self.inner.read().await.dynamic_leases.clone()
    }

    /// Database users waiting to be dropped.
    pub async fn retired_users(&self) -> Vec<RetiredUser> {
        self.inner.read().await.retired_users.clone()
    }

    /// Store new credentials for a dynamic secret; returns their version.
    pub async fn issue_dynamic_secret(
        &self,
        service_name: &str,
        secret_name: &str,
        sealed: Vec<u8>,
        lease: DynamicLease,
    ) -> Result<u64, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        drop(state);
        turn.commit(Command::IssueDynamicSecret {
            service_name: service_name.to_string(),
            secret_name: secret_name.to_string(),
            encrypted_value: sealed,
            lease,
        })
        .await?;
        Ok(turn.read().await.secret_versions[service_name][secret_name])
    }

    /// Remove a dynamic secret, retiring its user at `drop_at`. Returns
    /// whether it had a lease.
    pub async fn retire_dynamic_secret(
        &self,
        service_name: &str,
        secret_name: &str,
        drop_at: u64,
    ) -> Result<bool, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        if !state
            .dynamic_leases
            .get(service_name)
            .is_some_and(|svc| svc.contains_key(secret_name))
        {
            return Ok(false);
        }
        drop(state);
        turn.commit(Command::RetireDynamicSecret {
            service_name: service_name.to_string(),
            secret_name: secret_name.to_string(),
            drop_at,
        })
        .await
        .map(|_| true)
    }

    /// Stop tracking a retired user.
    pub async fn forget_retired_user(&self, engine: &str, username: &str) -> Result<(), RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        drop(state);
        turn.commit(Command::ForgetRetiredUser {
            engine: engine.to_string(),
            username: username.to_string(),
        })
        .await
        .map(|_| ())
    }

    /// Get a value from the key-value store.
    pub async fn kv_get(&self, key: &str) -> Option<Vec<u8>> {
        let state = self.inner.read().await;
        state.kv.get(key).cloned()
    }

    /// List all key-value pairs matching a given key prefix.
    pub async fn kv_list_prefix(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        let state = self.inner.read().await;
        state
            .kv
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Get all tracked cloud instances.
    pub async fn cloud_instances(&self) -> HashMap<String, TrackedCloudInstance> {
        let state = self.inner.read().await;
        state.cloud_instances.clone()
    }

    /// Get tracked cloud instances for a specific pool.
    pub async fn cloud_instances_for_pool(&self, pool: &str) -> Vec<TrackedCloudInstance> {
        let state = self.inner.read().await;
        state
            .cloud_instances
            .values()
            .filter(|i| i.pool == pool)
            .cloned()
            .collect()
    }

    /// Find a tracked cloud instance by its private IP.
    pub async fn cloud_instance_by_ip(&self, ip: &str) -> Option<TrackedCloudInstance> {
        let state = self.inner.read().await;
        state
            .cloud_instances
            .values()
            .find(|i| i.private_ip.as_deref() == Some(ip))
            .cloned()
    }

    /// Get all IP allocations for a namespace.
    pub async fn namespace_ips(&self, namespace: &str) -> HashMap<String, Ipv4Addr> {
        let state = self.inner.read().await;
        state
            .namespace_ips
            .get(namespace)
            .cloned()
            .unwrap_or_default()
    }

    /// The subnet octet assigned to a namespace, if any.
    pub async fn namespace_subnet(&self, namespace: &str) -> Option<u8> {
        self.inner
            .read()
            .await
            .namespace_subnets
            .get(namespace)
            .copied()
    }

    /// The IP assigned to one replica (`holder`, see [`namespace_ip_holder`]).
    pub async fn namespace_ip(&self, namespace: &str, holder: &str) -> Option<Ipv4Addr> {
        let state = self.inner.read().await;
        state
            .namespace_ips
            .get(namespace)
            .and_then(|ips| ips.get(holder).copied())
    }

    /// Return the IP of `holder` in `namespace`, allocating the namespace's
    /// subnet and a free host address first if needed. Check and allocation
    /// happen under one write lock, so concurrent callers never receive the
    /// same address. `Ok(None)` means no subnet or host address is free.
    pub async fn ensure_namespace_ip(
        &self,
        namespace: &str,
        holder: &str,
    ) -> Result<Option<Ipv4Addr>, RaftError> {
        let mut turn = self.turn().await;
        let subnet = turn.read().await.namespace_subnets.get(namespace).copied();
        let octet = match subnet {
            Some(octet) => octet,
            None => {
                let used: std::collections::HashSet<u8> = turn
                    .read()
                    .await
                    .namespace_subnets
                    .values()
                    .copied()
                    .collect();
                let Some(octet) = (1..=254).find(|o| !used.contains(o)) else {
                    return Ok(None);
                };
                turn.commit(Command::AllocateNamespaceSubnet {
                    namespace: namespace.to_string(),
                    octet,
                })
                .await?;
                octet
            }
        };
        let state = turn.read().await;
        let existing = state.namespace_ips.get(namespace);
        if let Some(ip) = existing.and_then(|ips| ips.get(holder))
            && ip.octets()[2] == octet
        {
            return Ok(Some(*ip));
        }
        // .1 is the gateway on every node's bridge.
        let used: std::collections::HashSet<u8> = existing
            .map(|ips| {
                ips.iter()
                    .filter(|(h, _)| h.as_str() != holder)
                    .map(|(_, ip)| ip.octets()[3])
                    .collect()
            })
            .unwrap_or_default();
        let Some(host) = (2..=254).find(|h| !used.contains(h)) else {
            return Ok(None);
        };
        let ip = Ipv4Addr::new(10, 200, octet, host);
        drop(state);
        turn.commit(Command::AllocateNamespaceIp {
            namespace: namespace.to_string(),
            holder: holder.to_string(),
            ip,
        })
        .await?;
        Ok(Some(ip))
    }

    /// Release every namespace IP whose `(namespace, holder)` is not in
    /// `live`; a namespace left without IPs loses its subnet. Returns how
    /// many IPs were released.
    pub async fn release_namespace_ips_except(
        &self,
        live: &std::collections::HashSet<(String, String)>,
    ) -> Result<usize, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        let mut stale: Vec<(String, String)> = state
            .namespace_ips
            .iter()
            .flat_map(|(ns, ips)| ips.keys().map(move |h| (ns.clone(), h.clone())))
            .filter(|key| !live.contains(key))
            .collect();
        // Subnets allocated without any IP (address space exhausted).
        stale.extend(
            state
                .namespace_subnets
                .keys()
                .filter(|ns| !state.namespace_ips.contains_key(*ns))
                .map(|ns| (ns.clone(), String::new())),
        );
        stale.sort();
        let released = stale.iter().filter(|(_, h)| !h.is_empty()).count();
        drop(state);
        for (namespace, holder) in stale {
            turn.commit(Command::ReleaseNamespaceIp { namespace, holder })
                .await?;
        }
        Ok(released)
    }

    /// Nodes holding a mesh address: every node that has joined the mesh.
    pub async fn mesh_nodes(&self) -> Vec<String> {
        self.inner.read().await.mesh_ips.keys().cloned().collect()
    }

    /// The mesh address assigned to `node_id`, if any.
    pub async fn mesh_ip(&self, node_id: &str) -> Option<Ipv4Addr> {
        self.inner.read().await.mesh_ips.get(node_id).copied()
    }

    /// Return the mesh address of `node_id`, allocating a free one in
    /// `10.100.0.0/16` first if needed (check and commit under one lock).
    /// `Ok(None)` means the mesh network is full.
    pub async fn ensure_mesh_ip(&self, node_id: &str) -> Result<Option<Ipv4Addr>, RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        if let Some(ip) = state.mesh_ips.get(node_id) {
            return Ok(Some(*ip));
        }
        let used: std::collections::HashSet<u32> =
            state.mesh_ips.values().map(|ip| u32::from(*ip)).collect();
        let base = u32::from(MESH_NETWORK);
        let hosts = (1u32 << (32 - MESH_PREFIX_LEN)) - 1;
        // Neither the network nor the broadcast address.
        let Some(ip) = (1..hosts)
            .map(|h| base + h)
            .find(|ip| !used.contains(ip))
            .map(Ipv4Addr::from)
        else {
            return Ok(None);
        };
        drop(state);
        turn.commit(Command::AllocateMeshIp {
            node_id: node_id.to_string(),
            ip,
        })
        .await?;
        Ok(Some(ip))
    }

    /// Release the mesh address of a node that left the fleet.
    pub async fn release_mesh_ip(&self, node_id: &str) -> Result<(), RaftError> {
        let mut turn = self.turn().await;
        let state = turn.read().await;
        if !state.mesh_ips.contains_key(node_id) {
            return Ok(());
        }
        drop(state);
        turn.commit(Command::ReleaseMeshIp {
            node_id: node_id.to_string(),
        })
        .await
        .map(drop)
    }

    /// Set a runtime replica count override for a service.
    /// Stored in the KV store so it survives snapshots.
    /// The reconciler reads this to override the config-defined replica count.
    pub async fn set_replica_override(
        &self,
        service_name: &str,
        count: u32,
    ) -> Result<(), RaftError> {
        self.apply_next(Command::KvPut {
            key: format!("replica-override/{service_name}"),
            value: count.to_le_bytes().to_vec(),
        })
        .await
        .map(drop)
    }

    /// Get the runtime replica count override for a service, if any.
    pub async fn get_replica_override(&self, service_name: &str) -> Option<u32> {
        let key = format!("replica-override/{service_name}");
        let state = self.inner.read().await;
        state
            .kv
            .get(&key)
            .and_then(|v| v.as_slice().try_into().ok().map(u32::from_le_bytes))
    }

    /// Every runtime replica count override, by service.
    pub async fn replica_overrides(&self) -> BTreeMap<String, u32> {
        let state = self.inner.read().await;
        state
            .kv
            .iter()
            .filter_map(|(key, value)| {
                let service = key.strip_prefix("replica-override/")?;
                let count = value.as_slice().try_into().ok().map(u32::from_le_bytes)?;
                Some((service.to_string(), count))
            })
            .collect()
    }

    /// Clear a runtime replica count override for a service.
    pub async fn clear_replica_override(&self, service_name: &str) -> Result<(), RaftError> {
        self.apply_next(Command::KvDelete {
            key: format!("replica-override/{service_name}"),
        })
        .await
        .map(drop)
    }

    /// Ask the reconciler to move a stateful instance to `node`: it prefers
    /// that node for the instance instead of the one it runs on now.
    pub async fn set_placement_move(
        &self,
        service_name: &str,
        instance_id: &str,
        node: &str,
    ) -> Result<(), RaftError> {
        self.apply_next(Command::KvPut {
            key: format!("placement-move/{service_name}/{instance_id}"),
            value: node.as_bytes().to_vec(),
        })
        .await
        .map(drop)
    }

    /// Every requested move: `(service, instance)` → destination node.
    pub async fn placement_moves(&self) -> BTreeMap<(String, String), String> {
        let state = self.inner.read().await;
        state
            .kv
            .iter()
            .filter_map(|(key, value)| {
                let (service, instance) = key.strip_prefix("placement-move/")?.split_once('/')?;
                let node = String::from_utf8(value.clone()).ok()?;
                Some(((service.to_string(), instance.to_string()), node))
            })
            .collect()
    }

    /// Forget a requested move, made or abandoned.
    pub async fn clear_placement_move(
        &self,
        service_name: &str,
        instance_id: &str,
    ) -> Result<(), RaftError> {
        self.apply_next(Command::KvDelete {
            key: format!("placement-move/{service_name}/{instance_id}"),
        })
        .await
        .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn secrets_are_versioned_durable_and_resealed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = || Arc::new(RaftStorage::new(dir.path(), &[5u8; 32]));
        let first = storage();
        first.initialize().await.unwrap();
        let sm = FleetStateMachine::with_log(first);

        assert_eq!(sm.put_secret("web", "key", b"a".to_vec()).await.unwrap(), 1);
        assert_eq!(sm.put_secret("web", "key", b"b".to_vec()).await.unwrap(), 2);
        assert_eq!(sm.put_secret("db", "pw", b"c".to_vec()).await.unwrap(), 1);
        assert_eq!(sm.secrets().await["web"]["key"], (b"b".to_vec(), 2));

        // A value set again after a delete gets a newer version.
        assert!(sm.delete_secret("web", "key").await.unwrap());
        assert!(!sm.delete_secret("web", "key").await.unwrap());
        assert!(!sm.secrets().await.contains_key("web"));
        assert_eq!(sm.put_secret("web", "key", b"d".to_vec()).await.unwrap(), 3);

        // Resealing swaps values only for secrets that still exist.
        sm.reseal_secrets(
            [
                (
                    "web".to_string(),
                    [("key".to_string(), b"D".to_vec())].into(),
                ),
                (
                    "gone".to_string(),
                    [("x".to_string(), b"X".to_vec())].into(),
                ),
            ]
            .into(),
            HashMap::new(),
            HashMap::new(),
        )
        .await
        .unwrap();

        let restarted = FleetStateMachine::with_log(storage());
        restarted.load().await.unwrap();
        let secrets = restarted.secrets().await;
        assert_eq!(secrets["web"]["key"], (b"D".to_vec(), 3));
        assert_eq!(secrets["db"]["pw"], (b"c".to_vec(), 1));
        assert!(!secrets.contains_key("gone"));
    }

    #[tokio::test]
    async fn mesh_ips_are_unique_stable_and_reusable() {
        let sm = FleetStateMachine::new();
        let a = sm.ensure_mesh_ip("a").await.unwrap().unwrap();
        let b = sm.ensure_mesh_ip("b").await.unwrap().unwrap();
        assert_eq!(a, Ipv4Addr::new(10, 100, 0, 1));
        assert_eq!(b, Ipv4Addr::new(10, 100, 0, 2));
        assert_eq!(sm.ensure_mesh_ip("a").await.unwrap(), Some(a));
        sm.release_mesh_ip("a").await.unwrap();
        assert_eq!(sm.mesh_ip("a").await, None);
        assert_eq!(sm.ensure_mesh_ip("c").await.unwrap(), Some(a));
        // Survives a snapshot round trip.
        let restored = FleetStateMachine::new();
        restored.restore(&sm.snapshot().await).await.unwrap();
        assert_eq!(restored.mesh_ip("b").await, Some(b));
    }

    #[tokio::test]
    async fn namespace_allocations_are_unique_durable_and_released() {
        let dir = tempfile::tempdir().unwrap();
        let storage = || Arc::new(RaftStorage::new(dir.path(), &[7u8; 32]));
        let first = storage();
        first.initialize().await.unwrap();
        let sm = FleetStateMachine::with_log(first);

        let a1 = sm
            .ensure_namespace_ip("a", "web@n1")
            .await
            .unwrap()
            .unwrap();
        let a2 = sm
            .ensure_namespace_ip("a", "web@n2")
            .await
            .unwrap()
            .unwrap();
        let b1 = sm
            .ensure_namespace_ip("b", "web@n1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a1, Ipv4Addr::new(10, 200, 1, 2));
        assert_eq!(a2, Ipv4Addr::new(10, 200, 1, 3));
        assert_eq!(b1, Ipv4Addr::new(10, 200, 2, 2));
        assert_eq!(
            sm.ensure_namespace_ip("a", "web@n1").await.unwrap(),
            Some(a1)
        );

        // Allocations survive a restart.
        let restarted = FleetStateMachine::with_log(storage());
        restarted.load().await.unwrap();
        assert_eq!(restarted.namespace_ip("a", "web@n2").await, Some(a2));
        assert_eq!(restarted.namespace_subnet("b").await, Some(2));

        // Releasing everything in b frees its subnet for the next namespace.
        let live = [("a".to_string(), "web@n1".to_string())].into();
        assert_eq!(
            restarted.release_namespace_ips_except(&live).await.unwrap(),
            2
        );
        assert_eq!(restarted.namespace_subnet("b").await, None);
        assert_eq!(restarted.namespace_ips("a").await.len(), 1);
        let c = restarted.ensure_namespace_ip("c", "x@n1").await.unwrap();
        assert_eq!(c, Some(Ipv4Addr::new(10, 200, 2, 2)));
        // a's freed host address is reused.
        let a3 = restarted.ensure_namespace_ip("a", "api@n1").await.unwrap();
        assert_eq!(a3, Some(a2));
    }

    fn apply_config_cmd(flake_ref: &str, rollback_of: Option<u64>) -> Command {
        Command::ApplyConfig {
            flake_ref: flake_ref.into(),
            config_json: format!("{{\"ref\":\"{flake_ref}\"}}"),
            applied_at: 1,
            applied_by: "tester".into(),
            rollback_of,
            closures: BTreeMap::new(),
            images: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn config_revisions_are_numbered_bounded_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RaftStorage::new(dir.path(), &[3u8; 32]));
        storage.initialize().await.unwrap();
        let sm = FleetStateMachine::with_log(storage);
        assert!(sm.current_config().await.is_none());
        for i in 1..=12u64 {
            let rev = sm
                .apply_config(apply_config_cmd(&format!("r{i}"), None))
                .await
                .unwrap();
            assert_eq!(rev, i);
        }
        let rev = sm
            .apply_config(apply_config_cmd("r5", Some(5)))
            .await
            .unwrap();
        assert_eq!(rev, 13);

        let restarted =
            FleetStateMachine::with_log(Arc::new(RaftStorage::new(dir.path(), &[3u8; 32])));
        restarted.load().await.unwrap();
        let revisions = restarted.config_revisions().await;
        assert_eq!(revisions.len(), MAX_CONFIG_REVISIONS);
        assert_eq!(revisions[0].revision, 4);
        let current = restarted.current_config().await.unwrap();
        assert_eq!((current.revision, current.rollback_of), (13, Some(5)));
        assert_eq!(current.flake_ref, "r5");
        // Numbering continues after a restart.
        assert_eq!(
            restarted
                .apply_config(apply_config_cmd("r14", None))
                .await
                .unwrap(),
            14
        );
    }

    #[tokio::test]
    async fn namespace_host_addresses_run_out() {
        let sm = FleetStateMachine::new();
        for i in 0..253 {
            assert!(
                sm.ensure_namespace_ip("a", &format!("s{i}@n"))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(sm.ensure_namespace_ip("a", "extra@n").await.unwrap(), None);
    }

    #[tokio::test]
    async fn apply_next_indices_are_monotonic() {
        let sm = FleetStateMachine::new();
        let i1 = sm
            .apply_next(Command::KvPut {
                key: "a".into(),
                value: b"1".to_vec(),
            })
            .await
            .unwrap();
        let i2 = sm
            .apply_next(Command::KvPut {
                key: "b".into(),
                value: b"2".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(i1, 1);
        assert_eq!(i2, 2);
        assert_eq!(sm.last_applied().await, 2);
    }

    #[tokio::test]
    async fn interleaved_callers_do_not_drop_writes() {
        // Regression: previously distinct callers used disjoint high index
        // ranges with a single shared `last_applied`, so a low-index write
        // after a high-index write was silently deduped. apply_next keeps
        // indices globally monotonic, so every write lands.
        let sm = FleetStateMachine::new();
        sm.apply_next(Command::KvPut {
            key: "first".into(),
            value: b"x".to_vec(),
        })
        .await
        .unwrap();
        sm.apply_next(Command::KvPut {
            key: "second".into(),
            value: b"y".to_vec(),
        })
        .await
        .unwrap();
        assert_eq!(sm.kv_get("first").await, Some(b"x".to_vec()));
        assert_eq!(sm.kv_get("second").await, Some(b"y".to_vec()));
    }

    #[tokio::test]
    async fn restore_preserves_last_applied_for_new_writes() {
        let sm = FleetStateMachine::new();
        sm.apply_next(Command::KvPut {
            key: "k".into(),
            value: b"v".to_vec(),
        })
        .await
        .unwrap();
        let snap = sm.snapshot().await;

        // Simulate a fresh process restoring the snapshot.
        let restored = FleetStateMachine::new();
        restored.restore(&snap).await.unwrap();
        assert_eq!(restored.last_applied().await, 1);
        assert_eq!(restored.kv_get("k").await, Some(b"v".to_vec()));

        // A post-restore write must continue past the restored index, not
        // collide with or be deduped against it.
        let idx = restored
            .apply_next(Command::KvPut {
                key: "k2".into(),
                value: b"v2".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(idx, 2);
        assert_eq!(restored.kv_get("k2").await, Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn apply_is_idempotent_on_replay() {
        let sm = FleetStateMachine::new();
        sm.apply(
            5,
            Command::KvPut {
                key: "k".into(),
                value: b"a".to_vec(),
            },
        )
        .await;
        // Replaying an already-applied index is a no-op.
        sm.apply(
            5,
            Command::KvPut {
                key: "k".into(),
                value: b"b".to_vec(),
            },
        )
        .await;
        assert_eq!(sm.kv_get("k").await, Some(b"a".to_vec()));
        assert_eq!(sm.last_applied().await, 5);
    }

    fn durable(dir: &std::path::Path, key: u8) -> FleetStateMachine {
        FleetStateMachine::with_log(Arc::new(RaftStorage::new(dir, &[key; 32])))
    }

    async fn durable_initialized(dir: &std::path::Path, key: u8) -> FleetStateMachine {
        let storage = RaftStorage::new(dir, &[key; 32]);
        storage.initialize().await.unwrap();
        FleetStateMachine::with_log(Arc::new(storage))
    }

    fn put(key: &str, value: &str) -> Command {
        Command::KvPut {
            key: key.into(),
            value: value.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn acknowledged_writes_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let sm = durable_initialized(dir.path(), 1).await;
        sm.apply_next(put("a", "1")).await.unwrap();
        sm.apply_next(Command::Deploy {
            service_name: "web".into(),
            store_path: "/nix/store/web".into(),
            placements: Vec::new(),
        })
        .await
        .unwrap();
        sm.set_replica_override("web", 3).await.unwrap();

        let reloaded = durable(dir.path(), 1);
        reloaded.load().await.unwrap();
        assert_eq!(reloaded.last_applied().await, 3);
        assert_eq!(reloaded.kv_get("a").await, Some(b"1".to_vec()));
        assert_eq!(
            reloaded.get_deployment("web").await.unwrap().store_path,
            "/nix/store/web"
        );
        assert_eq!(reloaded.get_replica_override("web").await, Some(3));

        reloaded.clear_replica_override("web").await.unwrap();
        let again = durable(dir.path(), 1);
        again.load().await.unwrap();
        assert_eq!(again.get_replica_override("web").await, None);
    }

    #[tokio::test]
    async fn earlier_secret_versions_are_kept_resealed_and_restorable() {
        let sm = FleetStateMachine::new();
        for i in 1..=(SECRET_HISTORY as u8 + 3) {
            sm.put_secret("web", "key", vec![i]).await.unwrap();
        }
        let history = &sm.secret_history().await["web"]["key"];
        assert_eq!(history.len(), SECRET_HISTORY);
        // Versions 1-2 fell out; 3..=11 are kept, 12 is current.
        assert_eq!(history[0], (3, vec![3]));
        assert_eq!(sm.rollback_secret("web", "key", 2).await.unwrap(), None);
        assert_eq!(sm.rollback_secret("web", "key", 5).await.unwrap(), Some(13));
        assert_eq!(sm.secrets().await["web"]["key"], (vec![5], 13));

        sm.reseal_secrets(
            HashMap::new(),
            [(
                "web".into(),
                [("key".into(), [(12, b"R".to_vec())].into())].into(),
            )]
            .into(),
            HashMap::new(),
        )
        .await
        .unwrap();
        let history = &sm.secret_history().await["web"]["key"];
        assert!(history.contains(&(12, b"R".to_vec())));

        sm.delete_secret("web", "key").await.unwrap();
        assert!(sm.secret_history().await.is_empty());
    }

    #[tokio::test]
    async fn dynamic_secrets_replace_and_retire_their_users() {
        let sm = FleetStateMachine::new();
        let lease = |user: &str, issued_at: u64| DynamicLease {
            engine: "pg".into(),
            role: "readonly".into(),
            username: user.into(),
            issued_at,
            expires_at: issued_at + 300,
        };
        assert_eq!(lease("a", 100).renew_at(), 300);
        let v1 = sm
            .issue_dynamic_secret("web", "db", b"one".to_vec(), lease("a", 100))
            .await
            .unwrap();
        let v2 = sm
            .issue_dynamic_secret("web", "db", b"two".to_vec(), lease("b", 300))
            .await
            .unwrap();
        assert_eq!((v1, v2), (1, 2));
        assert_eq!(sm.secrets().await["web"]["db"], (b"two".to_vec(), 2));
        assert!(sm.secret_history().await.is_empty());
        assert_eq!(sm.dynamic_leases().await["web"]["db"].username, "b");
        // The replaced user is dropped when its password expires.
        assert_eq!(
            sm.retired_users().await,
            [RetiredUser {
                engine: "pg".into(),
                username: "a".into(),
                drop_at: 400,
            }]
        );

        assert!(sm.retire_dynamic_secret("web", "db", 350).await.unwrap());
        assert!(!sm.retire_dynamic_secret("web", "db", 350).await.unwrap());
        assert!(sm.secrets().await.is_empty());
        assert!(sm.dynamic_leases().await.is_empty());
        assert_eq!(sm.retired_users().await.len(), 2);
        sm.forget_retired_user("pg", "a").await.unwrap();
        let left = sm.retired_users().await;
        assert_eq!((left[0].username.as_str(), left[0].drop_at), ("b", 350));

        // Issued again later, the version keeps climbing.
        let v3 = sm
            .issue_dynamic_secret("web", "db", b"three".to_vec(), lease("c", 500))
            .await
            .unwrap();
        assert_eq!(v3, 3);
    }

    #[tokio::test]
    async fn transit_keys_gain_versions_and_reseal_whole() {
        let sm = FleetStateMachine::new();
        let key = TransitKey {
            namespace: "default".into(),
            versions: vec![b"k1".to_vec()],
        };
        assert!(sm.create_transit_key("orders", key.clone()).await.unwrap());
        assert!(!sm.create_transit_key("orders", key).await.unwrap());
        assert_eq!(
            sm.add_transit_key_version("orders", b"k2".to_vec())
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            sm.add_transit_key_version("nope", vec![]).await.unwrap(),
            None
        );

        // A reseal that raced a rotation (wrong version count) is ignored.
        sm.reseal_secrets(
            HashMap::new(),
            HashMap::new(),
            [("orders".to_string(), vec![b"K1".to_vec()])].into(),
        )
        .await
        .unwrap();
        assert_eq!(sm.transit_key("orders").await.unwrap().versions.len(), 2);
        assert_eq!(sm.transit_key("orders").await.unwrap().versions[0], b"k1");
        sm.reseal_secrets(
            HashMap::new(),
            HashMap::new(),
            [("orders".to_string(), vec![b"K1".to_vec(), b"K2".to_vec()])].into(),
        )
        .await
        .unwrap();
        assert_eq!(sm.transit_key("orders").await.unwrap().versions[1], b"K2");

        assert!(sm.delete_transit_key("orders").await.unwrap());
        assert!(sm.transit_keys().await.is_empty());
    }

    #[tokio::test]
    async fn placement_moves_are_listed_by_instance() {
        let sm = FleetStateMachine::new();
        sm.set_placement_move("db", "db-0", "node-3").await.unwrap();
        sm.set_placement_move("db", "db-1", "node-1").await.unwrap();
        sm.set_replica_override("db", 2).await.unwrap();
        let moves = sm.placement_moves().await;
        assert_eq!(moves.len(), 2);
        assert_eq!(moves[&("db".into(), "db-0".into())], "node-3");
        sm.clear_placement_move("db", "db-0").await.unwrap();
        assert_eq!(
            sm.placement_moves().await.into_keys().collect::<Vec<_>>(),
            vec![("db".to_string(), "db-1".to_string())]
        );
    }

    #[tokio::test]
    async fn checkpoint_compacts_and_later_writes_replay() {
        let dir = tempfile::tempdir().unwrap();
        let sm = durable_initialized(dir.path(), 1).await;
        for i in 0..5 {
            sm.apply_next(put(&format!("k{i}"), "v")).await.unwrap();
        }
        assert_eq!(sm.checkpoint().await.unwrap(), Some(5));
        assert_eq!(
            std::fs::read_dir(dir.path().join("raft/log"))
                .unwrap()
                .count(),
            0
        );
        sm.apply_next(put("after", "x")).await.unwrap();

        let reloaded = durable(dir.path(), 1);
        reloaded.load().await.unwrap();
        assert_eq!(reloaded.last_applied().await, 6);
        assert_eq!(reloaded.kv_get("k4").await, Some(b"v".to_vec()));
        assert_eq!(reloaded.kv_get("after").await, Some(b"x".to_vec()));
    }

    #[tokio::test]
    async fn installed_snapshot_replaces_persisted_state() {
        let dir = tempfile::tempdir().unwrap();
        let sm = durable_initialized(dir.path(), 1).await;
        sm.apply_next(put("old", "1")).await.unwrap();
        sm.apply_next(put("old2", "2")).await.unwrap();

        // An operator backup taken from a different (older) fleet.
        let other = FleetStateMachine::new();
        other.apply_next(put("restored", "yes")).await.unwrap();
        let backup = other.snapshot().await;

        let index = sm.install_snapshot(&backup).await.unwrap();
        assert_eq!(index, 3, "restores take a fresh index");
        sm.apply_next(put("next", "z")).await.unwrap();

        let reloaded = durable(dir.path(), 1);
        reloaded.load().await.unwrap();
        assert_eq!(reloaded.kv_get("old").await, None);
        assert_eq!(reloaded.kv_get("restored").await, Some(b"yes".to_vec()));
        assert_eq!(reloaded.kv_get("next").await, Some(b"z".to_vec()));
        assert_eq!(reloaded.last_applied().await, 4);
    }

    #[tokio::test]
    async fn unreadable_state_fails_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let sm = durable_initialized(dir.path(), 1).await;
        sm.apply_next(put("a", "1")).await.unwrap();

        let wrong_key = durable(dir.path(), 2);
        assert!(wrong_key.load().await.is_err());
    }

    #[tokio::test]
    async fn failed_persist_applies_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let sm = durable_initialized(dir.path(), 1).await;
        let log = dir.path().join("raft/log");
        std::fs::remove_dir(&log).unwrap();
        std::fs::write(&log, b"not a directory").unwrap();

        assert!(sm.apply_next(put("a", "1")).await.is_err());
        assert_eq!(sm.kv_get("a").await, None);
        assert_eq!(sm.last_applied().await, 0);
    }

    #[tokio::test]
    async fn legacy_fleet_key_storage_is_re_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let fleet_key = [9u8; 32];
        let legacy = RaftStorage::new(dir.path(), &fleet_key);
        legacy.initialize().await.unwrap();
        for (index, key) in [(1, "a"), (2, "b")] {
            legacy
                .append_log_legacy_format(&LogEntry {
                    index,
                    term: TERM,
                    command: put(key, "v"),
                })
                .await
                .unwrap();
        }

        let storage = RaftStorage::new(dir.path(), &[1; 32]).with_legacy_key(&fleet_key);
        let sm = FleetStateMachine::with_log(Arc::new(storage));
        sm.load().await.unwrap();
        assert_eq!(sm.kv_get("b").await, Some(b"v".to_vec()));

        // Everything is now under the Raft key alone.
        let migrated = durable(dir.path(), 1);
        migrated.load().await.unwrap();
        assert_eq!(migrated.last_applied().await, 2);
        assert_eq!(migrated.kv_get("a").await, Some(b"v".to_vec()));
    }

    fn deploy(path: &str, machines: &[&str]) -> Command {
        Command::Deploy {
            service_name: "web".into(),
            store_path: path.into(),
            placements: machines
                .iter()
                .enumerate()
                .map(|(i, m)| PlacementRecord {
                    instance_id: format!("web-{i}"),
                    machine_name: m.to_string(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn generations_track_store_paths_with_bounded_history() {
        let sm = FleetStateMachine::new();
        sm.apply_next(deploy("/nix/store/v1", &["a"]))
            .await
            .unwrap();
        // Placement-only change keeps the generation.
        sm.apply_next(deploy("/nix/store/v1", &["a", "b"]))
            .await
            .unwrap();
        let web = sm.get_deployment("web").await.unwrap();
        assert_eq!(web.generation, 1);
        assert_eq!(web.placements.len(), 2);
        assert!(web.history.is_empty());

        for v in 2..=15 {
            sm.apply_next(deploy(&format!("/nix/store/v{v}"), &["a"]))
                .await
                .unwrap();
        }
        let web = sm.get_deployment("web").await.unwrap();
        assert_eq!(web.generation, 15);
        assert_eq!(web.history.len(), MAX_DEPLOYMENT_HISTORY);
        assert_eq!(web.history.first().unwrap().generation, 5);
        assert_eq!(web.revision(14).unwrap().store_path, "/nix/store/v14");
        assert_eq!(web.revision(15).unwrap().store_path, "/nix/store/v15");
        assert!(web.revision(4).is_none());

        assert!(!web.differs_from("/nix/store/v15", &web.placements));
        assert!(web.differs_from("/nix/store/v16", &web.placements));
        assert!(web.differs_from("/nix/store/v15", &[]));
    }
}
