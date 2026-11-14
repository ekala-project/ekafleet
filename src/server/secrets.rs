//! Static secret distribution.
//!
//! Values live in Raft sealed under the fleet key. Each node gets, for the
//! services assigned to it, only the secrets those services declare,
//! re-encrypted under the key derived for that node, which it is sent first.

#![allow(clippy::result_large_err)] // tonic::Status, as in every gRPC handler

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use tonic::{Request, Status};
use zeroize::Zeroizing;

use super::api::{FleetControlService, FleetKeyState};
use super::audit::{AuditAction, AuditOutcome};
use super::rbac::{Permission, require_permission};
use super::state::FleetState;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    DeleteSecretRequest, DeleteSecretResponse, FleetKeyUpdate, ListSecretsRequest,
    ListSecretsResponse, RotateFleetKeyResponse, SecretInfo, SecretUpdate, ServerMessage,
    SetSecretRequest, SetSecretResponse,
};
use crate::raft::state::FleetStateMachine;
use crate::secrets::key_derivation::derive_agent_key;
use crate::secrets::store::SecretStore;

/// Where a rotated fleet key is staged until the secrets are resealed under
/// it (see [`settle_fleet_key`]).
pub const NEXT_FLEET_KEY_FILE: &str = "fleet-key.next";

/// Fallback interval; assignments and secret changes wake the publisher.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);

/// Pushes static secrets to the nodes whose services declare them.
pub struct SecretPublisher {
    state: FleetState,
    raft: FleetStateMachine,
    fleet_key: Arc<RwLock<FleetKeyState>>,
    store: Arc<RwLock<SecretStore>>,
    domain: String,
    sent: Mutex<HashMap<String, NodeSent>>,
}

/// What one control stream has been sent.
#[derive(Default)]
struct NodeSent {
    connection_id: u64,
    key_version: u64,
    /// (service, secret) → version sent; 0 = sent as deleted.
    secrets: HashMap<(String, String), u64>,
}

impl SecretPublisher {
    pub fn new(
        state: FleetState,
        raft: FleetStateMachine,
        fleet_key: Arc<RwLock<FleetKeyState>>,
        store: Arc<RwLock<SecretStore>>,
        domain: &str,
    ) -> Self {
        Self {
            state,
            raft,
            fleet_key,
            store,
            domain: domain.to_string(),
            sent: Mutex::default(),
        }
    }

    /// Send every connected node the declared secrets of its services that
    /// it has not been sent on its current stream. Returns how many secret
    /// updates were sent.
    pub async fn publish(&self) -> usize {
        // Lock order (fleet key, then store) matches key rotation, so a
        // node never gets values sealed under a key it has not been sent.
        let fleet_key = self.fleet_key.read().await;
        if fleet_key.version == 0 {
            return 0;
        }
        let store = self.store.read().await;
        let stored = self.raft.secrets().await;
        let connections = self.state.connections().await;
        let mut sent = self.sent.lock().await;
        sent.retain(|node, _| connections.iter().any(|(n, _)| n == node));

        let mut count = 0;
        for (node, connection_id) in connections {
            let Some(desired) = self.state.assigned_desired_state(&node).await else {
                continue;
            };
            let entry = sent.entry(node.clone()).or_default();
            if entry.connection_id != connection_id {
                *entry = NodeSent {
                    connection_id,
                    ..Default::default()
                };
            }
            let agent_id = format!("spiffe://{}/agent/{}", self.domain, node);

            let mut wanted = HashSet::new();
            let mut updates = Vec::new();
            for spec in &desired.services {
                for name in &spec.secrets {
                    let key = (spec.name.clone(), name.clone());
                    let update = match stored.get(&spec.name).and_then(|s| s.get(name)) {
                        Some((sealed, version)) if entry.secrets.get(&key) != Some(version) => {
                            match store.seal_for_agent(&spec.name, name, sealed, &agent_id) {
                                Ok(encrypted_value) => Some(SecretUpdate {
                                    service_name: spec.name.clone(),
                                    secret_name: name.clone(),
                                    encrypted_value,
                                    version: *version,
                                    deleted: false,
                                }),
                                Err(e) => {
                                    tracing::error!(
                                        service = %spec.name,
                                        secret = %name,
                                        error = %e,
                                        "Cannot re-encrypt secret for agent"
                                    );
                                    None
                                }
                            }
                        }
                        None if entry.secrets.get(&key) != Some(&0) => Some(SecretUpdate {
                            service_name: spec.name.clone(),
                            secret_name: name.clone(),
                            deleted: true,
                            ..Default::default()
                        }),
                        _ => None,
                    };
                    if let Some(update) = update {
                        updates.push((key.clone(), update));
                    }
                    wanted.insert(key);
                }
            }
            entry.secrets.retain(|key, _| wanted.contains(key));
            if updates.is_empty() {
                continue;
            }

            if entry.key_version != fleet_key.version {
                let derived = zeroize::Zeroizing::new(derive_agent_key(&fleet_key.key, &agent_id));
                let msg = ServerMessage {
                    payload: Some(ServerPayload::FleetKey(FleetKeyUpdate {
                        encrypted_key: derived.to_vec(),
                        version: fleet_key.version,
                    })),
                };
                if !self.state.send_to_agent(&node, msg).await {
                    continue;
                }
                entry.key_version = fleet_key.version;
            }
            for (key, update) in updates {
                let version = update.version;
                let msg = ServerMessage {
                    payload: Some(ServerPayload::Secret(update)),
                };
                if !self.state.send_to_agent(&node, msg).await {
                    break;
                }
                tracing::debug!(node = %node, service = %key.0, secret = %key.1, version, "Secret sent");
                entry.secrets.insert(key, version);
                count += 1;
            }
        }
        count
    }

    /// Publish on every assignment or secret change, and every
    /// [`PUBLISH_INTERVAL`], until `shutdown`.
    pub fn spawn(self, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        let wake = self.state.assignments_changed();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PUBLISH_INTERVAL);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => {}
                    _ = wake.notified() => {}
                }
                self.publish().await;
            }
        })
    }
}

/// Warnings for static secrets `config` declares that have no value yet:
/// those services do not start until they are set.
pub async fn missing_secret_warnings(
    config: &crate::config::FleetConfig,
    raft: &FleetStateMachine,
) -> Vec<String> {
    let stored = raft.secrets().await;
    let mut warnings: Vec<String> = config
        .services
        .iter()
        .flat_map(|(service, cfg)| {
            crate::config::static_secrets(cfg)
                .into_iter()
                .filter(|name| !stored.get(service).is_some_and(|s| s.contains_key(name)))
                .map(|name| {
                    format!(
                        "service '{service}' declares secret '{name}', which has no value; \
                         it will not start until `ekafleet secret set {service} {name}`"
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    warnings.sort();
    warnings
}

/// Whether `key` opens the first stored secret (`None` if there are none).
fn key_opens_secrets(
    key: &[u8; 32],
    secrets: &HashMap<String, HashMap<String, (Vec<u8>, u64)>>,
) -> Option<bool> {
    let store = SecretStore::new(key);
    secrets.iter().find_map(|(service, values)| {
        values
            .iter()
            .next()
            .map(|(name, (sealed, _))| store.open(service, name, sealed).is_ok())
    })
}

/// Finish or undo a fleet key rotation interrupted by a crash: a staged key
/// is adopted if the stored secrets were already resealed under it (or
/// there are none) and discarded otherwise. Returns the fleet key to use.
pub async fn settle_fleet_key(
    data_dir: &std::path::Path,
    current: Zeroizing<Vec<u8>>,
    staged: Option<Zeroizing<Vec<u8>>>,
    raft: &FleetStateMachine,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let Some(staged) = staged else {
        return Ok(current);
    };
    let next = data_dir.join(NEXT_FLEET_KEY_FILE);
    let as_array = |key: &[u8]| -> anyhow::Result<[u8; 32]> {
        key.try_into()
            .map_err(|_| anyhow::anyhow!("fleet key must be 32 bytes"))
    };
    let secrets = raft.secrets().await;
    let current_opens = key_opens_secrets(&Zeroizing::new(as_array(&current)?), &secrets);
    let staged_opens = key_opens_secrets(&Zeroizing::new(as_array(&staged)?), &secrets);
    match (current_opens, staged_opens) {
        (Some(true), _) => {
            tracing::warn!("Discarding a fleet key rotation that did not complete");
            tokio::fs::remove_file(&next).await?;
            Ok(current)
        }
        (None, _) | (_, Some(true)) => {
            tracing::warn!("Completing an interrupted fleet key rotation");
            tokio::fs::rename(&next, data_dir.join("fleet-key")).await?;
            Ok(staged)
        }
        _ => anyhow::bail!(
            "stored secrets open with neither {} nor {}",
            data_dir.join("fleet-key").display(),
            next.display()
        ),
    }
}

#[allow(clippy::result_large_err)]
fn check_names(service: &str, secret: &str) -> Result<(), Status> {
    crate::secrets::validate_name("service", service).map_err(Status::invalid_argument)?;
    crate::secrets::validate_name("secret", secret).map_err(Status::invalid_argument)
}

impl FleetControlService {
    /// The publisher pushing this server's secrets to agents.
    pub fn secret_publisher(&self) -> SecretPublisher {
        SecretPublisher::new(
            self.state.clone(),
            self.raft_state.clone(),
            self.fleet_key.clone(),
            self.secret_store.clone(),
            &self.domain,
        )
    }

    pub(super) async fn handle_set_secret(
        &self,
        request: Request<SetSecretRequest>,
    ) -> Result<SetSecretResponse, Status> {
        require_permission(&request, Permission::ManageSecrets)?;
        let req = request.get_ref();
        let resource = format!("{}/{}", req.service_name, req.secret_name);
        check_names(&req.service_name, &req.secret_name)?;
        if req.value.is_empty() {
            return Err(Status::invalid_argument("secret value is empty"));
        }
        if req.value.len() > crate::secrets::MAX_SECRET_SIZE {
            return Err(Status::invalid_argument(format!(
                "secret value exceeds {} bytes",
                crate::secrets::MAX_SECRET_SIZE
            )));
        }
        self.require_service_access(&request, &req.service_name)
            .await?;

        let (actor_request, req) = {
            let (metadata, extensions, req) = request.into_parts();
            (Request::from_parts(metadata, extensions, ()), req)
        };
        let value = Zeroizing::new(req.value);
        // Sealed and stored under the read locks, so a key rotation cannot
        // reseal the stored values in between and miss this one.
        let version = {
            let _fleet_key = self.fleet_key.read().await;
            let store = self.secret_store.read().await;
            let sealed = store
                .seal(&req.service_name, &req.secret_name, &value)
                .map_err(|e| Status::internal(e.to_string()))?;
            self.raft_state
                .put_secret(&req.service_name, &req.secret_name, sealed)
                .await
                .map_err(|e| Status::internal(format!("failed to store secret: {e}")))?
        };
        self.audit(
            &actor_request,
            AuditAction::SecretWrite,
            &resource,
            &format!("set version {version}"),
            AuditOutcome::Success,
        )
        .await;
        tracing::info!(service = %req.service_name, secret = %req.secret_name, version, "Secret stored");
        self.state.assignments_changed().trigger();
        Ok(SetSecretResponse { version })
    }

    pub(super) async fn handle_list_secrets(
        &self,
        request: Request<ListSecretsRequest>,
    ) -> Result<ListSecretsResponse, Status> {
        require_permission(&request, Permission::Read)?;
        let filter = request.get_ref().service_name.clone();
        if !filter.is_empty() {
            self.require_service_access(&request, &filter).await?;
        }
        let visible = self.visible_services(&request).await;

        // (service, secret) → (version, declared)
        let mut entries: std::collections::BTreeMap<(String, String), (u64, bool)> =
            Default::default();
        for (service, values) in self.raft_state.secrets().await {
            for (name, (_, version)) in values {
                entries.insert((service.clone(), name), (version, false));
            }
        }
        if let Some(Ok(config)) = self.raft_state.current_config().await.map(|r| r.config()) {
            for (service, cfg) in &config.services {
                for name in crate::config::static_secrets(cfg) {
                    entries.entry((service.clone(), name)).or_default().1 = true;
                }
            }
        }
        let secrets = entries
            .into_iter()
            .filter(|((service, _), _)| filter.is_empty() || *service == filter)
            .filter(|((service, _), _)| visible.as_ref().is_none_or(|v| v.contains(service)))
            .map(
                |((service_name, secret_name), (version, declared))| SecretInfo {
                    service_name,
                    secret_name,
                    version,
                    declared,
                },
            )
            .collect();
        Ok(ListSecretsResponse { secrets })
    }

    pub(super) async fn handle_delete_secret(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<DeleteSecretResponse, Status> {
        require_permission(&request, Permission::ManageSecrets)?;
        let req = request.get_ref();
        check_names(&req.service_name, &req.secret_name)?;
        self.require_service_access(&request, &req.service_name)
            .await?;
        let deleted = self
            .raft_state
            .delete_secret(&req.service_name, &req.secret_name)
            .await
            .map_err(|e| Status::internal(format!("failed to delete secret: {e}")))?;
        self.audit(
            &request,
            AuditAction::SecretWrite,
            &format!("{}/{}", req.service_name, req.secret_name),
            if deleted {
                "delete"
            } else {
                "delete (no value)"
            },
            AuditOutcome::Success,
        )
        .await;
        if deleted {
            tracing::info!(service = %req.service_name, secret = %req.secret_name, "Secret deleted");
            self.state.assignments_changed().trigger();
        }
        Ok(DeleteSecretResponse { deleted })
    }

    /// Replace the fleet key: every stored secret is resealed under the new
    /// key, and agents get their new derived key before any value sealed
    /// for it. The new key is staged on disk until the resealed values are
    /// stored, so a crash in between is settled at boot.
    pub(super) async fn handle_rotate_fleet_key(&self) -> Result<RotateFleetKeyResponse, Status> {
        use ring::rand::{SecureRandom, SystemRandom};
        tracing::info!("Fleet key rotation requested");

        let mut new_key = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(new_key.as_mut())
            .map_err(|_| Status::internal("RNG failure during key generation"))?;
        let new_store = SecretStore::new(&new_key);

        let mut fleet_key = self.fleet_key.write().await;
        let mut store = self.secret_store.write().await;
        let mut resealed: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
        let mut count = 0usize;
        for (service, values) in self.raft_state.secrets().await {
            for (name, (sealed, _)) in values {
                let value = store.open(&service, &name, &sealed).map_err(|e| {
                    Status::internal(format!("secret {service}/{name} is unreadable: {e}"))
                })?;
                let sealed = new_store
                    .seal(&service, &name, &value)
                    .map_err(|e| Status::internal(e.to_string()))?;
                resealed
                    .entry(service.clone())
                    .or_default()
                    .insert(name, sealed);
                count += 1;
            }
        }

        let hex: Zeroizing<String> =
            Zeroizing::new(new_key.iter().map(|b| format!("{b:02x}")).collect());
        let staged = self.data_dir.join(NEXT_FLEET_KEY_FILE);
        super::seal::write_maybe_sealed(&staged, hex.as_bytes(), "staged fleet encryption key")
            .await
            .map_err(|e| Status::internal(format!("failed to stage rotated key: {e}")))?;
        if let Err(e) = self.raft_state.reseal_secrets(resealed).await {
            let _ = tokio::fs::remove_file(&staged).await;
            return Err(Status::internal(format!(
                "failed to store resealed secrets: {e}"
            )));
        }
        tokio::fs::rename(&staged, self.data_dir.join("fleet-key"))
            .await
            .map_err(|e| Status::internal(format!("failed to commit rotated key: {e}")))?;

        let prev_version = fleet_key.version;
        fleet_key.version += 1;
        fleet_key.key = Zeroizing::new(new_key.to_vec());
        *store = new_store;
        let new_version = fleet_key.version;

        // Push the new derived key to every connected agent now; the
        // publisher also re-sends it before any value sealed under it.
        let node_ids = self.state.connected_nodes().await;
        let mut notified: u32 = 0;
        for node in &node_ids {
            let agent_id = format!("spiffe://{}/agent/{}", self.domain, node);
            let derived = Zeroizing::new(derive_agent_key(new_key.as_ref(), &agent_id));
            let msg = ServerMessage {
                payload: Some(ServerPayload::FleetKey(FleetKeyUpdate {
                    encrypted_key: derived.to_vec(),
                    version: new_version,
                })),
            };
            if self.state.send_to_agent(node, msg).await {
                notified += 1;
            }
        }
        drop(store);
        drop(fleet_key);

        tracing::info!(
            prev_version,
            new_version,
            secrets = count,
            notified,
            total_agents = node_ids.len(),
            "Fleet key rotated"
        );
        Ok(RotateFleetKeyResponse {
            success: true,
            previous_version: prev_version,
            new_version,
            agents_notified: notified,
            message: format!(
                "Fleet key rotated from v{prev_version} to v{new_version} ({count} secrets resealed), \
                 {notified}/{} agents notified",
                node_ids.len()
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{DesiredState, ServiceSpec};

    const FLEET_KEY: [u8; 32] = [3; 32];

    fn publisher(state: &FleetState, raft: &FleetStateMachine) -> SecretPublisher {
        SecretPublisher::new(
            state.clone(),
            raft.clone(),
            Arc::new(RwLock::new(FleetKeyState {
                key: Zeroizing::new(FLEET_KEY.to_vec()),
                version: 1,
            })),
            Arc::new(RwLock::new(SecretStore::new(&FLEET_KEY))),
            "fleet.test",
        )
    }

    async fn put(raft: &FleetStateMachine, service: &str, name: &str, value: &[u8]) -> u64 {
        let sealed = SecretStore::new(&FLEET_KEY)
            .seal(service, name, value)
            .unwrap();
        raft.put_secret(service, name, sealed).await.unwrap()
    }

    fn drain(rx: &mut tokio::sync::mpsc::Receiver<ServerMessage>) -> Vec<ServerPayload> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|m| m.payload)
            .filter(|p| !matches!(p, ServerPayload::DesiredState(_)))
            .collect()
    }

    /// Open a pushed secret as the agent would.
    async fn open(update: &SecretUpdate, node: &str) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let mut injector = crate::secrets::injector::SecretInjector::new(dir.path());
        injector.update_key(&derive_agent_key(
            &FLEET_KEY,
            &format!("spiffe://fleet.test/agent/{node}"),
        ));
        injector
            .inject(
                &update.service_name,
                &update.secret_name,
                &update.encrypted_value,
            )
            .await
            .unwrap();
        std::fs::read(
            dir.path()
                .join(&update.service_name)
                .join(&update.secret_name),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn nodes_get_their_key_then_declared_secrets_once_per_version() {
        let state = FleetState::new();
        let raft = FleetStateMachine::new();
        let publisher = publisher(&state, &raft);
        let (_, mut rx) = state
            .register_agent_connection("n1", "10.0.0.1:1".into(), "default".into())
            .await;
        state
            .assign_desired_state(
                "n1",
                DesiredState {
                    services: vec![ServiceSpec {
                        name: "web".into(),
                        secrets: vec!["key".into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            )
            .await;
        put(&raft, "web", "key", b"v1").await;
        // Stored but not declared by anything on n1: never sent.
        put(&raft, "web", "other", b"x").await;
        put(&raft, "db", "key", b"x").await;

        assert_eq!(publisher.publish().await, 1);
        let sent = drain(&mut rx);
        let [ServerPayload::FleetKey(key), ServerPayload::Secret(update)] = &sent[..] else {
            panic!("expected key then secret, got {sent:?}");
        };
        assert_eq!(
            key.encrypted_key,
            derive_agent_key(&FLEET_KEY, "spiffe://fleet.test/agent/n1").to_vec()
        );
        assert_eq!((update.version, update.deleted), (1, false));
        assert_eq!(open(update, "n1").await, b"v1");

        // Nothing new: nothing sent.
        assert_eq!(publisher.publish().await, 0);
        assert!(drain(&mut rx).is_empty());

        // A new version follows (the key was already sent on this stream).
        put(&raft, "web", "key", b"v2").await;
        assert_eq!(publisher.publish().await, 1);
        let sent = drain(&mut rx);
        let [ServerPayload::Secret(update)] = &sent[..] else {
            panic!("expected a secret, got {sent:?}");
        };
        assert_eq!(open(update, "n1").await, b"v2");

        // Deleting sends a removal, once.
        raft.delete_secret("web", "key").await.unwrap();
        assert_eq!(publisher.publish().await, 1);
        let sent = drain(&mut rx);
        assert!(matches!(&sent[..], [ServerPayload::Secret(u)] if u.deleted));
        assert_eq!(publisher.publish().await, 0);

        // A reconnect starts over: key first, then the current value.
        put(&raft, "web", "key", b"v3").await;
        drop(rx);
        let (_, mut rx) = state
            .register_agent_connection("n1", "10.0.0.1:2".into(), "default".into())
            .await;
        assert_eq!(publisher.publish().await, 1);
        let sent = drain(&mut rx);
        let [ServerPayload::FleetKey(_), ServerPayload::Secret(update)] = &sent[..] else {
            panic!("expected key then secret, got {sent:?}");
        };
        assert_eq!(update.version, 3);
        assert_eq!(open(update, "n1").await, b"v3");
    }

    #[tokio::test]
    async fn missing_declared_secrets_are_reported() {
        let raft = FleetStateMachine::new();
        put(&raft, "web", "set", b"x").await;
        let config: crate::config::FleetConfig = serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "services": {"web": {"command": "/bin/web", "secrets": {
                "set": {}, "unset": {}, "engine": {"type": "dynamic"},
            }}},
        }))
        .unwrap();
        let warnings = missing_secret_warnings(&config, &raft).await;
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("'unset'"), "{warnings:?}");
    }

    #[tokio::test]
    async fn interrupted_rotations_settle_to_the_key_that_opens_the_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let old = Zeroizing::new(vec![1u8; 32]);
        let new = Zeroizing::new(vec![2u8; 32]);
        let stage = || std::fs::write(dir.path().join(NEXT_FLEET_KEY_FILE), "staged").unwrap();
        let staged = dir.path().join(NEXT_FLEET_KEY_FILE);

        // No secrets: the staged key wins.
        let raft = FleetStateMachine::new();
        stage();
        let key = settle_fleet_key(dir.path(), old.clone(), Some(new.clone()), &raft)
            .await
            .unwrap();
        assert_eq!(*key, *new);
        assert!(!staged.exists());
        assert!(dir.path().join("fleet-key").exists());

        // Secrets still under the old key: the rotation is discarded.
        let sealed = SecretStore::new(&[1u8; 32]).seal("web", "k", b"v").unwrap();
        raft.put_secret("web", "k", sealed).await.unwrap();
        stage();
        let key = settle_fleet_key(dir.path(), old.clone(), Some(new.clone()), &raft)
            .await
            .unwrap();
        assert_eq!(*key, *old);
        assert!(!staged.exists());

        // Already resealed: the staged key is adopted.
        let sealed = SecretStore::new(&[2u8; 32]).seal("web", "k", b"v").unwrap();
        raft.reseal_secrets([("web".into(), [("k".into(), sealed)].into())].into())
            .await
            .unwrap();
        stage();
        let key = settle_fleet_key(dir.path(), old.clone(), Some(new.clone()), &raft)
            .await
            .unwrap();
        assert_eq!(*key, *new);

        // Neither opens them: refuse to start.
        stage();
        let other = Zeroizing::new(vec![9u8; 32]);
        assert!(
            settle_fleet_key(dir.path(), other.clone(), Some(other), &raft)
                .await
                .is_err()
        );
    }
}
