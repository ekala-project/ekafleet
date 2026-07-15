use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Fleet state machine for Raft consensus.
/// Stores all persistent fleet state: deployments, secrets, DNS, scheduling plans.
#[derive(Clone)]
pub struct FleetStateMachine {
    inner: Arc<RwLock<StateMachineInner>>,
}

#[derive(Default, Serialize, Deserialize)]
struct StateMachineInner {
    /// Current deployed services and their placements
    deployments: HashMap<String, DeploymentState>,
    /// Encrypted secrets
    secrets: HashMap<String, HashMap<String, Vec<u8>>>,
    /// DNS zone data
    dns_zones: HashMap<String, Vec<DnsEntry>>,
    /// General-purpose key-value store (used for volume tracking, etc.)
    #[serde(default)]
    kv: HashMap<String, Vec<u8>>,
    /// Cloud-provisioned machine instances tracked across the fleet.
    #[serde(default)]
    cloud_instances: HashMap<String, TrackedCloudInstance>,
    /// Last applied log index
    last_applied: u64,
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
    pub generation: u64,
    pub deployed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        }
    }

    /// Apply a command to the state machine.
    pub async fn apply(&self, index: u64, command: Command) {
        let mut state = self.inner.write().await;

        if index <= state.last_applied {
            return; // Already applied
        }

        match command {
            Command::Deploy {
                service_name,
                store_path,
                placements,
            } => {
                let generation = state
                    .deployments
                    .get(&service_name)
                    .map(|d| d.generation + 1)
                    .unwrap_or(1);

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                state.deployments.insert(
                    service_name.clone(),
                    DeploymentState {
                        service_name,
                        store_path,
                        placements,
                        generation,
                        deployed_at: now,
                    },
                );
            }
            Command::Undeploy { service_name } => {
                state.deployments.remove(&service_name);
            }
            Command::PutSecret {
                service_name,
                secret_name,
                encrypted_value,
            } => {
                state
                    .secrets
                    .entry(service_name)
                    .or_default()
                    .insert(secret_name, encrypted_value);
            }
            Command::DeleteSecret {
                service_name,
                secret_name,
            } => {
                if let Some(svc) = state.secrets.get_mut(&service_name) {
                    svc.remove(&secret_name);
                }
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
                    inst.joined_at = Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    );
                }
            }
            Command::UntrackCloudInstance { instance_id } => {
                state.cloud_instances.remove(&instance_id);
            }
        }

        state.last_applied = index;
    }

    /// Get the current deployment state for a service.
    pub async fn get_deployment(&self, service_name: &str) -> Option<DeploymentState> {
        let state = self.inner.read().await;
        state.deployments.get(service_name).cloned()
    }

    /// Get all current deployments.
    pub async fn all_deployments(&self) -> HashMap<String, DeploymentState> {
        let state = self.inner.read().await;
        state.deployments.clone()
    }

    /// Serialize the state machine for snapshotting.
    pub async fn snapshot(&self) -> Vec<u8> {
        let state = self.inner.read().await;
        serde_json::to_vec(&*state).unwrap_or_default()
    }

    /// Restore from a snapshot.
    pub async fn restore(&self, data: &[u8]) -> Result<(), serde_json::Error> {
        let restored: StateMachineInner = serde_json::from_slice(data)?;
        let mut state = self.inner.write().await;
        *state = restored;
        Ok(())
    }

    /// Get the last applied log index.
    pub async fn last_applied(&self) -> u64 {
        let state = self.inner.read().await;
        state.last_applied
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

    /// Set a runtime replica count override for a service.
    /// Stored in the KV store so it survives snapshots.
    /// The reconciler reads this to override the config-defined replica count.
    pub async fn set_replica_override(&self, service_name: &str, count: u32) {
        let key = format!("replica-override/{service_name}");
        let value = count.to_le_bytes().to_vec();
        let mut state = self.inner.write().await;
        state.kv.insert(key, value);
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

    /// Clear a runtime replica count override for a service.
    pub async fn clear_replica_override(&self, service_name: &str) {
        let key = format!("replica-override/{service_name}");
        let mut state = self.inner.write().await;
        state.kv.remove(&key);
    }
}
