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
    /// Last applied log index
    last_applied: u64,
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
}
