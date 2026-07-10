#![allow(dead_code)]

use std::collections::HashMap;

use crate::attestation::join_token::JoinTokenStore;
use crate::config::{CloudProviderConfig, FleetConfig};
use crate::server::scaling::{CreateMachineRequest, PoolScalingDecision, PoolScalingEngine};

use super::bootstrap;
use super::instance_tracker::InstanceTracker;
use super::CloudProviderRegistry;

/// Maximum number of instances to create per pool per evaluation cycle.
const MAX_SCALE_UP_PER_CYCLE: u32 = 3;

/// Bridges pool scaling decisions to cloud provider actions.
///
/// On each cycle the actuator:
/// 1. Evaluates pool scaling policies via [`PoolScalingEngine`]
/// 2. For scale-up: provisions new cloud VMs and registers join tokens
/// 3. For scale-down: selects a victim, drains it, and terminates
pub struct ScalingActuator {
    pool_engine: PoolScalingEngine,
    providers: CloudProviderRegistry,
    tracker: InstanceTracker,
    join_tokens: JoinTokenStore,
    fleet_config: FleetConfig,
    server_addr: String,
    ca_cert_pem: String,
}

impl ScalingActuator {
    pub fn new(
        pool_engine: PoolScalingEngine,
        providers: CloudProviderRegistry,
        tracker: InstanceTracker,
        join_tokens: JoinTokenStore,
        fleet_config: FleetConfig,
        server_addr: String,
        ca_cert_pem: String,
    ) -> Self {
        Self {
            pool_engine,
            providers,
            tracker,
            join_tokens,
            fleet_config,
            server_addr,
            ca_cert_pem,
        }
    }

    /// Run a single scaling evaluation cycle.
    pub async fn run_cycle(&mut self) {
        let decisions = self.pool_engine.evaluate().await;

        for decision in decisions {
            if decision.desired_count > decision.current_count {
                self.handle_scale_up(&decision).await;
            } else if decision.desired_count < decision.current_count {
                self.handle_scale_down(&decision).await;
            }
        }
    }

    /// Provision new cloud VMs for a scale-up decision.
    async fn handle_scale_up(&mut self, decision: &PoolScalingDecision) {
        let Some(provider) = self.providers.get(&decision.pool_name) else {
            tracing::debug!(
                pool = %decision.pool_name,
                "No cloud provider configured for pool — skipping scale-up"
            );
            return;
        };

        let Some(pool_config) = self.fleet_config.node_pools.get(&decision.pool_name) else {
            return;
        };
        let Some(cloud_config) = &pool_config.cloud else {
            return;
        };

        let instances_to_create = (decision.desired_count - decision.current_count)
            .min(MAX_SCALE_UP_PER_CYCLE);

        for _ in 0..instances_to_create {
            match self
                .create_instance(&decision.pool_name, cloud_config, provider)
                .await
            {
                Ok(instance_id) => {
                    tracing::info!(
                        pool = %decision.pool_name,
                        instance_id = %instance_id,
                        "Cloud instance created for pool scale-up"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        pool = %decision.pool_name,
                        error = %e,
                        "Failed to create cloud instance"
                    );
                    break; // Stop trying if one fails
                }
            }
        }

        self.pool_engine.record_scale(&decision.pool_name);
    }

    /// Select and terminate a cloud VM for a scale-down decision.
    async fn handle_scale_down(&mut self, decision: &PoolScalingDecision) {
        let Some(provider) = self.providers.get(&decision.pool_name) else {
            tracing::debug!(
                pool = %decision.pool_name,
                "No cloud provider configured for pool — skipping scale-down"
            );
            return;
        };

        let instances_to_remove = decision.current_count - decision.desired_count;

        for _ in 0..instances_to_remove {
            let Some(candidate) = self
                .tracker
                .select_scaledown_candidate(&decision.pool_name)
                .await
            else {
                tracing::debug!(
                    pool = %decision.pool_name,
                    "No cloud instances to remove for scale-down"
                );
                break;
            };

            // TODO: Drain the node before termination if it has joined the fleet.
            // For now, we terminate directly. The reconciler will reschedule
            // any services that were running on the terminated node.

            match provider
                .destroy_machine(&candidate.cloud_instance_id)
                .await
            {
                Ok(()) => {
                    self.tracker
                        .untrack(&candidate.cloud_instance_id)
                        .await;
                    tracing::info!(
                        pool = %decision.pool_name,
                        instance_id = %candidate.cloud_instance_id,
                        "Cloud instance terminated for pool scale-down"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        pool = %decision.pool_name,
                        instance_id = %candidate.cloud_instance_id,
                        error = %e,
                        "Failed to terminate cloud instance"
                    );
                    break;
                }
            }
        }

        self.pool_engine.record_scale(&decision.pool_name);
    }

    /// Create a single cloud instance and track it.
    async fn create_instance(
        &self,
        pool_name: &str,
        cloud_config: &CloudProviderConfig,
        provider: &dyn super::CloudProviderDyn,
    ) -> Result<String, anyhow::Error> {
        // Generate a one-time join token for this instance
        let token = generate_join_token();
        self.join_tokens.register(&token).await;

        // Generate user-data bootstrap script
        let user_data =
            bootstrap::generate_user_data(&self.server_addr, &token, &self.ca_cert_pem);

        let request = CreateMachineRequest {
            pool: pool_name.to_string(),
            labels: HashMap::new(),
            instance_type: cloud_config.instance_type.clone(),
            image_id: cloud_config.image_id.clone(),
            user_data,
            region: cloud_config.region.clone(),
            zone: cloud_config.zone.clone(),
            fleet_name: self.fleet_config.name.clone(),
            subnet_id: cloud_config.subnet_id.clone(),
            security_group_ids: cloud_config.security_group_ids.clone(),
            ssh_key_name: cloud_config.ssh_key_name.clone(),
            disk_size_gb: cloud_config.disk_size_gb,
            resource_group: cloud_config.resource_group.clone(),
            project: cloud_config.project.clone(),
        };

        let instance = provider.create_machine(&request).await?;
        let instance_id = instance.instance_id.clone();
        let provider_name = instance.provider.clone();

        // Track the instance in Raft state
        self.tracker
            .track(
                &instance_id,
                &provider_name,
                pool_name,
                instance.private_ip.as_deref(),
            )
            .await;

        Ok(instance_id)
    }

    /// Periodic reconciliation: detect orphaned cloud instances and clean them up.
    pub async fn reconcile_orphans(&self) {
        for (pool_name, _pool_config) in &self.fleet_config.node_pools {
            let Some(provider) = self.providers.get(pool_name) else {
                continue;
            };

            let tracked = self.tracker.for_pool(pool_name).await;
            let tracked_ids: std::collections::HashSet<String> = tracked
                .iter()
                .map(|i| i.cloud_instance_id.clone())
                .collect();

            match provider
                .list_fleet_machines(&self.fleet_config.name, pool_name)
                .await
            {
                Ok(cloud_instances) => {
                    for cloud_inst in &cloud_instances {
                        if !tracked_ids.contains(&cloud_inst.instance_id) {
                            tracing::warn!(
                                pool = %pool_name,
                                instance_id = %cloud_inst.instance_id,
                                "Orphaned cloud instance detected — terminating"
                            );
                            if let Err(e) =
                                provider.destroy_machine(&cloud_inst.instance_id).await
                            {
                                tracing::error!(
                                    instance_id = %cloud_inst.instance_id,
                                    error = %e,
                                    "Failed to terminate orphaned instance"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        pool = %pool_name,
                        error = %e,
                        "Failed to list cloud instances for orphan reconciliation"
                    );
                }
            }
        }
    }
}

/// Generate a cryptographically random join token (64 hex chars = 256 bits).
fn generate_join_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("system RNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
