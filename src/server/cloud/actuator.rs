#![allow(dead_code)]

use std::collections::HashMap;

use crate::attestation::join_token::JoinTokenStore;
use crate::config::{CloudProviderConfig, FleetConfig};
use crate::server::events::{EventCategory, EventLevel, EventStore};
use crate::server::scaling::{CreateMachineRequest, PoolScalingDecision, PoolScalingEngine};
use crate::server::state::FleetState;

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
/// Duration to wait after marking a node unschedulable before terminating.
/// Gives the reconciler time to reschedule services off the node.
const DRAIN_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct ScalingActuator {
    pool_engine: PoolScalingEngine,
    providers: CloudProviderRegistry,
    tracker: InstanceTracker,
    join_tokens: JoinTokenStore,
    fleet_state: FleetState,
    fleet_config: FleetConfig,
    server_addr: String,
    ca_cert_pem: String,
    events: Option<EventStore>,
}

impl ScalingActuator {
    pub fn new(
        pool_engine: PoolScalingEngine,
        providers: CloudProviderRegistry,
        tracker: InstanceTracker,
        join_tokens: JoinTokenStore,
        fleet_state: FleetState,
        fleet_config: FleetConfig,
        server_addr: String,
        ca_cert_pem: String,
    ) -> Self {
        Self {
            pool_engine,
            providers,
            tracker,
            join_tokens,
            fleet_state,
            fleet_config,
            server_addr,
            ca_cert_pem,
            events: None,
        }
    }

    /// Attach an event store for emitting scaling events.
    pub fn with_events(mut self, events: EventStore) -> Self {
        self.events = Some(events);
        self
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
                    if let Some(events) = &self.events {
                        events
                            .emit_detail(
                                EventLevel::Info,
                                EventCategory::Scaling,
                                None,
                                None,
                                &format!(
                                    "Scale up: created cloud instance {instance_id} in pool {}",
                                    decision.pool_name
                                ),
                            )
                            .await;
                    }
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

            // Drain the node before termination if it has joined the fleet.
            if let Some(node_id) = &candidate.fleet_node_id {
                tracing::info!(
                    node_id = %node_id,
                    instance_id = %candidate.cloud_instance_id,
                    "Draining node before cloud instance termination"
                );
                self.fleet_state.set_schedulable(node_id, false).await;
                // Allow time for the reconciler to reschedule services
                // off this node before we terminate it.
                tokio::time::sleep(DRAIN_WAIT).await;
            }

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
                    if let Some(events) = &self.events {
                        events
                            .emit_detail(
                                EventLevel::Info,
                                EventCategory::Scaling,
                                None,
                                candidate.fleet_node_id.as_deref(),
                                &format!(
                                    "Scale down: terminated cloud instance {} in pool {}",
                                    candidate.cloud_instance_id, decision.pool_name
                                ),
                            )
                            .await;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::scaling::{CloudProvider, CreateMachineRequest, MachineInstance, MachineState};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Mock cloud provider that tracks create/destroy calls.
    struct MockCloudProvider {
        creates: AtomicU32,
        destroys: AtomicU32,
    }

    impl MockCloudProvider {
        fn new() -> Self {
            Self {
                creates: AtomicU32::new(0),
                destroys: AtomicU32::new(0),
            }
        }

        fn create_count(&self) -> u32 {
            self.creates.load(Ordering::Relaxed)
        }

        fn destroy_count(&self) -> u32 {
            self.destroys.load(Ordering::Relaxed)
        }
    }

    impl CloudProvider for MockCloudProvider {
        async fn create_machine(
            &self,
            request: &CreateMachineRequest,
        ) -> Result<MachineInstance, anyhow::Error> {
            let n = self.creates.fetch_add(1, Ordering::Relaxed);
            Ok(MachineInstance {
                instance_id: format!("mock-{n}"),
                provider: "mock".to_string(),
                state: MachineState::Running,
                public_ip: None,
                private_ip: Some(format!("10.0.0.{}", 100 + n)),
                labels: request.labels.clone(),
                pool: request.pool.clone(),
                created_at: 1000 + n as u64,
            })
        }

        async fn destroy_machine(&self, _instance_id: &str) -> Result<(), anyhow::Error> {
            self.destroys.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn describe_machine(
            &self,
            _instance_id: &str,
        ) -> Result<Option<MachineInstance>, anyhow::Error> {
            Ok(None)
        }

        async fn list_fleet_machines(
            &self,
            _fleet_name: &str,
            _pool: &str,
        ) -> Result<Vec<MachineInstance>, anyhow::Error> {
            Ok(vec![])
        }
    }

    fn test_fleet_config() -> FleetConfig {
        use crate::config::{
            CapacityConfig, CloudProviderConfig, CloudProviderType, NodePoolConfig,
            PoolScalingConfig, PoolScalingRule,
        };

        let mut node_pools = HashMap::new();
        node_pools.insert(
            "workers".to_string(),
            NodePoolConfig {
                labels: HashMap::new(),
                scaling: Some(PoolScalingConfig {
                    min_count: 1,
                    max_count: 5,
                    rules: vec![PoolScalingRule {
                        metric_name: "cpu_utilization".into(),
                        target_value: 0.7,
                        scale_up_threshold: 1.2,
                        scale_down_threshold: 0.5,
                    }],
                }),
                scheduler_algorithm: None,
                memory_oversubscription: false,
                cloud: Some(CloudProviderConfig {
                    provider: CloudProviderType::Aws,
                    region: "us-east-1".into(),
                    instance_type: "t3.large".into(),
                    image_id: "ami-test".into(),
                    subnet_id: None,
                    security_group_ids: vec![],
                    ssh_key_name: None,
                    zone: None,
                    disk_size_gb: None,
                    resource_group: None,
                    project: None,
                    machine_capacity: CapacityConfig {
                        cpu: 2000,
                        memory: 4096,
                        disk: 50000,
                    },
                }),
            },
        );

        FleetConfig {
            name: "test-fleet".into(),
            domain: "fleet.internal".into(),
            services: HashMap::new(),
            machines: HashMap::new(),
            node_pools,
            hooks: Default::default(),
            admission_webhooks: vec![],
        }
    }

    #[tokio::test]
    async fn create_instance_tracks_and_registers_token() {
        let raft = crate::raft::state::FleetStateMachine::new();
        let tracker = InstanceTracker::new(raft);
        let join_tokens = JoinTokenStore::new();
        let fleet_state = FleetState::new();
        let fleet_config = test_fleet_config();
        let pool_engine = crate::server::scaling::PoolScalingEngine::new(fleet_state.clone());

        // Build a registry with the mock provider
        let mut providers: HashMap<String, Box<dyn super::super::CloudProviderDyn>> =
            HashMap::new();
        providers.insert("workers".to_string(), Box::new(MockCloudProvider::new()));
        let registry = super::super::CloudProviderRegistry::from_raw(providers);

        let actuator = ScalingActuator::new(
            pool_engine,
            registry,
            tracker.clone(),
            join_tokens.clone(),
            fleet_state,
            fleet_config.clone(),
            "127.0.0.1:7400".into(),
            "FAKE-CA-PEM".into(),
        );

        let cloud_config = fleet_config.node_pools["workers"].cloud.as_ref().unwrap();
        let provider = MockCloudProvider::new();
        let result = actuator
            .create_instance("workers", cloud_config, &provider)
            .await;

        assert!(result.is_ok());
        let instance_id = result.unwrap();
        assert!(instance_id.starts_with("mock-"));

        // Should be tracked
        assert_eq!(tracker.active_count_for_pool("workers").await, 1);
    }

    #[test]
    fn generate_join_token_is_64_hex_chars() {
        let token = generate_join_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_join_token_is_unique() {
        let a = generate_join_token();
        let b = generate_join_token();
        assert_ne!(a, b);
    }
}
