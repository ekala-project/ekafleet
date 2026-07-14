#![allow(dead_code)]

use std::collections::HashMap;

use crate::attestation::join_token::JoinTokenStore;
use crate::config::{CloudProviderConfig, FleetConfig};
use crate::server::events::{EventCategory, EventLevel, EventStore};
use crate::server::scaling::{CreateMachineRequest, PoolScalingDecision, PoolScalingEngine};
use crate::server::state::FleetState;

use super::CloudProviderRegistry;
use super::bootstrap;
use super::instance_tracker::InstanceTracker;

/// Maximum number of instances to create per pool per evaluation cycle.
const MAX_SCALE_UP_PER_CYCLE: u32 = 3;

/// Bridges pool scaling decisions to cloud provider actions.
///
/// On each cycle the actuator:
/// 1. Evaluates pool scaling policies via [`PoolScalingEngine`]
/// 2. For scale-up: provisions new cloud VMs and registers join tokens
/// 3. For scale-down: selects a victim, drains it, and terminates
/// Default duration to wait after marking a node unschedulable before
/// terminating. Gives the reconciler time to reschedule services off the node.
/// Overridden by `drain_wait_seconds` in CloudProviderConfig.
const DEFAULT_DRAIN_WAIT_SECS: u64 = 30;

/// Maximum backoff duration for repeated failures (10 minutes).
const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(600);

/// Base cooldown for the first failure (60 seconds).
const BASE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

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
    /// Per-pool failure tracking for exponential backoff.
    /// Maps pool name to (consecutive failure count, last failure time).
    failure_counts: HashMap<String, (u32, std::time::Instant)>,
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
            failure_counts: HashMap::new(),
        }
    }

    /// Check if a pool is in backoff due to previous failures.
    fn is_in_backoff(&self, pool_name: &str) -> bool {
        if let Some((count, last_failure)) = self.failure_counts.get(pool_name) {
            let backoff = BASE_BACKOFF
                .mul_f64(2.0_f64.powi((*count).saturating_sub(1) as i32))
                .min(MAX_BACKOFF);
            last_failure.elapsed() < backoff
        } else {
            false
        }
    }

    /// Record a failure for a pool (increments backoff).
    fn record_failure(&mut self, pool_name: &str) {
        let entry = self
            .failure_counts
            .entry(pool_name.to_string())
            .or_insert((0, std::time::Instant::now()));
        entry.0 += 1;
        entry.1 = std::time::Instant::now();

        let backoff = BASE_BACKOFF
            .mul_f64(2.0_f64.powi(entry.0.saturating_sub(1) as i32))
            .min(MAX_BACKOFF);
        tracing::warn!(
            pool = %pool_name,
            failures = entry.0,
            next_retry_secs = backoff.as_secs(),
            "Pool in backoff after provider failure"
        );
    }

    /// Clear backoff for a pool after a successful operation.
    fn clear_failure(&mut self, pool_name: &str) {
        self.failure_counts.remove(pool_name);
    }

    /// Attach an event store for emitting scaling events.
    pub fn with_events(mut self, events: EventStore) -> Self {
        self.events = Some(events);
        self
    }

    /// Run a single scaling evaluation cycle, including launch health checks.
    pub async fn run_cycle(&mut self) {
        // Check for instances that failed to boot or join
        self.check_launch_health().await;

        let decisions = self.pool_engine.evaluate().await;

        for decision in decisions {
            if decision.desired_count > decision.current_count {
                self.handle_scale_up(&decision).await;
            } else if decision.desired_count < decision.current_count {
                self.handle_scale_down(&decision).await;
            }
        }
    }

    /// Detect and clean up instances that failed to boot or whose agent
    /// never joined the fleet within the configured timeout.
    async fn check_launch_health(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (pool_name, pool_config) in &self.fleet_config.node_pools {
            let Some(cloud_config) = &pool_config.cloud else {
                continue;
            };
            let Some(provider) = self.providers.get(pool_name) else {
                continue;
            };

            let join_timeout = cloud_config.join_timeout_seconds;
            let instances = self.tracker.for_pool(pool_name).await;

            for instance in &instances {
                let age = now.saturating_sub(instance.created_at);

                // Instance agent never joined and exceeded join timeout
                if instance.fleet_node_id.is_none() && age > join_timeout {
                    tracing::warn!(
                        pool = %pool_name,
                        instance_id = %instance.cloud_instance_id,
                        age_seconds = age,
                        timeout = join_timeout,
                        "Instance failed to join within timeout, terminating"
                    );

                    if let Err(e) = provider.destroy_machine(&instance.cloud_instance_id).await {
                        tracing::error!(
                            instance_id = %instance.cloud_instance_id,
                            error = %e,
                            "Failed to terminate timed-out instance"
                        );
                        continue;
                    }

                    self.tracker.untrack(&instance.cloud_instance_id).await;

                    if let Some(events) = &self.events {
                        events
                            .emit_detail(
                                EventLevel::Info,
                                EventCategory::Scaling,
                                None,
                                None,
                                &format!(
                                    "Terminated instance {} in pool {} (join timeout after {}s)",
                                    instance.cloud_instance_id, pool_name, age
                                ),
                            )
                            .await;
                    }
                }
            }
        }
    }

    /// Provision new cloud VMs for a scale-up decision.
    async fn handle_scale_up(&mut self, decision: &PoolScalingDecision) {
        // Skip if pool is in backoff from previous failures
        if self.is_in_backoff(&decision.pool_name) {
            tracing::debug!(
                pool = %decision.pool_name,
                "Pool in failure backoff — skipping scale-up"
            );
            return;
        }

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

        let instances_to_create =
            (decision.desired_count - decision.current_count).min(MAX_SCALE_UP_PER_CYCLE);

        let mut any_success = false;
        for _ in 0..instances_to_create {
            match self
                .create_instance(&decision.pool_name, cloud_config, provider)
                .await
            {
                Ok(instance_id) => {
                    any_success = true;
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
                    // If spot instance failed and fallback is enabled, retry on-demand
                    let should_fallback = cloud_config
                        .spot
                        .as_ref()
                        .map(|s| s.enabled && s.fallback_to_on_demand)
                        .unwrap_or(false);

                    if should_fallback {
                        tracing::warn!(
                            pool = %decision.pool_name,
                            error = %e,
                            "Spot instance creation failed, falling back to on-demand"
                        );
                        let mut fallback_config = cloud_config.clone();
                        fallback_config.spot = None;
                        match self
                            .create_instance(&decision.pool_name, &fallback_config, provider)
                            .await
                        {
                            Ok(instance_id) => {
                                any_success = true;
                                tracing::info!(
                                    pool = %decision.pool_name,
                                    instance_id = %instance_id,
                                    "On-demand fallback instance created"
                                );
                            }
                            Err(e2) => {
                                tracing::error!(
                                    pool = %decision.pool_name,
                                    error = %e2,
                                    "On-demand fallback also failed"
                                );
                                self.record_failure(&decision.pool_name);
                                break;
                            }
                        }
                    } else {
                        tracing::error!(
                            pool = %decision.pool_name,
                            error = %e,
                            "Failed to create cloud instance"
                        );
                        self.record_failure(&decision.pool_name);
                        break;
                    }
                }
            }
        }

        if any_success {
            self.clear_failure(&decision.pool_name);
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
                .select_scaledown_candidate(&decision.pool_name, &self.fleet_state)
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
                let drain_secs = self
                    .fleet_config
                    .node_pools
                    .get(&decision.pool_name)
                    .and_then(|p| p.cloud.as_ref())
                    .map(|c| c.drain_wait_seconds)
                    .unwrap_or(DEFAULT_DRAIN_WAIT_SECS);
                tokio::time::sleep(std::time::Duration::from_secs(drain_secs)).await;
            }

            match provider.destroy_machine(&candidate.cloud_instance_id).await {
                Ok(()) => {
                    self.tracker.untrack(&candidate.cloud_instance_id).await;
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
        let user_data = bootstrap::generate_user_data(&self.server_addr, &token, &self.ca_cert_pem);

        // image_id must be resolved by the time we create instances
        let image_id = cloud_config
            .image_id
            .clone()
            .expect("image_id must be resolved before creating instances");

        let request = CreateMachineRequest {
            pool: pool_name.to_string(),
            labels: HashMap::new(),
            instance_type: cloud_config.instance_type.clone(),
            image_id,
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
            iam_instance_profile: cloud_config.iam_instance_profile.clone(),
            spot: cloud_config.spot.clone(),
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
                            if let Err(e) = provider.destroy_machine(&cloud_inst.instance_id).await
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
    use crate::server::scaling::{
        CloudProvider, CreateMachineRequest, MachineInstance, MachineState,
    };
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
                    image_id: Some("ami-test".into()),
                    image: None,
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
                    iam_instance_profile: None,
                    spot: None,
                    launch_timeout_seconds: 300,
                    join_timeout_seconds: 600,
                    drain_wait_seconds: 30,
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
            policies: vec![],
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
