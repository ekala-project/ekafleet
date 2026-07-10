#![allow(dead_code)]

pub mod actuator;
pub mod aws;
pub mod azure;
pub mod bootstrap;
pub mod gcp;
pub mod instance_tracker;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::config::CloudProviderType;
use crate::server::scaling::{CloudProvider, CreateMachineRequest, MachineInstance};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe cloud provider trait. Wraps [`CloudProvider`] so we can store
/// heterogeneous provider types in the [`CloudProviderRegistry`].
pub trait CloudProviderDyn: Send + Sync {
    fn create_machine(
        &self,
        request: &CreateMachineRequest,
    ) -> BoxFuture<'_, Result<MachineInstance, anyhow::Error>>;

    fn destroy_machine(
        &self,
        instance_id: &str,
    ) -> BoxFuture<'_, Result<(), anyhow::Error>>;

    fn describe_machine(
        &self,
        instance_id: &str,
    ) -> BoxFuture<'_, Result<Option<MachineInstance>, anyhow::Error>>;

    fn list_fleet_machines(
        &self,
        fleet_name: &str,
        pool: &str,
    ) -> BoxFuture<'_, Result<Vec<MachineInstance>, anyhow::Error>>;
}

/// Blanket implementation: any `CloudProvider` is also a `CloudProviderDyn`.
impl<T: CloudProvider + 'static> CloudProviderDyn for T {
    fn create_machine(
        &self,
        request: &CreateMachineRequest,
    ) -> BoxFuture<'_, Result<MachineInstance, anyhow::Error>> {
        let req = request.clone();
        Box::pin(async move { CloudProvider::create_machine(self, &req).await })
    }

    fn destroy_machine(
        &self,
        instance_id: &str,
    ) -> BoxFuture<'_, Result<(), anyhow::Error>> {
        let id = instance_id.to_string();
        Box::pin(async move { CloudProvider::destroy_machine(self, &id).await })
    }

    fn describe_machine(
        &self,
        instance_id: &str,
    ) -> BoxFuture<'_, Result<Option<MachineInstance>, anyhow::Error>> {
        let id = instance_id.to_string();
        Box::pin(async move { CloudProvider::describe_machine(self, &id).await })
    }

    fn list_fleet_machines(
        &self,
        fleet_name: &str,
        pool: &str,
    ) -> BoxFuture<'_, Result<Vec<MachineInstance>, anyhow::Error>> {
        let fleet = fleet_name.to_string();
        let p = pool.to_string();
        Box::pin(async move { CloudProvider::list_fleet_machines(self, &fleet, &p).await })
    }
}

/// Registry that maps pool names to their cloud provider implementations.
pub struct CloudProviderRegistry {
    providers: HashMap<String, Box<dyn CloudProviderDyn>>,
}

impl CloudProviderRegistry {
    /// Build a registry from the fleet's node pool configuration.
    /// Only pools with a `cloud` config get a provider entry.
    pub fn from_pool_configs(
        pools: &HashMap<String, crate::config::NodePoolConfig>,
    ) -> Self {
        let mut providers: HashMap<String, Box<dyn CloudProviderDyn>> = HashMap::new();

        for (pool_name, pool_config) in pools {
            if let Some(cloud) = &pool_config.cloud {
                let provider: Box<dyn CloudProviderDyn> = match cloud.provider {
                    CloudProviderType::Aws => Box::new(aws::AwsCloudProvider::new(cloud)),
                    CloudProviderType::Azure => Box::new(azure::AzureCloudProvider::new(cloud)),
                    CloudProviderType::Gcp => Box::new(gcp::GcpCloudProvider::new(cloud)),
                };
                providers.insert(pool_name.clone(), provider);
            }
        }

        Self { providers }
    }

    /// Build a registry from pre-constructed providers.
    pub fn from_raw(providers: HashMap<String, Box<dyn CloudProviderDyn>>) -> Self {
        Self { providers }
    }

    /// Get the cloud provider for a given pool, if one is configured.
    pub fn get(&self, pool: &str) -> Option<&dyn CloudProviderDyn> {
        self.providers.get(pool).map(|p| p.as_ref())
    }

    /// Check whether a pool has a cloud provider configured.
    pub fn has_provider(&self, pool: &str) -> bool {
        self.providers.contains_key(pool)
    }
}
