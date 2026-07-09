#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Per-pool or per-namespace resource quotas that prevent one service class
/// from consuming all cluster resources.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResourceQuota {
    /// Maximum total CPU (millicores) that can be allocated within this quota scope.
    pub max_cpu: Option<u64>,
    /// Maximum total memory (MB) that can be allocated.
    pub max_memory: Option<u64>,
    /// Maximum total disk (MB) that can be allocated.
    pub max_disk: Option<u64>,
    /// Maximum number of service instances.
    pub max_instances: Option<u32>,
}

/// Tracks resource usage against quotas.
#[derive(Clone)]
pub struct QuotaEnforcer {
    quotas: Arc<RwLock<HashMap<String, ResourceQuota>>>,
    usage: Arc<RwLock<HashMap<String, ResourceUsage>>>,
}

#[derive(Debug, Clone, Default)]
struct ResourceUsage {
    cpu: u64,
    memory: u64,
    disk: u64,
    instances: u32,
}

impl Default for QuotaEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaEnforcer {
    pub fn new() -> Self {
        Self {
            quotas: Arc::new(RwLock::new(HashMap::new())),
            usage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a quota for a scope (pool name or namespace).
    pub async fn set_quota(&self, scope: &str, quota: ResourceQuota) {
        self.quotas.write().await.insert(scope.to_string(), quota);
        tracing::info!(scope = %scope, "Resource quota set");
    }

    /// Check if a new allocation would exceed the quota.
    /// Returns Ok(()) if within limits, Err with reason if exceeded.
    pub async fn check(&self, scope: &str, cpu: u64, memory: u64, disk: u64) -> Result<(), String> {
        let quotas = self.quotas.read().await;
        let quota = match quotas.get(scope) {
            Some(q) => q,
            None => return Ok(()), // No quota = no limit
        };

        let usage = self.usage.read().await;
        let current = usage.get(scope).cloned().unwrap_or_default();

        if let Some(max_cpu) = quota.max_cpu
            && current.cpu + cpu > max_cpu
        {
            return Err(format!(
                "CPU quota exceeded for '{scope}': {} + {} > {max_cpu}",
                current.cpu, cpu
            ));
        }
        if let Some(max_mem) = quota.max_memory
            && current.memory + memory > max_mem
        {
            return Err(format!(
                "memory quota exceeded for '{scope}': {} + {} > {max_mem}",
                current.memory, memory
            ));
        }
        if let Some(max_disk) = quota.max_disk
            && current.disk + disk > max_disk
        {
            return Err(format!(
                "disk quota exceeded for '{scope}': {} + {} > {max_disk}",
                current.disk, disk
            ));
        }
        if let Some(max_inst) = quota.max_instances
            && current.instances + 1 > max_inst
        {
            return Err(format!(
                "instance quota exceeded for '{scope}': {} >= {max_inst}",
                current.instances
            ));
        }

        Ok(())
    }

    /// Record resource allocation against a scope.
    pub async fn allocate(&self, scope: &str, cpu: u64, memory: u64, disk: u64) {
        let mut usage = self.usage.write().await;
        let entry = usage.entry(scope.to_string()).or_default();
        entry.cpu += cpu;
        entry.memory += memory;
        entry.disk += disk;
        entry.instances += 1;
    }

    /// Release resource allocation from a scope.
    pub async fn release(&self, scope: &str, cpu: u64, memory: u64, disk: u64) {
        let mut usage = self.usage.write().await;
        if let Some(entry) = usage.get_mut(scope) {
            entry.cpu = entry.cpu.saturating_sub(cpu);
            entry.memory = entry.memory.saturating_sub(memory);
            entry.disk = entry.disk.saturating_sub(disk);
            entry.instances = entry.instances.saturating_sub(1);
        }
    }

    /// Get current usage for a scope.
    pub async fn usage(&self, scope: &str) -> Option<(u64, u64, u64, u32)> {
        let usage = self.usage.read().await;
        usage
            .get(scope)
            .map(|u| (u.cpu, u.memory, u.disk, u.instances))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quota_enforcement() {
        let enforcer = QuotaEnforcer::new();
        enforcer
            .set_quota(
                "default",
                ResourceQuota {
                    max_cpu: Some(4000),
                    max_memory: Some(8192),
                    max_disk: None,
                    max_instances: Some(10),
                },
            )
            .await;

        assert!(enforcer.check("default", 1000, 2048, 0).await.is_ok());
        enforcer.allocate("default", 1000, 2048, 0).await;

        assert!(enforcer.check("default", 3500, 1024, 0).await.is_err()); // CPU exceeded
        assert!(enforcer.check("default", 1000, 1024, 0).await.is_ok());
    }
}
