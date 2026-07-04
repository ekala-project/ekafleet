#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::RwLock;

/// Traffic splitter for canary deployments.
/// Routes requests between stable and canary backends based on configured weights.
#[derive(Clone)]
pub struct TrafficSplitter {
    inner: Arc<RwLock<SplitterState>>,
    rng: Arc<SystemRandom>,
}

struct SplitterState {
    configs: HashMap<String, SplitConfig>,
}

struct SplitConfig {
    canary_weight: u32,
    canary_backend: String,
    stable_backend: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub name: String,
    pub is_canary: bool,
}

impl Default for TrafficSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficSplitter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SplitterState {
                configs: HashMap::new(),
            })),
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Configure traffic splitting for a service.
    /// `canary_weight` is a value 0-100 representing the percentage of
    /// traffic that goes to the canary backend.
    pub async fn configure(
        &self,
        service_name: &str,
        canary_weight: u32,
        canary_backend: &str,
        stable_backend: &str,
    ) {
        let mut state = self.inner.write().await;
        state.configs.insert(
            service_name.to_string(),
            SplitConfig {
                canary_weight: canary_weight.min(100),
                canary_backend: canary_backend.to_string(),
                stable_backend: stable_backend.to_string(),
            },
        );
        tracing::info!(
            service = %service_name,
            canary_weight = canary_weight,
            canary = %canary_backend,
            stable = %stable_backend,
            "Traffic splitting configured"
        );
    }

    /// Select a backend for the given service based on configured weights.
    /// Uses cryptographic randomness for unbiased selection.
    pub async fn select_backend(&self, service_name: &str) -> Option<Backend> {
        let state = self.inner.read().await;
        let config = state.configs.get(service_name)?;

        // Generate a random value 0-99
        let mut rand_byte = [0u8; 4];
        self.rng.fill(&mut rand_byte).ok()?;
        let roll = u32::from_le_bytes(rand_byte) % 100;

        if roll < config.canary_weight {
            Some(Backend {
                name: config.canary_backend.clone(),
                is_canary: true,
            })
        } else {
            Some(Backend {
                name: config.stable_backend.clone(),
                is_canary: false,
            })
        }
    }

    /// Remove traffic splitting configuration for a service.
    pub async fn remove(&self, service_name: &str) -> bool {
        let mut state = self.inner.write().await;
        state.configs.remove(service_name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn select_backend_with_zero_canary_weight() {
        let splitter = TrafficSplitter::new();
        splitter.configure("svc", 0, "canary-v2", "stable-v1").await;

        // With weight=0, all traffic should go to stable
        for _ in 0..100 {
            let backend = splitter.select_backend("svc").await.unwrap();
            assert_eq!(backend.name, "stable-v1");
            assert!(!backend.is_canary);
        }
    }

    #[tokio::test]
    async fn select_backend_with_full_canary_weight() {
        let splitter = TrafficSplitter::new();
        splitter
            .configure("svc", 100, "canary-v2", "stable-v1")
            .await;

        // With weight=100, all traffic should go to canary
        for _ in 0..100 {
            let backend = splitter.select_backend("svc").await.unwrap();
            assert_eq!(backend.name, "canary-v2");
            assert!(backend.is_canary);
        }
    }

    #[tokio::test]
    async fn select_backend_unknown_service_returns_none() {
        let splitter = TrafficSplitter::new();

        let result = splitter.select_backend("unknown").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn select_backend_statistical_distribution() {
        let splitter = TrafficSplitter::new();
        splitter.configure("svc", 50, "canary", "stable").await;

        let mut canary_count = 0u32;
        let iterations = 1000;

        for _ in 0..iterations {
            let backend = splitter.select_backend("svc").await.unwrap();
            if backend.is_canary {
                canary_count += 1;
            }
        }

        // With 50/50 split and 1000 iterations, we expect roughly 500 canary selections.
        // Allow a generous margin for randomness.
        assert!(
            canary_count > 300 && canary_count < 700,
            "Expected ~500 canary selections, got {canary_count}"
        );
    }

    #[tokio::test]
    async fn remove_config() {
        let splitter = TrafficSplitter::new();
        splitter.configure("svc", 50, "canary", "stable").await;

        assert!(splitter.remove("svc").await);
        assert!(!splitter.remove("svc").await);
        assert!(splitter.select_backend("svc").await.is_none());
    }
}
