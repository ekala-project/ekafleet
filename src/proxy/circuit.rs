#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// Circuit breaker state for an upstream service endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests flow through.
    Closed,
    /// Too many failures — requests are rejected immediately.
    Open,
    /// Trial period — one request is allowed through to test recovery.
    HalfOpen,
}

/// Per-service circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitConfig {
    /// Number of consecutive failures to open the circuit.
    pub failure_threshold: u32,
    /// Duration the circuit stays open before transitioning to half-open.
    pub open_duration: Duration,
    /// Number of successes in half-open state to close the circuit.
    pub success_threshold: u32,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            success_threshold: 2,
        }
    }
}

struct BreakerState {
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    opened_at: Option<Instant>,
    config: CircuitConfig,
}

impl BreakerState {
    fn new(config: CircuitConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            opened_at: None,
            config,
        }
    }

    /// Check if a request is allowed through the circuit.
    fn allow_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if enough time has passed to transition to half-open
                if let Some(opened_at) = self.opened_at {
                    if opened_at.elapsed() >= self.config.open_duration {
                        self.state = CircuitState::HalfOpen;
                        self.consecutive_successes = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        match self.state {
            CircuitState::HalfOpen => {
                self.consecutive_successes += 1;
                if self.consecutive_successes >= self.config.success_threshold {
                    self.state = CircuitState::Closed;
                    self.opened_at = None;
                    tracing::info!("Circuit breaker closed (recovered)");
                }
            }
            CircuitState::Closed => {}
            CircuitState::Open => {}
        }
    }

    /// Record a failed request.
    fn record_failure(&mut self) {
        self.consecutive_successes = 0;
        self.consecutive_failures += 1;

        match self.state {
            CircuitState::Closed => {
                if self.consecutive_failures >= self.config.failure_threshold {
                    self.state = CircuitState::Open;
                    self.opened_at = Some(Instant::now());
                    tracing::warn!(
                        failures = self.consecutive_failures,
                        "Circuit breaker opened"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open immediately re-opens
                self.state = CircuitState::Open;
                self.opened_at = Some(Instant::now());
                tracing::warn!("Circuit breaker re-opened (half-open probe failed)");
            }
            CircuitState::Open => {}
        }
    }
}

/// Manages circuit breakers for multiple upstream services.
#[derive(Clone)]
pub struct CircuitBreakerRegistry {
    breakers: Arc<RwLock<HashMap<String, BreakerState>>>,
    default_config: CircuitConfig,
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self::new(CircuitConfig::default())
    }
}

impl CircuitBreakerRegistry {
    pub fn new(default_config: CircuitConfig) -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
            default_config,
        }
    }

    /// Configure a custom circuit breaker for a specific service.
    pub async fn configure(&self, service_name: &str, config: CircuitConfig) {
        let mut breakers = self.breakers.write().await;
        breakers.insert(service_name.to_string(), BreakerState::new(config));
    }

    /// Check if a request to the given service is allowed.
    pub async fn allow_request(&self, service_name: &str) -> bool {
        let mut breakers = self.breakers.write().await;
        let state = breakers
            .entry(service_name.to_string())
            .or_insert_with(|| BreakerState::new(self.default_config.clone()));
        state.allow_request()
    }

    /// Record a successful request to the given service.
    pub async fn record_success(&self, service_name: &str) {
        let mut breakers = self.breakers.write().await;
        if let Some(state) = breakers.get_mut(service_name) {
            state.record_success();
        }
    }

    /// Record a failed request to the given service.
    pub async fn record_failure(&self, service_name: &str) {
        let mut breakers = self.breakers.write().await;
        if let Some(state) = breakers.get_mut(service_name) {
            state.record_failure();
        }
    }

    /// Get the current circuit state for a service.
    pub async fn state(&self, service_name: &str) -> CircuitState {
        let breakers = self.breakers.read().await;
        breakers
            .get(service_name)
            .map(|s| s.state)
            .unwrap_or(CircuitState::Closed)
    }
}

/// Retry configuration for upstream requests.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff).
    pub base_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl RetryConfig {
    /// Compute the delay for the nth retry attempt (exponential backoff).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay = self.base_delay * 2u32.saturating_pow(attempt);
        delay.min(self.max_delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn circuit_starts_closed() {
        let registry = CircuitBreakerRegistry::default();
        assert!(registry.allow_request("svc").await);
    }

    #[tokio::test]
    async fn circuit_opens_after_threshold() {
        let registry = CircuitBreakerRegistry::new(CircuitConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(10),
            success_threshold: 1,
        });

        // Prime the circuit breaker entry
        assert!(registry.allow_request("svc").await);

        registry.record_failure("svc").await;
        registry.record_failure("svc").await;
        assert!(registry.allow_request("svc").await); // still closed

        registry.record_failure("svc").await;
        assert!(!registry.allow_request("svc").await); // now open
    }

    #[tokio::test]
    async fn success_resets_failure_count() {
        let registry = CircuitBreakerRegistry::new(CircuitConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(10),
            success_threshold: 1,
        });

        assert!(registry.allow_request("svc").await);

        registry.record_failure("svc").await;
        registry.record_failure("svc").await;
        registry.record_success("svc").await; // resets
        registry.record_failure("svc").await;
        registry.record_failure("svc").await;

        assert!(registry.allow_request("svc").await); // still closed (reset happened)
    }

    #[test]
    fn exponential_backoff() {
        let config = RetryConfig {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
        };

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(config.delay_for_attempt(4), Duration::from_millis(1600));
        assert_eq!(config.delay_for_attempt(5), Duration::from_secs(2)); // capped
    }
}
