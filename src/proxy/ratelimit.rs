#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

/// Per-service rate limiter using a token bucket algorithm.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    default_config: RateLimitConfig,
}

/// Rate limit configuration for a service.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second.
    pub requests_per_second: f64,
    /// Maximum burst size (bucket capacity).
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100.0,
            burst: 200,
        }
    }
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(config: &RateLimitConfig) -> Self {
        Self {
            tokens: config.burst as f64,
            capacity: config.burst as f64,
            refill_rate: config.requests_per_second,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl RateLimiter {
    pub fn new(default_config: RateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            default_config,
        }
    }

    /// Configure rate limiting for a specific service.
    pub async fn configure(&self, service_name: &str, config: RateLimitConfig) {
        let mut buckets = self.buckets.write().await;
        buckets.insert(service_name.to_string(), TokenBucket::new(&config));
    }

    /// Check if a request to the given service is allowed.
    /// Returns true if within rate limit, false if rate limited.
    pub async fn allow(&self, service_name: &str) -> bool {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(service_name.to_string())
            .or_insert_with(|| TokenBucket::new(&self.default_config));
        bucket.try_acquire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_within_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 10.0,
            burst: 5,
        });

        for _ in 0..5 {
            assert!(limiter.allow("svc").await);
        }
        // Burst exhausted
        assert!(!limiter.allow("svc").await);
    }

    #[tokio::test]
    async fn refills_over_time() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 1000.0,
            burst: 1,
        });

        assert!(limiter.allow("svc").await);
        assert!(!limiter.allow("svc").await);

        // Wait for refill
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(limiter.allow("svc").await);
    }
}
