use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// Local caching DNS resolver for agent nodes.
/// Resolves fleet.internal queries from cache (populated from server DNS updates).
/// Forwards external queries upstream.
#[derive(Clone)]
pub struct DnsResolver {
    fleet_domain: String,
    inner: Arc<RwLock<ResolverState>>,
}

struct ResolverState {
    cache: HashMap<String, CacheEntry>,
    #[allow(dead_code)] // TODO: used for forwarding non-fleet queries once DNS listener is wired
    upstream: Vec<String>,
}

struct CacheEntry {
    ips: Vec<Ipv4Addr>,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

impl DnsResolver {
    pub fn new(fleet_domain: &str, upstream_servers: Vec<String>) -> Self {
        Self {
            fleet_domain: fleet_domain.to_string(),
            inner: Arc::new(RwLock::new(ResolverState {
                cache: HashMap::new(),
                upstream: upstream_servers,
            })),
        }
    }

    /// Update cache with DNS records received from server.
    pub async fn update_cache(&self, service_name: &str, ips: Vec<Ipv4Addr>, ttl: Duration) {
        let mut state = self.inner.write().await;
        state.cache.insert(
            service_name.to_string(),
            CacheEntry {
                ips,
                inserted_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Resolve a query. Returns cached IPs for fleet queries, None for external.
    pub async fn resolve(&self, name: &str) -> ResolveResult {
        let fleet_suffix = format!(".service.{}", self.fleet_domain);

        if let Some(service_name) = name.strip_suffix(&fleet_suffix) {
            // Fleet query — check cache
            let state = self.inner.read().await;
            if let Some(entry) = state.cache.get(service_name)
                && !entry.is_expired()
            {
                return ResolveResult::Cached(entry.ips.clone());
            }
            // Cache miss or expired — need to query server
            ResolveResult::CacheMiss(service_name.to_string())
        } else if name.ends_with(&self.fleet_domain) {
            // Other fleet domain query
            ResolveResult::CacheMiss(name.to_string())
        } else {
            // External query — forward upstream
            ResolveResult::Forward
        }
    }

    /// Invalidate cache for a specific service (e.g., on health change).
    pub async fn invalidate(&self, service_name: &str) {
        let mut state = self.inner.write().await;
        state.cache.remove(service_name);
    }

    /// Clear all cached entries.
    pub async fn clear_cache(&self) {
        let mut state = self.inner.write().await;
        state.cache.clear();
    }

    /// Evict expired entries.
    pub async fn evict_expired(&self) {
        let mut state = self.inner.write().await;
        state.cache.retain(|_, entry| !entry.is_expired());
    }
}

#[derive(Debug)]
pub enum ResolveResult {
    /// Found in cache with these IPs.
    Cached(Vec<Ipv4Addr>),
    /// Fleet query but not in cache — service name that needs server lookup.
    CacheMiss(String),
    /// External query — forward to upstream DNS.
    Forward,
}
