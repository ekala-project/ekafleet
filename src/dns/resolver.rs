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
    /// Namespace-scoped cache: (namespace, service_name) → CacheEntry.
    /// Records with a namespace are only returned to queries from within
    /// the same namespace. Fleet-wide records use the unscoped `cache`.
    namespace_cache: HashMap<(String, String), CacheEntry>,
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
                namespace_cache: HashMap::new(),
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

    /// Update cache with a namespace-scoped DNS record.
    /// These records are only returned to queries from within the same namespace.
    pub async fn update_namespace_cache(
        &self,
        namespace: &str,
        service_name: &str,
        ips: Vec<Ipv4Addr>,
        ttl: Duration,
    ) {
        let mut state = self.inner.write().await;
        state.namespace_cache.insert(
            (namespace.to_string(), service_name.to_string()),
            CacheEntry {
                ips,
                inserted_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Resolve a query. Returns cached IPs for fleet queries, None for external.
    pub async fn resolve(&self, name: &str) -> ResolveResult {
        self.resolve_in_namespace(name, "").await
    }

    /// Resolve a query scoped to a namespace. Namespace-scoped records are only
    /// returned when the query originates from within that namespace (identified
    /// by the caller). Fleet-wide records (empty namespace) are always visible.
    pub async fn resolve_in_namespace(&self, name: &str, namespace: &str) -> ResolveResult {
        let fleet_suffix = format!(".service.{}", self.fleet_domain);

        if let Some(service_name) = name.strip_suffix(&fleet_suffix) {
            let state = self.inner.read().await;

            // Check namespace-scoped cache first (if namespace is specified)
            if !namespace.is_empty()
                && let Some(entry) = state
                    .namespace_cache
                    .get(&(namespace.to_string(), service_name.to_string()))
                && !entry.is_expired()
            {
                return ResolveResult::Cached(entry.ips.clone());
            }

            // Fall back to fleet-wide cache
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
        state.namespace_cache.clear();
    }

    /// Evict expired entries.
    pub async fn evict_expired(&self) {
        let mut state = self.inner.write().await;
        state.cache.retain(|_, entry| !entry.is_expired());
        state.namespace_cache.retain(|_, entry| !entry.is_expired());
    }

    /// Get the configured upstream DNS servers for forwarding non-fleet queries.
    pub async fn upstream_servers(&self) -> Vec<String> {
        let state = self.inner.read().await;
        state.upstream.clone()
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
