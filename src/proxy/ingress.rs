//! Per-route ingress options beyond host and path matching: weighted
//! splits across services, client-IP affinity, per-client rate limits and
//! the SPIFFE IDs a route admits.
//!
//! Each route has one upstream pool per receiving service, named by
//! [`pool_name`]. A route without options sends everything to the pool
//! named after it.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use super::l4::TcpRoutes;
use super::ratelimit::{RateLimitConfig, RateLimiter};
use super::router::ProxyRouter;
use super::routes::Route;
use super::tls::IngressTls;
use super::upstream::UpstreamPool;

/// The upstream pool of `route` for `split_service`, or for the route's
/// own service when `None`.
pub fn pool_name(route: &str, split_service: Option<&str>) -> String {
    match split_service {
        None => route.to_string(),
        Some(service) => format!("{route}@{service}"),
    }
}

/// The options of one route.
pub struct RouteOptions {
    /// Upstream pool → percent of the traffic; zero-weight pools are left
    /// out.
    groups: Vec<(String, u32)>,
    limiter: Option<RateLimiter>,
    affinity: bool,
    /// SPIFFE IDs a client certificate must carry; empty: anyone.
    pub allowed_callers: Vec<String>,
    /// Served over HTTPS (its certificate is loaded).
    pub tls: bool,
    picks: AtomicU64,
}

impl RouteOptions {
    pub fn from_route(route: &Route) -> Self {
        let split: u32 = route.split.iter().map(|s| s.weight).sum();
        let mut groups = vec![(pool_name(&route.name, None), 100u32.saturating_sub(split))];
        groups.extend(
            route
                .split
                .iter()
                .map(|s| (pool_name(&route.name, Some(&s.service)), s.weight)),
        );
        groups.retain(|(_, weight)| *weight > 0);
        Self {
            groups,
            limiter: route.rate_limit.as_ref().map(|l| {
                RateLimiter::new(RateLimitConfig {
                    requests_per_second: l.requests_per_second,
                    burst: l.burst,
                })
            }),
            affinity: route.client_ip_affinity,
            allowed_callers: route.allowed_callers.clone(),
            tls: route.tls.is_some(),
            picks: AtomicU64::new(0),
        }
    }

    /// Whether a request from `client` is within the route's rate limit.
    /// IPv6 clients are limited per /64, which one host usually holds.
    pub async fn admit(&self, client: IpAddr) -> bool {
        match &self.limiter {
            None => true,
            Some(limiter) => limiter.allow(&client_key(client)).await,
        }
    }

    /// Whether a client presenting `spiffe_id` (if any) may use the route.
    pub fn authorized(&self, spiffe_id: Option<&str>) -> bool {
        self.allowed_callers.is_empty()
            || spiffe_id.is_some_and(|id| self.allowed_callers.iter().any(|c| c == id))
    }

    /// Choose the upstream pool and endpoint for a request from `client`.
    /// The pool is drawn by weight (from the client's address, with
    /// affinity); when it has no usable endpoint, the other pools are
    /// tried in turn.
    pub async fn pick(
        &self,
        upstream: &UpstreamPool,
        client: IpAddr,
    ) -> Option<(String, SocketAddr)> {
        let total: u64 = self.groups.iter().map(|(_, w)| u64::from(*w)).sum();
        if total == 0 {
            return None;
        }
        let draw = if self.affinity {
            hash_of(&(client_key(client), "split"))
        } else {
            mix(self.picks.fetch_add(1, Ordering::Relaxed))
        } % total;
        let mut first = 0;
        let mut cumulative = 0;
        for (i, (_, weight)) in self.groups.iter().enumerate() {
            cumulative += u64::from(*weight);
            if draw < cumulative {
                first = i;
                break;
            }
        }
        for i in 0..self.groups.len() {
            let pool = &self.groups[(first + i) % self.groups.len()].0;
            let endpoint = if self.affinity {
                upstream
                    .usable_endpoints(pool)
                    .await
                    .into_iter()
                    .max_by_key(|endpoint| hash_of(&(client_key(client), endpoint)))
            } else {
                upstream.next_endpoint(pool).await
            };
            if let Some(endpoint) = endpoint {
                return Some((pool.clone(), endpoint));
            }
        }
        None
    }

    /// Forget idle clients' rate-limit state.
    pub async fn prune(&self) {
        if let Some(limiter) = &self.limiter {
            limiter.prune().await;
        }
    }
}

/// The client identity rate limits and affinity apply to.
fn client_key(client: IpAddr) -> String {
    match client {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = ip.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// A hash that is the same in every run of the same binary, so a client
/// sticks to its replica across proxy restarts.
fn hash_of(value: &impl Hash) -> u64 {
    #[allow(deprecated)]
    let mut hasher = std::hash::SipHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// splitmix64: spreads consecutive picks over the weight range.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Everything the proxy serves ingress routes with.
#[derive(Clone, Default)]
pub struct Ingress {
    pub router: ProxyRouter,
    pub upstream: UpstreamPool,
    pub routes: RouteTable,
    /// Listeners of TCP routes; without, TCP routes are not served.
    pub tcp: Option<TcpRoutes>,
    /// Certificates of TLS routes; without, they are served over HTTP only.
    pub tls: Option<IngressTls>,
}

/// The options of every route, by route name, and the TCP routes by port.
#[derive(Clone, Default)]
pub struct RouteTable {
    inner: Arc<RwLock<Tables>>,
}

#[derive(Default)]
struct Tables {
    options: HashMap<String, Arc<RouteOptions>>,
    tcp: HashMap<u16, String>,
}

impl RouteTable {
    pub async fn get(&self, route: &str) -> Option<Arc<RouteOptions>> {
        self.inner.read().await.options.get(route).cloned()
    }

    /// The route forwarding TCP `port`, and its options.
    pub async fn tcp(&self, port: u16) -> Option<(String, Arc<RouteOptions>)> {
        let tables = self.inner.read().await;
        let route = tables.tcp.get(&port)?;
        Some((route.clone(), tables.options.get(route)?.clone()))
    }

    /// Serve exactly `routes`. Options of routes whose definition did not
    /// change are kept, rate-limit state included.
    pub async fn replace(&self, routes: &[Route], previous: &[Route]) {
        let mut tables = self.inner.write().await;
        let mut options = HashMap::new();
        for route in routes {
            let unchanged = previous
                .iter()
                .any(|p| p.name == route.name && p.same_options(route));
            let kept = unchanged
                .then(|| tables.options.get(&route.name).cloned())
                .flatten();
            options.insert(
                route.name.clone(),
                kept.unwrap_or_else(|| Arc::new(RouteOptions::from_route(route))),
            );
        }
        tables.options = options;
        tables.tcp = routes
            .iter()
            .filter_map(|r| Some((r.tcp_port?, r.name.clone())))
            .collect();
    }

    /// Forget idle clients' rate-limit state on every route.
    pub async fn prune(&self) {
        let options: Vec<_> = self.inner.read().await.options.values().cloned().collect();
        for route in options {
            route.prune().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::routes::{RateLimit, SplitBackends};

    fn route(split: &[(&str, u32)], affinity: bool) -> Route {
        Route {
            name: "site".into(),
            host: "*".into(),
            path_prefix: "/".into(),
            backends: vec![],
            split: split
                .iter()
                .map(|(service, weight)| SplitBackends {
                    service: service.to_string(),
                    weight: *weight,
                    backends: vec![],
                })
                .collect(),
            tcp_port: None,
            rate_limit: None,
            client_ip_affinity: affinity,
            tls: None,
            allowed_callers: vec![],
        }
    }

    async fn pools(entries: &[(&str, &[&str])]) -> UpstreamPool {
        let upstream = UpstreamPool::new();
        upstream
            .replace_all(
                entries
                    .iter()
                    .map(|(name, addrs)| {
                        (
                            name.to_string(),
                            addrs.iter().map(|a| a.parse().unwrap()).collect(),
                        )
                    })
                    .collect(),
            )
            .await;
        upstream
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn traffic_is_split_by_weight() {
        let options = RouteOptions::from_route(&route(&[("v2", 20)], false));
        let upstream = pools(&[("site", &["10.0.0.1:80"]), ("site@v2", &["10.0.0.2:80"])]).await;
        let mut to_v2 = 0;
        for _ in 0..1000 {
            let (pool, _) = options.pick(&upstream, ip("192.0.2.1")).await.unwrap();
            if pool == "site@v2" {
                to_v2 += 1;
            }
        }
        assert!((150..250).contains(&to_v2), "{to_v2} of 1000");

        // A share without usable endpoints falls back to the others.
        let upstream = pools(&[("site", &["10.0.0.1:80"]), ("site@v2", &[])]).await;
        for _ in 0..50 {
            assert_eq!(
                options.pick(&upstream, ip("192.0.2.1")).await.unwrap().0,
                "site"
            );
        }

        // All traffic split away: the route's own service gets none.
        let all = RouteOptions::from_route(&route(&[("v2", 100)], false));
        let upstream = pools(&[("site", &["10.0.0.1:80"]), ("site@v2", &["10.0.0.2:80"])]).await;
        for _ in 0..50 {
            assert_eq!(
                all.pick(&upstream, ip("192.0.2.1")).await.unwrap().0,
                "site@v2"
            );
        }
    }

    #[tokio::test]
    async fn affinity_keeps_a_client_on_its_replica() {
        let options = RouteOptions::from_route(&route(&[], true));
        let addrs = ["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80", "10.0.0.4:80"];
        let upstream = pools(&[("site", &addrs)]).await;
        let mut seen = std::collections::HashSet::new();
        for client in 1..=40 {
            let client = ip(&format!("192.0.2.{client}"));
            let (_, first) = options.pick(&upstream, client).await.unwrap();
            for _ in 0..5 {
                assert_eq!(options.pick(&upstream, client).await.unwrap().1, first);
            }
            seen.insert(first);
        }
        assert!(seen.len() > 1, "clients spread over replicas");

        // Losing another replica does not move a client.
        let client = ip("192.0.2.7");
        let (_, mine) = options.pick(&upstream, client).await.unwrap();
        let other = addrs.iter().find(|a| **a != mine.to_string()).unwrap();
        upstream
            .mark_unhealthy("site", other.parse().unwrap())
            .await;
        assert_eq!(options.pick(&upstream, client).await.unwrap().1, mine);
    }

    #[tokio::test]
    async fn rate_limits_apply_per_client() {
        let mut r = route(&[], false);
        r.rate_limit = Some(RateLimit {
            requests_per_second: 0.001,
            burst: 2,
        });
        let options = RouteOptions::from_route(&r);
        for _ in 0..2 {
            assert!(options.admit(ip("192.0.2.1")).await);
        }
        assert!(!options.admit(ip("192.0.2.1")).await);
        assert!(options.admit(ip("192.0.2.2")).await);
        // One IPv6 /64 is one client.
        assert!(options.admit(ip("2001:db8::1")).await);
        assert!(options.admit(ip("2001:db8::2")).await);
        assert!(!options.admit(ip("2001:db8::3")).await);
    }

    #[test]
    fn callers_are_checked_only_when_listed() {
        let mut r = route(&[], false);
        assert!(RouteOptions::from_route(&r).authorized(None));
        r.allowed_callers = vec!["spiffe://t/service/web".into()];
        let options = RouteOptions::from_route(&r);
        assert!(!options.authorized(None));
        assert!(!options.authorized(Some("spiffe://t/service/api")));
        assert!(options.authorized(Some("spiffe://t/service/web")));
    }
}
