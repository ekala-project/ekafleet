//! Agent-side fleet DNS: the record snapshot the server last pushed.
//!
//! Each `DnsUpdate` replaces the whole record set (see `server::dns`), so
//! the agent keeps answering with the last known records while the server
//! is unreachable. Names outside the fleet domain are forwarded upstream.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::proto::{DnsRecord, DnsRecordType};

/// The records for one name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    pub a: Vec<Ipv4Addr>,
    /// (port, target name relative to the fleet domain).
    pub srv: Vec<(u16, String)>,
    pub ttl: u32,
}

/// How to answer a query.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A fleet name with these records (possibly none of the asked type).
    Found(Records),
    /// A fleet name that does not exist.
    NxDomain,
    /// Not a fleet name: forward upstream.
    Forward,
}

#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<RwLock<ResolverState>>,
}

struct ResolverState {
    /// Lower-case fleet domain, without a trailing dot.
    domain: String,
    /// Fleet-wide records, by relative name.
    fleet: HashMap<String, Records>,
    /// Namespace-scoped records, by (namespace, relative name).
    namespaced: HashMap<(String, String), Records>,
    upstream: Vec<SocketAddr>,
}

impl DnsResolver {
    pub fn new(fleet_domain: &str, upstream: Vec<SocketAddr>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ResolverState {
                domain: normalize(fleet_domain),
                fleet: HashMap::new(),
                namespaced: HashMap::new(),
                upstream,
            })),
        }
    }

    /// The fleet domain answers are given for (learned from the node SVID).
    pub async fn set_domain(&self, domain: &str) {
        self.inner.write().await.domain = normalize(domain);
    }

    pub async fn set_upstream(&self, upstream: Vec<SocketAddr>) {
        self.inner.write().await.upstream = upstream;
    }

    pub async fn upstream_servers(&self) -> Vec<SocketAddr> {
        self.inner.read().await.upstream.clone()
    }

    /// Replace every record with the server's snapshot. Malformed values
    /// are skipped.
    pub async fn replace(&self, records: &[DnsRecord]) {
        let mut fleet: HashMap<String, Records> = HashMap::new();
        let mut namespaced: HashMap<(String, String), Records> = HashMap::new();
        for record in records {
            let name = normalize(&record.name);
            let entry = if record.namespace.is_empty() {
                fleet.entry(name).or_default()
            } else {
                namespaced
                    .entry((record.namespace.clone(), name))
                    .or_default()
            };
            entry.ttl = record.ttl;
            match DnsRecordType::try_from(record.record_type) {
                Ok(DnsRecordType::A) => {
                    entry.a.extend(
                        record
                            .values
                            .iter()
                            .filter_map(|v| v.parse::<Ipv4Addr>().ok()),
                    );
                }
                Ok(DnsRecordType::Srv) => {
                    entry
                        .srv
                        .extend(record.values.iter().filter_map(|v| parse_srv(v)));
                }
                _ => {}
            }
        }
        let mut state = self.inner.write().await;
        state.fleet = fleet;
        state.namespaced = namespaced;
    }

    /// Look `name` up for a client in `namespace` (`None` on the host).
    /// Namespace records shadow fleet-wide ones of the same name, and are
    /// invisible outside their namespace.
    pub async fn lookup(&self, name: &str, namespace: Option<&str>) -> Lookup {
        let name = normalize(name);
        let state = self.inner.read().await;
        let relative = if name == state.domain {
            ""
        } else if let Some(relative) = name
            .strip_suffix(state.domain.as_str())
            .and_then(|rest| rest.strip_suffix('.'))
        {
            relative
        } else {
            return Lookup::Forward;
        };
        if relative.is_empty() {
            return Lookup::Found(Records::default());
        }
        let scoped = namespace.and_then(|ns| {
            state
                .namespaced
                .get(&(ns.to_string(), relative.to_string()))
        });
        match scoped.or_else(|| state.fleet.get(relative)) {
            Some(records) => Lookup::Found(records.clone()),
            None => Lookup::NxDomain,
        }
    }

    /// The fleet domain.
    pub async fn domain(&self) -> String {
        self.inner.read().await.domain.clone()
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// `"<port> <target>"`.
fn parse_srv(value: &str) -> Option<(u16, String)> {
    let (port, target) = value.split_once(' ')?;
    Some((port.parse().ok()?, normalize(target)))
}

/// Nameservers from a resolv.conf, except `own` (this agent's listener).
pub fn upstream_from_resolv_conf(contents: &str, own: Option<SocketAddr>) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver").then_some(())?;
            let ip: std::net::IpAddr = words.next()?.parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .filter(|addr| Some(*addr) != own)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, kind: DnsRecordType, values: &[&str], ns: &str) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            record_type: kind as i32,
            values: values.iter().map(|v| v.to_string()).collect(),
            ttl: 10,
            namespace: ns.into(),
        }
    }

    #[tokio::test]
    async fn snapshots_replace_records_and_scope_namespaces() {
        let resolver = DnsResolver::new("Fleet.Test.", vec![]);
        resolver
            .replace(&[
                record(
                    "web.service",
                    DnsRecordType::A,
                    &["10.100.0.1", "bogus"],
                    "",
                ),
                record("web.service", DnsRecordType::Srv, &["8080 a.node", "x"], ""),
                record("db.service", DnsRecordType::A, &["10.200.1.2"], "acme"),
                record("web.service", DnsRecordType::A, &["10.200.1.9"], "acme"),
            ])
            .await;

        let Lookup::Found(web) = resolver.lookup("WEB.service.fleet.test.", None).await else {
            panic!("web not found");
        };
        assert_eq!(web.a, [Ipv4Addr::new(10, 100, 0, 1)]);
        assert_eq!(web.srv, [(8080, "a.node".to_string())]);
        assert_eq!(web.ttl, 10);

        // Namespaced names are invisible outside the namespace, and shadow
        // fleet-wide ones inside it.
        assert_eq!(
            resolver.lookup("db.service.fleet.test", None).await,
            Lookup::NxDomain
        );
        assert_eq!(
            resolver
                .lookup("db.service.fleet.test", Some("globex"))
                .await,
            Lookup::NxDomain
        );
        let Lookup::Found(db) = resolver.lookup("db.service.fleet.test", Some("acme")).await else {
            panic!("db not found in acme");
        };
        assert_eq!(db.a, [Ipv4Addr::new(10, 200, 1, 2)]);
        let Lookup::Found(web) = resolver
            .lookup("web.service.fleet.test", Some("acme"))
            .await
        else {
            panic!("web not found in acme");
        };
        assert_eq!(web.a, [Ipv4Addr::new(10, 200, 1, 9)]);

        assert_eq!(resolver.lookup("example.com", None).await, Lookup::Forward);
        assert_eq!(
            resolver.lookup("notfleet.test", None).await,
            Lookup::Forward
        );
        assert_eq!(
            resolver.lookup("fleet.test", None).await,
            Lookup::Found(Records::default())
        );

        // The next snapshot replaces everything.
        resolver.replace(&[]).await;
        assert_eq!(
            resolver.lookup("web.service.fleet.test", None).await,
            Lookup::NxDomain
        );
    }

    #[test]
    fn upstreams_come_from_resolv_conf_without_ourselves() {
        let own: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let conf = "# generated\nnameserver 127.0.0.1\nnameserver 192.0.2.53\nsearch x\nnameserver ::1\nnameserver bad\n";
        assert_eq!(
            upstream_from_resolv_conf(conf, Some(own)),
            [
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "[::1]:53".parse().unwrap()
            ]
        );
    }
}
