use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Authoritative DNS for the fleet domain (e.g., fleet.internal).
/// Runs on server nodes. Manages A and SRV records for services.
#[derive(Clone)]
pub struct DnsAuthority {
    domain: String,
    inner: Arc<RwLock<ZoneData>>,
}

struct ZoneData {
    /// service_name → list of (ip, port)
    records: HashMap<String, Vec<ServiceEndpoint>>,
}

#[derive(Debug, Clone)]
struct ServiceEndpoint {
    ip: Ipv4Addr,
    port: u16,
    healthy: bool,
}

impl DnsAuthority {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            inner: Arc::new(RwLock::new(ZoneData {
                records: HashMap::new(),
            })),
        }
    }

    /// Update records for a service based on current placements and health.
    pub async fn update_service(&self, service_name: &str, endpoints: Vec<(Ipv4Addr, u16, bool)>) {
        let mut zone = self.inner.write().await;
        let entries: Vec<ServiceEndpoint> = endpoints
            .into_iter()
            .map(|(ip, port, healthy)| ServiceEndpoint { ip, port, healthy })
            .collect();

        tracing::debug!(
            service = %service_name,
            endpoints = entries.len(),
            "DNS records updated"
        );

        zone.records.insert(service_name.to_string(), entries);
    }

    /// Remove all records for a service.
    pub async fn remove_service(&self, service_name: &str) {
        let mut zone = self.inner.write().await;
        zone.records.remove(service_name);
    }

    /// Resolve a service name to healthy A record IPs.
    pub async fn resolve_a(&self, service_name: &str) -> Vec<Ipv4Addr> {
        let zone = self.inner.read().await;
        zone.records
            .get(service_name)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|e| e.healthy)
                    .map(|e| e.ip)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Resolve a service name to SRV record data (host, port).
    pub async fn resolve_srv(&self, service_name: &str) -> Vec<(Ipv4Addr, u16)> {
        let zone = self.inner.read().await;
        zone.records
            .get(service_name)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|e| e.healthy)
                    .map(|e| (e.ip, e.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the domain this authority serves.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Get all service names with records.
    pub async fn services(&self) -> Vec<String> {
        let zone = self.inner.read().await;
        zone.records.keys().cloned().collect()
    }
}
