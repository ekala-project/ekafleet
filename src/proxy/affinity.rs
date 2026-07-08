#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Session affinity (sticky sessions) for the upstream pool.
/// Routes requests from the same client IP to the same backend.
#[derive(Clone)]
pub struct SessionAffinity {
    /// client_ip → (service_name, sticky backend addr, last_seen timestamp)
    sessions: Arc<RwLock<HashMap<String, StickySession>>>,
    /// How long a sticky session lasts before expiring.
    ttl_seconds: u64,
}

struct StickySession {
    backend: SocketAddr,
    last_seen: u64,
}

impl SessionAffinity {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ttl_seconds,
        }
    }

    /// Look up a sticky backend for a client IP and service.
    pub async fn get(&self, client_ip: &str, service_name: &str) -> Option<SocketAddr> {
        let key = format!("{client_ip}:{service_name}");
        let sessions = self.sessions.read().await;
        let session = sessions.get(&key)?;

        let now = now_epoch();
        if now - session.last_seen > self.ttl_seconds {
            return None; // expired
        }
        Some(session.backend)
    }

    /// Record or update a sticky session.
    pub async fn set(&self, client_ip: &str, service_name: &str, backend: SocketAddr) {
        let key = format!("{client_ip}:{service_name}");
        let mut sessions = self.sessions.write().await;
        sessions.insert(
            key,
            StickySession {
                backend,
                last_seen: now_epoch(),
            },
        );
    }

    /// Remove expired sessions.
    pub async fn cleanup(&self) {
        let now = now_epoch();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, s| now - s.last_seen <= self.ttl_seconds);
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sticky_session() {
        let affinity = SessionAffinity::new(3600);
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();

        affinity.set("192.168.1.1", "web", addr).await;
        assert_eq!(affinity.get("192.168.1.1", "web").await, Some(addr));
        assert_eq!(affinity.get("192.168.1.2", "web").await, None);
    }
}
