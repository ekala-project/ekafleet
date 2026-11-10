//! Agent side of gossip: start SWIM when the server sends `GossipConfig`.
//!
//! The agent cannot start gossip on its own because it does not hold the
//! cluster key; the server sends it over the authenticated control stream.
//! The first `GossipConfig` binds the socket and starts the protocol; later
//! ones (fleet key rotation, reconnects) swap the key and add seeds.

use std::net::{IpAddr, SocketAddr};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::gossip::swim::SwimMembership;
use crate::proto::GossipConfig;

/// Lazily started gossip membership for this agent.
pub struct AgentGossip {
    node_id: String,
    listen: Option<SocketAddr>,
    server_ip: IpAddr,
    swim: Mutex<Option<SwimMembership>>,
    shutdown: CancellationToken,
}

impl AgentGossip {
    /// `listen` of `None` disables gossip. `server_ip` is the host the agent
    /// joined; the server's gossip port comes from `GossipConfig`.
    pub fn new(
        node_id: &str,
        listen: Option<SocketAddr>,
        server_ip: IpAddr,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            node_id: node_id.to_string(),
            listen,
            server_ip,
            swim: Mutex::new(None),
            shutdown,
        }
    }

    /// The running membership, once started.
    pub async fn membership(&self) -> Option<SwimMembership> {
        self.swim.lock().await.clone()
    }

    /// Start gossip, or update its key and seeds, from a server `GossipConfig`.
    pub async fn apply_config(&self, config: GossipConfig) {
        let Some(listen) = self.listen else {
            tracing::debug!("Gossip disabled; ignoring GossipConfig");
            return;
        };
        let Ok(key) = <[u8; 32]>::try_from(config.cluster_key.as_slice()) else {
            tracing::warn!(
                len = config.cluster_key.len(),
                "GossipConfig has an invalid cluster key"
            );
            return;
        };

        let mut guard = self.swim.lock().await;
        let swim = match guard.as_ref() {
            Some(swim) => {
                swim.set_key(&key);
                swim.clone()
            }
            None => {
                let swim = SwimMembership::new(&self.node_id, listen, &key);
                match swim.start(self.shutdown.child_token()).await {
                    Ok(addr) => tracing::info!(addr = %addr, "Gossip started"),
                    Err(e) => {
                        tracing::error!(addr = %listen, error = %e, "Failed to start gossip");
                        return;
                    }
                }
                *guard = Some(swim.clone());
                swim
            }
        };
        drop(guard);

        if let Ok(port) = u16::try_from(config.server_port)
            && port != 0
            && !config.server_node_id.is_empty()
        {
            swim.add_seed(
                &config.server_node_id,
                SocketAddr::new(self.server_ip, port),
            )
            .await;
        }
        for member in config.members {
            match member.addr.parse::<SocketAddr>() {
                Ok(addr) => swim.add_seed(&member.node_id, addr).await,
                Err(_) => tracing::debug!(addr = %member.addr, "Ignoring malformed gossip seed"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(key: [u8; 32], server_port: u16) -> GossipConfig {
        GossipConfig {
            cluster_key: key.to_vec(),
            server_node_id: "server-1".into(),
            server_port: server_port.into(),
            members: vec![crate::proto::GossipMember {
                node_id: "node-b".into(),
                addr: "127.0.0.1:9".into(),
            }],
        }
    }

    #[tokio::test]
    async fn first_config_starts_gossip_with_seeds() {
        let shutdown = CancellationToken::new();
        let gossip = AgentGossip::new(
            "node-a",
            Some("127.0.0.1:0".parse().unwrap()),
            "127.0.0.1".parse().unwrap(),
            shutdown.clone(),
        );
        assert!(gossip.membership().await.is_none());

        gossip.apply_config(config([1; 32], 7401)).await;
        let swim = gossip.membership().await.expect("gossip started");
        let mut ids: Vec<String> = swim.all_members().await.into_iter().map(|m| m.0).collect();
        ids.sort();
        assert_eq!(ids, ["node-b", "server-1"]);

        // A second config (key rotation) reuses the running membership.
        gossip.apply_config(config([2; 32], 7401)).await;
        assert_eq!(swim.all_members().await.len(), 2);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn disabled_or_bad_key_does_not_start() {
        let shutdown = CancellationToken::new();
        let disabled = AgentGossip::new("a", None, "127.0.0.1".parse().unwrap(), shutdown.clone());
        disabled.apply_config(config([1; 32], 7401)).await;
        assert!(disabled.membership().await.is_none());

        let enabled = AgentGossip::new(
            "a",
            Some("127.0.0.1:0".parse().unwrap()),
            "127.0.0.1".parse().unwrap(),
            shutdown.clone(),
        );
        let mut bad = config([1; 32], 7401);
        bad.cluster_key.truncate(16);
        enabled.apply_config(bad).await;
        assert!(enabled.membership().await.is_none());
        shutdown.cancel();
    }
}
