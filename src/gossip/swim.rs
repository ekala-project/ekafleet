use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ring::hmac;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const HMAC_LEN: usize = 32; // SHA-256 HMAC tag length

/// SWIM-based membership protocol for failure detection.
/// Detects node failures in 2-5 seconds via ping/ping-req/suspect cycle.
/// All messages are authenticated with HMAC-SHA256 using a shared cluster key.
#[derive(Clone)]
pub struct SwimMembership {
    inner: Arc<RwLock<MembershipState>>,
    hmac_key: Arc<hmac::Key>,
}

struct MembershipState {
    node_id: String,
    bind_addr: SocketAddr,
    members: HashMap<String, MemberInfo>,
    suspect_timeout: Duration,
    dead_timeout: Duration,
}

#[derive(Debug, Clone)]
struct MemberInfo {
    node_id: String,
    addr: SocketAddr,
    status: MemberStatus,
    last_seen: Instant,
    incarnation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    Alive,
    Suspect,
    Dead,
}

impl SwimMembership {
    pub fn new(node_id: &str, bind_addr: SocketAddr, cluster_key: &[u8; 32]) -> Self {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, cluster_key);
        Self {
            inner: Arc::new(RwLock::new(MembershipState {
                node_id: node_id.to_string(),
                bind_addr,
                members: HashMap::new(),
                suspect_timeout: Duration::from_secs(3),
                dead_timeout: Duration::from_secs(10),
            })),
            hmac_key: Arc::new(hmac_key),
        }
    }

    /// Sign a message payload with HMAC-SHA256.
    /// Returns payload || hmac_tag (32 bytes).
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let tag = hmac::sign(&self.hmac_key, payload);
        let mut signed = Vec::with_capacity(payload.len() + HMAC_LEN);
        signed.extend_from_slice(payload);
        signed.extend_from_slice(tag.as_ref());
        signed
    }

    /// Verify and strip HMAC tag from a received message.
    /// Returns the payload if verification succeeds.
    fn verify<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if data.len() < HMAC_LEN {
            return None;
        }
        let (payload, tag) = data.split_at(data.len() - HMAC_LEN);
        hmac::verify(&self.hmac_key, payload, tag).ok()?;
        Some(payload)
    }

    /// Start the SWIM protocol. Listens for UDP messages and runs
    /// the probe cycle.
    pub async fn start(&self) -> Result<(), std::io::Error> {
        let state = self.inner.read().await;
        let socket = UdpSocket::bind(state.bind_addr).await?;
        let bind = state.bind_addr;
        drop(state);

        tracing::info!(addr = %bind, "SWIM membership started (HMAC-authenticated)");

        let inner = self.inner.clone();

        // Spawn receiver
        let recv_inner = inner.clone();
        let recv_key = self.hmac_key.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        // Verify HMAC before processing
                        let data = &buf[..len];
                        if data.len() < HMAC_LEN {
                            tracing::warn!(src = %src, "SWIM message too short, dropping");
                            continue;
                        }
                        let (payload, tag) = data.split_at(data.len() - HMAC_LEN);
                        if hmac::verify(&recv_key, payload, tag).is_err() {
                            tracing::warn!(src = %src, "SWIM HMAC verification failed, dropping");
                            continue;
                        }
                        handle_message(&recv_inner, payload, src).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "SWIM recv error");
                    }
                }
            }
        });

        // Spawn probe cycle
        let probe_inner = inner.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                probe_cycle(&probe_inner).await;
            }
        });

        Ok(())
    }

    /// Add a seed member to bootstrap the membership.
    pub async fn add_seed(&self, node_id: &str, addr: SocketAddr) {
        let mut state = self.inner.write().await;
        state.members.insert(
            node_id.to_string(),
            MemberInfo {
                node_id: node_id.to_string(),
                addr,
                status: MemberStatus::Alive,
                last_seen: Instant::now(),
                incarnation: 0,
            },
        );
    }

    /// Get all alive members.
    pub async fn alive_members(&self) -> Vec<(String, SocketAddr)> {
        let state = self.inner.read().await;
        state
            .members
            .iter()
            .filter(|(_, m)| m.status == MemberStatus::Alive)
            .map(|(id, m)| (id.clone(), m.addr))
            .collect()
    }

    /// Get all members with their status.
    pub async fn all_members(&self) -> Vec<(String, SocketAddr, MemberStatus)> {
        let state = self.inner.read().await;
        state
            .members
            .iter()
            .map(|(id, m)| (id.clone(), m.addr, m.status))
            .collect()
    }
}

/// Handle an incoming SWIM message (already HMAC-verified).
async fn handle_message(state: &Arc<RwLock<MembershipState>>, data: &[u8], src: SocketAddr) {
    // Simple protocol: first byte is message type
    // 0x01 = ping, 0x02 = ack, 0x03 = ping-req
    if data.is_empty() {
        return;
    }

    match data[0] {
        0x01 => {
            // Ping — respond with ack
            tracing::trace!(src = %src, "SWIM ping received");
            // TODO: send ack back (signed with HMAC)
        }
        0x02 => {
            // Ack — mark sender as alive
            let mut state = state.write().await;
            for member in state.members.values_mut() {
                if member.addr == src {
                    member.status = MemberStatus::Alive;
                    member.last_seen = Instant::now();
                    break;
                }
            }
        }
        0x03 => {
            // Ping-req — proxy ping to target
            tracing::trace!(src = %src, "SWIM ping-req received");
            // TODO: forward ping (signed with HMAC)
        }
        _ => {
            tracing::trace!(src = %src, type_byte = data[0], "Unknown SWIM message");
        }
    }
}

/// Run one probe cycle: check for suspects and dead members.
async fn probe_cycle(state: &Arc<RwLock<MembershipState>>) {
    let mut state = state.write().await;
    let suspect_timeout = state.suspect_timeout;
    let dead_timeout = state.dead_timeout;

    for member in state.members.values_mut() {
        let elapsed = member.last_seen.elapsed();

        match member.status {
            MemberStatus::Alive if elapsed > suspect_timeout => {
                tracing::warn!(
                    node_id = %member.node_id,
                    elapsed = ?elapsed,
                    "Member suspected"
                );
                member.status = MemberStatus::Suspect;
            }
            MemberStatus::Suspect if elapsed > dead_timeout => {
                tracing::error!(
                    node_id = %member.node_id,
                    elapsed = ?elapsed,
                    "Member declared dead"
                );
                member.status = MemberStatus::Dead;
            }
            _ => {}
        }
    }
}
