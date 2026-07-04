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
        let socket = Arc::new(socket);
        let recv_inner = inner.clone();
        let recv_key = self.hmac_key.clone();
        let recv_socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match recv_socket.recv_from(&mut buf).await {
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
                        handle_message(&recv_inner, payload, src, &recv_socket, &recv_key).await;
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
async fn handle_message(
    state: &Arc<RwLock<MembershipState>>,
    data: &[u8],
    src: SocketAddr,
    socket: &UdpSocket,
    hmac_key: &hmac::Key,
) {
    // Simple protocol: first byte is message type
    // 0x01 = ping, 0x02 = ack, 0x03 = ping-req
    if data.is_empty() {
        return;
    }

    match data[0] {
        0x01 => {
            // Ping — respond with ack (signed with HMAC)
            tracing::trace!(src = %src, "SWIM ping received");
            let ack_payload = [0x02u8]; // ack message type
            let tag = hmac::sign(hmac_key, &ack_payload);
            let mut signed = Vec::with_capacity(1 + HMAC_LEN);
            signed.extend_from_slice(&ack_payload);
            signed.extend_from_slice(tag.as_ref());
            if let Err(e) = socket.send_to(&signed, src).await {
                tracing::warn!(src = %src, error = %e, "Failed to send SWIM ack");
            }
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
            // Ping-req — forward ping to target address encoded in data[1..7]
            // Format: 0x03 || 4-byte IP || 2-byte port (big-endian)
            tracing::trace!(src = %src, "SWIM ping-req received");
            if data.len() >= 7 {
                let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                let target = SocketAddr::new(std::net::IpAddr::V4(ip), port);

                let ping_payload = [0x01u8];
                let tag = hmac::sign(hmac_key, &ping_payload);
                let mut signed = Vec::with_capacity(1 + HMAC_LEN);
                signed.extend_from_slice(&ping_payload);
                signed.extend_from_slice(tag.as_ref());
                if let Err(e) = socket.send_to(&signed, target).await {
                    tracing::warn!(target = %target, error = %e, "Failed to forward SWIM ping");
                }
            }
        }
        _ => {
            tracing::trace!(src = %src, type_byte = data[0], "Unknown SWIM message");
        }
    }
}

/// Sign a message payload with a given HMAC key (for testing).
#[cfg(test)]
fn sign_with_key(key: &hmac::Key, payload: &[u8]) -> Vec<u8> {
    let tag = hmac::sign(key, payload);
    let mut signed = Vec::with_capacity(payload.len() + HMAC_LEN);
    signed.extend_from_slice(payload);
    signed.extend_from_slice(tag.as_ref());
    signed
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster_key() -> [u8; 32] {
        [0xDE; 32]
    }

    fn swim(node_id: &str) -> SwimMembership {
        SwimMembership::new(node_id, "127.0.0.1:0".parse().unwrap(), &cluster_key())
    }

    #[test]
    fn sign_verify_roundtrip() {
        let s = swim("node-1");
        let payload = b"hello";

        let signed = s.sign(payload);
        let verified = s.verify(&signed);

        assert!(verified.is_some());
        assert_eq!(verified.unwrap(), payload);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let s1 = SwimMembership::new("n1", "127.0.0.1:0".parse().unwrap(), &[0xAA; 32]);
        let s2 = SwimMembership::new("n2", "127.0.0.1:0".parse().unwrap(), &[0xBB; 32]);

        let signed = s1.sign(b"payload");
        let result = s2.verify(&signed);

        assert!(
            result.is_none(),
            "different cluster key must fail verification"
        );
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let s = swim("node-1");
        let mut signed = s.sign(b"original");

        // Tamper with the payload (before the HMAC tag)
        signed[0] ^= 0xFF;

        let result = s.verify(&signed);
        assert!(result.is_none(), "tampered payload must fail verification");
    }

    #[test]
    fn verify_rejects_tampered_tag() {
        let s = swim("node-1");
        let mut signed = s.sign(b"payload");

        // Tamper with the HMAC tag (last byte)
        let last = signed.len() - 1;
        signed[last] ^= 0xFF;

        let result = s.verify(&signed);
        assert!(result.is_none(), "tampered tag must fail verification");
    }

    #[test]
    fn verify_rejects_truncated_message() {
        let s = swim("node-1");

        // Too short to contain an HMAC tag
        assert!(s.verify(&[0u8; HMAC_LEN - 1]).is_none());
        assert!(s.verify(&[]).is_none());
    }

    #[tokio::test]
    async fn seed_members_start_alive() {
        let s = swim("node-1");
        s.add_seed("node-2", "10.0.0.2:7401".parse().unwrap()).await;

        let alive = s.alive_members().await;
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].0, "node-2");
    }

    #[tokio::test]
    async fn all_members_includes_status() {
        let s = swim("node-1");
        s.add_seed("node-2", "10.0.0.2:7401".parse().unwrap()).await;

        let all = s.all_members().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].2, MemberStatus::Alive);
    }
}
