//! SWIM-style membership and failure detection over UDP.
//!
//! Every probe interval each node pings every member it knows that is not
//! dead. A member that answers (ack) or pings us is alive. One that stays
//! silent past the suspect timeout is suspected, and past the dead timeout it is
//! declared dead. A ping from an unknown node adds it, so a node joins by
//! pinging any seed and is then learned by everyone it pings.
//!
//! # Wire format
//!
//! ```text
//! type (1) || timestamp_ms (8, big-endian) || node_id (UTF-8) || HMAC-SHA256 tag (32)
//! ```
//!
//! The tag covers everything before it, keyed with the cluster key. Messages
//! with a bad tag, a timestamp outside [`MAX_CLOCK_SKEW`], an invalid node ID,
//! or our own node ID are dropped before they touch membership state.
//!
//! The cluster key is shared by every member, so it authenticates *membership
//! in the fleet*, not *which* member sent a message: any key holder can claim
//! any node ID. Membership here is advisory (failure detection); nothing
//! security-relevant, such as WireGuard peer keys, is taken from gossip.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::hmac;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::gossip::catalog::ServiceCatalog;

/// Default UDP port for gossip.
pub const DEFAULT_GOSSIP_PORT: u16 = 7401;

/// Largest accepted difference between a message's timestamp and local time.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(30);

const HMAC_LEN: usize = 32; // SHA-256 HMAC tag length
const HEADER_LEN: usize = 1 + 8;
const MAX_DATAGRAM: usize = 1500;
/// New members are not added beyond this many known members.
const MAX_MEMBERS: usize = 4096;

const MSG_PING: u8 = 0x01;
const MSG_ACK: u8 = 0x02;

/// SWIM-based membership protocol for failure detection.
///
/// All messages are authenticated with HMAC-SHA256 under a shared cluster key
/// (see the module docs for what that does and does not prove).
#[derive(Clone)]
pub struct SwimMembership {
    inner: Arc<RwLock<MembershipState>>,
    hmac_key: Arc<std::sync::RwLock<Arc<hmac::Key>>>,
}

/// Liveness of a gossip member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    /// Answered within the suspect timeout.
    Alive,
    /// Silent for longer than the suspect timeout.
    Suspect,
    /// Silent for longer than the dead timeout; no longer probed.
    Dead,
}

/// Probe and failure-detection timings.
#[derive(Debug, Clone, Copy)]
pub struct SwimTimings {
    /// How often every live member is pinged.
    pub probe_interval: Duration,
    /// Silence after which an alive member becomes suspect.
    pub suspect_timeout: Duration,
    /// Silence after which a suspect member is declared dead.
    pub dead_timeout: Duration,
}

impl Default for SwimTimings {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(1),
            suspect_timeout: Duration::from_secs(3),
            dead_timeout: Duration::from_secs(10),
        }
    }
}

struct MembershipState {
    node_id: String,
    bind_addr: SocketAddr,
    members: HashMap<String, MemberInfo>,
    timings: SwimTimings,
    catalog: Option<ServiceCatalog>,
}

#[derive(Debug, Clone)]
struct MemberInfo {
    node_id: String,
    addr: SocketAddr,
    status: MemberStatus,
    last_seen: Instant,
    incarnation: u64,
}

/// A decoded, authenticated message.
#[derive(Debug, PartialEq, Eq)]
struct Message {
    kind: u8,
    node_id: String,
}

impl SwimMembership {
    /// Create a member that will listen on `bind_addr` with the default timings.
    pub fn new(node_id: &str, bind_addr: SocketAddr, cluster_key: &[u8; 32]) -> Self {
        Self::with_timings(node_id, bind_addr, cluster_key, SwimTimings::default())
    }

    /// Create a member with explicit probe and failure-detection timings.
    pub fn with_timings(
        node_id: &str,
        bind_addr: SocketAddr,
        cluster_key: &[u8; 32],
        timings: SwimTimings,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MembershipState {
                node_id: node_id.to_string(),
                bind_addr,
                members: HashMap::new(),
                timings,
                catalog: None,
            })),
            hmac_key: Arc::new(std::sync::RwLock::new(Arc::new(hmac::Key::new(
                hmac::HMAC_SHA256,
                cluster_key,
            )))),
        }
    }

    /// Get this node's identifier for use in protocol messages.
    pub async fn node_id(&self) -> String {
        let state = self.inner.read().await;
        state.node_id.clone()
    }

    /// Replace the cluster key (on fleet key rotation). Messages tagged with
    /// the old key are dropped from then on.
    pub fn set_key(&self, cluster_key: &[u8; 32]) {
        let key = Arc::new(hmac::Key::new(hmac::HMAC_SHA256, cluster_key));
        *self.hmac_key.write().unwrap_or_else(|e| e.into_inner()) = key;
    }

    /// Attach a service catalog for gossip propagation.
    ///
    /// The catalog is not yet piggybacked on probe messages.
    pub async fn attach_catalog(&self, catalog: ServiceCatalog) {
        let mut state = self.inner.write().await;
        state.catalog = Some(catalog);
        tracing::info!("Service catalog attached to SWIM membership");
    }

    /// Bind the UDP socket and start the receive loop and probe cycle.
    ///
    /// Returns the bound address (useful with port 0). Both tasks stop when
    /// `shutdown` is cancelled.
    pub async fn start(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<SocketAddr, std::io::Error> {
        let (bind_addr, probe_interval) = {
            let state = self.inner.read().await;
            (state.bind_addr, state.timings.probe_interval)
        };
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr()?;
        tracing::info!(addr = %local_addr, "SWIM membership started (HMAC-authenticated)");

        let recv = self.clone();
        let recv_socket = socket.clone();
        let recv_shutdown = shutdown.child_token();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_DATAGRAM];
            loop {
                tokio::select! {
                    _ = recv_shutdown.cancelled() => break,
                    result = recv_socket.recv_from(&mut buf) => match result {
                        Ok((len, src)) => recv.handle_datagram(&buf[..len], src, &recv_socket).await,
                        Err(e) => tracing::warn!(error = %e, "SWIM recv error"),
                    },
                }
            }
        });

        let probe = self.clone();
        let probe_shutdown = shutdown.child_token();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(probe_interval);
            loop {
                tokio::select! {
                    _ = probe_shutdown.cancelled() => break,
                    _ = interval.tick() => {}
                }
                probe.probe_cycle(&socket).await;
            }
        });

        Ok(local_addr)
    }

    /// Add a seed member to bootstrap the membership.
    ///
    /// A known member keeps its state; only its address is updated.
    pub async fn add_seed(&self, node_id: &str, addr: SocketAddr) {
        let mut state = self.inner.write().await;
        if node_id == state.node_id {
            return;
        }
        if let Some(member) = state.members.get_mut(node_id) {
            member.addr = addr;
            return;
        }
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

    /// Status of one member, if known.
    pub async fn member_status(&self, node_id: &str) -> Option<MemberStatus> {
        let state = self.inner.read().await;
        state.members.get(node_id).map(|m| m.status)
    }

    fn key(&self) -> Arc<hmac::Key> {
        self.hmac_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Encode and tag a message from this node.
    fn encode(&self, kind: u8, node_id: &str) -> Vec<u8> {
        encode_message(&self.key(), kind, node_id, unix_millis())
    }

    /// Verify and decode a datagram. `None` means drop it.
    fn decode(&self, data: &[u8]) -> Option<Message> {
        decode_message(&self.key(), data, unix_millis())
    }

    async fn handle_datagram(&self, data: &[u8], src: SocketAddr, socket: &UdpSocket) {
        let Some(msg) = self.decode(data) else {
            tracing::debug!(src = %src, "Dropping unauthenticated or stale SWIM message");
            return;
        };
        let own_id = self.node_id().await;
        if msg.node_id == own_id {
            return;
        }
        self.mark_alive(&msg.node_id, src).await;
        if msg.kind == MSG_PING {
            let ack = self.encode(MSG_ACK, &own_id);
            if let Err(e) = socket.send_to(&ack, src).await {
                tracing::warn!(src = %src, error = %e, "Failed to send SWIM ack");
            }
        }
    }

    /// Record that `node_id` was heard from at `src`.
    async fn mark_alive(&self, node_id: &str, src: SocketAddr) {
        let mut state = self.inner.write().await;
        if let Some(member) = state.members.get_mut(node_id) {
            if member.status != MemberStatus::Alive {
                // A suspected or dead member that answers has come back;
                // record it as a new incarnation (SWIM refutation).
                member.incarnation += 1;
                tracing::info!(
                    node_id = %node_id,
                    incarnation = member.incarnation,
                    "Gossip member is alive again"
                );
            }
            member.status = MemberStatus::Alive;
            member.last_seen = Instant::now();
            member.addr = src;
        } else if state.members.len() < MAX_MEMBERS {
            tracing::info!(node_id = %node_id, addr = %src, "Gossip member joined");
            state.members.insert(
                node_id.to_string(),
                MemberInfo {
                    node_id: node_id.to_string(),
                    addr: src,
                    status: MemberStatus::Alive,
                    last_seen: Instant::now(),
                    incarnation: 0,
                },
            );
        } else {
            tracing::warn!(node_id = %node_id, "Gossip member table full, ignoring new member");
        }
    }

    /// Ping every live member, then apply suspect/dead transitions.
    async fn probe_cycle(&self, socket: &UdpSocket) {
        let (own_id, targets, timings) = {
            let state = self.inner.read().await;
            let targets: Vec<SocketAddr> = state
                .members
                .values()
                .filter(|m| m.status != MemberStatus::Dead)
                .map(|m| m.addr)
                .collect();
            (state.node_id.clone(), targets, state.timings)
        };
        let ping = self.encode(MSG_PING, &own_id);
        for addr in targets {
            if let Err(e) = socket.send_to(&ping, addr).await {
                tracing::debug!(target = %addr, error = %e, "Failed to send SWIM ping");
            }
        }

        let mut state = self.inner.write().await;
        for member in state.members.values_mut() {
            let elapsed = member.last_seen.elapsed();
            match member.status {
                MemberStatus::Alive if elapsed > timings.suspect_timeout => {
                    tracing::warn!(node_id = %member.node_id, elapsed = ?elapsed, "Gossip member suspected");
                    member.status = MemberStatus::Suspect;
                }
                MemberStatus::Suspect if elapsed > timings.dead_timeout => {
                    tracing::error!(node_id = %member.node_id, elapsed = ?elapsed, "Gossip member declared dead");
                    member.status = MemberStatus::Dead;
                }
                _ => {}
            }
        }
    }
}

/// Encode `kind || timestamp_ms || node_id` and append its HMAC tag.
fn encode_message(key: &hmac::Key, kind: u8, node_id: &str, now_ms: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(HEADER_LEN + node_id.len() + HMAC_LEN);
    msg.push(kind);
    msg.extend_from_slice(&now_ms.to_be_bytes());
    msg.extend_from_slice(node_id.as_bytes());
    let tag = hmac::sign(key, &msg);
    msg.extend_from_slice(tag.as_ref());
    msg
}

/// Verify the tag, freshness and fields of a datagram.
fn decode_message(key: &hmac::Key, data: &[u8], now_ms: u64) -> Option<Message> {
    if data.len() < HEADER_LEN + HMAC_LEN {
        return None;
    }
    let (payload, tag) = data.split_at(data.len() - HMAC_LEN);
    hmac::verify(key, payload, tag).ok()?;

    let kind = payload[0];
    if kind != MSG_PING && kind != MSG_ACK {
        return None;
    }
    let sent_ms = u64::from_be_bytes(payload[1..HEADER_LEN].try_into().ok()?);
    if sent_ms.abs_diff(now_ms) > MAX_CLOCK_SKEW.as_millis() as u64 {
        return None;
    }
    let node_id = std::str::from_utf8(&payload[HEADER_LEN..]).ok()?;
    crate::attestation::join_token::validate_node_id(node_id).ok()?;
    Some(Message {
        kind,
        node_id: node_id.to_string(),
    })
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn key(byte: u8) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &[byte; 32])
    }

    fn fast() -> SwimTimings {
        SwimTimings {
            probe_interval: Duration::from_millis(50),
            suspect_timeout: Duration::from_millis(300),
            dead_timeout: Duration::from_millis(600),
        }
    }

    fn local(node_id: &str, cluster_key: [u8; 32]) -> SwimMembership {
        SwimMembership::with_timings(
            node_id,
            "127.0.0.1:0".parse().unwrap(),
            &cluster_key,
            fast(),
        )
    }

    async fn wait_for(cond: impl AsyncFn() -> bool) -> bool {
        for _ in 0..100 {
            if cond().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[test]
    fn encode_decode_roundtrip() {
        let msg = encode_message(&key(1), MSG_PING, "node-1", NOW);
        assert_eq!(
            decode_message(&key(1), &msg, NOW),
            Some(Message {
                kind: MSG_PING,
                node_id: "node-1".into()
            })
        );
    }

    #[test]
    fn decode_rejects_wrong_key() {
        let msg = encode_message(&key(1), MSG_PING, "node-1", NOW);
        assert_eq!(decode_message(&key(2), &msg, NOW), None);
    }

    #[test]
    fn decode_rejects_tampering() {
        let msg = encode_message(&key(1), MSG_PING, "node-1", NOW);
        for i in 0..msg.len() {
            let mut tampered = msg.clone();
            tampered[i] ^= 0x01;
            assert_eq!(decode_message(&key(1), &tampered, NOW), None, "byte {i}");
        }
    }

    #[test]
    fn decode_rejects_stale_and_future_messages() {
        let skew = MAX_CLOCK_SKEW.as_millis() as u64;
        let old = encode_message(&key(1), MSG_PING, "n", NOW - skew - 1);
        let future = encode_message(&key(1), MSG_PING, "n", NOW + skew + 1);
        let edge = encode_message(&key(1), MSG_PING, "n", NOW - skew);
        assert_eq!(decode_message(&key(1), &old, NOW), None);
        assert_eq!(decode_message(&key(1), &future, NOW), None);
        assert!(decode_message(&key(1), &edge, NOW).is_some());
    }

    #[test]
    fn decode_rejects_truncated_unknown_and_invalid_ids() {
        assert_eq!(decode_message(&key(1), &[], NOW), None);
        assert_eq!(decode_message(&key(1), &[0u8; HMAC_LEN], NOW), None);
        let unknown = encode_message(&key(1), 0x03, "n", NOW);
        assert_eq!(decode_message(&key(1), &unknown, NOW), None);
        let empty_id = encode_message(&key(1), MSG_PING, "", NOW);
        assert_eq!(decode_message(&key(1), &empty_id, NOW), None);
        let bad_id = encode_message(&key(1), MSG_PING, "../x", NOW);
        assert_eq!(decode_message(&key(1), &bad_id, NOW), None);
    }

    #[tokio::test]
    async fn seed_members_start_alive() {
        let s = local("node-1", [0xDE; 32]);
        s.add_seed("node-2", "10.0.0.2:7401".parse().unwrap()).await;
        s.add_seed("node-1", "10.0.0.1:7401".parse().unwrap()).await;

        let all = s.all_members().await;
        assert_eq!(all.len(), 1, "a node never seeds itself");
        assert_eq!(all[0].0, "node-2");
        assert_eq!(all[0].2, MemberStatus::Alive);
    }

    #[tokio::test]
    async fn members_discover_each_other_through_a_seed() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server = local("server-1", [7; 32]);
        let a = local("node-a", [7; 32]);
        let b = local("node-b", [7; 32]);
        let server_addr = server.start(shutdown.clone()).await.unwrap();
        a.start(shutdown.clone()).await.unwrap();
        b.start(shutdown.clone()).await.unwrap();
        a.add_seed("server-1", server_addr).await;
        b.add_seed("server-1", server_addr).await;

        assert!(
            wait_for(async || server.alive_members().await.len() == 2).await,
            "the seed learns both members from their pings"
        );
        // A node told about another (as the server does in GossipConfig)
        // reaches it directly and the other side learns it back.
        let (_, b_addr) = server
            .alive_members()
            .await
            .into_iter()
            .find(|(id, _)| id == "node-b")
            .unwrap();
        a.add_seed("node-b", b_addr).await;
        assert!(
            wait_for(async || b.member_status("node-a").await == Some(MemberStatus::Alive)).await
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn wrong_key_member_is_never_admitted() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server = local("server-1", [7; 32]);
        let intruder = local("intruder", [8; 32]);
        let server_addr = server.start(shutdown.clone()).await.unwrap();
        intruder.start(shutdown.clone()).await.unwrap();
        intruder.add_seed("server-1", server_addr).await;

        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(server.member_status("intruder").await, None);
        // And the intruder never hears a valid ack, so it suspects the seed.
        assert_ne!(
            intruder.member_status("server-1").await,
            Some(MemberStatus::Alive)
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn silent_member_is_suspected_then_dead_and_can_return() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let a = local("node-a", [7; 32]);
        let a_addr = a.start(shutdown.clone()).await.unwrap();

        // A member nobody answers for.
        a.add_seed("node-gone", "127.0.0.1:9".parse().unwrap())
            .await;
        assert!(
            wait_for(async || a.member_status("node-gone").await == Some(MemberStatus::Dead)).await
        );

        // It comes back and pings: alive again.
        let back = local("node-gone", [7; 32]);
        let back_shutdown = tokio_util::sync::CancellationToken::new();
        back.start(back_shutdown.clone()).await.unwrap();
        back.add_seed("node-a", a_addr).await;
        assert!(
            wait_for(async || a.member_status("node-gone").await == Some(MemberStatus::Alive))
                .await
        );
        back_shutdown.cancel();
        shutdown.cancel();
    }

    #[tokio::test]
    async fn rotated_key_drops_members_on_the_old_key() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let a = local("node-a", [7; 32]);
        let b = local("node-b", [7; 32]);
        let a_addr = a.start(shutdown.clone()).await.unwrap();
        b.start(shutdown.clone()).await.unwrap();
        b.add_seed("node-a", a_addr).await;
        assert!(
            wait_for(async || a.member_status("node-b").await == Some(MemberStatus::Alive)).await
        );

        a.set_key(&[9; 32]);
        assert!(
            wait_for(async || a.member_status("node-b").await == Some(MemberStatus::Suspect)).await
        );
        b.set_key(&[9; 32]);
        assert!(
            wait_for(async || a.member_status("node-b").await == Some(MemberStatus::Alive)).await
        );
        shutdown.cancel();
    }
}
