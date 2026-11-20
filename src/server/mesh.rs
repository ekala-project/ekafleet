//! Server side of the WireGuard mesh.
//!
//! The server allocates every node a mesh address in Raft and tells the
//! agent on connect (`MeshAssignment`). The agent brings up its interface
//! and answers with a peer advertisement signed by its node SVID. The server
//! accepts an advertisement only when it arrived on that node's own mTLS
//! stream, is signed with the very certificate the stream authenticated
//! with (so the signing identity chains to the fleet CA), and claims exactly
//! the assigned address. Every connected agent then receives the verified
//! advertisements of all other nodes in a `PeerUpdate`, which it verifies
//! again before configuring peers.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use tokio::sync::RwLock;

use super::state::FleetState;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{MeshAssignment, PeerUpdate, ServerMessage, WireguardPeer};
use crate::raft::state::{FleetStateMachine, MESH_PREFIX_LEN};

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("mesh advertisements require a stream authenticated by a node SVID")]
    NotMtls,
    #[error("advertisement is for node {claimed}, but the stream is node {node_id}")]
    WrongNode { node_id: String, claimed: String },
    #[error("no mesh address is assigned to node {0}")]
    Unassigned(String),
    #[error("advertised address {advertised} is not the assigned {assigned}/32")]
    WrongAddress {
        advertised: String,
        assigned: Ipv4Addr,
    },
    #[error("invalid WireGuard public key")]
    BadPublicKey,
    #[error("invalid endpoint {0:?}")]
    BadEndpoint(String),
    #[error("advertisement is not signed with the stream's node certificate")]
    CertMismatch,
    #[error(transparent)]
    Advert(#[from] crate::mesh::advert::AdvertError),
}

/// Verified peer advertisements, by node.
#[derive(Clone)]
pub struct MeshRegistry {
    peers: Arc<RwLock<BTreeMap<String, WireguardPeer>>>,
    /// Namespace addresses of the replicas on each node, routed to it.
    routes: Arc<RwLock<BTreeMap<String, Vec<String>>>>,
    raft: FleetStateMachine,
    domain: String,
}

impl MeshRegistry {
    pub fn new(raft: FleetStateMachine, domain: &str) -> Self {
        Self {
            peers: Arc::default(),
            routes: Arc::default(),
            raft,
            domain: domain.to_string(),
        }
    }

    /// The IPv4 underlay address (WireGuard endpoint) each node advertised.
    pub async fn underlay_addresses(&self) -> BTreeMap<String, std::net::Ipv4Addr> {
        self.peers
            .read()
            .await
            .iter()
            .filter_map(
                |(node, peer)| match peer.endpoint.parse::<std::net::SocketAddr>() {
                    Ok(std::net::SocketAddr::V4(addr)) => Some((node.clone(), *addr.ip())),
                    _ => None,
                },
            )
            .collect()
    }

    /// The node's mesh address, allocated on first use. `None` (logged) if
    /// the mesh network is full or Raft refused the allocation.
    pub async fn assignment(&self, node_id: &str) -> Option<MeshAssignment> {
        match self.raft.ensure_mesh_ip(node_id).await {
            Ok(Some(ip)) => Some(MeshAssignment {
                mesh_ip: ip.to_string(),
                prefix_len: MESH_PREFIX_LEN.into(),
            }),
            Ok(None) => {
                tracing::error!(node_id, "Mesh network is full; node gets no mesh address");
                None
            }
            Err(e) => {
                tracing::error!(node_id, error = %e, "Cannot allocate mesh address");
                None
            }
        }
    }

    /// Validate and record `peer`, received on the control stream of
    /// `node_id` that authenticated with the DER certificate `stream_cert`.
    /// Returns the node's mesh address and whether the advertisement
    /// changed.
    pub async fn accept(
        &self,
        node_id: &str,
        peer: WireguardPeer,
        stream_cert: Option<&[u8]>,
    ) -> Result<(Ipv4Addr, bool), MeshError> {
        let stream_cert = stream_cert.ok_or(MeshError::NotMtls)?;
        if peer.node_id != node_id {
            return Err(MeshError::WrongNode {
                node_id: node_id.to_string(),
                claimed: peer.node_id,
            });
        }
        let assigned = self
            .raft
            .mesh_ip(node_id)
            .await
            .ok_or_else(|| MeshError::Unassigned(node_id.to_string()))?;
        if peer.allowed_ip != format!("{assigned}/32") {
            return Err(MeshError::WrongAddress {
                advertised: peer.allowed_ip,
                assigned,
            });
        }
        if !valid_public_key(&peer.public_key) {
            return Err(MeshError::BadPublicKey);
        }
        if peer.endpoint.parse::<SocketAddr>().is_err() {
            return Err(MeshError::BadEndpoint(peer.endpoint));
        }
        crate::mesh::advert::verify_advert(&peer, &self.domain)?;
        if pem_certificate_der(&peer.signing_cert_pem).as_deref() != Some(stream_cert) {
            return Err(MeshError::CertMismatch);
        }

        // Routes come from placement, never from the node itself.
        let peer = WireguardPeer {
            routed_ips: Vec::new(),
            ..peer
        };
        let mut peers = self.peers.write().await;
        let changed = peers.get(node_id) != Some(&peer);
        peers.insert(node_id.to_string(), peer);
        Ok((assigned, changed))
    }

    /// Every node's advertisement except `node_id`'s own, each with the
    /// namespace addresses routed to that node.
    pub async fn peers_for(&self, node_id: &str) -> PeerUpdate {
        let routes = self.routes.read().await;
        PeerUpdate {
            peers: self
                .peers
                .read()
                .await
                .iter()
                .filter(|(id, _)| id.as_str() != node_id)
                .map(|(id, peer)| WireguardPeer {
                    routed_ips: routes.get(id).cloned().unwrap_or_default(),
                    ..peer.clone()
                })
                .collect(),
        }
    }

    /// Route every replica's namespace address to the node it is placed
    /// on, so ingress proxies on other nodes reach it. Sends every agent
    /// its new peer set when the routes changed.
    pub async fn sync_routes(&self, state: &FleetState) {
        let routes: BTreeMap<String, Vec<String>> = self
            .raft
            .namespace_ips_by_node()
            .await
            .into_iter()
            .map(|(node, ips)| (node, ips.iter().map(Ipv4Addr::to_string).collect()))
            .collect();
        {
            let mut current = self.routes.write().await;
            if *current == routes {
                return;
            }
            *current = routes;
        }
        self.distribute(state).await;
    }

    /// Send each connected agent its current peer set.
    pub async fn distribute(&self, state: &FleetState) {
        for node_id in state.connected_nodes().await {
            let update = self.peers_for(&node_id).await;
            let msg = ServerMessage {
                payload: Some(ServerPayload::Peers(update)),
            };
            state.send_to_agent(&node_id, msg).await;
        }
    }

    /// Forget the nodes that are not connected and `keep` rejects (gone
    /// from the configuration and the cloud tracker): their
    /// advertisements and mesh addresses. The remaining agents are sent
    /// their new peer sets when any was forgotten. Returns those nodes.
    pub async fn prune(&self, state: &FleetState, keep: impl Fn(&str) -> bool) -> Vec<String> {
        let connected: std::collections::HashSet<String> =
            state.connected_nodes().await.into_iter().collect();
        let mut known: std::collections::BTreeSet<String> =
            self.raft.mesh_nodes().await.into_iter().collect();
        known.extend(self.peers.read().await.keys().cloned());
        let mut forgotten = Vec::new();
        for node in known {
            if keep(&node) || connected.contains(&node) {
                continue;
            }
            if let Err(e) = self.raft.release_mesh_ip(&node).await {
                tracing::warn!(node_id = %node, error = %e, "Cannot release a mesh address");
                continue;
            }
            self.peers.write().await.remove(&node);
            tracing::info!(node_id = %node, "Removed a departed node from the mesh");
            forgotten.push(node);
        }
        if !forgotten.is_empty() {
            self.distribute(state).await;
        }
        forgotten
    }

    /// Handle an advertisement from `node_id`'s stream: record it and, if
    /// it changed, update the node's VXLAN underlay address and send every
    /// agent its new peer set.
    pub async fn handle_advert(
        &self,
        state: &FleetState,
        node_id: &str,
        peer: WireguardPeer,
        stream_cert: Option<&[u8]>,
    ) {
        match self.accept(node_id, peer, stream_cert).await {
            Ok((ip, changed)) => {
                state.update_mesh_ip(node_id, ip).await;
                if changed {
                    tracing::info!(node_id, mesh_ip = %ip, "Mesh peer advertisement accepted");
                    self.distribute(state).await;
                }
            }
            Err(e) => {
                tracing::warn!(node_id, error = %e, "Mesh peer advertisement rejected");
            }
        }
    }
}

/// A WireGuard public key: base64 of 32 bytes.
fn valid_public_key(key: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .is_ok_and(|bytes| bytes.len() == 32)
}

/// DER of the first certificate in `pem`.
fn pem_certificate_der(pem: &str) -> Option<Vec<u8>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    crate::ca::pki::pem_certs(&mut reader)
        .next()?
        .ok()
        .map(|der| der.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &str = "fleet.test";

    /// A node certificate for `node_id` and its PKCS#8 key, self-signed:
    /// `accept` trusts the stream's certificate, not a chain.
    fn node_cert(node_id: &str) -> (String, Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            format!("spiffe://{DOMAIN}/agent/{node_id}")
                .try_into()
                .unwrap(),
        )];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), cert.der().to_vec(), key.serialize_der())
    }

    fn advert(node_id: &str, allowed_ip: &str, cert_pem: &str, key: &[u8]) -> WireguardPeer {
        let public_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let endpoint = "192.0.2.10:51820";
        let signature =
            crate::mesh::advert::sign_advert(node_id, &public_key, endpoint, allowed_ip, key)
                .unwrap();
        WireguardPeer {
            node_id: node_id.into(),
            public_key,
            endpoint: endpoint.into(),
            allowed_ip: allowed_ip.into(),
            signature,
            signing_cert_pem: cert_pem.into(),
            routed_ips: Vec::new(),
        }
    }

    #[tokio::test]
    async fn replica_namespace_addresses_are_routed_to_their_nodes() {
        let raft = FleetStateMachine::new();
        let mesh = MeshRegistry::new(raft.clone(), DOMAIN);
        let state = FleetState::new();
        for node in ["a", "b"] {
            let ip = mesh.assignment(node).await.unwrap().mesh_ip;
            let (pem, der, key) = node_cert(node);
            let mut peer = advert(node, &format!("{ip}/32"), &pem, &key);
            // A node cannot claim routes for itself.
            peer.routed_ips = vec!["10.200.9.9".into()];
            mesh.accept(node, peer, Some(&der)).await.unwrap();
        }
        let web = raft
            .ensure_namespace_ip("acme", &crate::raft::state::namespace_ip_holder("web", "b"))
            .await
            .unwrap()
            .unwrap();
        let mut rx = state
            .register_agent("a", "192.0.2.1".into(), String::new())
            .await;

        mesh.sync_routes(&state).await;
        let Some(ServerPayload::Peers(update)) = rx.try_recv().unwrap().payload else {
            panic!("no peer update");
        };
        assert_eq!(update.peers.len(), 1);
        assert_eq!(update.peers[0].node_id, "b");
        assert_eq!(update.peers[0].routed_ips, vec![web.to_string()]);
        // Unchanged routes are not re-sent.
        mesh.sync_routes(&state).await;
        assert!(rx.try_recv().is_err());
        assert!(mesh.peers_for("b").await.peers[0].routed_ips.is_empty());
    }

    #[tokio::test]
    async fn departed_nodes_leave_the_mesh() {
        let raft = FleetStateMachine::new();
        let mesh = MeshRegistry::new(raft.clone(), DOMAIN);
        let state = FleetState::new();
        for node in ["kept", "connected", "gone"] {
            let ip = mesh.assignment(node).await.unwrap().mesh_ip;
            let (pem, der, key) = node_cert(node);
            mesh.accept(
                node,
                advert(node, &format!("{ip}/32"), &pem, &key),
                Some(&der),
            )
            .await
            .unwrap();
        }
        let mut rx = state
            .register_agent("connected", "192.0.2.1".into(), String::new())
            .await;

        let forgotten = mesh.prune(&state, |node| node == "kept").await;
        assert_eq!(forgotten, vec!["gone".to_string()]);
        assert_eq!(raft.mesh_ip("gone").await, None);
        assert!(raft.mesh_ip("kept").await.is_some());
        // The connected agent learns that the peer is gone.
        let mut peers = None;
        while let Ok(msg) = rx.try_recv() {
            if let Some(ServerPayload::Peers(update)) = msg.payload {
                peers = Some(update);
            }
        }
        let peers: Vec<String> = peers
            .unwrap()
            .peers
            .into_iter()
            .map(|p| p.node_id)
            .collect();
        assert_eq!(peers, vec!["kept".to_string()]);
        // Nothing more to forget.
        assert!(mesh.prune(&state, |node| node == "kept").await.is_empty());
    }

    #[tokio::test]
    async fn accepts_only_bound_advertisements_for_the_assigned_address() {
        let raft = FleetStateMachine::new();
        let mesh = MeshRegistry::new(raft.clone(), DOMAIN);
        let assigned = mesh.assignment("a").await.unwrap();
        assert_eq!(assigned.mesh_ip, "10.100.0.1");
        assert_eq!(assigned.prefix_len, 16);
        let (pem, der, key) = node_cert("a");
        let good = advert("a", "10.100.0.1/32", &pem, &key);

        assert!(matches!(
            mesh.accept("a", good.clone(), None).await,
            Err(MeshError::NotMtls)
        ));
        assert!(matches!(
            mesh.accept("b", good.clone(), Some(&der)).await,
            Err(MeshError::WrongNode { .. })
        ));
        let wrong_ip = advert("a", "10.100.0.9/32", &pem, &key);
        assert!(matches!(
            mesh.accept("a", wrong_ip, Some(&der)).await,
            Err(MeshError::WrongAddress { .. })
        ));
        // Signed by another certificate for the same identity.
        let (_, other_der, _) = node_cert("a");
        assert!(matches!(
            mesh.accept("a", good.clone(), Some(&other_der)).await,
            Err(MeshError::CertMismatch)
        ));
        let mut tampered = good.clone();
        tampered.endpoint = "192.0.2.66:51820".into();
        assert!(matches!(
            mesh.accept("a", tampered, Some(&der)).await,
            Err(MeshError::Advert(_))
        ));
        let mut bad_key = good.clone();
        bad_key.public_key = "not-a-key".into();
        assert!(matches!(
            mesh.accept("a", bad_key, Some(&der)).await,
            Err(MeshError::BadPublicKey)
        ));
        // A node without an assignment cannot advertise.
        let (b_pem, b_der, b_key) = node_cert("b");
        assert!(matches!(
            mesh.accept(
                "b",
                advert("b", "10.100.0.2/32", &b_pem, &b_key),
                Some(&b_der)
            )
            .await,
            Err(MeshError::Unassigned(_))
        ));

        let ip = Ipv4Addr::new(10, 100, 0, 1);
        assert_eq!(
            mesh.accept("a", good.clone(), Some(&der)).await.unwrap(),
            (ip, true)
        );
        assert_eq!(
            mesh.accept("a", good.clone(), Some(&der)).await.unwrap(),
            (ip, false)
        );
        assert!(mesh.peers_for("a").await.peers.is_empty());
        assert_eq!(mesh.peers_for("b").await.peers, vec![good]);
    }
}
