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
    raft: FleetStateMachine,
    domain: String,
}

impl MeshRegistry {
    pub fn new(raft: FleetStateMachine, domain: &str) -> Self {
        Self {
            peers: Arc::default(),
            raft,
            domain: domain.to_string(),
        }
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

        let mut peers = self.peers.write().await;
        let changed = peers.get(node_id) != Some(&peer);
        peers.insert(node_id.to_string(), peer);
        Ok((assigned, changed))
    }

    /// Every node's advertisement except `node_id`'s own.
    pub async fn peers_for(&self, node_id: &str) -> PeerUpdate {
        PeerUpdate {
            peers: self
                .peers
                .read()
                .await
                .iter()
                .filter(|(id, _)| id.as_str() != node_id)
                .map(|(_, peer)| peer.clone())
                .collect(),
        }
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
    rustls_pemfile::certs(&mut reader)
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
        }
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
