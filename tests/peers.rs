//! WireGuard peer distribution through the real server: agents send adverts
//! signed with their node SVIDs, the server verifies and relays them, and
//! unsigned or wrongly signed adverts are never relayed.

mod common;

use std::time::Duration;

use common::{ADMIN_TOKEN, DOMAIN, TestServer, channel, create_token, identity_of, start_server};
use ekafleet::agent::join::{AttestedNode, attest_with_join_token};
use ekafleet::mesh::advert::{AdvertVerifier, pkcs8_der_from_pem, sign_advert};
use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::server_message::Payload as ServerPayload;
use ekafleet::proto::{AgentMessage, Heartbeat, ServerMessage, WireguardPeer, agent_message};
use tokio::sync::mpsc;
use tonic::Streaming;

const KEY_A: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn attest(server: &TestServer, node_id: &str) -> AttestedNode {
    let token = create_token(server, Some(ADMIN_TOKEN), node_id)
        .await
        .unwrap();
    attest_with_join_token(channel(server, None).await, &token, node_id)
        .await
        .unwrap()
}

fn heartbeat(node_id: &str) -> AgentMessage {
    AgentMessage {
        payload: Some(agent_message::Payload::Heartbeat(Heartbeat {
            node_id: node_id.to_string(),
            timestamp: 0,
            available_resources: None,
            pool: String::new(),
            version: String::new(),
            mesh_ip: String::new(),
        })),
    }
}

fn advert_msg(advert: WireguardPeer) -> AgentMessage {
    AgentMessage {
        payload: Some(agent_message::Payload::PeerAdvert(advert)),
    }
}

/// Open a control stream as `node_id`, authenticated by `identity` (mTLS) or,
/// without one, by the admin bearer token.
async fn open_stream(
    server: &TestServer,
    node: Option<&AttestedNode>,
    node_id: &str,
) -> (mpsc::Sender<AgentMessage>, Streaming<ServerMessage>) {
    let (tx, rx) = mpsc::channel(16);
    tx.send(heartbeat(node_id)).await.unwrap();
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let inbound = match node {
        Some(node) => FleetControlClient::new(channel(server, Some(identity_of(node))).await)
            .stream_control(stream)
            .await
            .unwrap()
            .into_inner(),
        None => {
            let mut req = tonic::Request::new(stream);
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {ADMIN_TOKEN}").parse().unwrap(),
            );
            FleetControlClient::new(channel(server, None).await)
                .stream_control(req)
                .await
                .unwrap()
                .into_inner()
        }
    };
    (tx, inbound)
}

/// The next `PeerUpdate` on `inbound`, if one arrives within `wait`.
async fn next_peers(
    inbound: &mut Streaming<ServerMessage>,
    wait: Duration,
) -> Option<Vec<WireguardPeer>> {
    tokio::time::timeout(wait, async {
        loop {
            let msg = inbound.message().await.unwrap().expect("stream open");
            if let Some(ServerPayload::Peers(update)) = msg.payload {
                return update.peers;
            }
        }
    })
    .await
    .ok()
}

fn signed(node: &AttestedNode, node_id: &str, key: &str, ip: &str) -> WireguardPeer {
    let mut advert = WireguardPeer {
        node_id: node_id.to_string(),
        public_key: key.to_string(),
        endpoint: "192.0.2.10:51820".to_string(),
        allowed_ip: format!("{ip}/32"),
        issued_at: now_ms(),
        ..Default::default()
    };
    let key_der = pkcs8_der_from_pem(&node.key_pem).unwrap();
    sign_advert(&mut advert, &node.cert_pem, &key_der).unwrap();
    advert
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_advert_is_relayed_and_bad_ones_are_not() {
    let server = start_server().await;
    let node_a = attest(&server, "node-a").await;
    let node_b = attest(&server, "node-b").await;

    // node-b is watching; on connect it gets the (empty) current peer set.
    let (_b_tx, mut b_in) = open_stream(&server, Some(&node_b), "node-b").await;
    let initial = next_peers(&mut b_in, Duration::from_secs(5)).await;
    assert_eq!(initial, Some(vec![]));

    let (a_tx, _a_in) = open_stream(&server, Some(&node_a), "node-a").await;

    // 1. Unsigned.
    let mut unsigned = signed(&node_a, "node-a", KEY_A, "10.100.0.1");
    unsigned.signature.clear();
    a_tx.send(advert_msg(unsigned)).await.unwrap();
    // 2. Signed by node-a but claiming node-b (node-a's stream).
    a_tx.send(advert_msg(signed(&node_a, "node-b", KEY_B, "10.100.0.2")))
        .await
        .unwrap();
    // 3. Tampered after signing: WireGuard key swapped.
    let mut tampered = signed(&node_a, "node-a", KEY_A, "10.100.0.1");
    tampered.public_key = KEY_B.to_string();
    a_tx.send(advert_msg(tampered)).await.unwrap();
    // 4. node-b's genuine advert replayed over node-a's stream.
    a_tx.send(advert_msg(signed(&node_b, "node-b", KEY_B, "10.100.0.2")))
        .await
        .unwrap();
    // 5. Finally a valid advert.
    let good = signed(&node_a, "node-a", KEY_A, "10.100.0.1");
    a_tx.send(advert_msg(good.clone())).await.unwrap();

    // The first relayed update holds only the valid advert: none of the bad
    // ones were accepted (each acceptance would broadcast).
    let relayed = next_peers(&mut b_in, Duration::from_secs(5))
        .await
        .expect("valid advert relayed");
    assert_eq!(relayed, vec![good.clone()]);
    // node-b can verify it independently with only the pinned CA.
    AdvertVerifier::new(&server.root_ca_pem, DOMAIN)
        .unwrap()
        .verify(&relayed[0])
        .unwrap();

    // 6. Replaying the same advert is refused; nothing more is relayed.
    a_tx.send(advert_msg(good)).await.unwrap();
    assert_eq!(
        next_peers(&mut b_in, Duration::from_millis(500)).await,
        None
    );

    // When node-a disconnects its advert is withdrawn.
    drop(a_tx);
    drop(_a_in);
    let after = next_peers(&mut b_in, Duration::from_secs(5))
        .await
        .expect("withdrawal relayed");
    assert!(after.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn bearer_token_stream_cannot_advertise() {
    let server = start_server().await;
    let node_a = attest(&server, "node-a").await;
    let (_b_tx, mut b_in) =
        open_stream(&server, Some(&attest(&server, "node-b").await), "node-b").await;
    assert_eq!(
        next_peers(&mut b_in, Duration::from_secs(5)).await,
        Some(vec![])
    );

    // A genuinely signed advert, but sent over a bearer-token stream.
    let (tx, _in) = open_stream(&server, None, "node-a").await;
    tx.send(advert_msg(signed(&node_a, "node-a", KEY_A, "10.100.0.1")))
        .await
        .unwrap();
    assert_eq!(
        next_peers(&mut b_in, Duration::from_millis(800)).await,
        None
    );
}
