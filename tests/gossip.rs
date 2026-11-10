//! Gossip bootstrap through the real server: an attested agent receives
//! `GossipConfig` on its control stream, starts SWIM with it, and the server's
//! membership sees the agent alive.

mod common;

use std::time::Duration;

use common::{ADMIN_TOKEN, channel, create_token, identity_of, start_server_with_gossip};
use ekafleet::agent::gossip::AgentGossip;
use ekafleet::agent::join::attest_with_join_token;
use ekafleet::gossip::swim::{MemberStatus, SwimMembership};
use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::server_message::Payload as ServerPayload;
use ekafleet::proto::{AgentMessage, GossipConfig, Heartbeat, agent_message};
use tokio_util::sync::CancellationToken;

/// Open a control stream as `node_id` and return the first `GossipConfig`.
async fn receive_gossip_config(
    server: &common::TestServer,
    identity: tonic::transport::Identity,
    node_id: &str,
) -> (GossipConfig, tokio::sync::mpsc::Sender<AgentMessage>) {
    let mut client = FleetControlClient::new(channel(server, Some(identity)).await);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(AgentMessage {
        payload: Some(agent_message::Payload::Heartbeat(Heartbeat {
            node_id: node_id.to_string(),
            timestamp: 0,
            available_resources: None,
            pool: String::new(),
            version: String::new(),
            mesh_ip: String::new(),
        })),
    })
    .await
    .unwrap();
    let mut inbound = client
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let config = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = inbound.message().await.unwrap().expect("stream open");
            if let Some(ServerPayload::Gossip(config)) = msg.payload {
                return config;
            }
        }
    })
    .await
    .expect("server sends GossipConfig on connect");
    (config, tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn attested_agent_joins_server_gossip() {
    let shutdown = CancellationToken::new();
    let key = ekafleet::gossip::derive_cluster_key(&common::FLEET_KEY);
    let server_swim = SwimMembership::new("server-test", "127.0.0.1:0".parse().unwrap(), &key);
    let gossip_addr = server_swim.start(shutdown.clone()).await.unwrap();
    let server = start_server_with_gossip(Some(ekafleet::server::api::ServerGossip {
        swim: server_swim.clone(),
        node_id: "server-test".into(),
        port: gossip_addr.port(),
    }))
    .await;

    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();
    let (config, _stream) = receive_gossip_config(&server, identity_of(&node), "node-a").await;

    assert_eq!(
        config.cluster_key,
        key.to_vec(),
        "key derived from the fleet key"
    );
    assert_eq!(config.server_node_id, "server-test");
    assert_eq!(config.server_port, u32::from(gossip_addr.port()));

    let agent = AgentGossip::new(
        "node-a",
        Some("127.0.0.1:0".parse().unwrap()),
        "127.0.0.1".parse().unwrap(),
        shutdown.clone(),
    );
    agent.apply_config(config).await;

    let mut alive = false;
    for _ in 0..50 {
        if server_swim.member_status("node-a").await == Some(MemberStatus::Alive) {
            alive = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(alive, "server gossip sees the agent alive");
    let agent_swim = agent.membership().await.unwrap();
    assert_eq!(
        agent_swim.member_status("server-test").await,
        Some(MemberStatus::Alive)
    );
    shutdown.cancel();
}

#[tokio::test(flavor = "multi_thread")]
async fn no_gossip_config_when_gossip_is_disabled() {
    let server = start_server_with_gossip(None).await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();

    let mut client = FleetControlClient::new(channel(&server, Some(identity_of(&node))).await);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(AgentMessage {
        payload: Some(agent_message::Payload::Heartbeat(Heartbeat {
            node_id: "node-a".into(),
            timestamp: 0,
            available_resources: None,
            pool: String::new(),
            version: String::new(),
            mesh_ip: String::new(),
        })),
    })
    .await
    .unwrap();
    let mut inbound = client
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    // Drain what the server sends on connect; none of it is GossipConfig.
    while let Ok(Ok(Some(msg))) =
        tokio::time::timeout(Duration::from_millis(500), inbound.message()).await
    {
        assert!(!matches!(msg.payload, Some(ServerPayload::Gossip(_))));
    }
    drop(tx);
}
