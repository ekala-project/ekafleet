//! End-to-end join-token flow against the real gRPC server (`serve_grpc`).
//!
//! Covers: an admin creates a token over the API, a credential-less agent
//! presents it to `Attest`, receives a node SVID bound to its node ID, and uses
//! that SVID for mTLS on `StreamControl`. Also covers the rejection paths:
//! replay, binding mismatch, takeover of an attested node ID, unauthenticated
//! token creation and an SVID speaking for another node.

mod common;

use common::{ADMIN_TOKEN, DOMAIN, channel, create_token, heartbeat, identity_of, start_server};
use ekafleet::agent::join::{JoinError, attest_with_join_token};
use ekafleet::proto::CreateJoinTokenRequest;
use ekafleet::proto::fleet_control_client::FleetControlClient;

#[tokio::test(flavor = "multi_thread")]
async fn join_token_flow_issues_working_node_svid() {
    let server = start_server().await;

    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    assert_eq!(token.len(), 64, "token is 32 random bytes, hex-encoded");

    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .expect("attestation with a fresh token succeeds");
    assert_eq!(node.spiffe_id, "spiffe://fleet.internal/agent/node-a");
    assert_eq!(node.trust_domain, DOMAIN);
    assert!(node.expires_at > 0);

    heartbeat(&server, identity_of(&node), "node-a")
        .await
        .expect("node SVID authenticates StreamControl");
}

#[tokio::test(flavor = "multi_thread")]
async fn join_token_cannot_be_replayed() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();

    attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();
    let replay = attest_with_join_token(channel(&server, None).await, &token, "node-b").await;
    assert!(
        matches!(replay, Err(JoinError::Rejected(_))),
        "a consumed token must not attest again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_join_token_is_rejected() {
    let server = start_server().await;
    let result = attest_with_join_token(channel(&server, None).await, "not-a-token", "n").await;
    assert!(matches!(result, Err(JoinError::Rejected(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn bound_join_token_only_attests_its_node() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "node-a")
        .await
        .unwrap();

    let wrong = attest_with_join_token(channel(&server, None).await, &token, "node-b").await;
    assert!(matches!(wrong, Err(JoinError::Rejected(_))));

    // The failed attempt must not have burned the token.
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();
    assert!(node.spiffe_id.ends_with("/agent/node-a"));
}

#[tokio::test(flavor = "multi_thread")]
async fn unbound_join_token_cannot_take_over_attested_node() {
    let server = start_server().await;
    let first = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    attest_with_join_token(channel(&server, None).await, &first, "node-a")
        .await
        .unwrap();

    let second = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let takeover = attest_with_join_token(channel(&server, None).await, &second, "node-a").await;
    assert!(
        matches!(takeover, Err(JoinError::Rejected(_))),
        "an unbound token must not mint a second SVID for an attested node"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn node_svid_cannot_speak_for_another_node() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();

    let status = heartbeat(&server, identity_of(&node), "node-b")
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_join_token_requires_admin_bearer_token() {
    let server = start_server().await;

    let anonymous = create_token(&server, None, "").await.unwrap_err();
    assert_eq!(anonymous.code(), tonic::Code::Unauthenticated);

    let wrong = create_token(&server, Some("wrong"), "").await.unwrap_err();
    assert_eq!(wrong.code(), tonic::Code::Unauthenticated);

    let invalid_id = create_token(&server, Some(ADMIN_TOKEN), "../etc")
        .await
        .unwrap_err();
    assert_eq!(invalid_id.code(), tonic::Code::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread")]
async fn node_svid_is_not_admin() {
    let server = start_server().await;
    let token = create_token(&server, Some(ADMIN_TOKEN), "").await.unwrap();
    let node = attest_with_join_token(channel(&server, None).await, &token, "node-a")
        .await
        .unwrap();

    // An attested agent must not be able to mint join tokens for others.
    let mut client = FleetControlClient::new(channel(&server, Some(identity_of(&node))).await);
    let status = client
        .create_join_token(CreateJoinTokenRequest {
            node_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}
