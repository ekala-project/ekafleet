//! `RaftAddMember` / `RaftRemoveMember`: changing the servers of the Raft
//! cluster (`ekafleet raft add/remove`). Served by the leader only, to
//! callers holding [`Permission::ManageCluster`].
//!
//! A new server is first added as a learner and replicates the log until it
//! has caught up, and only then becomes a voter, so adding a server never
//! leaves the cluster waiting on a member with no state.

// tonic's `Status` is the error these handlers return.
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;

use openraft::{BasicNode, ChangeMembers};
use tonic::{Request, Status};

use super::api::FleetControlService;
use super::audit::{AuditAction, AuditOutcome};
use super::rbac::{Permission, require_fleet_permission};
use crate::proto::{RaftAddMemberRequest, RaftRemoveMemberRequest, RaftStatusResponse};
use crate::raft::RaftError;
use crate::raft::consensus::{NodeId, Raft};

/// A membership change refused or failed by Raft, as a gRPC status: a
/// server that lost leadership meanwhile names the new leader.
pub(super) fn change_failed(e: RaftError) -> Status {
    match e {
        RaftError::NotLeader {
            leader_addr: Some(addr),
            ..
        } => {
            let mut metadata = tonic::metadata::MetadataMap::new();
            if let Ok(value) = addr.parse() {
                metadata.insert(super::leadership::LEADER_METADATA, value);
            }
            Status::with_metadata(
                tonic::Code::Unavailable,
                format!("this server is no longer the leader; the leader is {addr}"),
                metadata,
            )
        }
        RaftError::NotLeader { .. } => Status::unavailable(e.to_string()),
        e => Status::failed_precondition(e.to_string()),
    }
}

/// A fleet state write refused or failed by Raft, as a gRPC status.
pub(super) fn write_failed(e: RaftError) -> Status {
    match e {
        RaftError::NotLeader { .. } => change_failed(e),
        e => Status::internal(e.to_string()),
    }
}

impl FleetControlService {
    fn cluster(&self) -> Result<&Raft, Status> {
        self.raft_state
            .raft()
            .ok_or_else(|| Status::failed_precondition("this server does not run Raft"))
    }

    pub(super) async fn handle_raft_add_member(
        &self,
        request: Request<RaftAddMemberRequest>,
    ) -> Result<RaftStatusResponse, Status> {
        require_fleet_permission(&request, Permission::ManageCluster)?;
        let RaftAddMemberRequest { id, addr } = request.get_ref().clone();
        let addr = super::parse_peers(&format!("{id}={addr}"))
            .map_err(|e| Status::invalid_argument(e.to_string()))?
            .remove(&id)
            .unwrap_or_default();
        let raft = self.cluster()?;
        let membership = raft.metrics().borrow().membership_config.clone();
        let membership = membership.membership();
        match membership.get_node(&id) {
            Some(node) if node.addr != addr => {
                return Err(Status::already_exists(format!(
                    "server {id} is a member at {}; remove it first",
                    node.addr
                )));
            }
            Some(_) if membership.voter_ids().any(|v| v == id) => {
                return Ok(super::leadership::raft_status(raft));
            }
            _ => {}
        }
        tracing::info!(id, %addr, "Adding a server to the cluster");
        // Blocks until the learner has caught up with the log.
        raft.add_learner(id, BasicNode::new(&addr), true)
            .await
            .map_err(|e| change_failed(RaftError::from_client_write(e)))?;
        raft.change_membership(ChangeMembers::AddVoterIds(BTreeSet::from([id])), false)
            .await
            .map_err(|e| change_failed(RaftError::from_client_write(e)))?;
        self.audit(
            &request,
            AuditAction::ClusterMembership,
            &format!("raft/{id}"),
            &format!("added server {id} at {addr}"),
            AuditOutcome::Success,
        )
        .await;
        Ok(super::leadership::raft_status(raft))
    }

    pub(super) async fn handle_raft_remove_member(
        &self,
        request: Request<RaftRemoveMemberRequest>,
    ) -> Result<RaftStatusResponse, Status> {
        require_fleet_permission(&request, Permission::ManageCluster)?;
        let id: NodeId = request.get_ref().id;
        let raft = self.cluster()?;
        let membership = raft.metrics().borrow().membership_config.clone();
        let membership = membership.membership();
        if membership.get_node(&id).is_none() {
            return Err(Status::not_found(format!("server {id} is not a member")));
        }
        let voters: BTreeSet<NodeId> = membership.voter_ids().collect();
        if voters.len() == 1 && voters.contains(&id) {
            return Err(Status::failed_precondition(
                "cannot remove the last voting server",
            ));
        }
        tracing::info!(id, "Removing a server from the cluster");
        let change = if voters.contains(&id) {
            ChangeMembers::RemoveVoters(BTreeSet::from([id]))
        } else {
            ChangeMembers::RemoveNodes(BTreeSet::from([id]))
        };
        raft.change_membership(change, false)
            .await
            .map_err(|e| change_failed(RaftError::from_client_write(e)))?;
        self.audit(
            &request,
            AuditAction::ClusterMembership,
            &format!("raft/{id}"),
            &format!("removed server {id}"),
            AuditOutcome::Success,
        )
        .await;
        Ok(super::leadership::raft_status(raft))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;
    use crate::raft::consensus::testing::{Router, node};
    use crate::raft::state::FleetStateMachine;
    use crate::server::rbac::Role;

    fn service(state: FleetStateMachine) -> FleetControlService {
        FleetControlService::new(
            crate::server::state::FleetState::new(),
            "fleet.test",
            crate::attestation::join_token::JoinTokenStore::new(),
            state.clone(),
            crate::server::cloud::instance_tracker::InstanceTracker::new(state),
            "127.0.0.1:0",
            crate::server::events::EventStore::new(),
            crate::server::rbac::TokenStore::new(),
            tempfile::tempdir().unwrap().keep(),
        )
    }

    fn as_role<T>(msg: T, role: Role) -> Request<T> {
        let mut req = Request::new(msg);
        req.extensions_mut().insert(role);
        req
    }

    fn voters(status: &RaftStatusResponse) -> Vec<NodeId> {
        status
            .members
            .iter()
            .filter(|m| m.voter)
            .map(|m| m.id)
            .collect()
    }

    #[tokio::test]
    async fn servers_are_added_as_voters_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let router = Router::default();
        let mut nodes = Vec::new();
        for id in 1..=3u64 {
            nodes.push(node(&router, id, dir.path().join(id.to_string()).as_path()).await);
        }
        let (raft, state) = &nodes[0];
        state.attach(raft.clone());
        raft.initialize(BTreeMap::from([(1, BasicNode::new("s1:7400"))]))
            .await
            .unwrap();
        raft.wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader == Some(1), "leader")
            .await
            .unwrap();
        let svc = service(state.clone());

        let add = |id: u64, addr: &str| RaftAddMemberRequest {
            id,
            addr: addr.into(),
        };
        let refused = svc
            .handle_raft_add_member(as_role(add(2, "s2:7400"), Role::Operator))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
        let bad = svc
            .handle_raft_add_member(as_role(add(2, "no-port"), Role::Admin))
            .await
            .unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);

        for (id, addr) in [(2, "s2:7400"), (3, "s3:7400")] {
            let status = svc
                .handle_raft_add_member(as_role(add(id, addr), Role::Admin))
                .await
                .unwrap();
            assert!(voters(&status).contains(&id), "{status:?}");
        }
        // Again with the same address: nothing to do. Elsewhere: refused.
        let same = svc
            .handle_raft_add_member(as_role(add(3, "s3:7400"), Role::Admin))
            .await
            .unwrap();
        assert_eq!(voters(&same), vec![1, 2, 3]);
        let moved = svc
            .handle_raft_add_member(as_role(add(3, "s9:7400"), Role::Admin))
            .await
            .unwrap_err();
        assert_eq!(moved.code(), tonic::Code::AlreadyExists);

        // The new voters replicate what the leader commits.
        state
            .apply_next(crate::raft::state::Command::KvPut {
                key: "k".into(),
                value: b"replicated".to_vec(),
            })
            .await
            .unwrap();
        for (_, follower) in &nodes[1..] {
            let mut value = None;
            for _ in 0..100 {
                value = follower.kv_get("k").await;
                if value.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(value.as_deref(), Some(&b"replicated"[..]));
        }

        let status = svc
            .handle_raft_remove_member(as_role(RaftRemoveMemberRequest { id: 2 }, Role::Admin))
            .await
            .unwrap();
        assert_eq!(voters(&status), vec![1, 3]);
        assert!(status.members.iter().all(|m| m.id != 2));
        let gone = svc
            .handle_raft_remove_member(as_role(RaftRemoveMemberRequest { id: 2 }, Role::Admin))
            .await
            .unwrap_err();
        assert_eq!(gone.code(), tonic::Code::NotFound);
        let audited = svc
            .audit_log
            .query(&crate::server::audit::AuditQuery::default())
            .await;
        assert_eq!(
            audited
                .iter()
                .filter(|e| e.action == AuditAction::ClusterMembership)
                .count(),
            3
        );
        for (raft, _) in nodes {
            raft.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn the_last_voter_is_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        let router = Router::default();
        let (raft, state) = node(&router, 1, dir.path()).await;
        state.attach(raft.clone());
        raft.initialize(BTreeMap::from([(1, BasicNode::new("s1:7400"))]))
            .await
            .unwrap();
        raft.wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader == Some(1), "leader")
            .await
            .unwrap();
        let svc = service(state);
        let refused = svc
            .handle_raft_remove_member(as_role(RaftRemoveMemberRequest { id: 1 }, Role::Admin))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        raft.shutdown().await.unwrap();
    }

    #[test]
    fn peers_are_parsed_and_validated() {
        let peers = crate::server::parse_peers("1=10.0.0.1:7400, 2=s2.example:7400,").unwrap();
        assert_eq!(
            peers,
            BTreeMap::from([
                (1, "10.0.0.1:7400".to_string()),
                (2, "s2.example:7400".to_string()),
            ])
        );
        assert!(crate::server::parse_peers("").unwrap().is_empty());
        for bad in [
            "10.0.0.1:7400",
            "0=a:1",
            "x=a:1",
            "1=a",
            "1=:7400",
            "1=a:1,1=b:1",
        ] {
            assert!(crate::server::parse_peers(bad).is_err(), "{bad}");
        }
    }
}
