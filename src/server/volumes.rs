//! Volume snapshot RPCs: routed to the node holding the volume, which
//! snapshots it locally (see `agent::storage`).

#![allow(clippy::result_large_err)] // tonic::Status, as in every gRPC handler

use std::time::Duration;

use tonic::{Request, Status};

use super::api::FleetControlService;
use super::audit::{AuditAction, AuditOutcome};
use super::rbac::{Permission, require_permission};
use crate::proto::agent_command_response::Result as CommandResult;
use crate::proto::server_message::Payload;
use crate::proto::{
    ServerMessage, VolumeSnapshotAction, VolumeSnapshotCommand, VolumeSnapshotInfo,
    VolumeSnapshotRequest, VolumeSnapshotResponse,
};

/// Restores stop the service and copy the whole volume, so allow for size.
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(1800);

impl FleetControlService {
    pub(super) async fn handle_volume_snapshot(
        &self,
        request: Request<VolumeSnapshotRequest>,
        action: VolumeSnapshotAction,
    ) -> Result<VolumeSnapshotResponse, Status> {
        let list = action == VolumeSnapshotAction::VolumeSnapshotList;
        require_permission(
            &request,
            if list {
                Permission::Read
            } else {
                Permission::Deploy
            },
        )?;
        let req = request.get_ref().clone();
        if req.service_name.is_empty() {
            return Err(Status::invalid_argument("service name is required"));
        }
        if !list && req.volume_name.is_empty() {
            return Err(Status::invalid_argument("volume name is required"));
        }
        let needs_id = matches!(
            action,
            VolumeSnapshotAction::VolumeSnapshotRestore
                | VolumeSnapshotAction::VolumeSnapshotDelete
        );
        if needs_id && req.snapshot_id.is_empty() {
            return Err(Status::invalid_argument("snapshot id is required"));
        }
        self.require_service_access(&request, &req.service_name)
            .await?;

        let nodes = self.snapshot_nodes(&req, list).await?;
        let mut snapshots = Vec::new();
        for node in &nodes {
            let result = self.snapshot_on(node, &req, action).await;
            if !list {
                let (audit_action, verb) = match action {
                    VolumeSnapshotAction::VolumeSnapshotRestore => {
                        (AuditAction::VolumeRestore, "restore")
                    }
                    VolumeSnapshotAction::VolumeSnapshotDelete => {
                        (AuditAction::VolumeSnapshot, "delete")
                    }
                    _ => (AuditAction::VolumeSnapshot, "create"),
                };
                let id = match &result {
                    Ok(s) => s
                        .first()
                        .map_or(req.snapshot_id.as_str(), |s| &s.snapshot_id),
                    Err(_) => req.snapshot_id.as_str(),
                };
                self.audit(
                    &request,
                    audit_action,
                    &format!("{}/{}", req.service_name, req.volume_name),
                    &format!("{verb} {id} on {node}"),
                    if result.is_ok() {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Failed
                    },
                )
                .await;
            }
            snapshots.extend(result?);
        }
        Ok(VolumeSnapshotResponse { snapshots })
    }

    /// The node(s) to ask: the one named, else the nodes running the
    /// service (exactly one unless listing).
    async fn snapshot_nodes(
        &self,
        req: &VolumeSnapshotRequest,
        list: bool,
    ) -> Result<Vec<String>, Status> {
        if !req.node.is_empty() {
            return Ok(vec![req.node.clone()]);
        }
        let mut nodes = Vec::new();
        for node in self.state.assigned_nodes().await {
            if let Some(ds) = self.state.assigned_desired_state(&node).await
                && ds.services.iter().any(|s| s.name == req.service_name)
            {
                nodes.push(node);
            }
        }
        nodes.sort();
        match nodes.len() {
            0 => Err(Status::not_found(format!(
                "service '{}' is not assigned to any node",
                req.service_name
            ))),
            1 => Ok(nodes),
            _ if list => Ok(nodes),
            _ => Err(Status::failed_precondition(format!(
                "service '{}' runs on {}; pick one with --node",
                req.service_name,
                nodes.join(", ")
            ))),
        }
    }

    async fn snapshot_on(
        &self,
        node: &str,
        req: &VolumeSnapshotRequest,
        action: VolumeSnapshotAction,
    ) -> Result<Vec<VolumeSnapshotInfo>, Status> {
        let correlation_id = uuid::Uuid::new_v4().to_string();
        let msg = ServerMessage {
            payload: Some(Payload::VolumeSnapshotCommand(VolumeSnapshotCommand {
                correlation_id: correlation_id.clone(),
                action: action as i32,
                service_name: req.service_name.clone(),
                volume_name: req.volume_name.clone(),
                snapshot_id: req.snapshot_id.clone(),
            })),
        };
        let resp = self
            .state
            .send_command(node, msg, correlation_id, SNAPSHOT_TIMEOUT)
            .await?;
        if !resp.success {
            return Err(Status::failed_precondition(format!(
                "{node}: {}",
                resp.error_message
            )));
        }
        Ok(match resp.result {
            Some(CommandResult::VolumeSnapshotResult(r)) => r.snapshots,
            _ => Vec::new(),
        })
    }
}
