//! System operation handlers for FleetControlService.
//!
//! Handles: system_gc, system_reboot, system_rebuild, inspect_service,
//! list_generations, switch_generation, diff_generations.

use std::time::Duration;

use tonic::{Response, Status};

use super::api::FleetControlService;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::ServerMessage;

impl FleetControlService {
    pub(super) async fn handle_system_gc(
        &self,
        req: crate::proto::SystemGcRequest,
    ) -> Result<Response<crate::proto::SystemGcResponse>, Status> {
        let action = if req.dry_run { "dry-run" } else { "collect" };
        tracing::info!(action, "System GC requested");

        let nodes = self.state.connected_nodes().await;
        if nodes.is_empty() {
            return Ok(Response::new(crate::proto::SystemGcResponse {
                results: vec![],
            }));
        }

        let mut handles = Vec::with_capacity(nodes.len());
        for node_id in &nodes {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            let msg = ServerMessage {
                payload: Some(ServerPayload::SystemGcCommand(
                    crate::proto::SystemGcCommand {
                        correlation_id: correlation_id.clone(),
                        dry_run: req.dry_run,
                    },
                )),
            };
            let state = self.state.clone();
            let nid = node_id.clone();
            handles.push(tokio::spawn(async move {
                let resp = state
                    .send_command(&nid, msg, correlation_id, Duration::from_secs(600))
                    .await;
                (nid, resp)
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            let (node_id, resp) = handle
                .await
                .map_err(|e| Status::internal(format!("task join error: {e}")))?;
            match resp {
                Ok(r) if r.success => {
                    if let Some(crate::proto::agent_command_response::Result::GcResult(gc)) =
                        r.result
                    {
                        results.push(crate::proto::NodeGcResult {
                            node_id,
                            freed_bytes: gc.freed_bytes,
                            output: gc.output,
                        });
                    } else {
                        results.push(crate::proto::NodeGcResult {
                            node_id,
                            freed_bytes: 0,
                            output: "GC completed (no details)".to_string(),
                        });
                    }
                }
                Ok(r) => {
                    results.push(crate::proto::NodeGcResult {
                        node_id,
                        freed_bytes: 0,
                        output: format!("Error: {}", r.error_message),
                    });
                }
                Err(e) => {
                    results.push(crate::proto::NodeGcResult {
                        node_id,
                        freed_bytes: 0,
                        output: format!("Error: {e}"),
                    });
                }
            }
        }

        Ok(Response::new(crate::proto::SystemGcResponse { results }))
    }

    pub(super) async fn handle_system_reboot(
        &self,
        req: crate::proto::SystemRebootRequest,
    ) -> Result<Response<crate::proto::SystemRebootResponse>, Status> {
        let max_parallel = if req.max_parallel == 0 {
            1
        } else {
            req.max_parallel as usize
        };
        tracing::info!(pool = %req.pool, max_parallel, "System reboot requested");

        let all_nodes = self.state.connected_nodes().await;
        let nodes = if req.pool.is_empty() {
            all_nodes
        } else {
            let (status_nodes, _, _) = self.state.fleet_status().await;
            status_nodes
                .iter()
                .filter(|n| req.pool.is_empty() || n.pool == req.pool)
                .map(|n| n.node_id.clone())
                .collect()
        };

        if nodes.is_empty() {
            return Ok(Response::new(crate::proto::SystemRebootResponse {
                success: true,
                message: "No nodes to reboot".to_string(),
            }));
        }

        let total = nodes.len();
        let mut rebooted = 0;
        let mut errors = Vec::new();

        for batch in nodes.chunks(max_parallel) {
            let mut handles = Vec::with_capacity(batch.len());
            for node_id in batch {
                let correlation_id = uuid::Uuid::new_v4().to_string();
                let msg = ServerMessage {
                    payload: Some(ServerPayload::SystemRebootCommand(
                        crate::proto::SystemRebootCommand {
                            correlation_id: correlation_id.clone(),
                        },
                    )),
                };
                let state = self.state.clone();
                let nid = node_id.clone();
                handles.push(tokio::spawn(async move {
                    let resp = state
                        .send_command(&nid, msg, correlation_id, Duration::from_secs(30))
                        .await;
                    (nid, resp)
                }));
            }

            for handle in handles {
                let (node_id, resp) = handle
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {e}")))?;
                match resp {
                    Ok(r) if r.success => {
                        rebooted += 1;
                        tracing::info!(node_id = %node_id, "Reboot command accepted");
                    }
                    Ok(r) => {
                        errors.push(format!("{node_id}: {}", r.error_message));
                    }
                    Err(e) => {
                        errors.push(format!("{node_id}: {e}"));
                    }
                }
            }

            if !batch.is_empty() {
                tracing::info!(batch_size = batch.len(), "Waiting for rebooted nodes to reconnect");
                tokio::time::sleep(Duration::from_secs(10)).await;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
                loop {
                    let connected = self.state.connected_nodes().await;
                    let all_back = batch.iter().all(|n| connected.contains(n));
                    if all_back || tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }

        let message = if errors.is_empty() {
            format!("Rolling reboot completed: {rebooted}/{total} nodes rebooted")
        } else {
            format!(
                "Rolling reboot completed with errors: {rebooted}/{total} rebooted, errors: {}",
                errors.join("; ")
            )
        };

        Ok(Response::new(crate::proto::SystemRebootResponse {
            success: errors.is_empty(),
            message,
        }))
    }

    pub(super) async fn handle_system_rebuild(
        &self,
        req: crate::proto::SystemRebuildRequest,
    ) -> Result<Response<crate::proto::SystemRebuildResponse>, Status> {
        let target = if req.all {
            "all machines".to_string()
        } else {
            req.machine.clone()
        };
        tracing::info!(target = %target, "System rebuild requested");

        let target_nodes = if req.all {
            self.state.connected_nodes().await
        } else if req.machine.is_empty() {
            return Err(Status::invalid_argument(
                "machine must be specified (or set all=true)",
            ));
        } else {
            vec![req.machine.clone()]
        };

        if target_nodes.is_empty() {
            return Ok(Response::new(crate::proto::SystemRebuildResponse {
                success: true,
                message: "No nodes to rebuild".to_string(),
            }));
        }

        let mut handles = Vec::with_capacity(target_nodes.len());
        for node_id in &target_nodes {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            let msg = ServerMessage {
                payload: Some(ServerPayload::SystemRebuildCommand(
                    crate::proto::SystemRebuildCommand {
                        correlation_id: correlation_id.clone(),
                    },
                )),
            };
            let state = self.state.clone();
            let nid = node_id.clone();
            handles.push(tokio::spawn(async move {
                let resp = state
                    .send_command(&nid, msg, correlation_id, Duration::from_secs(300))
                    .await;
                (nid, resp)
            }));
        }

        let mut outputs = Vec::new();
        let mut all_success = true;
        for handle in handles {
            let (node_id, resp) = handle
                .await
                .map_err(|e| Status::internal(format!("task join error: {e}")))?;
            match resp {
                Ok(r) if r.success => {
                    let output = match r.result {
                        Some(crate::proto::agent_command_response::Result::RebuildResult(rb)) => {
                            rb.output
                        }
                        _ => "Rebuild completed".to_string(),
                    };
                    outputs.push(format!("{node_id}: {output}"));
                }
                Ok(r) => {
                    all_success = false;
                    outputs.push(format!("{node_id}: Error: {}", r.error_message));
                }
                Err(e) => {
                    all_success = false;
                    outputs.push(format!("{node_id}: Error: {e}"));
                }
            }
        }

        Ok(Response::new(crate::proto::SystemRebuildResponse {
            success: all_success,
            message: outputs.join("\n"),
        }))
    }

    pub(super) async fn handle_inspect_service(
        &self,
        req: crate::proto::InspectServiceRequest,
    ) -> Result<Response<crate::proto::InspectServiceResponse>, Status> {
        tracing::info!(
            service = %req.service_name,
            node = %req.node_id,
            "Inspect service requested"
        );

        if req.node_id.is_empty() {
            return Err(Status::invalid_argument("node_id is required"));
        }

        let correlation_id = uuid::Uuid::new_v4().to_string();
        let msg = ServerMessage {
            payload: Some(ServerPayload::InspectServiceCommand(
                crate::proto::InspectServiceCommand {
                    correlation_id: correlation_id.clone(),
                    service_name: req.service_name.clone(),
                },
            )),
        };

        let resp = self
            .state
            .send_command(&req.node_id, msg, correlation_id, Duration::from_secs(30))
            .await?;

        if !resp.success {
            return Err(Status::internal(resp.error_message));
        }

        match resp.result {
            Some(crate::proto::agent_command_response::Result::InspectResult(r)) => {
                Ok(Response::new(crate::proto::InspectServiceResponse {
                    unit_file: r.unit_file,
                    active_state: r.active_state,
                    sub_state: r.sub_state,
                    main_pid: r.main_pid,
                    control_group: r.control_group,
                    cpu_usage_nsec: r.cpu_usage_nsec,
                    memory_current: r.memory_current,
                    memory_peak: r.memory_peak,
                    io_read_bytes: r.io_read_bytes,
                    io_write_bytes: r.io_write_bytes,
                    tasks_current: r.tasks_current,
                }))
            }
            _ => Err(Status::internal("unexpected response type from agent")),
        }
    }

    pub(super) async fn handle_list_generations(
        &self,
        req: crate::proto::ListGenerationsRequest,
    ) -> Result<Response<crate::proto::ListGenerationsResponse>, Status> {
        tracing::info!(machine = %req.machine, "List generations requested");

        let correlation_id = uuid::Uuid::new_v4().to_string();
        let msg = ServerMessage {
            payload: Some(ServerPayload::ListGenerationsCommand(
                crate::proto::ListGenerationsCommand {
                    correlation_id: correlation_id.clone(),
                },
            )),
        };

        let resp = self
            .state
            .send_command(&req.machine, msg, correlation_id, Duration::from_secs(30))
            .await?;

        if !resp.success {
            return Err(Status::internal(resp.error_message));
        }

        match resp.result {
            Some(crate::proto::agent_command_response::Result::ListGenerationsResult(r)) => {
                Ok(Response::new(crate::proto::ListGenerationsResponse {
                    generations: r.generations,
                }))
            }
            _ => Err(Status::internal("unexpected response type from agent")),
        }
    }

    pub(super) async fn handle_switch_generation(
        &self,
        req: crate::proto::SwitchGenerationRequest,
    ) -> Result<Response<crate::proto::SwitchGenerationResponse>, Status> {
        tracing::info!(
            machine = %req.machine,
            generation = req.generation,
            action = %req.action,
            "Switch generation requested"
        );

        let correlation_id = uuid::Uuid::new_v4().to_string();
        let msg = ServerMessage {
            payload: Some(ServerPayload::SwitchGenerationCommand(
                crate::proto::SwitchGenerationCommand {
                    correlation_id: correlation_id.clone(),
                    generation: req.generation,
                    action: req.action.clone(),
                },
            )),
        };

        let resp = self
            .state
            .send_command(&req.machine, msg, correlation_id, Duration::from_secs(120))
            .await?;

        if !resp.success {
            return Ok(Response::new(crate::proto::SwitchGenerationResponse {
                success: false,
                message: resp.error_message,
            }));
        }

        match resp.result {
            Some(crate::proto::agent_command_response::Result::SwitchGenerationResult(r)) => {
                Ok(Response::new(crate::proto::SwitchGenerationResponse {
                    success: true,
                    message: r.message,
                }))
            }
            _ => Ok(Response::new(crate::proto::SwitchGenerationResponse {
                success: true,
                message: format!(
                    "Generation {} {} on {}",
                    req.generation, req.action, req.machine
                ),
            })),
        }
    }

    pub(super) async fn handle_diff_generations(
        &self,
        req: crate::proto::DiffGenerationsRequest,
    ) -> Result<Response<crate::proto::DiffGenerationsResponse>, Status> {
        tracing::info!(
            machine = %req.machine,
            gen_a = req.gen_a,
            gen_b = req.gen_b,
            "Diff generations requested"
        );

        let correlation_id = uuid::Uuid::new_v4().to_string();
        let msg = ServerMessage {
            payload: Some(ServerPayload::DiffGenerationsCommand(
                crate::proto::DiffGenerationsCommand {
                    correlation_id: correlation_id.clone(),
                    gen_a: req.gen_a,
                    gen_b: req.gen_b,
                },
            )),
        };

        let resp = self
            .state
            .send_command(&req.machine, msg, correlation_id, Duration::from_secs(30))
            .await?;

        if !resp.success {
            return Err(Status::internal(resp.error_message));
        }

        match resp.result {
            Some(crate::proto::agent_command_response::Result::DiffGenerationsResult(r)) => {
                Ok(Response::new(crate::proto::DiffGenerationsResponse {
                    diff: r.diff,
                }))
            }
            _ => Err(Status::internal("unexpected response type from agent")),
        }
    }
}
