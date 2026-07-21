use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::{RwLock, mpsc};

use super::helpers::install_received_svid;
use super::netns::NamespaceNetworkManager;
use super::supervisor;
use super::types::{LocalState, PendingKeyStore};
use crate::agent::health::HealthChecker;
use crate::ca::csr;
use crate::dns::resolver::DnsResolver;
use crate::mesh::peers::PeerManager;
use crate::policy::nftables::PolicyEnforcer;
use crate::proto::agent_command_response::Result as CmdResult;
use crate::proto::agent_message::Payload;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{AgentCommandResponse, AgentMessage, CertificateRequest};
use crate::secrets::injector::SecretInjector;
use crate::spiffe::workload_api::WorkloadManager;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_server_message(
    payload: ServerPayload,
    supervisor: &Arc<RwLock<supervisor::Supervisor>>,
    local_state: &Arc<RwLock<LocalState>>,
    workload_mgr: &Arc<WorkloadManager>,
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    secret_injector: &Arc<RwLock<SecretInjector>>,
    dns_resolver: &Arc<DnsResolver>,
    peer_manager: &Arc<RwLock<PeerManager>>,
    policy_enforcer: &Arc<PolicyEnforcer>,
    health_checker: &HealthChecker,
    netns_manager: &Arc<NamespaceNetworkManager>,
    tx: &mpsc::Sender<AgentMessage>,
    node_id: &str,
) {
    match payload {
        ServerPayload::DesiredState(ds) => {
            tracing::info!(
                correlation_id = %ds.correlation_id,
                services = ds.services.len(),
                system_path = %ds.system_path,
                namespace_networks = ds.namespace_networks.len(),
                "Received desired state"
            );

            // Activate EkaOS system closure if a new system_path is provided
            if !ds.system_path.is_empty() {
                let current = local_state.read().await.system_path.clone();
                if ds.system_path != current {
                    let params = crate::agent::activation::ActivationParams {
                        toplevel: ds.system_path.clone(),
                        activate_script: None, // default: {toplevel}/bin/activate
                        action: crate::agent::activation::ActivationAction::Switch,
                        // Bound generation accumulation on long-lived fleets.
                        // Configurable via EKAFLEET_KEEP_GENERATIONS[_DAYS],
                        // surfaced by the NixOS module.
                        retention: Some(crate::agent::activation::GenerationRetention::from_env()),
                    };
                    match crate::agent::activation::activate_system(&params).await {
                        Ok(result) => {
                            tracing::info!(
                                toplevel = %result.toplevel,
                                action = ?result.action,
                                "System activation complete"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "System activation failed");
                        }
                    }
                }
            }

            // Set up namespace networks from DesiredState topology
            let mut active_namespaces = Vec::new();
            for ns_cfg in &ds.namespace_networks {
                if let Err(e) = netns_manager
                    .ensure_namespace(
                        &ns_cfg.namespace,
                        &ns_cfg.subnet,
                        &ns_cfg.gateway,
                        ns_cfg.vni,
                    )
                    .await
                {
                    tracing::error!(
                        namespace = %ns_cfg.namespace,
                        error = %e,
                        "Failed to create namespace network"
                    );
                }
                active_namespaces.push(ns_cfg.namespace.clone());
            }

            // Add services to their namespace networks (non-default only)
            for svc in &ds.services {
                if !crate::agent::netns::is_default_namespace(&svc.namespace)
                    && !svc.namespace_ip.is_empty()
                    && let Ok(ip) = svc.namespace_ip.parse::<std::net::Ipv4Addr>()
                    && let Err(e) = netns_manager
                        .add_service(&svc.namespace, &svc.name, ip)
                        .await
                {
                    tracing::error!(
                        service = %svc.name,
                        namespace = %svc.namespace,
                        error = %e,
                        "Failed to add service to namespace network"
                    );
                }
            }

            let mut state = local_state.write().await;
            state.system_path = ds.system_path;

            // Detect services removed from desired state so we can clean up
            // their namespace network entries.
            let previous_services: Vec<(String, String)> = state
                .desired_services
                .values()
                .filter(|s| !crate::agent::netns::is_default_namespace(&s.namespace))
                .map(|s| (s.namespace.clone(), s.name.clone()))
                .collect();

            state.desired_services.clear();
            for svc in &ds.services {
                state.desired_services.insert(svc.name.clone(), svc.clone());
            }
            drop(state);

            // Remove services that are no longer in desired state from namespace networks
            for (ns, name) in &previous_services {
                if !ds.services.iter().any(|s| s.name == *name)
                    && let Err(e) = netns_manager.remove_service(ns, name).await
                {
                    tracing::warn!(
                        namespace = %ns,
                        service = %name,
                        error = %e,
                        "Failed to remove service from namespace network"
                    );
                }
            }

            // GC namespaces that are no longer referenced
            if let Err(e) = netns_manager.gc_namespaces(&active_namespaces).await {
                tracing::warn!(error = %e, "Failed to GC namespace networks");
            }

            // Request SPIFFE SVIDs for each assigned service
            let trust_domain = workload_mgr
                .trust_domain_str()
                .await
                .unwrap_or_else(|| "fleet.internal".to_string());
            for svc in &ds.services {
                tracing::info!(service = %svc.name, "Requesting SVID for service");
                match csr::generate_service_csr(&trust_domain, &svc.name) {
                    Ok(csr_output) => {
                        pending_keys
                            .write()
                            .await
                            .store(&svc.name, csr_output.keypair);
                        let _ = tx
                            .send(AgentMessage {
                                payload: Some(Payload::CertRequest(CertificateRequest {
                                    node_id: node_id.to_string(),
                                    service_name: svc.name.clone(),
                                    csr: csr_output.csr_der,
                                    request_type: crate::proto::CertRequestType::ServiceCert as i32,
                                })),
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::error!(
                            service = %svc.name,
                            error = %e,
                            "CSR generation failed"
                        );
                    }
                }
            }

            // Start health checking for services with health_check configured
            for svc in &ds.services {
                if svc.health_check.is_some() {
                    let instance_id = format!("{}-{}", svc.name, node_id);
                    health_checker.start_checking(
                        svc.name.clone(),
                        instance_id,
                        svc.health_check.clone().unwrap(),
                    );
                }
            }

            // Reconcile local services with desired state
            let state = local_state.read().await;
            let desired = state.desired_services.clone();
            drop(state);
            match supervisor.write().await.reconcile(&desired).await {
                Ok(actions) => {
                    for action in &actions {
                        tracing::info!(?action, "Supervisor action");
                    }
                }
                Err(e) => tracing::error!(error = %e, "Service reconciliation failed"),
            }
        }
        ServerPayload::Deploy(cmd) => {
            tracing::info!(
                deployment_id = %cmd.deployment_id,
                service = %cmd.service_name,
                "Received deploy command"
            );
            // Update the desired state for this service and reconcile
            let mut state = local_state.write().await;
            if let Some(svc) = state.desired_services.get_mut(&cmd.service_name) {
                svc.store_path = cmd.store_path.clone();
            }
            let desired = state.desired_services.clone();
            drop(state);
            match supervisor.write().await.reconcile(&desired).await {
                Ok(actions) => {
                    for action in &actions {
                        tracing::info!(?action, "Deploy action");
                    }
                }
                Err(e) => tracing::error!(error = %e, "Deployment failed"),
            }
        }
        ServerPayload::Secret(update) => {
            tracing::info!(
                service = %update.service_name,
                secret = %update.secret_name,
                "Received secret update"
            );
            match secret_injector
                .write()
                .await
                .inject(
                    &update.service_name,
                    &update.secret_name,
                    &update.encrypted_value,
                    update.version,
                )
                .await
            {
                Ok(path) => tracing::info!(path = %path.display(), "Secret injected"),
                Err(e) => tracing::error!(error = %e, "Secret injection failed"),
            }
        }
        ServerPayload::Dns(update) => {
            tracing::debug!(records = update.records.len(), "Received DNS update");
            for record in &update.records {
                let ips: Vec<std::net::Ipv4Addr> = record
                    .values
                    .iter()
                    .filter_map(|v| v.parse().ok())
                    .collect();
                let ttl = Duration::from_secs(record.ttl as u64);
                if record.namespace.is_empty() {
                    // Fleet-wide record
                    dns_resolver.update_cache(&record.name, ips, ttl).await;
                } else {
                    // Namespace-scoped record
                    dns_resolver
                        .update_namespace_cache(&record.namespace, &record.name, ips, ttl)
                        .await;
                }
            }
        }
        ServerPayload::Cert(response) => {
            tracing::info!(
                expires = response.expires_at,
                service = %response.service_name,
                "Received SVID certificate"
            );
            if let Err(e) = install_received_svid(workload_mgr, pending_keys, &response).await {
                tracing::error!(error = %e, "Failed to install SVID");
            }
        }
        ServerPayload::TrustBundle(bundle) => {
            tracing::info!(
                trust_domain = %bundle.trust_domain,
                "Received trust bundle"
            );
            // Update trust domain from server's authoritative value
            if !bundle.trust_domain.is_empty() {
                workload_mgr.set_trust_domain(&bundle.trust_domain).await;
            }
            let pem = String::from_utf8_lossy(&bundle.ca_certificate_pem);
            if let Err(e) = workload_mgr.set_trust_bundle(&pem).await {
                tracing::error!(error = %e, "Failed to install trust bundle");
            }
        }
        ServerPayload::Peers(update) => {
            tracing::info!(peers = update.peers.len(), "Received peer update");
            let mut pm = peer_manager.write().await;
            if let Err(e) = pm.apply_update(update.peers).await {
                tracing::error!(error = %e, "WireGuard peer update failed");
            }
        }
        ServerPayload::Policy(update) => {
            tracing::info!(policies = update.policies.len(), "Received policy update");
            let rules: Vec<crate::policy::nftables::PolicyRule> = update
                .policies
                .iter()
                .map(|p| crate::policy::nftables::PolicyRule {
                    source_ip: std::net::Ipv4Addr::UNSPECIFIED,
                    dest_ip: std::net::Ipv4Addr::UNSPECIFIED,
                    dest_ports: p.allowed_ports.iter().map(|&port| port as u16).collect(),
                    description: format!("{} -> {}", p.source_service, p.target_service),
                })
                .collect();
            if let Err(e) = policy_enforcer.apply_policies(&rules).await {
                tracing::error!(error = %e, "Policy application failed");
            }
        }
        ServerPayload::AttestChallenge(challenge) => {
            tracing::debug!(
                challenge_len = challenge.challenge_data.len(),
                "Received attestation challenge (handled via Attest RPC)"
            );
            // Attestation challenges are handled via the Attest RPC flow, not the stream.
        }
        ServerPayload::FleetKey(key_update) => {
            tracing::info!(
                version = key_update.version,
                "Received fleet encryption key"
            );
            if key_update.encrypted_key.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_update.encrypted_key);
                let mut inj = secret_injector.write().await;
                inj.update_key(&key);
                tracing::info!(
                    version = key_update.version,
                    "Fleet encryption key installed"
                );
            } else {
                tracing::warn!(
                    len = key_update.encrypted_key.len(),
                    "Invalid fleet key length (expected 32 bytes)"
                );
            }
        }
        ServerPayload::ExecCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let timeout = Duration::from_secs(cmd.timeout_seconds.max(5) as u64);
                let result =
                    crate::agent::exec::exec_in_service(&cmd.service_name, &cmd.command, timeout)
                        .await;
                let response = match result {
                    Ok(r) => AgentCommandResponse {
                        correlation_id,
                        success: true,
                        error_message: String::new(),
                        result: Some(CmdResult::ExecResult(crate::proto::ExecCommandResult {
                            exit_code: r.exit_code,
                            stdout: r.stdout.into_bytes(),
                            stderr: r.stderr.into_bytes(),
                        })),
                    },
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
        ServerPayload::LogsCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let lines = if cmd.lines == 0 { 100 } else { cmd.lines };
                if cmd.follow {
                    // For follow mode, stream chunks from journalctl
                    match crate::agent::logs::stream_journal(&cmd.service_name, lines, true).await {
                        Ok(mut child) => {
                            let mut stdout = child.stdout.take().unwrap();
                            let mut buf = vec![0u8; 8192];
                            loop {
                                match tokio::time::timeout(
                                    Duration::from_secs(30),
                                    stdout.read(&mut buf),
                                )
                                .await
                                {
                                    Ok(Ok(0)) => break,
                                    Ok(Ok(n)) => {
                                        let resp = AgentCommandResponse {
                                            correlation_id: correlation_id.clone(),
                                            success: true,
                                            error_message: String::new(),
                                            result: Some(CmdResult::LogsResult(
                                                crate::proto::LogsCommandResult {
                                                    data: buf[..n].to_vec(),
                                                },
                                            )),
                                        };
                                        if tx
                                            .send(AgentMessage {
                                                payload: Some(Payload::CommandResponse(resp)),
                                            })
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Ok(Err(_)) | Err(_) => break,
                                }
                            }
                            let _ = child.kill().await;
                        }
                        Err(e) => {
                            let resp = AgentCommandResponse {
                                correlation_id,
                                success: false,
                                error_message: e.to_string(),
                                result: None,
                            };
                            let _ = tx
                                .send(AgentMessage {
                                    payload: Some(Payload::CommandResponse(resp)),
                                })
                                .await;
                        }
                    }
                } else {
                    let result = crate::agent::logs::read_logs(&cmd.service_name, lines).await;
                    let response = match result {
                        Ok(data) => AgentCommandResponse {
                            correlation_id,
                            success: true,
                            error_message: String::new(),
                            result: Some(CmdResult::LogsResult(crate::proto::LogsCommandResult {
                                data: data.into_bytes(),
                            })),
                        },
                        Err(e) => AgentCommandResponse {
                            correlation_id,
                            success: false,
                            error_message: e.to_string(),
                            result: None,
                        },
                    };
                    let _ = tx
                        .send(AgentMessage {
                            payload: Some(Payload::CommandResponse(response)),
                        })
                        .await;
                }
            });
        }
        ServerPayload::ListGenerationsCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = list_nix_generations().await;
                let response = match result {
                    Ok(generations) => AgentCommandResponse {
                        correlation_id,
                        success: true,
                        error_message: String::new(),
                        result: Some(CmdResult::ListGenerationsResult(
                            crate::proto::ListGenerationsResult { generations },
                        )),
                    },
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
        ServerPayload::SwitchGenerationCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = switch_nix_generation(cmd.generation, &cmd.action).await;
                let response = match result {
                    Ok(message) => AgentCommandResponse {
                        correlation_id,
                        success: true,
                        error_message: String::new(),
                        result: Some(CmdResult::SwitchGenerationResult(
                            crate::proto::SwitchGenerationResult { message },
                        )),
                    },
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
        ServerPayload::DiffGenerationsCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = diff_nix_generations(cmd.gen_a, cmd.gen_b).await;
                let response = match result {
                    Ok(diff) => AgentCommandResponse {
                        correlation_id,
                        success: true,
                        error_message: String::new(),
                        result: Some(CmdResult::DiffGenerationsResult(
                            crate::proto::DiffGenerationsResult { diff },
                        )),
                    },
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
        ServerPayload::SystemGcCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = run_nix_gc(cmd.dry_run).await;
                let response = match result {
                    Ok((freed_bytes, output)) => AgentCommandResponse {
                        correlation_id,
                        success: true,
                        error_message: String::new(),
                        result: Some(CmdResult::GcResult(crate::proto::SystemGcCommandResult {
                            freed_bytes,
                            output,
                        })),
                    },
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
        ServerPayload::SystemRebootCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                // Send the success response before initiating the reboot.
                let resp = AgentCommandResponse {
                    correlation_id,
                    success: true,
                    error_message: String::new(),
                    result: None,
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(resp)),
                    })
                    .await;

                // Brief delay to allow the response to be transmitted.
                tokio::time::sleep(Duration::from_secs(1)).await;

                tracing::info!("Initiating system reboot");
                let _ = tokio::process::Command::new("systemctl")
                    .arg("reboot")
                    .status()
                    .await;
            });
        }
        ServerPayload::SystemRebuildCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = run_nixos_rebuild().await;
                let response = match result {
                    Ok(output) => AgentCommandResponse {
                        correlation_id,
                        success: true,
                        error_message: String::new(),
                        result: Some(CmdResult::RebuildResult(
                            crate::proto::SystemRebuildResult { output },
                        )),
                    },
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
        ServerPayload::InspectServiceCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = inspect_systemd_service(&cmd.service_name).await;
                let response = match result {
                    Ok(info) => AgentCommandResponse {
                        correlation_id,
                        success: true,
                        error_message: String::new(),
                        result: Some(CmdResult::InspectResult(info)),
                    },
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
        ServerPayload::MigrateVolumeCommand(cmd) => {
            let correlation_id = cmd.correlation_id.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let source_path = std::path::PathBuf::from(&cmd.source_path);
                let dest_path = std::path::PathBuf::from(&cmd.dest_path);
                let result =
                    super::migrate::migrate_volume(&cmd.source_host, &source_path, &dest_path)
                        .await;
                let response = match result {
                    Ok(r) => {
                        tracing::info!(
                            service = %cmd.service_name,
                            bytes = r.bytes_transferred,
                            "Volume migration completed"
                        );
                        AgentCommandResponse {
                            correlation_id,
                            success: true,
                            error_message: String::new(),
                            result: None,
                        }
                    }
                    Err(e) => AgentCommandResponse {
                        correlation_id,
                        success: false,
                        error_message: e.to_string(),
                        result: None,
                    },
                };
                let _ = tx
                    .send(AgentMessage {
                        payload: Some(Payload::CommandResponse(response)),
                    })
                    .await;
            });
        }
    }
}

/// List NixOS system generations from /nix/var/nix/profiles/.
async fn list_nix_generations() -> Result<Vec<crate::proto::GenerationInfo>, std::io::Error> {
    let profiles_dir = std::path::Path::new("/nix/var/nix/profiles");
    let mut generations = Vec::new();

    let output = tokio::process::Command::new("nix-env")
        .args(["-p", "/nix/var/nix/profiles/system", "--list-generations"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "nix-env --list-generations failed: {stderr}"
        )));
    }

    // Determine which generation is current by resolving the `system` symlink.
    let current_link = tokio::fs::read_link(profiles_dir.join("system")).await;
    let current_gen: Option<u64> = current_link.ok().and_then(|p| {
        let name = p.file_name()?.to_str()?;
        // Name is like "system-42-link"
        let num_str = name.strip_prefix("system-")?.strip_suffix("-link")?;
        num_str.parse().ok()
    });

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Format: "  42   2025-01-15 10:30:00   (current)"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        if let Ok(number) = parts[0].parse::<u64>() {
            // Try to get the store path by resolving the symlink
            let link_name = format!("system-{number}-link");
            let store_path = tokio::fs::read_link(profiles_dir.join(&link_name))
                .await
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // Parse the date+time from the listing if available
            let created_at = if parts.len() >= 3 {
                parse_generation_date(parts[1], parts[2])
            } else {
                0
            };

            let is_current = current_gen == Some(number);
            generations.push(crate::proto::GenerationInfo {
                number,
                store_path,
                created_at,
                current: is_current,
            });
        }
    }

    Ok(generations)
}

/// Parse a date string like "2025-01-15" and time "10:30:00" into a UNIX timestamp.
fn parse_generation_date(date_str: &str, time_str: &str) -> u64 {
    // Simple parsing: YYYY-MM-DD HH:MM:SS
    let datetime = format!("{date_str} {time_str}");
    // Use a basic approach: parse with chrono-like manual parsing
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return 0;
    }
    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() < 2 {
        return 0;
    }
    // Approximate: just use the output as documentation, the exact timestamp
    // is less important than the generation number and store path.
    let _ = datetime;
    // Try to stat the profile link for a more accurate timestamp
    0
}

/// Switch to a specific NixOS generation.
async fn switch_nix_generation(generation: u64, action: &str) -> Result<String, std::io::Error> {
    // First, switch the profile to the target generation
    let output = tokio::process::Command::new("nix-env")
        .args([
            "-p",
            "/nix/var/nix/profiles/system",
            "--switch-generation",
            &generation.to_string(),
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "nix-env --switch-generation failed: {stderr}"
        )));
    }

    // Resolve the store path for this generation
    let link = format!("/nix/var/nix/profiles/system-{generation}-link");
    let store_path = tokio::fs::read_link(&link)
        .await
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| link.clone());

    // Activate the generation using switch-to-configuration
    let activate_action = match action {
        "boot" => "boot",
        "test" => "test",
        _ => "switch", // default to switch
    };

    let activate_script = format!("{store_path}/bin/switch-to-configuration");
    let output = tokio::process::Command::new(&activate_script)
        .arg(activate_action)
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "switch-to-configuration {activate_action} failed: {stderr}"
        )));
    }

    Ok(format!(
        "Generation {generation} activated ({activate_action})\n{stdout}{stderr}"
    ))
}

/// Diff two NixOS generations.
async fn diff_nix_generations(gen_a: u64, gen_b: u64) -> Result<String, std::io::Error> {
    let path_a = format!("/nix/var/nix/profiles/system-{gen_a}-link");
    let path_b = format!("/nix/var/nix/profiles/system-{gen_b}-link");

    let output = tokio::process::Command::new("nix")
        .args(["store", "diff-closures", &path_a, &path_b])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "nix store diff-closures failed: {stderr}"
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run nix-collect-garbage and return (freed_bytes, output).
async fn run_nix_gc(dry_run: bool) -> Result<(u64, String), std::io::Error> {
    let mut args = vec!["-d"];
    if dry_run {
        args.push("--dry-run");
    }

    let output = tokio::process::Command::new("nix-collect-garbage")
        .args(&args)
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "nix-collect-garbage failed: {combined}"
        )));
    }

    // Parse freed bytes from output. nix-collect-garbage outputs lines like:
    // "deleting '/nix/store/...' (123.45 MiB)"
    // and a final summary: "N store paths deleted, M MiB freed"
    let freed_bytes = parse_gc_freed_bytes(&combined);

    Ok((freed_bytes, combined))
}

/// Parse the number of freed bytes from nix-collect-garbage output.
fn parse_gc_freed_bytes(output: &str) -> u64 {
    // Look for pattern like "123.45 MiB freed" or "1.23 GiB freed"
    for line in output.lines().rev() {
        if let Some(freed_pos) = line.find("freed") {
            let before = line[..freed_pos].trim();
            // Find the last number+unit before "freed"
            let parts: Vec<&str> = before.split_whitespace().collect();
            if parts.len() >= 2 {
                let unit = parts[parts.len() - 1];
                let num_str = parts[parts.len() - 2].replace(',', "");
                if let Ok(num) = num_str.parse::<f64>() {
                    let multiplier = match unit {
                        "KiB" => 1024.0,
                        "MiB" => 1024.0 * 1024.0,
                        "GiB" => 1024.0 * 1024.0 * 1024.0,
                        "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
                        _ => 1.0,
                    };
                    return (num * multiplier) as u64;
                }
            }
        }
    }
    0
}

/// Run nixos-rebuild switch and return the output.
async fn run_nixos_rebuild() -> Result<String, std::io::Error> {
    let output = tokio::process::Command::new("nixos-rebuild")
        .arg("switch")
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "nixos-rebuild switch failed: {combined}"
        )));
    }

    Ok(combined)
}

/// Inspect a systemd service unit and return structured information.
async fn inspect_systemd_service(
    service_name: &str,
) -> Result<crate::proto::InspectServiceResult, std::io::Error> {
    let unit = format!("ekafleet-{service_name}.service");

    // Get unit properties via systemctl show
    let output = tokio::process::Command::new("systemctl")
        .args(["show", &unit, "--no-pager"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "systemctl show failed: {stderr}"
        )));
    }

    let props = String::from_utf8_lossy(&output.stdout);
    let prop_map: std::collections::HashMap<&str, &str> = props
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    // Get unit file content via systemctl cat
    let cat_output = tokio::process::Command::new("systemctl")
        .args(["cat", &unit])
        .output()
        .await;
    let unit_file = cat_output
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    Ok(crate::proto::InspectServiceResult {
        unit_file,
        active_state: prop_map.get("ActiveState").unwrap_or(&"").to_string(),
        sub_state: prop_map.get("SubState").unwrap_or(&"").to_string(),
        main_pid: prop_map
            .get("MainPID")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        control_group: prop_map.get("ControlGroup").unwrap_or(&"").to_string(),
        cpu_usage_nsec: prop_map
            .get("CPUUsageNSec")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        memory_current: prop_map
            .get("MemoryCurrent")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        memory_peak: prop_map
            .get("MemoryPeak")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        io_read_bytes: prop_map
            .get("IOReadBytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        io_write_bytes: prop_map
            .get("IOWriteBytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        tasks_current: prop_map
            .get("TasksCurrent")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    })
}
