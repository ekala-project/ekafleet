use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};

use super::helpers::install_received_svid;
use super::supervisor;
use super::types::{LocalState, PendingKeyStore};
use crate::agent::health::HealthChecker;
use crate::ca::csr;
use crate::dns::resolver::DnsResolver;
use crate::mesh::peers::PeerManager;
use crate::policy::nftables::PolicyEnforcer;
use crate::proto::agent_message::Payload;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{AgentMessage, CertificateRequest};
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
    tx: &mpsc::Sender<AgentMessage>,
    node_id: &str,
) {
    match payload {
        ServerPayload::DesiredState(ds) => {
            tracing::info!(
                correlation_id = %ds.correlation_id,
                services = ds.services.len(),
                system_path = %ds.system_path,
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

            let mut state = local_state.write().await;
            state.system_path = ds.system_path;
            state.desired_services.clear();
            for svc in &ds.services {
                state.desired_services.insert(svc.name.clone(), svc.clone());
            }
            drop(state);

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
                dns_resolver
                    .update_cache(&record.name, ips, Duration::from_secs(record.ttl as u64))
                    .await;
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
    }
}
