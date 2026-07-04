pub mod health;
pub mod supervisor;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use crate::dns::resolver::DnsResolver;
use crate::mesh::peers::PeerManager;
use crate::mesh::wireguard::WireguardManager;
use crate::policy::nftables::PolicyEnforcer;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    AgentMessage, CertificateRequest, Heartbeat, NodeResources, ServiceSpec, StatusReport,
};
use crate::secrets::injector::SecretInjector;
use crate::spiffe::workload_api::WorkloadManager;

#[allow(dead_code)]
pub struct AgentConfig {
    pub server_addr: String,
    pub token: String,
    pub data_dir: PathBuf,
    pub ca_cert_pem: Option<String>,
}

/// Tracks local desired state as received from server.
#[derive(Default)]
struct LocalState {
    desired_services: HashMap<String, ServiceSpec>,
    system_path: String,
}

pub async fn run(config: AgentConfig) -> anyhow::Result<()> {
    // Validate server address format before connecting
    config
        .server_addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("invalid server address '{}': {e}", config.server_addr))?;

    tracing::info!(
        server = %config.server_addr,
        data_dir = %config.data_dir.display(),
        "Starting ekafleet agent"
    );

    let channel = if let Some(ca_pem) = &config.ca_cert_pem {
        // TLS connection with CA certificate verification
        let endpoint = format!("https://{}", config.server_addr);
        let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
        let tls_config = tonic::transport::ClientTlsConfig::new().ca_certificate(ca_cert);
        tonic::transport::Endpoint::from_shared(endpoint)?
            .tls_config(tls_config)?
            .connect()
            .await?
    } else {
        // Plaintext fallback (development only)
        tracing::warn!("Connecting without TLS — use --ca-cert in production");
        let endpoint = format!("http://{}", config.server_addr);
        tonic::transport::Endpoint::from_shared(endpoint)?
            .connect()
            .await?
    };

    // Attach bearer token to all outgoing requests
    let token: tonic::metadata::MetadataValue<_> = format!("Bearer {}", config.token).parse()?;
    #[allow(clippy::result_large_err)]
    let mut client =
        FleetControlClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    let node_id = get_node_id(&config.data_dir)?;
    tracing::info!(node_id = %node_id, "Agent identity established");

    let local_state = Arc::new(RwLock::new(LocalState::default()));
    let workload_mgr = Arc::new(WorkloadManager::new(&config.data_dir, "fleet.internal"));
    let supervisor = Arc::new(RwLock::new(supervisor::Supervisor::new(&config.data_dir)));
    let secret_injector = Arc::new(RwLock::new(SecretInjector::new(
        &config.data_dir,
        &[0u8; 32], // TODO: derive from fleet key distributed by server
    )));
    let dns_resolver = Arc::new(DnsResolver::new("fleet.internal", vec![]));
    let wg_manager = WireguardManager::new("wg-fleet", 51820);
    let peer_manager = Arc::new(RwLock::new(PeerManager::new(wg_manager)));
    let policy_enforcer = Arc::new(PolicyEnforcer::new());

    // Channel for outgoing messages to server
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);

    // Send initial heartbeat
    tx.send(AgentMessage {
        payload: Some(Payload::Heartbeat(Heartbeat {
            node_id: node_id.clone(),
            timestamp: now_epoch(),
            available_resources: Some(collect_resources()),
        })),
    })
    .await?;

    // Open bidirectional stream
    let response = client.stream_control(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

    // Spawn heartbeat sender
    let heartbeat_tx = tx.clone();
    let hb_node_id = node_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let msg = AgentMessage {
                payload: Some(Payload::Heartbeat(Heartbeat {
                    node_id: hb_node_id.clone(),
                    timestamp: now_epoch(),
                    available_resources: Some(collect_resources()),
                })),
            };
            if heartbeat_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn periodic status reporter
    let status_tx = tx.clone();
    let status_node_id = node_id.clone();
    let status_state = local_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let state = status_state.read().await;
            let running = state
                .desired_services
                .iter()
                .map(|(name, spec)| crate::proto::ServiceInstance {
                    service_name: name.clone(),
                    instance_id: format!("{}-{}", name, status_node_id),
                    store_path: spec.store_path.clone(),
                    state: crate::proto::ServiceState::ServiceRunning as i32,
                })
                .collect();
            drop(state);

            let msg = AgentMessage {
                payload: Some(Payload::Status(StatusReport {
                    node_id: status_node_id.clone(),
                    running_services: running,
                    current_system_path: String::new(),
                })),
            };
            if status_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn SVID renewal checker
    let renewal_tx = tx.clone();
    let renewal_node_id = node_id.clone();
    let renewal_mgr = workload_mgr.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let renewals = renewal_mgr.needs_renewal().await;
            for service_name in renewals {
                tracing::info!(service = %service_name, "Requesting SVID renewal");
                let _ = renewal_tx
                    .send(AgentMessage {
                        payload: Some(Payload::CertRequest(CertificateRequest {
                            node_id: renewal_node_id.clone(),
                            service_name,
                            csr: vec![0x01],
                        })),
                    })
                    .await;
            }
        }
    });

    // Process incoming server messages
    while let Some(msg) = inbound.message().await? {
        match msg.payload {
            Some(ServerPayload::DesiredState(ds)) => {
                tracing::info!(
                    correlation_id = %ds.correlation_id,
                    services = ds.services.len(),
                    "Received desired state"
                );
                let mut state = local_state.write().await;
                state.system_path = ds.system_path;
                state.desired_services.clear();
                for svc in &ds.services {
                    state.desired_services.insert(svc.name.clone(), svc.clone());
                }
                drop(state);

                // Request SPIFFE SVIDs for each assigned service
                for svc in &ds.services {
                    tracing::info!(service = %svc.name, "Requesting SVID for service");
                    let _ = tx
                        .send(AgentMessage {
                            payload: Some(Payload::CertRequest(CertificateRequest {
                                node_id: node_id.clone(),
                                service_name: svc.name.clone(),
                                csr: vec![0x01], // placeholder CSR
                            })),
                        })
                        .await;
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
            Some(ServerPayload::Deploy(cmd)) => {
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
            Some(ServerPayload::Secret(update)) => {
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
            Some(ServerPayload::Dns(update)) => {
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
            Some(ServerPayload::Cert(response)) => {
                tracing::info!(expires = response.expires_at, "Received SVID certificate");
                // Install SVID via workload manager
                // The certificate field contains the service cert we need to figure out which
                // service it's for. For now we extract the CN from the first line of PEM.
                if let Err(e) = install_received_svid(&workload_mgr, &response).await {
                    tracing::error!(error = %e, "Failed to install SVID");
                }
            }
            Some(ServerPayload::TrustBundle(bundle)) => {
                tracing::info!(
                    trust_domain = %bundle.trust_domain,
                    "Received trust bundle"
                );
                let pem = String::from_utf8_lossy(&bundle.ca_certificate_pem);
                if let Err(e) = workload_mgr.set_trust_bundle(&pem).await {
                    tracing::error!(error = %e, "Failed to install trust bundle");
                }
            }
            Some(ServerPayload::Peers(update)) => {
                tracing::info!(peers = update.peers.len(), "Received peer update");
                let mut pm = peer_manager.write().await;
                if let Err(e) = pm.apply_update(update.peers).await {
                    tracing::error!(error = %e, "WireGuard peer update failed");
                }
            }
            Some(ServerPayload::Policy(update)) => {
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
            None => {}
        }
    }

    tracing::warn!("Server stream ended");
    Ok(())
}

/// Install an SVID received from the server's CertificateResponse.
/// Extracts the service name from the certificate CN.
async fn install_received_svid(
    mgr: &WorkloadManager,
    response: &crate::proto::CertificateResponse,
) -> Result<(), std::io::Error> {
    let cert_pem = String::from_utf8(response.certificate.clone())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Extract service name from the certificate's CN (first line of PEM content)
    let service_name = extract_cn_from_pem(&cert_pem).unwrap_or_else(|| "unknown".to_string());

    mgr.install_svid(
        &service_name,
        &response.certificate,
        &response.chain,
        response.expires_at,
    )
    .await?;

    Ok(())
}

/// Extract the Common Name (CN) from a PEM certificate by parsing the DER.
fn extract_cn_from_pem(pem: &str) -> Option<String> {
    let cert_start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let cert_end = pem.find("-----END CERTIFICATE-----")? + "-----END CERTIFICATE-----".len();
    let cert_pem = &pem[cert_start..cert_end];

    let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let der = certs.first()?;

    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?;
    Some(cn.to_string())
}

fn get_node_id(data_dir: &Path) -> anyhow::Result<String> {
    let id_path = data_dir.join("node-id");
    if id_path.exists() {
        Ok(std::fs::read_to_string(&id_path)?.trim().to_string())
    } else {
        let id = uuid::Uuid::new_v4().to_string();
        if let Some(parent) = id_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&id_path, &id)?;
        Ok(id)
    }
}

pub(crate) fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn collect_resources() -> NodeResources {
    let cpu_millicores = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.matches("processor").count() as u64 * 1000)
        .unwrap_or(0);

    let memory_mb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemAvailable:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb / 1024)
        })
        .unwrap_or(0);

    let disk_mb = std::fs::read_to_string("/proc/mounts")
        .ok()
        .and_then(|mounts| {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "/" {
                    #[cfg(unix)]
                    {
                        use std::ffi::CString;
                        let path = CString::new(parts[1]).ok()?;
                        unsafe {
                            let mut stat: libc::statvfs = std::mem::zeroed();
                            if libc::statvfs(path.as_ptr(), &mut stat) == 0 {
                                return Some(
                                    (stat.f_bavail as u64 * stat.f_frsize as u64) / (1024 * 1024),
                                );
                            }
                        }
                    }
                }
            }
            None
        })
        .unwrap_or(0);

    NodeResources {
        cpu_millicores,
        memory_mb,
        disk_mb,
    }
}
