pub mod activation;
pub mod health;
pub mod storage;
pub mod supervisor;
pub mod template;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use crate::agent::health::HealthChecker;
use crate::ca::csr;
use crate::dns::resolver::DnsResolver;
use crate::mesh::peers::PeerManager;
use crate::mesh::wireguard::WireguardManager;
use crate::policy::nftables::PolicyEnforcer;
use crate::proto::agent_message::Payload;
use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    AgentMessage, CertificateRequest, HealthReport, Heartbeat, NodeResources, ServiceSpec,
    StatusReport,
};
use crate::secrets::injector::SecretInjector;
use crate::spiffe::workload_api::WorkloadManager;

/// The agent's own SPIFFE node identity (spiffe://<domain>/agent/<node-id>).
/// Persisted to disk and used for mTLS with the server.
pub struct NodeIdentity {
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub spiffe_id: Option<String>,
    pub expires_at: u64,
    data_dir: PathBuf,
}

#[allow(dead_code)]
impl NodeIdentity {
    fn new(data_dir: &Path) -> Self {
        Self {
            cert_pem: None,
            key_pem: None,
            spiffe_id: None,
            expires_at: 0,
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// Try to load a persisted node SVID from disk.
    async fn load(&mut self) -> bool {
        let cert_path = self.data_dir.join("node-svid.pem");
        let key_path = self.data_dir.join("node-svid-key.pem");

        match (
            tokio::fs::read_to_string(&cert_path).await,
            tokio::fs::read_to_string(&key_path).await,
        ) {
            (Ok(cert), Ok(key)) => {
                // Extract SPIFFE ID from cert SAN
                let spiffe_id =
                    crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&cert);
                tracing::info!(spiffe_id = ?spiffe_id, "Loaded persisted node SVID");
                self.cert_pem = Some(cert);
                self.key_pem = Some(key);
                self.spiffe_id = spiffe_id;
                true
            }
            _ => false,
        }
    }

    /// Persist node SVID to disk with restrictive permissions.
    async fn save(&self) -> Result<(), std::io::Error> {
        if let (Some(cert), Some(key)) = (&self.cert_pem, &self.key_pem) {
            let cert_path = self.data_dir.join("node-svid.pem");
            let key_path = self.data_dir.join("node-svid-key.pem");

            tokio::fs::create_dir_all(&self.data_dir).await?;
            tokio::fs::write(&cert_path, cert).await?;
            tokio::fs::write(&key_path, key).await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o400);
                tokio::fs::set_permissions(&key_path, perms).await?;
            }

            tracing::info!(
                spiffe_id = ?self.spiffe_id,
                "Node SVID persisted to disk"
            );
        }
        Ok(())
    }

    /// Install a node SVID received from attestation.
    async fn install(
        &mut self,
        cert_pem: String,
        key_pem: String,
        spiffe_id: String,
        expires_at: u64,
    ) -> Result<(), std::io::Error> {
        self.cert_pem = Some(cert_pem);
        self.key_pem = Some(key_pem);
        self.spiffe_id = Some(spiffe_id);
        self.expires_at = expires_at;
        self.save().await
    }

    /// Check if the node SVID exists and is valid.
    pub fn has_valid_svid(&self) -> bool {
        self.cert_pem.is_some() && self.key_pem.is_some()
    }
}

/// Holds keypairs for pending certificate requests.
/// When the agent generates a CSR, the keypair is stored here.
/// When the signed certificate arrives, the keypair is retrieved and
/// paired with the certificate.
struct PendingKeyStore {
    keys: HashMap<String, rcgen::KeyPair>,
}

impl PendingKeyStore {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn store(&mut self, service_name: &str, keypair: rcgen::KeyPair) {
        self.keys.insert(service_name.to_string(), keypair);
    }

    fn take(&mut self, service_name: &str) -> Option<rcgen::KeyPair> {
        self.keys.remove(service_name)
    }
}

#[allow(dead_code)]
pub struct AgentConfig {
    pub server_addr: String,
    /// Legacy bearer token for authentication.
    pub token: String,
    /// One-time join token for SPIFFE node attestation (replaces token).
    pub join_token: Option<String>,
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

    let node_id = get_node_id(&config.data_dir)?;
    tracing::info!(node_id = %node_id, "Agent identity established");

    // Load or prepare node SVID for mTLS
    let node_identity = Arc::new(RwLock::new(NodeIdentity::new(&config.data_dir)));
    {
        let mut ni = node_identity.write().await;
        if ni.load().await {
            tracing::info!("Node SVID loaded from disk");
        } else {
            tracing::info!("No persisted node SVID — will use bearer token auth");
        }
    }

    // Determine authentication mode: mTLS (node SVID) or bearer token
    let ni = node_identity.read().await;
    let use_mtls = ni.has_valid_svid();
    let node_cert_pem = ni.cert_pem.clone();
    let node_key_pem = ni.key_pem.clone();
    drop(ni);

    let channel = if let Some(ca_pem) = &config.ca_cert_pem {
        let endpoint = format!("https://{}", config.server_addr);
        let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
        let mut tls_config = tonic::transport::ClientTlsConfig::new().ca_certificate(ca_cert);

        // Use node SVID for mTLS if available
        if use_mtls {
            if let (Some(cert), Some(key)) = (&node_cert_pem, &node_key_pem) {
                tracing::info!("Using node SVID for mTLS authentication");
                let identity =
                    tonic::transport::Identity::from_pem(cert.as_bytes(), key.as_bytes());
                tls_config = tls_config.identity(identity);
            }
        }

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

    // Attach authentication metadata to all outgoing requests
    let token: tonic::metadata::MetadataValue<_> = format!("Bearer {}", config.token).parse()?;
    let mtls_flag = use_mtls;
    #[allow(clippy::result_large_err)]
    let mut client =
        FleetControlClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            if mtls_flag {
                // mTLS authenticated — signal to server interceptor
                req.metadata_mut()
                    .insert("x-ekafleet-mtls", "true".parse().unwrap());
            } else {
                // Legacy bearer token auth
                req.metadata_mut().insert("authorization", token.clone());
            }
            Ok(req)
        });

    let local_state = Arc::new(RwLock::new(LocalState::default()));
    // Trust domain starts as default; updated when TrustBundleUpdate is received from server.
    let workload_mgr = Arc::new(WorkloadManager::new(&config.data_dir, "fleet.internal"));
    let pending_keys = Arc::new(RwLock::new(PendingKeyStore::new()));
    let supervisor = Arc::new(RwLock::new(supervisor::Supervisor::new(&config.data_dir)));
    // Secret injector initialized with zeroed key; updated when FleetKeyUpdate is received
    let secret_injector = Arc::new(RwLock::new(SecretInjector::new(
        &config.data_dir,
        &[0u8; 32],
    )));
    let health_checker = HealthChecker::new();
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
            pool: String::new(),
        })),
    })
    .await?;

    // Open bidirectional stream
    let response = client.stream_control(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

    // Spawn SPIFFE Workload API socket listener
    let wapi_mgr = workload_mgr.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::spiffe::socket::serve_workload_api(wapi_mgr, None).await {
            tracing::error!(error = %e, "Workload API socket failed");
        }
    });

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
                    pool: String::new(),
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
    let renewal_keys = pending_keys.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let renewals = renewal_mgr.needs_renewal().await;
            for service_name in renewals {
                tracing::info!(service = %service_name, "Requesting SVID renewal");
                // Get current trust domain for CSR generation
                let trust_domain = renewal_mgr
                    .trust_domain_str()
                    .await
                    .unwrap_or_else(|| "fleet.internal".to_string());
                match csr::generate_service_csr(&trust_domain, &service_name) {
                    Ok(csr_output) => {
                        renewal_keys
                            .write()
                            .await
                            .store(&service_name, csr_output.keypair);
                        let _ = renewal_tx
                            .send(AgentMessage {
                                payload: Some(Payload::CertRequest(CertificateRequest {
                                    node_id: renewal_node_id.clone(),
                                    service_name,
                                    csr: csr_output.csr_der,
                                    request_type: crate::proto::CertRequestType::ServiceCert as i32,
                                })),
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::error!(service = %service_name, error = %e, "CSR generation failed");
                    }
                }
            }
        }
    });

    // Spawn periodic health reporter
    let health_tx = tx.clone();
    let health_node_id = node_id.clone();
    let health_checker_clone = health_checker.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let services = health_checker_clone.reports(&health_node_id).await;
            if services.is_empty() {
                continue;
            }
            let msg = AgentMessage {
                payload: Some(Payload::Health(HealthReport {
                    node_id: health_node_id.clone(),
                    services,
                })),
            };
            if health_tx.send(msg).await.is_err() {
                break;
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
                    system_path = %ds.system_path,
                    "Received desired state"
                );

                // Activate EkaOS system closure if a new system_path is provided
                if !ds.system_path.is_empty() {
                    let current = local_state.read().await.system_path.clone();
                    if ds.system_path != current {
                        let params = activation::ActivationParams {
                            toplevel: ds.system_path.clone(),
                            activate_script: None, // default: {toplevel}/bin/activate
                            action: activation::ActivationAction::Switch,
                        };
                        match activation::activate_system(&params).await {
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
                                        node_id: node_id.clone(),
                                        service_name: svc.name.clone(),
                                        csr: csr_output.csr_der,
                                        request_type: crate::proto::CertRequestType::ServiceCert
                                            as i32,
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
                tracing::info!(
                    expires = response.expires_at,
                    service = %response.service_name,
                    "Received SVID certificate"
                );
                if let Err(e) = install_received_svid(&workload_mgr, &pending_keys, &response).await
                {
                    tracing::error!(error = %e, "Failed to install SVID");
                }
            }
            Some(ServerPayload::TrustBundle(bundle)) => {
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
            Some(ServerPayload::AttestChallenge(challenge)) => {
                tracing::debug!(
                    challenge_len = challenge.challenge_data.len(),
                    "Received attestation challenge (handled via Attest RPC)"
                );
                // Attestation challenges are handled via the Attest RPC flow, not the stream.
            }
            Some(ServerPayload::FleetKey(key_update)) => {
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
            None => {}
        }
    }

    tracing::warn!("Server stream ended");
    Ok(())
}

/// Install an SVID received from the server's CertificateResponse.
///
/// If a pending keypair exists for this service (proper CSR flow), the cert
/// is paired with the local private key. Otherwise falls back to the legacy
/// combined cert+key format.
async fn install_received_svid(
    mgr: &WorkloadManager,
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    response: &crate::proto::CertificateResponse,
) -> Result<(), std::io::Error> {
    // Determine service name: prefer the explicit field, fall back to CN extraction
    let service_name = if !response.service_name.is_empty() {
        response.service_name.clone()
    } else {
        let cert_pem = String::from_utf8(response.certificate.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        extract_cn_from_pem(&cert_pem).unwrap_or_else(|| "unknown".to_string())
    };

    // Check if we have a pending keypair for this service (proper CSR flow)
    let local_keypair = pending_keys.write().await.take(&service_name);

    if let Some(keypair) = local_keypair {
        // Proper CSR flow: pair server-signed cert with our local private key
        let cert_pem = String::from_utf8(response.certificate.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let chain_pem = String::from_utf8(response.chain.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let key_pem = keypair.serialize_pem();

        mgr.install_svid_split(
            &service_name,
            &cert_pem,
            &key_pem,
            &chain_pem,
            response.expires_at,
        )
        .await?;
    } else {
        // Legacy flow: cert+key combined from server
        mgr.install_svid(
            &service_name,
            &response.certificate,
            &response.chain,
            response.expires_at,
        )
        .await?;
    }

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
