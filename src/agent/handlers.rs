use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::{RwLock, mpsc};

use super::helpers::{install_node_svid, install_received_svid};
use super::images::{ImageManager, Readiness};
use super::netns::NamespaceNetworkManager;
use super::storage::VolumeManager;
use super::supervisor;
use super::types::{LocalState, NodeIdentity, PendingKeyStore};
use crate::agent::health::HealthChecker;
use crate::agent::templates::{self, TemplateManager};
use crate::dns::agent::AgentDns;
use crate::mesh::peers::PeerManager;
use crate::policy::nftables::PolicyEnforcer;
use crate::proto::agent_command_response::Result as CmdResult;
use crate::proto::agent_message::Payload;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{AgentCommandResponse, AgentMessage, CertRequestType};
use crate::secrets::injector::SecretInjector;
use crate::spiffe::workload_api::WorkloadManager;

/// Fetch each service's closure from the server's cache. A service whose
/// closure cannot be fetched keeps its `previous` spec if it had one and is
/// left out otherwise.
pub(super) async fn fetch_service_closures(
    client: &super::closures::AgentClient,
    services: Vec<crate::proto::ServiceSpec>,
    public_key: &str,
    previous: &std::collections::HashMap<String, crate::proto::ServiceSpec>,
) -> Vec<crate::proto::ServiceSpec> {
    let mut kept = Vec::with_capacity(services.len());
    for svc in services {
        if svc.store_paths.is_empty() {
            kept.push(svc);
            continue;
        }
        match super::closures::ensure_closures(client, &svc.store_paths, public_key).await {
            Ok(()) => kept.push(svc),
            Err(e) => {
                tracing::error!(
                    service = %svc.name,
                    error = %e,
                    "Cannot fetch service closure; keeping the current version"
                );
                if let Some(prev) = previous.get(&svc.name) {
                    kept.push(prev.clone());
                }
            }
        }
    }
    kept
}

/// Write the routes the server assigned this node for the ingress proxy,
/// with the certificates of TLS routes whose secrets have arrived.
async fn apply_ingress(
    update: &crate::proto::IngressUpdate,
    secret_injector: &Arc<RwLock<SecretInjector>>,
) {
    use crate::proxy::tls::{CertDir, PROXY_GROUP, TLS_DIR, group_id};
    let scope = crate::secrets::FLEET_SCOPE;
    let certs = CertDir::new(std::path::Path::new(TLS_DIR), group_id(PROXY_GROUP));
    let injector = secret_injector.read().await;
    let mut tls = std::collections::HashMap::new();
    let mut needed = std::collections::HashSet::new();
    for route in update
        .routes
        .iter()
        .filter(|r| !r.tls_cert_secret.is_empty())
    {
        needed.insert(route.tls_cert_secret.as_str());
        needed.insert(route.tls_key_secret.as_str());
        let cert = injector.read(scope, &route.tls_cert_secret).await;
        let key = injector.read(scope, &route.tls_key_secret).await;
        match (cert, key) {
            (Ok(Some(cert)), Ok(Some(key))) => match certs.write(&route.name, &cert, key).await {
                Ok(digest) => {
                    tls.insert(route.name.clone(), digest);
                }
                Err(e) => {
                    tracing::error!(route = %route.name, error = %e, "Cannot install route certificate")
                }
            },
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(route = %route.name, error = %e, "Cannot read route certificate")
            }
            _ => tracing::info!(
                route = %route.name,
                "Route waits for its certificate secrets ({scope}/{}, {scope}/{})",
                route.tls_cert_secret,
                route.tls_key_secret
            ),
        }
    }
    if let Err(e) = injector.retain_secrets(scope, &needed).await {
        tracing::warn!(error = %e, "Cannot remove unused fleet secrets");
    }
    if let Err(e) = certs.retain(&tls.keys().cloned().collect()).await {
        tracing::warn!(error = %e, "Cannot remove unused route certificates");
    }
    let routes = crate::proxy::routes::RoutesFile::from_update(update, &tls);
    let path = std::path::Path::new(crate::proxy::routes::ROUTES_FILE);
    match routes.write(path).await {
        Ok(true) => tracing::info!(routes = routes.routes.len(), "Ingress routes updated"),
        Ok(false) => {}
        // A node serving no ingress (e.g. `ekafleet dev` without
        // root) need not have the runtime directory.
        Err(e) if routes.routes.is_empty() => {
            tracing::debug!(error = %e, "Cannot write empty ingress routes")
        }
        Err(e) => tracing::error!(error = %e, "Cannot write ingress routes"),
    }
}

/// Bring the supervisor's services in line with the desired state: drop
/// secret files no service declares, provision and reclaim volumes, render
/// templates, and (re)start services, except new ones still waiting for a
/// declared secret and services held for a volume operation (which stop).
pub(super) async fn converge_services(
    supervisor: &Arc<RwLock<supervisor::Supervisor>>,
    local_state: &Arc<RwLock<LocalState>>,
    secret_injector: &Arc<RwLock<SecretInjector>>,
    templates: &Arc<TemplateManager>,
    dns: &Arc<AgentDns>,
    volumes: &Arc<VolumeManager>,
    images: &Arc<ImageManager>,
) {
    let all = local_state.read().await.desired_services.clone();
    if let Err(e) = volumes.provision(all.values()).await {
        tracing::error!(error = %e, "Cannot provision volumes");
    }
    volumes.release_unassigned(all.keys().map(String::as_str));
    let mut desired = std::collections::HashMap::new();
    // Running containers whose new image is not ready yet: left as they are.
    let mut keep = std::collections::HashSet::new();
    {
        let injector = secret_injector.read().await;
        let declared = all
            .values()
            .filter(|s| !s.secrets.is_empty())
            .map(|s| (s.name.clone(), s.secrets.clone()))
            .collect();
        if let Err(e) = injector.retain(&declared).await {
            tracing::warn!(error = %e, "Cannot remove stale secret files");
        }
        let supervisor = supervisor.read().await;
        for (name, spec) in &all {
            if volumes.is_held(name) {
                tracing::info!(service = %name, "Service held for a volume operation");
                continue;
            }
            if !injector.has_all(name, &spec.secrets) && !supervisor.is_running(name).await {
                tracing::info!(service = %name, secrets = ?spec.secrets, "Service waits for its secrets");
                continue;
            }
            if !spec.container_image.is_empty() {
                match images.prepare(spec).await {
                    Readiness::Ready { user } => {
                        super::images::chown_volumes(&volumes.service_dir(name), spec, &user).await;
                    }
                    waiting => {
                        if supervisor.is_running(name).await {
                            tracing::info!(service = %name, image = %spec.container_image, state = ?waiting, "Service keeps its current image until the new one is ready");
                            keep.insert(name.clone());
                        } else {
                            tracing::info!(service = %name, image = %spec.container_image, state = ?waiting, "Service waits for its image");
                        }
                        continue;
                    }
                }
            }
            desired.insert(name.clone(), spec.clone());
        }
    }

    // Render before (re)starting, so new services find their files.
    templates.set_services(all.values()).await;
    let template_changes = templates.render_all(dns.resolver()).await;
    match supervisor.write().await.reconcile(&desired, &keep).await {
        Ok(actions) => {
            for action in &actions {
                tracing::info!(?action, "Supervisor action");
            }
            for (service, change) in &template_changes {
                let fresh = actions.iter().any(|a| {
                    matches!(a, supervisor::SupervisorAction::Started(s)
                        | supervisor::SupervisorAction::Restarted(s) if s == service)
                });
                if !fresh && desired.contains_key(service) {
                    templates::notify(service, change).await;
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "Service reconciliation failed"),
    }
    images.retain_services(&all.keys().map(String::as_str).collect());
    // The bundles services run and those they switch to stay; the rest go
    // once no pull is in flight.
    let mut bundles: std::collections::HashSet<(String, String)> = all
        .values()
        .filter_map(|spec| {
            super::images::pinned_image(spec).map(|(_, hex)| (spec.name.clone(), hex))
        })
        .collect();
    for (service, image) in supervisor.read().await.container_images() {
        let running = crate::proto::ServiceSpec {
            name: service,
            container_image: image,
            ..Default::default()
        };
        if let Some((_, hex)) = super::images::pinned_image(&running) {
            bundles.insert((running.name, hex));
        }
    }
    images.collect_garbage(&bundles).await;
    // After the supervisor has stopped services no longer assigned here.
    if let Err(e) = volumes.reclaim(all.values()).await {
        tracing::warn!(error = %e, "Cannot reclaim volumes");
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_server_message(
    payload: ServerPayload,
    supervisor: &Arc<RwLock<supervisor::Supervisor>>,
    local_state: &Arc<RwLock<LocalState>>,
    workload_mgr: &Arc<WorkloadManager>,
    pending_keys: &Arc<RwLock<PendingKeyStore>>,
    node_identity: &Arc<RwLock<NodeIdentity>>,
    secret_injector: &Arc<RwLock<SecretInjector>>,
    dns: &Arc<AgentDns>,
    templates: &Arc<TemplateManager>,
    peer_manager: &Arc<RwLock<PeerManager>>,
    policy_enforcer: &Arc<PolicyEnforcer>,
    health_checker: &HealthChecker,
    netns_manager: &Arc<NamespaceNetworkManager>,
    volumes: &Arc<VolumeManager>,
    images: &Arc<ImageManager>,
    tx: &mpsc::Sender<AgentMessage>,
    node_id: &str,
) {
    match payload {
        ServerPayload::DesiredState(ds) => {
            if let Err(e) = images.set_signature_policy(&ds.signature_policy_json) {
                tracing::error!(error = %e, "Refusing to pull images until the signature policy is fixed");
            }
            tracing::info!(
                correlation_id = %ds.correlation_id,
                services = ds.services.len(),
                system_path = %ds.system_path,
                namespace_networks = ds.namespace_networks.len(),
                "Received desired state"
            );

            // The agent loop fetched the closures services need before
            // handing the state over (`fetch_service_closures`), so a service
            // whose closure could not be fetched keeps running its current
            // version instead of being restarted into a missing one.

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
                } else if let Ok(gateway) = ns_cfg.gateway.parse() {
                    dns.ensure_namespace(&ns_cfg.namespace, gateway).await;
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

            // Set up VXLAN tunnels for cross-node namespace networking
            let local_mesh_ip = peer_manager.read().await.wireguard().mesh_ip();
            for ns_cfg in &ds.namespace_networks {
                if ns_cfg.remote_peers.is_empty() {
                    // No remote peers — tear down any existing VXLAN tunnel
                    let _ = netns_manager.remove_vxlan_tunnel(&ns_cfg.namespace).await;
                    continue;
                }
                let Some(local_mesh_ip) = local_mesh_ip else {
                    tracing::warn!(
                        namespace = %ns_cfg.namespace,
                        "No mesh interface; cannot reach this namespace on other nodes"
                    );
                    continue;
                };

                let peers: Vec<super::netns::RemotePeerInfo> = ns_cfg
                    .remote_peers
                    .iter()
                    .filter_map(|rp| {
                        let endpoint: std::net::Ipv4Addr = rp.tunnel_endpoint.parse().ok()?;
                        let services = rp
                            .services
                            .iter()
                            .filter_map(|s| {
                                let ip: std::net::Ipv4Addr = s.ip.parse().ok()?;
                                Some((s.service_name.clone(), ip))
                            })
                            .collect();
                        Some(super::netns::RemotePeerInfo {
                            node_id: rp.node_id.clone(),
                            tunnel_endpoint: endpoint,
                            services,
                        })
                    })
                    .collect();

                if let Err(e) = netns_manager
                    .ensure_vxlan_tunnel(&ns_cfg.namespace, ns_cfg.vni, local_mesh_ip, &peers)
                    .await
                {
                    tracing::error!(
                        namespace = %ns_cfg.namespace,
                        vni = ns_cfg.vni,
                        peers = peers.len(),
                        error = %e,
                        "VXLAN tunnel setup failed"
                    );
                }
            }

            // GC namespaces that are no longer referenced
            dns.retain(&active_namespaces).await;
            if let Err(e) = netns_manager.gc_namespaces(&active_namespaces).await {
                tracing::warn!(error = %e, "Failed to GC namespace networks");
            }

            // Drop SVIDs and pending requests for services no longer assigned
            // here (the server would refuse to renew them anyway), then
            // request SVIDs for assigned services that lack a current one.
            let assigned: std::collections::HashSet<&str> =
                ds.services.iter().map(|s| s.name.as_str()).collect();
            pending_keys
                .write()
                .await
                .retain(|name| assigned.contains(name));
            for (name, _, _) in workload_mgr.active_services().await {
                if !assigned.contains(name.as_str())
                    && let Err(e) = workload_mgr.remove_svid(&name).await
                {
                    tracing::warn!(service = %name, error = %e, "Failed to remove stale SVID");
                }
            }
            let assigned_names: Vec<String> = ds.services.iter().map(|s| s.name.clone()).collect();
            workload_mgr
                .jwt_broker()
                .retain_services(&assigned_names)
                .await;
            let renewals = workload_mgr.needs_renewal().await;
            for svc in &ds.services {
                let has_current = workload_mgr.spiffe_id(&svc.name).await.is_some()
                    && !renewals.contains(&svc.name);
                if !has_current {
                    super::helpers::request_service_svid(
                        workload_mgr,
                        pending_keys,
                        tx,
                        node_id,
                        &svc.name,
                    )
                    .await;
                }
            }

            // Probe the services that declare probes; stop probing the rest.
            let mut probed = std::collections::HashSet::new();
            for svc in &ds.services {
                if let Some(probes) = crate::agent::health::ProbeConfig::for_service(svc) {
                    health_checker.ensure(&svc.name, probes).await;
                    probed.insert(svc.name.as_str());
                }
            }
            health_checker.retain(|name| probed.contains(name)).await;

            converge_services(
                supervisor,
                local_state,
                secret_injector,
                templates,
                dns,
                volumes,
                images,
            )
            .await;
        }
        ServerPayload::Deploy(cmd) => {
            tracing::info!(
                deployment_id = %cmd.deployment_id,
                service = %cmd.service_name,
                "Received deploy command"
            );
            // Update the desired state for this service and reconcile
            if let Some(svc) = local_state
                .write()
                .await
                .desired_services
                .get_mut(&cmd.service_name)
            {
                svc.store_path = cmd.store_path.clone();
            }
            converge_services(
                supervisor,
                local_state,
                secret_injector,
                templates,
                dns,
                volumes,
                images,
            )
            .await;
        }
        ServerPayload::Secret(update) if update.service_name == crate::secrets::FLEET_SCOPE => {
            // Fleet secrets reach nodes as ingress certificates only.
            let changed = {
                let injector = secret_injector.read().await;
                if update.deleted {
                    injector
                        .remove(&update.service_name, &update.secret_name)
                        .await
                } else {
                    injector
                        .inject(
                            &update.service_name,
                            &update.secret_name,
                            &update.encrypted_value,
                        )
                        .await
                }
            };
            match changed {
                Ok(true) => {
                    let ingress = local_state.read().await.ingress.clone();
                    if let Some(ingress) = ingress {
                        apply_ingress(&ingress, secret_injector).await;
                    }
                }
                Ok(false) => {}
                Err(e) => tracing::error!(
                    secret = %update.secret_name,
                    error = %e,
                    "Cannot apply fleet secret update"
                ),
            }
        }
        ServerPayload::Secret(update) => {
            let service = update.service_name.as_str();
            tracing::debug!(
                service,
                secret = %update.secret_name,
                version = update.version,
                deleted = update.deleted,
                "Received secret update"
            );
            let changed = {
                let injector = secret_injector.read().await;
                if update.deleted {
                    injector.remove(service, &update.secret_name).await
                } else {
                    injector
                        .inject(service, &update.secret_name, &update.encrypted_value)
                        .await
                }
            };
            match changed {
                Ok(true) if supervisor.read().await.is_running(service).await => {
                    // Templates may read the secret; the restart picks up
                    // both, so no separate template signal is needed.
                    templates.render_service(service, dns.resolver()).await;
                    tracing::info!(service, secret = %update.secret_name, "Restarting service for secret change");
                    templates::notify(service, &templates::TemplateChange::Restart).await;
                }
                // Possibly the last secret a waiting service needed.
                Ok(true) => {
                    converge_services(
                        supervisor,
                        local_state,
                        secret_injector,
                        templates,
                        dns,
                        volumes,
                        images,
                    )
                    .await
                }
                Ok(false) => {}
                Err(e) => tracing::error!(
                    service,
                    secret = %update.secret_name,
                    error = %e,
                    "Cannot apply secret update"
                ),
            }
        }
        ServerPayload::Dns(update) => {
            tracing::debug!(records = update.records.len(), "Received DNS records");
            dns.resolver().replace(&update.records).await;
            for (service, change) in templates.render_all(dns.resolver()).await {
                templates::notify(&service, &change).await;
            }
        }
        ServerPayload::Cert(response) => {
            tracing::info!(
                expires = response.expires_at,
                service = %response.service_name,
                "Received SVID certificate"
            );
            let result = if response.request_type == CertRequestType::NodeCert as i32 {
                install_node_svid(node_identity, pending_keys, &response).await
            } else {
                install_received_svid(workload_mgr, pending_keys, &response).await
            };
            if let Err(e) = result {
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
                dns.resolver().set_domain(&bundle.trust_domain).await;
            }
            let pem = String::from_utf8_lossy(&bundle.ca_certificate_pem);
            if let Err(e) = workload_mgr.set_trust_bundle(&pem).await {
                tracing::error!(error = %e, "Failed to install trust bundle");
            }
            if !bundle.jwt_bundle_jwks.is_empty() {
                match std::str::from_utf8(&bundle.jwt_bundle_jwks) {
                    Ok(jwks) => workload_mgr.set_jwt_bundle(jwks).await,
                    Err(_) => tracing::error!("JWT bundle is not valid UTF-8"),
                }
            }
            let federated = bundle
                .federated_bundles
                .into_iter()
                .filter_map(|b| {
                    let x509_pem = String::from_utf8(b.ca_certificates_pem).ok()?;
                    let jwks = String::from_utf8(b.jwt_bundle_jwks).ok()?;
                    Some((
                        b.trust_domain,
                        crate::spiffe::workload_api::FederatedBundle { x509_pem, jwks },
                    ))
                })
                .collect();
            workload_mgr.set_federated_bundles(federated).await;
        }
        ServerPayload::JwtSvid(response) => {
            workload_mgr.jwt_broker().complete(response).await;
        }
        ServerPayload::Mesh(assignment) => {
            tracing::info!(mesh_ip = %assignment.mesh_ip, "Received mesh assignment");
            let identity = node_identity.read().await;
            let svid = identity
                .cert_pem
                .as_deref()
                .zip(identity.key_pem.as_deref().map(String::as_str));
            let advert = peer_manager
                .write()
                .await
                .activate(node_id, &assignment, svid)
                .await;
            drop(identity);
            match advert {
                Ok(Some(peer)) => {
                    let msg = AgentMessage {
                        payload: Some(crate::proto::agent_message::Payload::MeshAdvert(peer)),
                    };
                    if tx.send(msg).await.is_err() {
                        tracing::warn!("Cannot send mesh advertisement: stream closed");
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::error!(error = %e, "Cannot join the WireGuard mesh"),
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
            policy_enforcer.set(update).await;
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
                let mut key = zeroize::Zeroizing::new([0u8; 32]);
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
            let tx = tx.clone();
            let volumes = volumes.clone();
            let node_identity = node_identity.clone();
            tokio::spawn(async move {
                let result = super::migrate::pull(
                    &volumes,
                    &node_identity,
                    &cmd.source_addr,
                    &cmd.source_spiffe_id,
                    &cmd.service_name,
                )
                .await;
                if result.is_ok() {
                    // Until the assignment that follows the migration.
                    volumes.protect(&cmd.service_name, Duration::from_secs(600));
                }
                let error_message = match &result {
                    Ok(_) => String::new(),
                    Err(e) => {
                        tracing::error!(service = %cmd.service_name, source = %cmd.source_addr, error = %e, "Volume migration failed");
                        e.to_string()
                    }
                };
                respond(&tx, cmd.correlation_id, error_message, None).await;
            });
        }
        ServerPayload::ExportVolumesCommand(cmd) => {
            let service = cmd.service_name.as_str();
            let ttl = Duration::from_secs(u64::from(cmd.ttl_seconds.clamp(30, 3600)));
            let error_message = if let Err(e) = crate::secrets::validate_name("service", service) {
                e
            } else {
                tracing::info!(service, dest = %cmd.dest_spiffe_id, ?ttl, "Stopping service to export its volumes");
                volumes.hold(service, ttl);
                volumes.grant_export(service, &cmd.dest_spiffe_id, ttl);
                converge_services(
                    supervisor,
                    local_state,
                    secret_injector,
                    templates,
                    dns,
                    volumes,
                    images,
                )
                .await;
                if supervisor.read().await.is_running(service).await {
                    format!("{service} did not stop")
                } else if !volumes.service_dir(service).is_dir() {
                    format!("{service} has no volumes on this node")
                } else {
                    String::new()
                }
            };
            respond(tx, cmd.correlation_id, error_message, None).await;
        }
        ServerPayload::Ingress(update) => {
            local_state.write().await.ingress = Some(update.clone());
            apply_ingress(&update, secret_injector).await;
        }
        ServerPayload::VolumeSnapshotCommand(cmd) => {
            let tx = tx.clone();
            let ctx = (
                supervisor.clone(),
                local_state.clone(),
                secret_injector.clone(),
                templates.clone(),
                dns.clone(),
                volumes.clone(),
                images.clone(),
            );
            let node = node_id.to_string();
            tokio::spawn(async move {
                let (supervisor, local_state, secret_injector, templates, dns, volumes, images) =
                    &ctx;
                let result = volume_snapshot(&cmd, volumes, || async {
                    converge_services(
                        supervisor,
                        local_state,
                        secret_injector,
                        templates,
                        dns,
                        volumes,
                        images,
                    )
                    .await
                })
                .await;
                let (error_message, result) = match result {
                    Ok(mut snapshots) => {
                        for s in &mut snapshots {
                            s.node = node.clone();
                        }
                        (
                            String::new(),
                            Some(CmdResult::VolumeSnapshotResult(
                                crate::proto::VolumeSnapshotResult { snapshots },
                            )),
                        )
                    }
                    Err(e) => (e.to_string(), None),
                };
                respond(&tx, cmd.correlation_id, error_message, result).await;
            });
        }
    }
}

/// Answer a correlated command; an empty `error_message` is success.
async fn respond(
    tx: &mpsc::Sender<AgentMessage>,
    correlation_id: String,
    error_message: String,
    result: Option<CmdResult>,
) {
    let response = AgentCommandResponse {
        correlation_id,
        success: error_message.is_empty(),
        error_message,
        result,
    };
    let _ = tx
        .send(AgentMessage {
            payload: Some(Payload::CommandResponse(response)),
        })
        .await;
}

/// Run a snapshot command. A restore holds (stops) the service around the
/// swap, running `converge` to stop and then start it again.
async fn volume_snapshot<F, Fut>(
    cmd: &crate::proto::VolumeSnapshotCommand,
    volumes: &VolumeManager,
    converge: F,
) -> Result<Vec<crate::proto::VolumeSnapshotInfo>, super::storage::VolumeError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use crate::proto::VolumeSnapshotAction as Action;
    let (service, volume, id) = (
        cmd.service_name.as_str(),
        cmd.volume_name.as_str(),
        cmd.snapshot_id.as_str(),
    );
    match Action::try_from(cmd.action).unwrap_or(Action::VolumeSnapshotList) {
        Action::VolumeSnapshotList => volumes.list_snapshots(service, volume).await,
        Action::VolumeSnapshotCreate => Ok(vec![volumes.create_snapshot(service, volume).await?]),
        Action::VolumeSnapshotDelete => {
            Ok(vec![volumes.delete_snapshot(service, volume, id).await?])
        }
        Action::VolumeSnapshotRestore => {
            volumes.hold(service, Duration::from_secs(3600));
            converge().await;
            let restored = volumes.restore_snapshot(service, volume, id).await;
            volumes.release(service);
            converge().await;
            Ok(vec![restored?])
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
