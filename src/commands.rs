use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::{
    DrainRequest, PlanRequest, RollbackRequest, ScaleRequest, SnapshotRequest, StatusRequest,
};
use ekafleet::{agent, server};

use std::path::PathBuf;

use super::OutputFormat;

pub async fn connect_server(
    server: &str,
) -> anyhow::Result<FleetControlClient<tonic::transport::Channel>> {
    let endpoint = format!("http://{server}");
    let client = FleetControlClient::connect(endpoint).await?;
    Ok(client)
}

/// Execute ssh, replacing the current process.
pub fn exec_ssh(target: &str) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new("ssh").arg(target).exec()
}

/// Generate a cryptographically random token (64 hex chars = 256 bits).
pub fn generate_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("system RNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn cmd_dev(data_dir: PathBuf, http_listen: String, listen: String) -> anyhow::Result<()> {
    tracing::info!(
        data_dir = %data_dir.display(),
        grpc = %listen,
        http = %http_listen,
        "Starting ekafleet in dev mode (no TLS, no WireGuard)"
    );

    let dev_token = "dev-token";
    tracing::info!(token = dev_token, "Dev mode token (use for API access)");

    let config = server::ServerConfig {
        data_dir,
        peers: Vec::new(),
        grpc_listen: listen,
        http_listen,
        token: dev_token.to_string(),
        domain: "dev.local".to_string(),
        ca_socket: None,
    };

    server::run(config).await?;
    Ok(())
}

pub async fn cmd_proxy(
    listen: String,
    trust_domain: String,
    data_dir: PathBuf,
) -> anyhow::Result<()> {
    let listen_addr = listen.parse()?;
    ekafleet::proxy::standalone::run_standalone(ekafleet::proxy::standalone::ProxyConfig {
        listen: listen_addr,
        trust_domain,
        data_dir,
    })
    .await
}

pub async fn cmd_workload_api(
    data_dir: PathBuf,
    trust_domain: String,
    socket: PathBuf,
) -> anyhow::Result<()> {
    ekafleet::spiffe::socket::run_standalone(ekafleet::spiffe::socket::WorkloadApiConfig {
        data_dir,
        trust_domain,
        socket_path: socket,
    })
    .await
}

pub async fn cmd_ca_signer(
    data_dir: PathBuf,
    domain: String,
    socket: PathBuf,
) -> anyhow::Result<()> {
    ekafleet::ca::signer::serve(ekafleet::ca::signer::CaSignerConfig {
        data_dir,
        domain,
        socket_path: socket,
    })
    .await
}

pub async fn cmd_server(
    data_dir: PathBuf,
    peers: Option<String>,
    listen: String,
    http_listen: String,
    token: String,
    domain: String,
    ca_socket: Option<PathBuf>,
) -> anyhow::Result<()> {
    let peer_list: Vec<String> = peers
        .map(|p| p.split(',').map(String::from).collect())
        .unwrap_or_default();

    let config = server::ServerConfig {
        data_dir,
        peers: peer_list,
        grpc_listen: listen,
        http_listen,
        token,
        domain,
        ca_socket,
    };

    server::run(config).await?;
    Ok(())
}

pub async fn cmd_agent(
    join: String,
    token: String,
    join_token: Option<String>,
    data_dir: PathBuf,
    ca_cert: Option<PathBuf>,
) -> anyhow::Result<()> {
    let ca_cert_pem = match ca_cert {
        Some(path) => Some(std::fs::read_to_string(&path)?),
        None => None,
    };

    let config = agent::AgentConfig {
        server_addr: join,
        token,
        join_token,
        data_dir,
        ca_cert_pem,
    };

    agent::run(config).await?;
    Ok(())
}

pub async fn cmd_plan(config: PathBuf, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .plan(PlanRequest {
            config_path: config.display().to_string(),
        })
        .await?;
    let plan = resp.into_inner();

    if !plan.has_changes {
        println!("No changes detected.");
    } else {
        println!("Planned operations:");
        for op in &plan.operations {
            println!(
                "  {:?} {} on {} — {}",
                ekafleet::proto::OperationType::try_from(op.operation_type)
                    .unwrap_or(ekafleet::proto::OperationType::Create),
                op.service_name,
                op.target_node,
                op.description
            );
        }
    }
    Ok(())
}

pub async fn cmd_apply(
    config: PathBuf,
    auto_approve: bool,
    watch: bool,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let mut stream = client
        .apply(ekafleet::proto::ApplyRequest {
            config_path: config.display().to_string(),
            auto_approve,
            watch,
        })
        .await?
        .into_inner();

    while let Some(event) = stream.message().await? {
        let status = ekafleet::proto::ApplyStatus::try_from(event.status)
            .unwrap_or(ekafleet::proto::ApplyStatus::ApplyPending);
        println!("[{:?}] {} — {}", status, event.operation_id, event.message);
    }
    println!("Apply complete.");
    Ok(())
}

pub async fn cmd_status(server: String, output: &OutputFormat) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client.status(StatusRequest {}).await?;
    let status = resp.into_inner();

    if matches!(output, OutputFormat::Json) {
        let json = serde_json::json!({
            "fleet_name": status.fleet_name,
            "nodes": status.nodes.iter().map(|n| serde_json::json!({
                "node_id": n.node_id,
                "address": n.address,
                "healthy": n.healthy,
                "pool": n.pool,
                "last_heartbeat": n.last_heartbeat,
            })).collect::<Vec<_>>(),
            "services": status.services.iter().map(|s| serde_json::json!({
                "name": s.name,
                "healthy_count": s.healthy_count,
                "instances": s.instances.len(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("Fleet: {}", status.fleet_name);
    println!();
    println!("Nodes ({}):", status.nodes.len());
    for node in &status.nodes {
        let health = if node.healthy { "healthy" } else { "unhealthy" };
        let pool_label = if node.pool.is_empty() {
            String::new()
        } else {
            format!(" [{}]", node.pool)
        };
        println!(
            "  {}{} ({}) — {} — last heartbeat {}s ago",
            node.node_id, pool_label, node.address, health, node.last_heartbeat
        );
        if let Some(res) = &node.available_resources {
            println!(
                "    resources: {}m CPU, {}MB mem, {}MB disk",
                res.cpu_millicores, res.memory_mb, res.disk_mb
            );
        }
    }
    if !status.pools.is_empty() {
        println!();
        println!("Pools ({}):", status.pools.len());
        for pool in &status.pools {
            let sched = pool.total_schedulable.as_ref();
            let alloc = pool.total_allocated.as_ref();
            let sched_cpu = sched.map(|r| r.cpu_millicores).unwrap_or(0);
            let sched_mem = sched.map(|r| r.memory_mb).unwrap_or(0);
            let alloc_cpu = alloc.map(|r| r.cpu_millicores).unwrap_or(0);
            let alloc_mem = alloc.map(|r| r.memory_mb).unwrap_or(0);
            println!(
                "  {} — {} machines — {}m/{}m CPU, {}MB/{}MB mem",
                pool.name, pool.machine_count, alloc_cpu, sched_cpu, alloc_mem, sched_mem
            );
        }
    }
    println!();
    println!("Services ({}):", status.services.len());
    for svc in &status.services {
        println!(
            "  {} — {}/{} healthy — {} instances",
            svc.name,
            svc.healthy_count,
            svc.instances.len(),
            svc.instances.len()
        );
    }
    Ok(())
}

pub async fn cmd_drift(server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client.status(StatusRequest {}).await?;
    let status = resp.into_inner();

    let mut drifted = false;
    for node in &status.nodes {
        if !node.healthy {
            println!("DRIFT: node {} is unhealthy", node.node_id);
            drifted = true;
        }
    }
    for svc in &status.services {
        let unhealthy = svc.instances.len() as u32 - svc.healthy_count;
        if unhealthy > 0 {
            println!(
                "DRIFT: service {} has {} unhealthy instances",
                svc.name, unhealthy
            );
            drifted = true;
        }
    }
    if !drifted {
        println!("No drift detected.");
    }
    Ok(())
}

pub async fn cmd_rollback(
    machine: Option<String>,
    all: bool,
    to: Option<u64>,
    server: String,
) -> anyhow::Result<()> {
    if machine.is_none() && !all {
        anyhow::bail!("Specify a machine name or --all");
    }

    let mut client = connect_server(&server).await?;
    let resp = client
        .rollback(RollbackRequest {
            machine: machine.unwrap_or_default(),
            all,
            to_generation: to.unwrap_or(0),
        })
        .await?;
    let result = resp.into_inner();

    if result.success {
        println!("{}", result.message);
    } else {
        anyhow::bail!("Rollback failed: {}", result.message);
    }
    Ok(())
}

pub async fn cmd_capacity(server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client.status(StatusRequest {}).await?;
    let status = resp.into_inner();

    println!("Cluster capacity:");
    let mut total_cpu = 0u64;
    let mut total_mem = 0u64;
    let mut total_disk = 0u64;
    for node in &status.nodes {
        if let Some(res) = &node.available_resources {
            total_cpu += res.cpu_millicores;
            total_mem += res.memory_mb;
            total_disk += res.disk_mb;
        }
    }
    println!("  Nodes: {}", status.nodes.len());
    println!("  Available CPU: {}m", total_cpu);
    println!("  Available memory: {}MB", total_mem);
    println!("  Available disk: {}MB", total_disk);

    if !status.pools.is_empty() {
        println!();
        println!("By pool:");
        for pool in &status.pools {
            let sched = pool.total_schedulable.as_ref();
            let alloc = pool.total_allocated.as_ref();
            let sched_cpu = sched.map(|r| r.cpu_millicores).unwrap_or(0);
            let sched_mem = sched.map(|r| r.memory_mb).unwrap_or(0);
            let alloc_cpu = alloc.map(|r| r.cpu_millicores).unwrap_or(0);
            let alloc_mem = alloc.map(|r| r.memory_mb).unwrap_or(0);
            println!(
                "  {} — {} machines — {}m/{}m CPU used, {}MB/{}MB mem used",
                pool.name, pool.machine_count, alloc_cpu, sched_cpu, alloc_mem, sched_mem
            );
        }
    }
    Ok(())
}

pub async fn cmd_services(server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client.status(StatusRequest {}).await?;
    let status = resp.into_inner();

    if status.services.is_empty() {
        println!("No services deployed.");
    } else {
        for svc in &status.services {
            println!("{}:", svc.name);
            for inst in &svc.instances {
                let state = ekafleet::proto::ServiceState::try_from(inst.state)
                    .unwrap_or(ekafleet::proto::ServiceState::Unknown);
                let health = ekafleet::proto::HealthStatus::try_from(inst.health)
                    .unwrap_or(ekafleet::proto::HealthStatus::HealthUnknown);
                println!(
                    "  {} on {} — {:?} / {:?}",
                    inst.instance_id, inst.node_id, state, health
                );
            }
        }
    }
    Ok(())
}

pub async fn cmd_drain(machine: String, server: String, deadline: u64) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .drain(DrainRequest {
            machine: machine.clone(),
            deadline_seconds: deadline,
        })
        .await?;
    let result = resp.into_inner();

    if result.success {
        if result.rescheduled_services.is_empty() {
            println!("No services running on {machine}.");
        } else {
            println!("Drained {machine} — rescheduled services:");
            for svc in &result.rescheduled_services {
                println!("  {svc}");
            }
        }
    } else {
        anyhow::bail!("Drain failed");
    }
    Ok(())
}

pub async fn cmd_scale(service: String, count: u32, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .scale(ScaleRequest {
            service_name: service.clone(),
            desired_count: count,
        })
        .await?;
    let result = resp.into_inner();

    if result.success {
        println!("Service: {service}");
        println!("  Previous instances: {}", result.previous_count);
        println!("  New instances: {}", result.new_count);
        if result.previous_count == result.new_count {
            println!("  Already at desired count.");
        }
    } else {
        anyhow::bail!("Scale failed");
    }
    Ok(())
}

pub async fn cmd_token_create(type_str: String) -> anyhow::Result<()> {
    tracing::info!(token_type = %type_str, "Creating token");
    let token = generate_token();
    println!("{token}");
    Ok(())
}

pub async fn cmd_logs(
    service: String,
    follow: bool,
    tail: u32,
    node: Option<String>,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let mut stream = client
        .logs(ekafleet::proto::LogsRequest {
            service_name: service.clone(),
            lines: tail,
            follow,
            node_id: node.unwrap_or_default(),
        })
        .await?
        .into_inner();

    while let Some(chunk) = stream.message().await? {
        let text = String::from_utf8_lossy(&chunk.data);
        if !chunk.node_id.is_empty() {
            for line in text.lines() {
                println!("[{}] {}", chunk.node_id, line);
            }
        } else {
            print!("{text}");
        }
    }
    Ok(())
}

pub async fn cmd_ssh(machine: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client.status(StatusRequest {}).await?;
    let status = resp.into_inner();

    let node = status.nodes.iter().find(|n| n.node_id == machine);
    match node {
        Some(n) => {
            let addr = &n.address;
            tracing::info!(machine = %machine, address = %addr, "Connecting via SSH");
            let ssh_target = if addr.contains(':') {
                addr.split(':').next().unwrap_or(addr).to_string()
            } else {
                addr.to_string()
            };

            let err = exec_ssh(&ssh_target);
            anyhow::bail!("ssh exec failed: {err}");
        }
        None => {
            anyhow::bail!("Machine '{machine}' not found in fleet");
        }
    }
}

pub async fn cmd_dispatch(
    service: String,
    params: Vec<String>,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;

    let param_map: std::collections::HashMap<String, String> = params
        .iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect();

    let resp = client
        .dispatch(ekafleet::proto::DispatchRequest {
            service_name: service.clone(),
            params: param_map,
        })
        .await?;
    let result = resp.into_inner();

    if result.success {
        println!("Dispatched {service} → instance {}", result.instance_id);
    } else {
        anyhow::bail!("Dispatch failed: {}", result.message);
    }
    Ok(())
}

pub fn cmd_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    let mut cmd = super::Cli::command();
    clap_complete::generate(shell, &mut cmd, "ekafleet", &mut std::io::stdout());
}

pub async fn cmd_snapshot(output: PathBuf, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client.snapshot(SnapshotRequest {}).await?;
    let snapshot = resp.into_inner();

    tokio::fs::write(&output, &snapshot.data).await?;
    println!(
        "Snapshot saved to {} ({} bytes, Raft index {})",
        output.display(),
        snapshot.data.len(),
        snapshot.last_index
    );
    Ok(())
}

pub async fn cmd_restore(input: PathBuf, server: String) -> anyhow::Result<()> {
    let data = tokio::fs::read(&input).await?;
    println!("Restoring from {} ({} bytes)", input.display(), data.len());

    let mut client = connect_server(&server).await?;
    let resp = client
        .restore(ekafleet::proto::RestoreRequest { data })
        .await?;
    let result = resp.into_inner();

    if result.success {
        println!("{}", result.message);
    } else {
        anyhow::bail!("Restore failed: {}", result.message);
    }
    Ok(())
}

pub async fn cmd_validate(config: PathBuf) -> anyhow::Result<()> {
    let fleet_config = ekafleet::server::nix::eval_fleet(&config).await?;
    match ekafleet::config::validate(&fleet_config) {
        Ok(()) => {
            println!(
                "Configuration valid: {} services, {} machines, {} pools",
                fleet_config.services.len(),
                fleet_config.machines.len(),
                fleet_config.node_pools.len()
            );
        }
        Err(errors) => {
            eprintln!("Configuration errors:");
            for err in &errors {
                eprintln!("  - {err}");
            }
            anyhow::bail!("{} validation error(s)", errors.len());
        }
    }
    Ok(())
}

pub async fn cmd_events(
    category: Option<String>,
    service: Option<String>,
    node: Option<String>,
    limit: u32,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .events(ekafleet::proto::EventsRequest {
            category: category.unwrap_or_default(),
            service: service.unwrap_or_default(),
            node: node.unwrap_or_default(),
            limit,
        })
        .await?;
    let result = resp.into_inner();

    if result.events.is_empty() {
        println!("No events found.");
    } else {
        for event in &result.events {
            let svc = if event.service.is_empty() {
                String::new()
            } else {
                format!(" service={}", event.service)
            };
            let node = if event.node.is_empty() {
                String::new()
            } else {
                format!(" node={}", event.node)
            };
            println!(
                "[{}] {} {}{}{} — {}",
                event.timestamp, event.level, event.category, svc, node, event.message
            );
        }
    }
    Ok(())
}

pub async fn cmd_node_list(server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .list_nodes(ekafleet::proto::ListNodesRequest {})
        .await?;
    let result = resp.into_inner();

    if result.nodes.is_empty() {
        println!("No nodes connected.");
    } else {
        println!(
            "{:<36}  {:<20}  {:<12}  {:<8}  {:<10}  {}",
            "NODE ID", "ADDRESS", "POOL", "HEALTH", "SCHED", "SERVICES"
        );
        for node in &result.nodes {
            let health = if node.healthy { "ok" } else { "unhealthy" };
            let sched = if node.schedulable { "yes" } else { "cordoned" };
            println!(
                "{:<36}  {:<20}  {:<12}  {:<8}  {:<10}  {}",
                node.node_id,
                node.address,
                node.pool,
                health,
                sched,
                node.running_services.len()
            );
        }
    }
    Ok(())
}

pub async fn cmd_node_status(node: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .get_node(ekafleet::proto::GetNodeRequest {
            node_id: node.clone(),
        })
        .await?;
    let detail = resp.into_inner();

    println!("Node: {}", detail.node_id);
    println!("  Address:     {}", detail.address);
    println!("  Pool:        {}", detail.pool);
    println!(
        "  Health:      {}",
        if detail.healthy {
            "healthy"
        } else {
            "unhealthy"
        }
    );
    println!(
        "  Schedulable: {}",
        if detail.schedulable {
            "yes"
        } else {
            "cordoned"
        }
    );
    println!("  Heartbeat:   {}s ago", detail.last_heartbeat);
    if let Some(total) = &detail.total_resources {
        println!(
            "  Total:       {}m CPU, {}MB mem, {}MB disk",
            total.cpu_millicores, total.memory_mb, total.disk_mb
        );
    }
    if let Some(avail) = &detail.available_resources {
        println!(
            "  Available:   {}m CPU, {}MB mem, {}MB disk",
            avail.cpu_millicores, avail.memory_mb, avail.disk_mb
        );
    }
    if !detail.running_services.is_empty() {
        println!("  Services ({}):", detail.running_services.len());
        for svc in &detail.running_services {
            println!("    {} ({})", svc.service_name, svc.instance_id);
        }
    }
    Ok(())
}

pub async fn cmd_node_cordon(node: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .update_node(ekafleet::proto::UpdateNodeRequest {
            node_id: node.clone(),
            schedulable: false,
        })
        .await?;
    let result = resp.into_inner();
    if result.success {
        println!("Node {node} cordoned (marked unschedulable)");
    } else {
        anyhow::bail!("Failed to cordon node {node}");
    }
    Ok(())
}

pub async fn cmd_node_uncordon(node: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .update_node(ekafleet::proto::UpdateNodeRequest {
            node_id: node.clone(),
            schedulable: true,
        })
        .await?;
    let result = resp.into_inner();
    if result.success {
        println!("Node {node} uncordoned (marked schedulable)");
    } else {
        anyhow::bail!("Failed to uncordon node {node}");
    }
    Ok(())
}

pub async fn cmd_top_nodes(server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .top(ekafleet::proto::TopRequest {
            mode: "nodes".to_string(),
        })
        .await?;
    let result = resp.into_inner();

    if result.nodes.is_empty() {
        println!("No nodes connected.");
    } else {
        println!(
            "{:<36}  {:<12}  {:>10}  {:>10}  {:>10}  {:>10}  {}",
            "NODE ID", "POOL", "CPU USED", "CPU TOTAL", "MEM USED", "MEM TOTAL", "SVCS"
        );
        for node in &result.nodes {
            let cpu_pct = if node.cpu_total > 0 {
                format!("{}%", node.cpu_used * 100 / node.cpu_total)
            } else {
                "-".to_string()
            };
            let mem_pct = if node.memory_total > 0 {
                format!("{}%", node.memory_used * 100 / node.memory_total)
            } else {
                "-".to_string()
            };
            println!(
                "{:<36}  {:<12}  {:>7}m({:>3})  {:>7}m  {:>6}MB({:>3})  {:>6}MB  {}",
                node.node_id,
                node.pool,
                node.cpu_used,
                cpu_pct,
                node.cpu_total,
                node.memory_used,
                mem_pct,
                node.memory_total,
                node.service_count
            );
        }
    }
    Ok(())
}

pub async fn cmd_top_services(server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .top(ekafleet::proto::TopRequest {
            mode: "services".to_string(),
        })
        .await?;
    let result = resp.into_inner();

    if result.services.is_empty() {
        println!("No services deployed.");
    } else {
        println!(
            "{:<30}  {:>10}  {:>12}  {:>12}",
            "SERVICE", "INSTANCES", "CPU REQUEST", "MEM REQUEST"
        );
        for svc in &result.services {
            println!(
                "{:<30}  {:>10}  {:>9}m  {:>9}MB",
                svc.service_name, svc.instance_count, svc.cpu_request, svc.memory_request
            );
        }
    }
    Ok(())
}

pub async fn cmd_deployment_list(
    service: Option<String>,
    limit: u32,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .list_deployments(ekafleet::proto::ListDeploymentsRequest {
            service: service.unwrap_or_default(),
            limit,
        })
        .await?;
    let result = resp.into_inner();

    if result.deployments.is_empty() {
        println!("No deployments found.");
    } else {
        println!(
            "{:<36}  {:<20}  {:<12}  {:<10}  {}",
            "DEPLOYMENT ID", "SERVICE", "STATUS", "STRATEGY", "STARTED"
        );
        for d in &result.deployments {
            println!(
                "{:<36}  {:<20}  {:<12}  {:<10}  {}",
                d.deployment_id, d.service_name, d.status, d.strategy, d.started_at
            );
        }
    }
    Ok(())
}

pub async fn cmd_deployment_status(service: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .list_deployments(ekafleet::proto::ListDeploymentsRequest {
            service: service.clone(),
            limit: 10,
        })
        .await?;
    let result = resp.into_inner();

    if result.deployments.is_empty() {
        println!("No deployments for service '{service}'.");
    } else {
        println!("Deployment history for {service}:");
        for d in &result.deployments {
            let completed = if d.completed_at > 0 {
                d.completed_at.to_string()
            } else {
                "in progress".to_string()
            };
            println!(
                "  {} — {} ({}) — {} instances — started {} completed {}",
                d.deployment_id, d.status, d.strategy, d.instance_count, d.started_at, completed
            );
        }
    }
    Ok(())
}

pub async fn cmd_deployment_promote(service: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .promote_deployment(ekafleet::proto::PromoteRequest {
            service_name: service.clone(),
        })
        .await?;
    let result = resp.into_inner();
    if result.success {
        println!("{}", result.message);
    } else {
        anyhow::bail!("Promote failed: {}", result.message);
    }
    Ok(())
}

pub async fn cmd_deployment_fail(service: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .fail_deployment(ekafleet::proto::FailDeploymentRequest {
            service_name: service.clone(),
        })
        .await?;
    let result = resp.into_inner();
    if result.success {
        println!("{}", result.message);
    } else {
        anyhow::bail!("Fail deployment failed: {}", result.message);
    }
    Ok(())
}

pub async fn cmd_acl_token_create(
    role: String,
    description: String,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .create_acl_token(ekafleet::proto::CreateAclTokenRequest {
            role: role.clone(),
            description,
        })
        .await?;
    let result = resp.into_inner();
    println!("Token: {}", result.token);
    println!("Role:  {}", result.role);
    Ok(())
}

pub async fn cmd_acl_token_revoke(token: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .revoke_acl_token(ekafleet::proto::RevokeAclTokenRequest {
            token: token.clone(),
        })
        .await?;
    let result = resp.into_inner();
    if result.success {
        println!("Token revoked.");
    } else {
        anyhow::bail!("Failed to revoke token");
    }
    Ok(())
}

pub async fn cmd_acl_token_list(server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .list_acl_tokens(ekafleet::proto::ListAclTokensRequest {})
        .await?;
    let result = resp.into_inner();

    if result.tokens.is_empty() {
        println!("No tokens registered.");
    } else {
        println!("{:<12}  {}", "ROLE", "DESCRIPTION");
        for token in &result.tokens {
            println!("{:<12}  {}", token.role, token.description);
        }
    }
    Ok(())
}

pub async fn cmd_exec(
    service: String,
    command: Vec<String>,
    node: Option<String>,
    timeout: u32,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .exec(ekafleet::proto::ExecRequest {
            service_name: service,
            command,
            timeout_seconds: timeout,
            node_id: node.unwrap_or_default(),
        })
        .await?;
    let result = resp.into_inner();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    if result.exit_code != 0 {
        std::process::exit(result.exit_code);
    }
    Ok(())
}

// --- Closure analysis (local, no server) ---

pub async fn cmd_closure_diff(path_a: String, path_b: String) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("nix")
        .args(["store", "diff-closures", &path_a, &path_b])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix store diff-closures failed: {stderr}");
    }

    let text = String::from_utf8_lossy(&output.stdout);
    if text.is_empty() {
        println!("No differences between closures.");
    } else {
        print!("{text}");
    }
    Ok(())
}

pub async fn cmd_closure_deps(path: String, tree: bool) -> anyhow::Result<()> {
    let args = if tree {
        vec!["--query", "--tree", &path]
    } else {
        vec!["--query", "--requisites", &path]
    };

    let output = tokio::process::Command::new("nix-store")
        .args(&args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix-store query failed: {stderr}");
    }

    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

pub async fn cmd_closure_size(path: String) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("nix")
        .args(["path-info", "--closure-size", "--human-readable", &path])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix path-info failed: {stderr}");
    }

    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

// --- Generation management ---

pub async fn cmd_generation_list(machine: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .list_generations(ekafleet::proto::ListGenerationsRequest {
            machine: machine.clone(),
        })
        .await?;
    let result = resp.into_inner();

    if result.generations.is_empty() {
        println!("No generations found on {machine}.");
    } else {
        println!("{:>5}  {:>10}  {:<60}  {}", "GEN", "DATE", "STORE PATH", "");
        for entry in &result.generations {
            let current = if entry.current { " (current)" } else { "" };
            println!(
                "{:>5}  {:>10}  {:<60}  {}",
                entry.number, entry.created_at, entry.store_path, current
            );
        }
    }
    Ok(())
}

pub async fn cmd_generation_switch(
    machine: String,
    generation: u64,
    action: &str,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .switch_generation(ekafleet::proto::SwitchGenerationRequest {
            machine: machine.clone(),
            generation,
            action: action.to_string(),
        })
        .await?;
    let result = resp.into_inner();

    if result.success {
        println!("{}", result.message);
    } else {
        anyhow::bail!("{}", result.message);
    }
    Ok(())
}

pub async fn cmd_generation_diff(
    machine: String,
    gen_a: u64,
    gen_b: u64,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .diff_generations(ekafleet::proto::DiffGenerationsRequest {
            machine: machine.clone(),
            gen_a,
            gen_b,
        })
        .await?;
    let result = resp.into_inner();

    if result.diff.is_empty() {
        println!("No differences between generations {gen_a} and {gen_b} on {machine}.");
    } else {
        print!("{}", result.diff);
    }
    Ok(())
}

// --- System-wide operations ---

pub async fn cmd_system_gc(dry_run: bool, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .system_gc(ekafleet::proto::SystemGcRequest { dry_run })
        .await?;
    let result = resp.into_inner();

    if result.results.is_empty() {
        println!("No nodes to garbage-collect.");
    } else {
        let action = if dry_run { "would free" } else { "freed" };
        for r in &result.results {
            let mb = r.freed_bytes / (1024 * 1024);
            println!("{}: {action} {mb}MB", r.node_id);
            if !r.output.is_empty() {
                for line in r.output.lines() {
                    println!("  {line}");
                }
            }
        }
    }
    Ok(())
}

pub async fn cmd_system_reboot(
    pool: Option<String>,
    max_parallel: u32,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .system_reboot(ekafleet::proto::SystemRebootRequest {
            pool: pool.unwrap_or_default(),
            max_parallel,
        })
        .await?;
    let result = resp.into_inner();

    if result.success {
        println!("{}", result.message);
    } else {
        anyhow::bail!("{}", result.message);
    }
    Ok(())
}

pub async fn cmd_system_rebuild(
    machine: Option<String>,
    all: bool,
    server: String,
) -> anyhow::Result<()> {
    if machine.is_none() && !all {
        anyhow::bail!("Specify a machine name or --all");
    }

    let mut client = connect_server(&server).await?;
    let resp = client
        .system_rebuild(ekafleet::proto::SystemRebuildRequest {
            machine: machine.unwrap_or_default(),
            all,
        })
        .await?;
    let result = resp.into_inner();

    if result.success {
        println!("{}", result.message);
    } else {
        anyhow::bail!("{}", result.message);
    }
    Ok(())
}

// --- Service introspection ---

pub async fn cmd_service_inspect(
    service: String,
    node: Option<String>,
    server: String,
) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client
        .inspect_service(ekafleet::proto::InspectServiceRequest {
            service_name: service.clone(),
            node_id: node.unwrap_or_default(),
        })
        .await?;
    let info = resp.into_inner();

    println!("Service: {service}");
    println!(
        "  State:         {} ({})",
        info.active_state, info.sub_state
    );
    println!("  Main PID:      {}", info.main_pid);
    println!("  Control Group: {}", info.control_group);
    println!();
    println!("Resource Accounting:");
    println!("  CPU Usage:     {:.2}s", info.cpu_usage_nsec as f64 / 1e9);
    println!(
        "  Memory:        {}MB (peak {}MB)",
        info.memory_current / (1024 * 1024),
        info.memory_peak / (1024 * 1024)
    );
    println!("  IO Read:       {}MB", info.io_read_bytes / (1024 * 1024));
    println!("  IO Write:      {}MB", info.io_write_bytes / (1024 * 1024));
    println!("  Tasks:         {}", info.tasks_current);
    if !info.unit_file.is_empty() {
        println!();
        println!("Unit File:");
        for line in info.unit_file.lines() {
            println!("  {line}");
        }
    }
    Ok(())
}

pub async fn cmd_upgrade(store_path: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;

    // Step 1: Take a safety snapshot before upgrading
    println!("Taking pre-upgrade snapshot...");
    let snap_resp = client.snapshot(SnapshotRequest {}).await?;
    let snapshot = snap_resp.into_inner();
    let snapshot_file = format!(
        "ekafleet-pre-upgrade-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );
    tokio::fs::write(&snapshot_file, &snapshot.data).await?;
    println!(
        "Snapshot saved to {} ({} bytes, Raft index {})",
        snapshot_file,
        snapshot.data.len(),
        snapshot.last_index
    );

    // Step 2: Query current fleet status for upgrade plan
    let status_resp = client.status(StatusRequest {}).await?;
    let status = status_resp.into_inner();

    println!();
    println!("Upgrade plan:");
    println!("  New binary: {store_path}");
    println!("  Nodes to upgrade ({}):", status.nodes.len());
    for node in &status.nodes {
        let health = if node.healthy { "healthy" } else { "unhealthy" };
        println!("    {} ({}) - {}", node.node_id, node.address, health);
    }

    println!();
    println!("To complete the upgrade:");
    println!("  1. Deploy the new store path to each node:");
    for node in &status.nodes {
        println!(
            "     nix-copy-closure --to {} {store_path}",
            node.address.split(':').next().unwrap_or(&node.address)
        );
    }
    println!("  2. Restart ekafleet on each node (rolling, one at a time):");
    println!("     - Drain the node: ekafleet drain <node>");
    println!("     - Switch the binary: nix-env -i {store_path}");
    println!("     - Restart the service: systemctl restart ekafleet");
    println!("     - Verify health: ekafleet status");
    println!("  3. If anything goes wrong, restore from the snapshot:");
    println!("     ekafleet restore {snapshot_file}");

    Ok(())
}

// ---------------------------------------------------------------------------
// ekafleet images
// ---------------------------------------------------------------------------

pub async fn cmd_images_list(pool: Option<String>, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;

    // Use the snapshot RPC to get Raft state, then query KV for images
    let resp = client
        .snapshot(SnapshotRequest {})
        .await?
        .into_inner();

    let raft = ekafleet::raft::state::FleetStateMachine::new();
    raft.restore(&resp.data).await.map_err(|e| anyhow::anyhow!("{e}"))?;

    let image_tracker = ekafleet::server::cloud::image_tracker::ImageTracker::new(raft);
    let images = image_tracker.list_all().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let filtered: Vec<_> = if let Some(ref p) = pool {
        images.into_iter().filter(|i| &i.pool == p).collect()
    } else {
        images
    };

    if filtered.is_empty() {
        println!("No managed cloud images found.");
        return Ok(());
    }

    println!(
        "{:<30} {:<15} {:<12} {:<15} {:<10} {:<10}",
        "IMAGE_ID", "POOL", "PROVIDER", "STORE_HASH", "AGE", "LAST_USED"
    );
    for img in &filtered {
        let age = format_duration(now.saturating_sub(img.created_at));
        let last_used = format_duration(now.saturating_sub(img.last_used_at));
        println!(
            "{:<30} {:<15} {:<12} {:<15} {:<10} {:<10}",
            img.image_id,
            img.pool,
            img.provider,
            &img.store_path_hash[..12.min(img.store_path_hash.len())],
            age,
            last_used,
        );
    }

    Ok(())
}

pub async fn cmd_images_build(
    pool: String,
    config: std::path::PathBuf,
    server: String,
) -> anyhow::Result<()> {
    // Evaluate fleet config to get pool's cloud image settings
    let fleet_config = ekafleet::server::nix::eval_fleet(&config).await
        .map_err(|e| anyhow::anyhow!("failed to evaluate fleet config: {e}"))?;

    let pool_config = fleet_config
        .node_pools
        .get(&pool)
        .ok_or_else(|| anyhow::anyhow!("pool '{}' not found in fleet config", pool))?;

    let cloud_config = pool_config
        .cloud
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("pool '{}' has no cloud provider config", pool))?;

    let image_config = cloud_config
        .image
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("pool '{}' has no managed image config (uses static imageId)", pool))?;

    // Connect to server to access Raft state for tracking
    let mut client = connect_server(&server).await?;

    let resp = client
        .snapshot(SnapshotRequest {})
        .await?
        .into_inner();

    let raft = ekafleet::raft::state::FleetStateMachine::new();
    raft.restore(&resp.data).await.map_err(|e| anyhow::anyhow!("{e}"))?;

    let image_tracker = ekafleet::server::cloud::image_tracker::ImageTracker::new(raft);
    let manager = ekafleet::server::cloud::image::build_image_manager(cloud_config, image_config);

    println!("Building and registering image for pool '{pool}'...");

    let image_id = ekafleet::server::cloud::image::ensure_image(
        &pool,
        cloud_config,
        image_config,
        &fleet_config.name,
        &image_tracker,
        manager.as_ref(),
    )
    .await?;

    println!("Image ready: {image_id}");

    Ok(())
}

pub async fn cmd_images_gc(
    dry_run: bool,
    config: std::path::PathBuf,
    server: String,
) -> anyhow::Result<()> {
    let fleet_config = ekafleet::server::nix::eval_fleet(&config).await
        .map_err(|e| anyhow::anyhow!("failed to evaluate fleet config: {e}"))?;

    let mut client = connect_server(&server).await?;

    let resp = client
        .snapshot(SnapshotRequest {})
        .await?
        .into_inner();

    let raft = ekafleet::raft::state::FleetStateMachine::new();
    raft.restore(&resp.data).await.map_err(|e| anyhow::anyhow!("{e}"))?;

    let image_tracker = ekafleet::server::cloud::image_tracker::ImageTracker::new(raft);

    // Build active hashes and image managers
    let mut image_managers: std::collections::HashMap<
        String,
        Box<dyn ekafleet::server::cloud::image::CloudImageManagerDyn>,
    > = std::collections::HashMap::new();
    let mut active_hashes: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for (pool_name, pool_config) in &fleet_config.node_pools {
        let Some(cloud) = &pool_config.cloud else {
            continue;
        };
        let Some(image_config) = &cloud.image else {
            continue;
        };

        // Determine current active hash
        let toplevel_attr = format!(
            "{}.config.system.build.toplevel",
            image_config.nixos_config
        );
        if let Ok(store_path) = ekafleet::server::nix::build(&toplevel_attr).await {
            if let Some(hash) = ekafleet::server::cloud::image::extract_store_path_hash(&store_path) {
                active_hashes.insert(pool_name.clone(), hash.to_string());
            }
        }

        let manager_key = match cloud.provider {
            ekafleet::config::CloudProviderType::Aws => "aws",
            ekafleet::config::CloudProviderType::Azure => "azure",
            ekafleet::config::CloudProviderType::Gcp => "gcp",
        };
        let manager = ekafleet::server::cloud::image::build_image_manager(cloud, image_config);
        image_managers
            .entry(manager_key.to_string())
            .or_insert(manager);
    }

    if dry_run {
        println!("Dry run — would clean up the following expired images:");
        let all_images = image_tracker.list_all().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for img in &all_images {
            let is_active = active_hashes
                .get(&img.pool)
                .map_or(false, |h| h == &img.store_path_hash);
            if !is_active {
                let age = now.saturating_sub(img.created_at);
                println!(
                    "  {} (pool={}, age={}d, hash={})",
                    img.image_id,
                    img.pool,
                    age / 86400,
                    &img.store_path_hash[..12.min(img.store_path_hash.len())],
                );
            }
        }
    } else {
        ekafleet::server::cloud::image::cleanup_expired_images(
            &fleet_config,
            &image_tracker,
            &image_managers,
            &active_hashes,
        )
        .await;
        println!("Image garbage collection complete.");
    }

    Ok(())
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}
