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
    };

    server::run(config).await?;
    Ok(())
}

pub async fn cmd_server(
    data_dir: PathBuf,
    peers: Option<String>,
    listen: String,
    http_listen: String,
    token: String,
    domain: String,
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

pub async fn cmd_apply(config: PathBuf, auto_approve: bool, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let mut stream = client
        .apply(ekafleet::proto::ApplyRequest {
            config_path: config.display().to_string(),
            auto_approve,
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

pub async fn cmd_logs(service: String, server: String) -> anyhow::Result<()> {
    let mut client = connect_server(&server).await?;
    let resp = client.status(StatusRequest {}).await?;
    let status = resp.into_inner();

    let svc = status.services.iter().find(|s| s.name == service);
    match svc {
        Some(s) => {
            println!("Service {} has {} instances:", service, s.instances.len());
            for inst in &s.instances {
                println!(
                    "  {} on {} — use `journalctl -u ekafleet-{}` on that node",
                    inst.instance_id, inst.node_id, service
                );
            }
        }
        None => println!("Service '{service}' not found in fleet."),
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
