use ekafleet::agent;
use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::{PlanRequest, StatusRequest};
use ekafleet::server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ekafleet", about = "Unified fleet management for ekaos")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format: "text" (default) or "json" for machine-readable output
    #[arg(long, short, default_value = "text", global = true)]
    output: OutputFormat,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Single-process development mode (server + agent, no TLS, no WireGuard)
    Dev {
        /// Data directory for persistent state
        #[arg(long, default_value = "/tmp/ekafleet-dev")]
        data_dir: PathBuf,

        /// HTTP API listen address
        #[arg(long, default_value = "127.0.0.1:7402")]
        http_listen: String,

        /// gRPC listen address
        #[arg(long, default_value = "127.0.0.1:7400")]
        listen: String,
    },

    /// Start in server mode (control plane + agent capabilities)
    Server {
        /// Data directory for persistent state
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,

        /// Comma-separated list of peer server addresses for HA
        #[arg(long)]
        peers: Option<String>,

        /// gRPC listen address
        #[arg(long, default_value = "0.0.0.0:7400")]
        listen: String,

        /// HTTP API listen address
        #[arg(long, default_value = "0.0.0.0:7402")]
        http_listen: String,

        /// Bearer token required for agent authentication
        #[arg(long, env = "EKAFLEET_TOKEN")]
        token: String,

        /// SPIFFE trust domain for fleet identities
        #[arg(long, default_value = "fleet.internal")]
        domain: String,
    },

    /// Start in agent mode (data plane)
    Agent {
        /// Server address to join
        #[arg(long)]
        join: String,

        /// Authentication token (legacy — use --join-token for SPIFFE attestation)
        #[arg(long, default_value = "")]
        token: String,

        /// One-time join token for SPIFFE node attestation (replaces --token)
        #[arg(long)]
        join_token: Option<String>,

        /// Data directory for local state
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,

        /// Path to CA certificate PEM for TLS verification
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },

    /// Show desired-vs-actual diff
    Plan {
        /// Path to fleet.nix configuration
        #[arg(long, default_value = "fleet.nix")]
        config: PathBuf,

        /// Server address to query
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Execute deployment plan
    Apply {
        /// Path to fleet.nix configuration
        #[arg(long, default_value = "fleet.nix")]
        config: PathBuf,

        /// Skip confirmation prompt
        #[arg(long)]
        auto_approve: bool,

        /// Continuous reconciliation mode
        #[arg(long)]
        watch: bool,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Fleet health overview
    Status {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Detect state divergence
    Drift {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Revert to previous generation
    Rollback {
        /// Machine to rollback (omit for all)
        machine: Option<String>,

        /// Rollback all machines
        #[arg(long)]
        all: bool,

        /// Target generation number
        #[arg(long)]
        to: Option<u64>,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Resource utilization report
    Capacity {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Service placement listing
    Services {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Reschedule services off a machine
    Drain {
        /// Machine to drain
        machine: String,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Manual replica scaling
    Scale {
        /// Service name
        service: String,

        /// Desired replica count
        count: u32,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Generate join token
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    /// Aggregate logs from service replicas
    Logs {
        /// Service name
        service: String,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// SSH into a fleet machine
    Ssh {
        /// Machine to connect to
        machine: String,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Take a Raft state snapshot for disaster recovery
    Snapshot {
        /// Path to save the snapshot
        #[arg(long, default_value = "ekafleet-snapshot.bin")]
        output: std::path::PathBuf,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Restore Raft state from a snapshot
    Restore {
        /// Path to the snapshot file
        input: std::path::PathBuf,

        /// Data directory
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Create a new join token
    Create {
        /// Token type (agent or server)
        #[arg(long, default_value = "agent")]
        r#type: String,
    },
}

async fn connect_server(
    server: &str,
) -> anyhow::Result<FleetControlClient<tonic::transport::Channel>> {
    let endpoint = format!("http://{server}");
    let client = FleetControlClient::connect(endpoint).await?;
    Ok(client)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Dev {
            data_dir,
            http_listen,
            listen,
        } => {
            tracing::info!(
                data_dir = %data_dir.display(),
                grpc = %listen,
                http = %http_listen,
                "Starting ekafleet in dev mode (no TLS, no WireGuard)"
            );

            // Generate a dev token
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
        }

        Command::Server {
            data_dir,
            peers,
            listen,
            http_listen,
            token,
            domain,
        } => {
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
        }

        Command::Agent {
            join,
            token,
            join_token,
            data_dir,
            ca_cert,
        } => {
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
        }

        Command::Plan { config, server } => {
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
        }

        Command::Apply {
            config,
            auto_approve,
            watch: _,
            server,
        } => {
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
        }

        Command::Status { server } => {
            let mut client = connect_server(&server).await?;
            let resp = client.status(StatusRequest {}).await?;
            let status = resp.into_inner();

            if matches!(cli.output, OutputFormat::Json) {
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
        }

        Command::Drift { server } => {
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
        }

        Command::Rollback {
            machine,
            all,
            to,
            server: _,
        } => {
            match (machine.as_deref(), all, to) {
                (Some(m), _, Some(generation)) => {
                    println!("Rolling back {m} to generation {generation}")
                }
                (Some(m), _, None) => println!("Rolling back {m} to previous generation"),
                (None, true, Some(generation)) => {
                    println!("Rolling back all machines to generation {generation}")
                }
                (None, true, None) => println!("Rolling back all machines to previous generation"),
                _ => println!("Specify a machine name or --all"),
            }
            eprintln!("rollback requires server-side generation tracking (not yet wired)");
        }

        Command::Capacity { server } => {
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
        }

        Command::Services { server } => {
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
        }

        Command::Drain { machine, server } => {
            let mut client = connect_server(&server).await?;
            let resp = client.status(StatusRequest {}).await?;
            let status = resp.into_inner();

            let services_on_node: Vec<_> = status
                .services
                .iter()
                .filter(|s| s.instances.iter().any(|i| i.node_id == machine))
                .collect();

            if services_on_node.is_empty() {
                println!("No services running on {machine}.");
            } else {
                println!("Services to reschedule from {machine}:");
                for svc in &services_on_node {
                    println!("  {}", svc.name);
                }
                println!(
                    "\n{} services would be rescheduled.",
                    services_on_node.len()
                );
                eprintln!("drain execution requires reconciler integration (not yet wired)");
            }
        }

        Command::Scale {
            service,
            count,
            server,
        } => {
            let mut client = connect_server(&server).await?;
            let resp = client.status(StatusRequest {}).await?;
            let status = resp.into_inner();

            let current = status
                .services
                .iter()
                .find(|s| s.name == service)
                .map(|s| s.instances.len())
                .unwrap_or(0);

            println!("Service: {service}");
            println!("  Current instances: {current}");
            println!("  Desired instances: {count}");
            if current == count as usize {
                println!("  Already at desired count.");
            } else {
                eprintln!("scale execution requires reconciler integration (not yet wired)");
            }
        }

        Command::Token {
            action: TokenAction::Create { r#type },
        } => {
            tracing::info!(token_type = %r#type, "Creating token");
            let token = generate_token();
            println!("{token}");
        }

        Command::Logs { service, server } => {
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
        }

        Command::Ssh { machine, server } => {
            let mut client = connect_server(&server).await?;
            let resp = client.status(StatusRequest {}).await?;
            let status = resp.into_inner();

            let node = status.nodes.iter().find(|n| n.node_id == machine);
            match node {
                Some(n) => {
                    let addr = &n.address;
                    tracing::info!(machine = %machine, address = %addr, "Connecting via SSH");
                    let ssh_target = if addr.contains(':') {
                        // Strip port if present
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

        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "ekafleet", &mut std::io::stdout());
        }

        Command::Snapshot { output, server: _ } => {
            // TODO: call server's Raft snapshot RPC
            println!("Saving Raft snapshot to {}", output.display());
            eprintln!(
                "snapshot save requires server-side snapshot export (Raft snapshot method exists)"
            );
        }

        Command::Restore { input, data_dir } => {
            println!(
                "Restoring from {} to {}",
                input.display(),
                data_dir.display()
            );
            eprintln!("snapshot restore requires server-side import (Raft restore method exists)");
        }
    }

    Ok(())
}

/// Execute ssh, replacing the current process.
fn exec_ssh(target: &str) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new("ssh").arg(target).exec()
}

/// Generate a cryptographically random token (64 hex chars = 256 bits).
fn generate_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("system RNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
