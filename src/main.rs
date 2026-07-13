mod commands;

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

    /// Standalone SPIFFE Workload API daemon (process-isolated, unprivileged)
    WorkloadApi {
        /// Data directory containing spiffe/ subdirectory with SVIDs
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,

        /// SPIFFE trust domain for workload identities
        #[arg(long, default_value = "fleet.internal")]
        trust_domain: String,

        /// Unix socket path for the Workload API
        #[arg(long, default_value = "/run/ekafleet/workload-api.sock")]
        socket: PathBuf,
    },

    /// Standalone CA signing daemon (process-isolated, no network)
    CaSigner {
        /// Data directory for CA key and certificate
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,

        /// SPIFFE trust domain for fleet identities
        #[arg(long, default_value = "fleet.internal")]
        domain: String,

        /// Unix socket path for signing requests
        #[arg(long, default_value = "/run/ekafleet/ca.sock")]
        socket: PathBuf,
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

        /// Path to CA signer Unix socket (uses external ca-signer daemon instead of embedding CA)
        #[arg(long)]
        ca_socket: Option<PathBuf>,
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

    /// Service introspection (systemd unit, cgroup accounting)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Reschedule services off a machine
    Drain {
        /// Machine to drain
        machine: String,

        /// Deadline in seconds (0 = no deadline)
        #[arg(long, default_value = "0")]
        deadline: u64,

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

    /// Stream logs from service replicas
    Logs {
        /// Service name
        service: String,

        /// Stream logs continuously
        #[arg(long, short)]
        follow: bool,

        /// Number of lines to show
        #[arg(long, default_value = "100")]
        tail: u32,

        /// Target a specific node
        #[arg(long)]
        node: Option<String>,

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

    /// Dispatch a parameterized batch job
    Dispatch {
        /// Service name (must be a parameterized batch job)
        service: String,

        /// Parameters as KEY=VALUE pairs
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Validate fleet configuration without connecting to a server
    Validate {
        /// Path to fleet.nix configuration
        #[arg(long, default_value = "fleet.nix")]
        config: PathBuf,
    },

    /// Query fleet events
    Events {
        /// Filter by category (deployment, scaling, health, drain, etc.)
        #[arg(long)]
        category: Option<String>,

        /// Filter by service name
        #[arg(long)]
        service: Option<String>,

        /// Filter by node ID
        #[arg(long)]
        node: Option<String>,

        /// Maximum number of events to show
        #[arg(long, default_value = "50")]
        limit: u32,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Node management
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },

    /// Real-time resource usage
    Top {
        #[command(subcommand)]
        mode: TopMode,
    },

    /// Deployment management
    Deployment {
        #[command(subcommand)]
        action: DeploymentAction,
    },

    /// ACL token management
    Acl {
        #[command(subcommand)]
        action: AclAction,
    },

    /// Execute a command in a service's context
    Exec {
        /// Service name
        service: String,

        /// Command to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,

        /// Target a specific node
        #[arg(long)]
        node: Option<String>,

        /// Execution timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u32,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Nix store closure analysis
    Closure {
        #[command(subcommand)]
        action: ClosureAction,
    },

    /// NixOS generation management
    Generation {
        #[command(subcommand)]
        action: GenerationAction,
    },

    /// System-wide operations
    System {
        #[command(subcommand)]
        action: SystemAction,
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

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Orchestrate a rolling upgrade of the ekafleet binary across the fleet
    Upgrade {
        /// Nix store path of the new ekafleet binary
        store_path: String,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
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

#[derive(Subcommand)]
enum NodeAction {
    /// List all nodes
    List {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Show detailed node information
    Status {
        /// Node ID
        node: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Mark a node as unschedulable
    Cordon {
        /// Node ID
        node: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Mark a node as schedulable
    Uncordon {
        /// Node ID
        node: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum TopMode {
    /// Resource usage per node
    Nodes {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Resource usage per service
    Services {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum DeploymentAction {
    /// List recent deployments
    List {
        /// Filter by service name
        #[arg(long)]
        service: Option<String>,
        /// Maximum number of deployments
        #[arg(long, default_value = "20")]
        limit: u32,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Show deployment history for a service
    Status {
        /// Service name
        service: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Promote a canary deployment
    Promote {
        /// Service name
        service: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Fail a stuck deployment (triggers rollback)
    Fail {
        /// Service name
        service: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum AclAction {
    /// Token management
    Token {
        #[command(subcommand)]
        action: AclTokenAction,
    },
}

#[derive(Subcommand)]
enum AclTokenAction {
    /// Create a new ACL token
    Create {
        /// Role: admin, operator, or viewer
        #[arg(long)]
        role: String,
        /// Description for this token
        #[arg(long, default_value = "")]
        description: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Revoke an ACL token
    Revoke {
        /// Token to revoke
        token: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// List all ACL tokens
    List {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Show systemd unit file, cgroup accounting, and resource usage
    Inspect {
        /// Service name
        service: String,
        /// Target a specific node
        #[arg(long)]
        node: Option<String>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum ClosureAction {
    /// Diff two Nix store paths (show changed packages)
    Diff {
        /// First store path
        path_a: String,
        /// Second store path
        path_b: String,
    },
    /// Show full dependency tree of a store path
    Deps {
        /// Nix store path
        path: String,
        /// Show as tree instead of flat list
        #[arg(long)]
        tree: bool,
    },
    /// Calculate closure size
    Size {
        /// Nix store path
        path: String,
    },
}

#[derive(Subcommand)]
enum GenerationAction {
    /// List NixOS generations on a machine
    List {
        /// Machine to query
        machine: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Activate a generation and set as boot default
    Switch {
        /// Machine to target
        machine: String,
        /// Generation number
        generation: u64,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Set a generation as boot default only (next reboot)
    Boot {
        /// Machine to target
        machine: String,
        /// Generation number
        generation: u64,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Activate a generation in current session only (reverts on reboot)
    Test {
        /// Machine to target
        machine: String,
        /// Generation number
        generation: u64,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Diff two generations on a machine
    Diff {
        /// Machine to query
        machine: String,
        /// First generation number
        gen_a: u64,
        /// Second generation number
        gen_b: u64,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum SystemAction {
    /// Garbage-collect unused Nix store paths across the fleet
    Gc {
        /// Show what would be collected without actually collecting
        #[arg(long)]
        dry_run: bool,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Coordinated rolling reboot of fleet machines
    Reboot {
        /// Limit to a specific pool
        #[arg(long)]
        pool: Option<String>,
        /// Maximum concurrent reboots
        #[arg(long, default_value = "1")]
        max_parallel: u32,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Trigger NixOS rebuild on a machine
    Rebuild {
        /// Machine to rebuild
        machine: Option<String>,
        /// Rebuild all machines
        #[arg(long)]
        all: bool,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
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
        Command::WorkloadApi {
            data_dir,
            trust_domain,
            socket,
        } => commands::cmd_workload_api(data_dir, trust_domain, socket).await?,

        Command::CaSigner {
            data_dir,
            domain,
            socket,
        } => commands::cmd_ca_signer(data_dir, domain, socket).await?,

        Command::Dev {
            data_dir,
            http_listen,
            listen,
        } => commands::cmd_dev(data_dir, http_listen, listen).await?,

        Command::Server {
            data_dir,
            peers,
            listen,
            http_listen,
            token,
            domain,
            ca_socket,
        } => {
            commands::cmd_server(data_dir, peers, listen, http_listen, token, domain, ca_socket)
                .await?
        }

        Command::Agent {
            join,
            token,
            join_token,
            data_dir,
            ca_cert,
        } => commands::cmd_agent(join, token, join_token, data_dir, ca_cert).await?,

        Command::Plan { config, server } => commands::cmd_plan(config, server).await?,

        Command::Apply {
            config,
            auto_approve,
            watch,
            server,
        } => commands::cmd_apply(config, auto_approve, watch, server).await?,

        Command::Status { server } => commands::cmd_status(server, &cli.output).await?,

        Command::Drift { server } => commands::cmd_drift(server).await?,

        Command::Rollback {
            machine,
            all,
            to,
            server,
        } => commands::cmd_rollback(machine, all, to, server).await?,

        Command::Capacity { server } => commands::cmd_capacity(server).await?,

        Command::Services { server } => commands::cmd_services(server).await?,

        Command::Service { action } => match action {
            ServiceAction::Inspect {
                service,
                node,
                server,
            } => commands::cmd_service_inspect(service, node, server).await?,
        },

        Command::Drain {
            machine,
            deadline,
            server,
        } => commands::cmd_drain(machine, server, deadline).await?,

        Command::Scale {
            service,
            count,
            server,
        } => commands::cmd_scale(service, count, server).await?,

        Command::Token {
            action: TokenAction::Create { r#type },
        } => commands::cmd_token_create(r#type).await?,

        Command::Logs {
            service,
            follow,
            tail,
            node,
            server,
        } => commands::cmd_logs(service, follow, tail, node, server).await?,

        Command::Ssh { machine, server } => commands::cmd_ssh(machine, server).await?,

        Command::Dispatch {
            service,
            params,
            server,
        } => commands::cmd_dispatch(service, params, server).await?,

        Command::Completions { shell } => commands::cmd_completions(shell),

        Command::Snapshot { output, server } => commands::cmd_snapshot(output, server).await?,

        Command::Restore { input, server } => commands::cmd_restore(input, server).await?,

        Command::Upgrade { store_path, server } => {
            commands::cmd_upgrade(store_path, server).await?
        }

        Command::Validate { config } => commands::cmd_validate(config).await?,

        Command::Events {
            category,
            service,
            node,
            limit,
            server,
        } => commands::cmd_events(category, service, node, limit, server).await?,

        Command::Node { action } => match action {
            NodeAction::List { server } => commands::cmd_node_list(server).await?,
            NodeAction::Status { node, server } => commands::cmd_node_status(node, server).await?,
            NodeAction::Cordon { node, server } => commands::cmd_node_cordon(node, server).await?,
            NodeAction::Uncordon { node, server } => {
                commands::cmd_node_uncordon(node, server).await?
            }
        },

        Command::Top { mode } => match mode {
            TopMode::Nodes { server } => commands::cmd_top_nodes(server).await?,
            TopMode::Services { server } => commands::cmd_top_services(server).await?,
        },

        Command::Deployment { action } => match action {
            DeploymentAction::List {
                service,
                limit,
                server,
            } => commands::cmd_deployment_list(service, limit, server).await?,
            DeploymentAction::Status { service, server } => {
                commands::cmd_deployment_status(service, server).await?
            }
            DeploymentAction::Promote { service, server } => {
                commands::cmd_deployment_promote(service, server).await?
            }
            DeploymentAction::Fail { service, server } => {
                commands::cmd_deployment_fail(service, server).await?
            }
        },

        Command::Acl { action } => match action {
            AclAction::Token { action } => match action {
                AclTokenAction::Create {
                    role,
                    description,
                    server,
                } => commands::cmd_acl_token_create(role, description, server).await?,
                AclTokenAction::Revoke { token, server } => {
                    commands::cmd_acl_token_revoke(token, server).await?
                }
                AclTokenAction::List { server } => commands::cmd_acl_token_list(server).await?,
            },
        },

        Command::Exec {
            service,
            command,
            node,
            timeout,
            server,
        } => commands::cmd_exec(service, command, node, timeout, server).await?,

        Command::Closure { action } => match action {
            ClosureAction::Diff { path_a, path_b } => {
                commands::cmd_closure_diff(path_a, path_b).await?
            }
            ClosureAction::Deps { path, tree } => commands::cmd_closure_deps(path, tree).await?,
            ClosureAction::Size { path } => commands::cmd_closure_size(path).await?,
        },

        Command::Generation { action } => match action {
            GenerationAction::List { machine, server } => {
                commands::cmd_generation_list(machine, server).await?
            }
            GenerationAction::Switch {
                machine,
                generation,
                server,
            } => commands::cmd_generation_switch(machine, generation, "switch", server).await?,
            GenerationAction::Boot {
                machine,
                generation,
                server,
            } => commands::cmd_generation_switch(machine, generation, "boot", server).await?,
            GenerationAction::Test {
                machine,
                generation,
                server,
            } => commands::cmd_generation_switch(machine, generation, "test", server).await?,
            GenerationAction::Diff {
                machine,
                gen_a,
                gen_b,
                server,
            } => commands::cmd_generation_diff(machine, gen_a, gen_b, server).await?,
        },

        Command::System { action } => match action {
            SystemAction::Gc { dry_run, server } => {
                commands::cmd_system_gc(dry_run, server).await?
            }
            SystemAction::Reboot {
                pool,
                max_parallel,
                server,
            } => commands::cmd_system_reboot(pool, max_parallel, server).await?,
            SystemAction::Rebuild {
                machine,
                all,
                server,
            } => commands::cmd_system_rebuild(machine, all, server).await?,
        },
    }

    Ok(())
}
