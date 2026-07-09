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
        } => commands::cmd_dev(data_dir, http_listen, listen).await?,

        Command::Server {
            data_dir,
            peers,
            listen,
            http_listen,
            token,
            domain,
        } => commands::cmd_server(data_dir, peers, listen, http_listen, token, domain).await?,

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
            watch: _,
            server,
        } => commands::cmd_apply(config, auto_approve, server).await?,

        Command::Status { server } => commands::cmd_status(server, &cli.output).await?,

        Command::Drift { server } => commands::cmd_drift(server).await?,

        Command::Rollback {
            machine,
            all,
            to,
            server: _,
        } => commands::cmd_rollback(machine, all, to).await?,

        Command::Capacity { server } => commands::cmd_capacity(server).await?,

        Command::Services { server } => commands::cmd_services(server).await?,

        Command::Drain { machine, server } => commands::cmd_drain(machine, server).await?,

        Command::Scale {
            service,
            count,
            server,
        } => commands::cmd_scale(service, count, server).await?,

        Command::Token {
            action: TokenAction::Create { r#type },
        } => commands::cmd_token_create(r#type).await?,

        Command::Logs { service, server } => commands::cmd_logs(service, server).await?,

        Command::Ssh { machine, server } => commands::cmd_ssh(machine, server).await?,

        Command::Completions { shell } => commands::cmd_completions(shell),

        Command::Snapshot { output, server: _ } => commands::cmd_snapshot(output).await?,

        Command::Restore { input, data_dir } => commands::cmd_restore(input, data_dir).await?,
    }

    Ok(())
}
