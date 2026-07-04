use ekafleet::agent;
use ekafleet::server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ekafleet", about = "Unified fleet management for ekaos")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    },

    /// Start in agent mode (data plane)
    Agent {
        /// Server address to join
        #[arg(long)]
        join: String,

        /// Authentication token
        #[arg(long)]
        token: String,

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
        Command::Server {
            data_dir,
            peers,
            listen,
            http_listen,
            token,
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
            };

            server::run(config).await?;
        }

        Command::Agent {
            join,
            token,
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
                data_dir,
                ca_cert_pem,
            };

            agent::run(config).await?;
        }

        Command::Plan { config, server } => {
            tracing::info!(
                config = %config.display(),
                server = %server,
                "Planning deployment"
            );
            eprintln!("plan not yet implemented");
        }

        Command::Apply {
            config,
            auto_approve,
            watch,
            server,
        } => {
            tracing::info!(
                config = %config.display(),
                %auto_approve,
                %watch,
                server = %server,
                "Applying deployment"
            );
            eprintln!("apply not yet implemented");
        }

        Command::Status { server } => {
            tracing::info!(server = %server, "Querying fleet status");
            eprintln!("status not yet implemented");
        }

        Command::Drift { server } => {
            tracing::info!(server = %server, "Checking for drift");
            eprintln!("drift not yet implemented");
        }

        Command::Rollback {
            machine,
            all,
            to,
            server,
        } => {
            tracing::info!(
                ?machine,
                %all,
                ?to,
                server = %server,
                "Rolling back"
            );
            eprintln!("rollback not yet implemented");
        }

        Command::Capacity { server } => {
            tracing::info!(server = %server, "Querying capacity");
            eprintln!("capacity not yet implemented");
        }

        Command::Services { server } => {
            tracing::info!(server = %server, "Listing services");
            eprintln!("services not yet implemented");
        }

        Command::Drain { machine, server } => {
            tracing::info!(
                machine = %machine,
                server = %server,
                "Draining machine"
            );
            eprintln!("drain not yet implemented");
        }

        Command::Scale {
            service,
            count,
            server,
        } => {
            tracing::info!(
                service = %service,
                count = %count,
                server = %server,
                "Scaling service"
            );
            eprintln!("scale not yet implemented");
        }

        Command::Token {
            action: TokenAction::Create { r#type },
        } => {
            tracing::info!(token_type = %r#type, "Creating token");
            let token = generate_token();
            println!("{token}");
        }

        Command::Logs { service, server } => {
            tracing::info!(
                service = %service,
                server = %server,
                "Fetching logs"
            );
            eprintln!("logs not yet implemented");
        }
    }

    Ok(())
}

/// Generate a cryptographically random token (64 hex chars = 256 bits).
fn generate_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("system RNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
