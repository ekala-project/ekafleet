mod client_config;
mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ekafleet",
    about = "Unified fleet management for ekaos",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format: "text" (default) or "json" for machine-readable output
    #[arg(long, short, default_value = "text", global = true)]
    output: OutputFormat,

    /// Named context from the client config file to use for connection
    /// settings. Defaults to the file's `currentContext`.
    #[arg(long, global = true)]
    context: Option<String>,

    /// Override the server address (`host:port`) for this invocation. A
    /// comma-separated list is tried in order, and the CLI connects to
    /// whichever server leads.
    #[arg(long, global = true)]
    server: Option<String>,

    /// Override the bearer auth token for this invocation.
    #[arg(long, global = true)]
    token: Option<String>,

    /// Override the namespace to scope operations to.
    #[arg(long, global = true)]
    namespace: Option<String>,

    /// Override the PEM CA certificate path; when set the CLI connects over TLS.
    #[arg(long, global = true)]
    ca_cert: Option<PathBuf>,
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

        /// Do not run the in-process agent for this host
        #[arg(long)]
        no_agent: bool,

        /// Name of the in-process agent's node (defaults to the short hostname)
        #[arg(long, env = "EKAFLEET_NODE_NAME")]
        node_name: Option<String>,
    },

    /// Standalone service mesh proxy daemon (process-isolated, unprivileged)
    Proxy {
        /// HTTP listen address for proxied traffic
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,

        /// SPIFFE trust domain for mTLS authorization
        #[arg(long, default_value = "fleet.internal")]
        trust_domain: String,

        /// Data directory (for SVID material)
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,

        /// Ingress routes file written by the agent
        #[arg(long, default_value = ekafleet::proxy::routes::ROUTES_FILE)]
        routes_file: PathBuf,
    },

    /// Standalone CA signing daemon (process-isolated, no network)
    CaSigner {
        /// Data directory for CA key and certificate
        #[arg(long, default_value = "/var/lib/ekafleet-ca")]
        data_dir: PathBuf,

        /// SPIFFE trust domain for fleet identities
        #[arg(long, default_value = "fleet.internal")]
        domain: String,

        /// Unix socket path for signing requests
        #[arg(long, default_value = "/run/ekafleet-ca/ca.sock")]
        socket: PathBuf,
    },

    /// Start in server mode (control plane + agent capabilities)
    Server {
        /// Data directory for persistent state
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,

        /// This server's Raft node id (a positive integer, unique among
        /// the servers)
        #[arg(long, env = "EKAFLEET_NODE_ID", default_value_t = ekafleet::server::DEFAULT_NODE_ID)]
        node_id: u64,

        /// The servers of a new HA cluster, this one included, as
        /// `<node-id>=<host:port>,...` (their gRPC addresses). Read on first
        /// boot only; change membership later with `ekafleet raft`
        #[arg(long, env = "EKAFLEET_PEERS")]
        peers: Option<String>,

        /// gRPC listen address
        #[arg(long, default_value = "0.0.0.0:7400")]
        listen: String,

        /// HTTP API listen address
        #[arg(long, default_value = "0.0.0.0:7402")]
        http_listen: String,

        /// Federation listen address, where peer clusters fetch this
        /// cluster's trust bundles and exported services (off by default)
        #[arg(long, env = "EKAFLEET_FEDERATION_LISTEN")]
        federation_listen: Option<std::net::SocketAddr>,

        /// Admin bearer token for the API. Prefer --token-file: argv is
        /// readable by every local user.
        #[arg(long, env = "EKAFLEET_TOKEN", required_unless_present = "token_file")]
        token: Option<String>,

        /// File holding the admin bearer token
        #[arg(long, env = "EKAFLEET_TOKEN_FILE", conflicts_with = "token")]
        token_file: Option<PathBuf>,

        /// SPIFFE trust domain for fleet identities
        #[arg(long, default_value = "fleet.internal")]
        domain: String,

        /// Path to CA signer Unix socket (uses external ca-signer daemon instead of embedding CA)
        #[arg(long)]
        ca_socket: Option<PathBuf>,

        /// Also run an agent for this host in-process (needs root). It joins
        /// this server over loopback with a node SVID like any other node.
        #[arg(long, env = "EKAFLEET_EMBEDDED_AGENT")]
        embedded_agent: bool,

        /// Node name of the embedded agent (defaults to the short hostname)
        #[arg(long, env = "EKAFLEET_NODE_NAME", requires = "embedded_agent")]
        node_name: Option<String>,

        /// Data directory of the embedded agent [default: <data-dir>/agent]
        #[arg(long, requires = "embedded_agent")]
        agent_data_dir: Option<PathBuf>,

        /// Mesh address other nodes reach the embedded agent on
        #[arg(long, env = "EKAFLEET_ADVERTISE_ADDR", requires = "embedded_agent")]
        advertise_addr: Option<std::net::IpAddr>,

        /// UDP port of the embedded agent's WireGuard mesh interface
        #[arg(long, env = "EKAFLEET_MESH_PORT", default_value_t = 51820)]
        mesh_port: u16,

        /// Keep the embedded agent out of the WireGuard mesh
        #[arg(long, env = "EKAFLEET_NO_MESH")]
        no_mesh: bool,

        /// Where the agent answers DNS for the fleet domain (forwarding
        /// other names upstream)
        #[arg(long, env = "EKAFLEET_DNS_LISTEN", default_value = "127.0.0.1:53")]
        dns_listen: std::net::SocketAddr,

        /// Upstream resolvers for non-fleet names, comma-separated (default:
        /// the nameservers in /etc/resolv.conf)
        #[arg(long, env = "EKAFLEET_DNS_UPSTREAM")]
        dns_upstream: Option<String>,

        /// Run no DNS listeners
        #[arg(long, env = "EKAFLEET_NO_DNS")]
        no_dns: bool,
    },

    /// Start in agent mode (data plane)
    Agent {
        /// Server address to join (`ip:port`), or a comma-separated list of
        /// servers; the agent follows whichever leads
        #[arg(long)]
        join: String,

        /// Bearer token; only accepted by `ekafleet dev`. Real servers
        /// require a node SVID obtained with a join token.
        #[arg(long, env = "EKAFLEET_TOKEN", conflicts_with = "token_file")]
        token: Option<String>,

        /// File holding the bearer token (dev only)
        #[arg(long, env = "EKAFLEET_TOKEN_FILE")]
        token_file: Option<PathBuf>,

        /// One-time join token (from `ekafleet token create --type agent
        /// --node <name>`), exchanged for a node SVID on first start.
        /// Prefer --join-token-file: argv is readable by every local user.
        #[arg(long, env = "EKAFLEET_JOIN_TOKEN", conflicts_with = "join_token_file")]
        join_token: Option<String>,

        /// File holding the one-time join token
        #[arg(long, env = "EKAFLEET_JOIN_TOKEN_FILE")]
        join_token_file: Option<PathBuf>,

        /// This node's name; must match its `machines.<name>` entry in the
        /// fleet config. Defaults to the short system hostname.
        #[arg(long, env = "EKAFLEET_NODE_NAME")]
        node_name: Option<String>,

        /// Data directory for local state
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,

        /// Path to CA certificate PEM for TLS verification
        #[arg(long)]
        ca_cert: Option<PathBuf>,

        /// Address other nodes reach this node's WireGuard mesh port on.
        /// Defaults to the local address used to reach the server.
        #[arg(long, env = "EKAFLEET_ADVERTISE_ADDR")]
        advertise_addr: Option<std::net::IpAddr>,

        /// UDP port of the WireGuard mesh interface
        #[arg(long, env = "EKAFLEET_MESH_PORT", default_value_t = 51820)]
        mesh_port: u16,

        /// Do not join the WireGuard mesh (it is also skipped when the agent
        /// is not root or `wg`/`ip` are missing)
        #[arg(long, env = "EKAFLEET_NO_MESH")]
        no_mesh: bool,

        /// Where the agent answers DNS for the fleet domain (forwarding
        /// other names upstream)
        #[arg(long, env = "EKAFLEET_DNS_LISTEN", default_value = "127.0.0.1:53")]
        dns_listen: std::net::SocketAddr,

        /// Upstream resolvers for non-fleet names, comma-separated (default:
        /// the nameservers in /etc/resolv.conf)
        #[arg(long, env = "EKAFLEET_DNS_UPSTREAM")]
        dns_upstream: Option<String>,

        /// Run no DNS listeners
        #[arg(long, env = "EKAFLEET_NO_DNS")]
        no_dns: bool,
    },

    /// Show desired-vs-actual diff
    Plan {
        /// Flake reference evaluated by the server (attribute defaults to `fleet`)
        #[arg(long, visible_alias = "config", default_value = ".")]
        flake: String,

        /// Server address to query
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Execute deployment plan
    Apply {
        /// Flake reference evaluated by the server (attribute defaults to
        /// `fleet`). Local paths are made absolute; the server must be able
        /// to read them.
        #[arg(long, visible_alias = "config", default_value = ".")]
        flake: String,

        /// Skip the plan and confirmation prompt
        #[arg(long)]
        auto_approve: bool,

        /// Keep streaming the server's later reconciles (alias: --watch)
        #[arg(long, visible_alias = "watch")]
        follow: bool,

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

    /// List applied configuration revisions
    History {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Re-apply an earlier configuration revision
    Rollback {
        /// Configuration revision to re-apply (default: the previous one;
        /// see `ekafleet history`)
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

    /// Move stateful instances back to the nodes the scheduler prefers
    /// (shows the moves unless --apply)
    Rebalance {
        /// Request the moves instead of only showing them
        #[arg(long)]
        apply: bool,

        /// Most instances to move in this round
        #[arg(long, default_value_t = 1)]
        max_moves: u32,

        /// Only these services (repeatable)
        #[arg(long = "service")]
        services: Vec<String>,

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

        /// Stream logs continuously (alias: --watch)
        #[arg(long, short, visible_alias = "watch")]
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

        /// Stream new events continuously (alias: --watch)
        #[arg(long, short, visible_alias = "watch")]
        follow: bool,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },

    /// Query the audit log, newest first (Admin only)
    Audit {
        /// Only entries of this actor (token id or SPIFFE ID)
        #[arg(long)]
        actor: Option<String>,

        /// Only this action (e.g. apply, access, authenticate, token_create)
        #[arg(long)]
        action: Option<String>,

        /// Only this outcome (success, denied, failed)
        #[arg(long)]
        outcome: Option<String>,

        /// Maximum number of entries to show
        #[arg(long, default_value = "100")]
        limit: u32,

        /// Print JSON lines instead of a table
        #[arg(long)]
        json: bool,

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

    /// Secrets of services (delivered at /run/secrets/<name>)
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Transit encryption with server-held keys
    Transit {
        #[command(subcommand)]
        action: TransitAction,
    },

    /// Carry the keys shared by every server to a new one
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },

    /// Servers of the HA control plane (Raft cluster)
    Raft {
        #[command(subcommand)]
        action: RaftAction,
    },

    /// Persistent volumes of stateful services
    Volume {
        #[command(subcommand)]
        action: VolumeAction,
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

    /// Print version and build information
    Version,

    /// Inspect the client connection context (config file, contexts).
    Context {
        #[command(subcommand)]
        action: ContextAction,
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

    /// Managed cloud image operations
    Images {
        #[command(subcommand)]
        action: ImagesAction,
    },
}

#[derive(Subcommand)]
enum ContextAction {
    /// Show the effective connection context (after resolving config, env, flags).
    Show,
    /// List the contexts defined in the config file.
    List,
}

#[derive(Subcommand)]
enum TokenAction {
    /// Create a token. `--type server` (default) prints a random 256-bit
    /// token for `ekafleet server --token-file`; `--type agent` asks the
    /// server for a one-time join token bound to `--node`.
    Create {
        /// Token type (server or agent)
        #[arg(long, default_value = "server", value_parser = ["server", "agent"])]
        r#type: String,

        /// Node name the join token is bound to (`--type agent`)
        #[arg(long, required_if_eq("type", "agent"))]
        node: Option<String>,

        /// Join token lifetime, e.g. 30m, 1h, 7d (default 1h, max 7d)
        #[arg(long)]
        ttl: Option<String>,

        /// Server address (`--type agent`)
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
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
enum SecretAction {
    /// Set a secret's value, read from stdin (or --file); never from argv
    Set {
        /// Service the secret belongs to
        service: String,
        /// Secret name, as declared in the service's `secrets`
        name: String,
        /// Read the value from this file instead of stdin
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// List secret names and versions (never values)
    List {
        /// Only this service's secrets
        service: Option<String>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Delete a secret's value, with its earlier versions
    Delete {
        /// Service the secret belongs to
        service: String,
        /// Secret name
        name: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// List a secret's current and kept earlier versions
    Versions {
        /// Service the secret belongs to
        service: String,
        /// Secret name
        name: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// List dynamic secrets' database users, and users still to drop
    Leases {
        /// Only this service's leases
        service: Option<String>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Drop a dynamic secret's database user now and issue a new one
    Revoke {
        /// Service the secret belongs to
        service: String,
        /// Secret name
        name: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Make an earlier version current again (stored as a new version)
    Rollback {
        /// Service the secret belongs to
        service: String,
        /// Secret name
        name: String,
        /// Version to restore
        version: u64,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum TransitAction {
    /// Manage transit keys
    Key {
        #[command(subcommand)]
        action: TransitKeyAction,
    },
    /// Encrypt stdin (or --file); prints `ekafleet:v<N>:...`
    Encrypt {
        /// Transit key name
        key: String,
        /// Read the plaintext from this file instead of stdin
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Client certificate (e.g. a service SVID) for mTLS
        #[arg(long, requires = "key_file")]
        cert: Option<std::path::PathBuf>,
        /// Private key for --cert
        #[arg(long = "key-file", id = "key_file", requires = "cert")]
        key_file: Option<std::path::PathBuf>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Decrypt a value from stdin (or --file); writes the plaintext to stdout
    Decrypt {
        /// Transit key name
        key: String,
        /// Read the ciphertext from this file instead of stdin
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Client certificate (e.g. a service SVID) for mTLS
        #[arg(long, requires = "key_file")]
        cert: Option<std::path::PathBuf>,
        /// Private key for --cert
        #[arg(long = "key-file", id = "key_file", requires = "cert")]
        key_file: Option<std::path::PathBuf>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum KeysAction {
    /// Seal this server's shared keys (fleet key, binary cache key, root CA,
    /// JWT-SVID key) into a bundle for `ekafleet keys import`
    Export {
        /// The server's data directory
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,
        /// The `ekafleet ca-signer` data directory, when the CA runs there
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// SPIFFE trust domain for fleet identities
        #[arg(long, default_value = "fleet.internal")]
        domain: String,
        /// File holding the passphrase to seal the bundle with
        #[arg(long)]
        passphrase_file: PathBuf,
        /// Where to write the sealed bundle
        #[arg(long)]
        out: PathBuf,
    },
    /// Install the keys of a bundle before a new server's first start.
    /// Keys already present are kept; a server that made its own is refused
    Import {
        /// The sealed bundle from `ekafleet keys export`
        #[arg(long)]
        bundle: PathBuf,
        /// Data directory to install the keys into
        #[arg(long, default_value = "/var/lib/ekafleet")]
        data_dir: PathBuf,
        /// Which keys: `server` and `ca` split them between a server and its
        /// `ekafleet ca-signer`
        #[arg(long, value_enum, default_value = "all")]
        scope: ekafleet::server::keybundle::Scope,
        /// Refuse a bundle of another trust domain
        #[arg(long)]
        domain: Option<String>,
        /// File holding the bundle passphrase
        #[arg(long)]
        passphrase_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum RaftAction {
    /// Show the servers, the leader and replication progress
    Status {
        /// Server address (any server answers)
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Add a server: it catches up as a learner, then votes. Start it
    /// first with `--node-id <id>`
    Add {
        /// The new server's node id
        id: u64,
        /// Its gRPC address as the other servers reach it (`host:port`)
        addr: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Remove a server from the cluster
    Remove {
        /// The server's node id
        id: u64,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum TransitKeyAction {
    /// Create a key
    Create {
        /// Key name; it belongs to `--namespace` (default: the token's
        /// namespace, or "default")
        name: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Add a version; new values use it, old ones still decrypt
    Rotate {
        /// Key name
        name: String,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// List keys and their latest versions
    List {
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Delete a key; values encrypted with it can no longer be decrypted
    Delete {
        /// Key name
        name: String,
        /// Confirm the deletion
        #[arg(long)]
        yes: bool,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[derive(Subcommand)]
enum VolumeAction {
    /// Node-local volume snapshots
    Snapshot {
        #[command(subcommand)]
        action: VolumeSnapshotAction,
    },
}

#[derive(Subcommand)]
enum VolumeSnapshotAction {
    /// Snapshot a volume on the node running the service
    Create {
        service: String,
        volume: String,
        /// Node holding the volume (needed when the service runs on several)
        #[arg(long)]
        node: Option<String>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// List snapshots of a service's volumes on every node running it
    List {
        service: String,
        /// Only this volume
        volume: Option<String>,
        /// Only this node
        #[arg(long)]
        node: Option<String>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Replace a volume's data with a snapshot (stops and restarts the service)
    Restore {
        service: String,
        volume: String,
        snapshot: String,
        /// Node holding the volume (needed when the service runs on several)
        #[arg(long)]
        node: Option<String>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Delete a snapshot
    Delete {
        service: String,
        volume: String,
        snapshot: String,
        /// Node holding the volume (needed when the service runs on several)
        #[arg(long)]
        node: Option<String>,
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
        /// Namespace binding (empty for fleet-wide access)
        #[arg(long, default_value = "")]
        namespace: String,
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

#[derive(Subcommand)]
enum ImagesAction {
    /// List all managed cloud images
    List {
        /// Filter by pool name
        #[arg(long)]
        pool: Option<String>,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Build and register a cloud image for a pool
    Build {
        /// Pool name to build image for
        pool: String,
        /// Path to fleet.nix configuration
        #[arg(long, default_value = "fleet.nix")]
        config: PathBuf,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
    /// Garbage collect stale cloud images
    Gc {
        /// Show what would be deleted without actually deleting
        #[arg(long)]
        dry_run: bool,
        /// Path to fleet.nix configuration
        #[arg(long, default_value = "fleet.nix")]
        config: PathBuf,
        /// Server address
        #[arg(long, default_value = "127.0.0.1:7400")]
        server: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        // No color escapes in the journal or other non-terminal sinks.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Resolve the connection context once (config file + env + CLI flags) and
    // install it process-wide so `connect_server` picks up TLS/auth/namespace.
    let client_cfg = client_config::ClientConfig::load()?;
    let overrides = client_config::Overrides {
        context: cli.context.clone(),
        server: cli.server.clone(),
        token: cli.token.clone(),
        ca_cert: cli.ca_cert.clone(),
        namespace: cli.namespace.clone(),
    };
    client_config::init_context(client_config::ClientContext::resolve(
        &client_cfg,
        &overrides,
    ));

    match cli.command {
        Command::Proxy {
            listen,
            trust_domain,
            data_dir,
            routes_file,
        } => commands::cmd_proxy(listen, trust_domain, data_dir, routes_file).await?,

        Command::CaSigner {
            data_dir,
            domain,
            socket,
        } => commands::cmd_ca_signer(data_dir, domain, socket).await?,

        Command::Dev {
            data_dir,
            http_listen,
            listen,
            no_agent,
            node_name,
        } => {
            let agent = if no_agent {
                None
            } else {
                Some(ekafleet::server::EmbeddedAgentConfig {
                    node_name: commands::node_name_or_hostname(node_name)?,
                    data_dir: data_dir.join("agent"),
                    // Dev is a single-node playground.
                    mesh: ekafleet::mesh::peers::MeshSettings {
                        enabled: false,
                        ..Default::default()
                    },
                    dns: ekafleet::dns::agent::DnsSettings::disabled(),
                })
            };
            commands::cmd_dev(data_dir, http_listen, listen, agent).await?
        }

        Command::Server {
            data_dir,
            node_id,
            peers,
            listen,
            http_listen,
            federation_listen,
            token,
            token_file,
            domain,
            ca_socket,
            embedded_agent,
            node_name,
            agent_data_dir,
            advertise_addr,
            mesh_port,
            no_mesh,
            dns_listen,
            dns_upstream,
            no_dns,
        } => {
            let agent = if embedded_agent {
                Some(ekafleet::server::EmbeddedAgentConfig {
                    node_name: commands::node_name_or_hostname(node_name)?,
                    data_dir: agent_data_dir.unwrap_or_else(|| data_dir.join("agent")),
                    mesh: ekafleet::mesh::peers::MeshSettings {
                        enabled: !no_mesh,
                        advertise_addr,
                        listen_port: mesh_port,
                    },
                    dns: commands::dns_settings(dns_listen, dns_upstream, no_dns)?,
                })
            } else {
                None
            };
            commands::cmd_server(ekafleet::server::ServerConfig {
                data_dir,
                node_id,
                peers: ekafleet::server::parse_peers(peers.as_deref().unwrap_or_default())?,
                grpc_listen: listen,
                http_listen,
                token: commands::secret_arg(token, token_file)?
                    .ok_or_else(|| anyhow::anyhow!("--token or --token-file is required"))?
                    .to_string(),
                domain,
                ca_socket,
                allow_bearer_agents: false,
                embedded_agent: agent,
                federation_listen,
            })
            .await?
        }

        Command::Agent {
            join,
            token,
            token_file,
            join_token,
            join_token_file,
            node_name,
            data_dir,
            ca_cert,
            advertise_addr,
            mesh_port,
            no_mesh,
            dns_listen,
            dns_upstream,
            no_dns,
        } => {
            commands::cmd_agent(commands::AgentArgs {
                join,
                token: commands::secret_arg(token, token_file)?,
                join_token: commands::join_token_arg(join_token, join_token_file)?,
                node_name,
                data_dir,
                ca_cert,
                mesh: ekafleet::mesh::peers::MeshSettings {
                    enabled: !no_mesh,
                    advertise_addr,
                    listen_port: mesh_port,
                },
                dns: commands::dns_settings(dns_listen, dns_upstream, no_dns)?,
            })
            .await?
        }

        Command::Plan { flake, server } => commands::cmd_plan(flake, server).await?,

        Command::Apply {
            flake,
            auto_approve,
            follow,
            server,
        } => commands::cmd_apply(flake, auto_approve, follow, server).await?,

        Command::History { server } => commands::cmd_history(server, &cli.output).await?,

        Command::Status { server } => commands::cmd_status(server, &cli.output).await?,

        Command::Drift { server } => commands::cmd_drift(server).await?,

        Command::Rollback { to, server } => commands::cmd_rollback(to, server).await?,

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

        Command::Rebalance {
            apply,
            max_moves,
            services,
            server,
        } => commands::cmd_rebalance(apply, max_moves, services, server).await?,

        Command::Token {
            action:
                TokenAction::Create {
                    r#type,
                    node,
                    ttl,
                    server,
                },
        } => commands::cmd_token_create(r#type, node, ttl, server).await?,

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

        Command::Version => commands::cmd_version(&cli.output),

        Command::Context { action } => match action {
            ContextAction::Show => commands::cmd_context_show(&cli.output),
            ContextAction::List => commands::cmd_context_list(&client_cfg, &cli.output),
        },

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
            follow,
            server,
        } => commands::cmd_events(category, service, node, limit, follow, server).await?,

        Command::Audit {
            actor,
            action,
            outcome,
            limit,
            json,
            server,
        } => commands::cmd_audit(actor, action, outcome, limit, json, server).await?,

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

        Command::Secret { action } => match action {
            SecretAction::Set {
                service,
                name,
                file,
                server,
            } => commands::cmd_secret_set(service, name, file, server).await?,
            SecretAction::List { service, server } => {
                commands::cmd_secret_list(service, server).await?
            }
            SecretAction::Delete {
                service,
                name,
                server,
            } => commands::cmd_secret_delete(service, name, server).await?,
            SecretAction::Versions {
                service,
                name,
                server,
            } => commands::cmd_secret_versions(service, name, server).await?,
            SecretAction::Rollback {
                service,
                name,
                version,
                server,
            } => commands::cmd_secret_rollback(service, name, version, server).await?,
            SecretAction::Leases { service, server } => {
                commands::cmd_secret_leases(service, server).await?
            }
            SecretAction::Revoke {
                service,
                name,
                server,
            } => commands::cmd_secret_revoke(service, name, server).await?,
        },

        Command::Keys { action } => match action {
            KeysAction::Export {
                data_dir,
                ca_dir,
                domain,
                passphrase_file,
                out,
            } => {
                commands::cmd_keys_export(
                    &data_dir,
                    ca_dir.as_deref(),
                    &domain,
                    &passphrase_file,
                    &out,
                )
                .await?
            }
            KeysAction::Import {
                bundle,
                data_dir,
                scope,
                domain,
                passphrase_file,
            } => {
                commands::cmd_keys_import(
                    &bundle,
                    &data_dir,
                    scope,
                    domain.as_deref(),
                    &passphrase_file,
                )
                .await?
            }
        },
        Command::Raft { action } => match action {
            RaftAction::Status { server } => commands::cmd_raft_status(server).await?,
            RaftAction::Add { id, addr, server } => {
                commands::cmd_raft_add(id, addr, server).await?
            }
            RaftAction::Remove { id, server } => commands::cmd_raft_remove(id, server).await?,
        },
        Command::Transit { action } => match action {
            TransitAction::Key { action } => match action {
                TransitKeyAction::Create { name, server } => {
                    commands::cmd_transit_key_create(name, server).await?
                }
                TransitKeyAction::Rotate { name, server } => {
                    commands::cmd_transit_key_rotate(name, server).await?
                }
                TransitKeyAction::List { server } => commands::cmd_transit_key_list(server).await?,
                TransitKeyAction::Delete { name, yes, server } => {
                    commands::cmd_transit_key_delete(name, yes, server).await?
                }
            },
            TransitAction::Encrypt {
                key,
                file,
                cert,
                key_file,
                server,
            } => {
                let identity = commands::ClientIdentity {
                    cert,
                    key: key_file,
                };
                commands::cmd_transit_encrypt(key, file, identity, server).await?
            }
            TransitAction::Decrypt {
                key,
                file,
                cert,
                key_file,
                server,
            } => {
                let identity = commands::ClientIdentity {
                    cert,
                    key: key_file,
                };
                commands::cmd_transit_decrypt(key, file, identity, server).await?
            }
        },

        Command::Volume {
            action: VolumeAction::Snapshot { action },
        } => {
            use ekafleet::proto::VolumeSnapshotAction as A;
            let (action, service, volume, snapshot, node, server) = match action {
                VolumeSnapshotAction::Create {
                    service,
                    volume,
                    node,
                    server,
                } => (A::VolumeSnapshotCreate, service, volume, None, node, server),
                VolumeSnapshotAction::List {
                    service,
                    volume,
                    node,
                    server,
                } => (
                    A::VolumeSnapshotList,
                    service,
                    volume.unwrap_or_default(),
                    None,
                    node,
                    server,
                ),
                VolumeSnapshotAction::Restore {
                    service,
                    volume,
                    snapshot,
                    node,
                    server,
                } => (
                    A::VolumeSnapshotRestore,
                    service,
                    volume,
                    Some(snapshot),
                    node,
                    server,
                ),
                VolumeSnapshotAction::Delete {
                    service,
                    volume,
                    snapshot,
                    node,
                    server,
                } => (
                    A::VolumeSnapshotDelete,
                    service,
                    volume,
                    Some(snapshot),
                    node,
                    server,
                ),
            };
            let request = ekafleet::proto::VolumeSnapshotRequest {
                service_name: service,
                volume_name: volume,
                snapshot_id: snapshot.unwrap_or_default(),
                node: node.unwrap_or_default(),
            };
            commands::cmd_volume_snapshot(action, request, server).await?
        }

        Command::Acl { action } => match action {
            AclAction::Token { action } => match action {
                AclTokenAction::Create {
                    role,
                    description,
                    namespace,
                    server,
                } => commands::cmd_acl_token_create(role, description, namespace, server).await?,
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

        Command::Images { action } => match action {
            ImagesAction::List { pool, server } => commands::cmd_images_list(pool, server).await?,
            ImagesAction::Build {
                pool,
                config,
                server,
            } => commands::cmd_images_build(pool, config, server).await?,
            ImagesAction::Gc {
                dry_run,
                config,
                server,
            } => commands::cmd_images_gc(dry_run, config, server).await?,
        },
    }

    Ok(())
}
