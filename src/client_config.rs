//! Client-side connection context: a kubeconfig-style config file plus
//! layered resolution of the effective server address, auth token, TLS CA,
//! and namespace used for every RPC the CLI makes.
//!
//! Resolution precedence (lowest to highest):
//!   1. built-in defaults
//!   2. the current context in the config file
//!      (`$EKAFLEET_CONFIG`, else `$XDG_CONFIG_HOME/ekafleet/config.json`,
//!      else `$HOME/.config/ekafleet/config.json`)
//!   3. environment variables (`EKAFLEET_SERVER`, `EKAFLEET_TOKEN`,
//!      `EKAFLEET_NAMESPACE`, `EKAFLEET_CA_CERT`)
//!   4. explicit CLI flags (`--server`, `--token`, `--namespace`, `--ca-cert`)
//!
//! The active context can be selected with `--context` or `EKAFLEET_CONTEXT`,
//! otherwise the file's `currentContext` is used.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Default server address used when nothing else specifies one. Matches the
/// historical per-command `--server` default so existing invocations are
/// unaffected.
pub const DEFAULT_SERVER: &str = "127.0.0.1:7400";

/// Default namespace when none is configured.
pub const DEFAULT_NAMESPACE: &str = "default";

/// A single named connection context, as stored in the config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    /// Server address (`host:port`) for the gRPC control plane.
    #[serde(default)]
    pub server: Option<String>,
    /// Bearer token for authentication.
    #[serde(default)]
    pub token: Option<String>,
    /// Path to a PEM CA certificate. When set, the CLI connects over TLS.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// Namespace to scope operations to.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// The on-disk config file: a set of named contexts and the current one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientConfig {
    /// Name of the context used when `--context`/`EKAFLEET_CONTEXT` is unset.
    #[serde(default)]
    pub current_context: Option<String>,
    /// Named contexts keyed by name.
    #[serde(default)]
    pub contexts: HashMap<String, Context>,
}

impl ClientConfig {
    /// Load the config file from the resolved path, if it exists. A missing
    /// file yields an empty config; a malformed file is an error.
    pub fn load() -> anyhow::Result<Self> {
        let Some(path) = config_path() else {
            return Ok(Self::default());
        };
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).map_err(|e| {
                anyhow::anyhow!("failed to parse client config {}: {e}", path.display())
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!(
                "failed to read client config {}: {e}",
                path.display()
            )),
        }
    }

    /// Resolve the context to use given an optional explicit selection.
    /// Returns `None` when the config is empty and no context is selected.
    fn select<'a>(&'a self, selected: Option<&str>) -> Option<&'a Context> {
        let name = selected.or(self.current_context.as_deref())?;
        self.contexts.get(name)
    }
}

/// Explicit overrides supplied on the command line. Each `Some` wins over the
/// config file and environment.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub context: Option<String>,
    pub server: Option<String>,
    pub token: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub namespace: Option<String>,
}

/// The fully-resolved context used to open a connection and scope requests.
#[derive(Debug, Clone)]
pub struct ClientContext {
    pub server: String,
    pub token: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub namespace: String,
}

impl ClientContext {
    /// Resolve the effective context by layering defaults, the config file's
    /// selected context, environment variables, and CLI overrides.
    pub fn resolve(config: &ClientConfig, overrides: &Overrides) -> Self {
        let selected = overrides
            .context
            .clone()
            .or_else(|| env_nonempty("EKAFLEET_CONTEXT"));
        let ctx = config
            .select(selected.as_deref())
            .cloned()
            .unwrap_or_default();

        let server = overrides
            .server
            .clone()
            .or_else(|| env_nonempty("EKAFLEET_SERVER"))
            .or(ctx.server)
            .unwrap_or_else(|| DEFAULT_SERVER.to_string());

        let token = overrides
            .token
            .clone()
            .or_else(|| env_nonempty("EKAFLEET_TOKEN"))
            .or(ctx.token);

        let ca_cert = overrides
            .ca_cert
            .clone()
            .or_else(|| env_nonempty("EKAFLEET_CA_CERT").map(PathBuf::from))
            .or(ctx.ca_cert);

        let namespace = overrides
            .namespace
            .clone()
            .or_else(|| env_nonempty("EKAFLEET_NAMESPACE"))
            .or(ctx.namespace)
            .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string());

        Self {
            server,
            token,
            ca_cert,
            namespace,
        }
    }
}

/// Read an environment variable, treating unset or empty as absent.
fn env_nonempty(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|v| !v.is_empty())
}

/// Resolve the config file path from `EKAFLEET_CONFIG`, then
/// `$XDG_CONFIG_HOME/ekafleet/config.json`, then
/// `$HOME/.config/ekafleet/config.json`. Returns `None` if no home can be
/// determined (and no explicit path is set).
pub fn config_path() -> Option<PathBuf> {
    if let Some(explicit) = env_nonempty("EKAFLEET_CONFIG") {
        return Some(PathBuf::from(explicit));
    }
    if let Some(xdg) = env_nonempty("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("ekafleet").join("config.json"));
    }
    let home = env_nonempty("HOME")?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("ekafleet")
            .join("config.json"),
    )
}

/// Process-global resolved client context, initialized once from `main`.
static CONTEXT: OnceLock<ClientContext> = OnceLock::new();

/// Install the resolved context for the process. Idempotent: only the first
/// call wins.
pub fn init_context(ctx: ClientContext) {
    let _ = CONTEXT.set(ctx);
}

/// The process-global client context. Falls back to defaults if never
/// initialized (e.g. in tests).
pub fn context() -> &'static ClientContext {
    CONTEXT.get_or_init(|| ClientContext {
        server: DEFAULT_SERVER.to_string(),
        token: None,
        ca_cert: None,
        namespace: DEFAULT_NAMESPACE.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(current: &str, ctx: Context) -> ClientConfig {
        let mut contexts = HashMap::new();
        contexts.insert(current.to_string(), ctx);
        ClientConfig {
            current_context: Some(current.to_string()),
            contexts,
        }
    }

    #[test]
    fn resolve_uses_defaults_when_empty() {
        let ctx = ClientContext::resolve(&ClientConfig::default(), &Overrides::default());
        assert_eq!(ctx.server, DEFAULT_SERVER);
        assert_eq!(ctx.namespace, DEFAULT_NAMESPACE);
        assert!(ctx.token.is_none());
        assert!(ctx.ca_cert.is_none());
    }

    #[test]
    fn resolve_reads_current_context_from_file() {
        let config = cfg_with(
            "prod",
            Context {
                server: Some("10.0.0.1:7400".into()),
                token: Some("filetoken".into()),
                ca_cert: Some(PathBuf::from("/etc/ca.pem")),
                namespace: Some("team-a".into()),
            },
        );
        let ctx = ClientContext::resolve(&config, &Overrides::default());
        assert_eq!(ctx.server, "10.0.0.1:7400");
        assert_eq!(ctx.token.as_deref(), Some("filetoken"));
        assert_eq!(ctx.ca_cert, Some(PathBuf::from("/etc/ca.pem")));
        assert_eq!(ctx.namespace, "team-a");
    }

    #[test]
    fn cli_overrides_win_over_file() {
        let config = cfg_with(
            "prod",
            Context {
                server: Some("10.0.0.1:7400".into()),
                token: Some("filetoken".into()),
                namespace: Some("team-a".into()),
                ..Default::default()
            },
        );
        let overrides = Overrides {
            server: Some("localhost:9999".into()),
            namespace: Some("override-ns".into()),
            ..Default::default()
        };
        let ctx = ClientContext::resolve(&config, &overrides);
        assert_eq!(ctx.server, "localhost:9999");
        assert_eq!(ctx.namespace, "override-ns");
        // Token falls through to the file value since it was not overridden.
        assert_eq!(ctx.token.as_deref(), Some("filetoken"));
    }

    #[test]
    fn explicit_context_selects_named_entry() {
        let mut contexts = HashMap::new();
        contexts.insert(
            "prod".to_string(),
            Context {
                server: Some("prod:7400".into()),
                ..Default::default()
            },
        );
        contexts.insert(
            "staging".to_string(),
            Context {
                server: Some("staging:7400".into()),
                ..Default::default()
            },
        );
        let config = ClientConfig {
            current_context: Some("prod".into()),
            contexts,
        };
        let overrides = Overrides {
            context: Some("staging".into()),
            ..Default::default()
        };
        let ctx = ClientContext::resolve(&config, &overrides);
        assert_eq!(ctx.server, "staging:7400");
    }

    #[test]
    fn config_parses_camel_case_json() {
        let json = r#"{
            "currentContext": "prod",
            "contexts": {
                "prod": {
                    "server": "10.0.0.1:7400",
                    "token": "t",
                    "caCert": "/etc/ca.pem",
                    "namespace": "team-a"
                }
            }
        }"#;
        let config: ClientConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.current_context.as_deref(), Some("prod"));
        let prod = &config.contexts["prod"];
        assert_eq!(prod.server.as_deref(), Some("10.0.0.1:7400"));
        assert_eq!(prod.ca_cert, Some(PathBuf::from("/etc/ca.pem")));
    }
}
