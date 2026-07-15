#![allow(dead_code)]

use std::path::Path;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use crate::config::FleetConfig;

/// Default timeout for `nix eval` commands.
const DEFAULT_EVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Default timeout for `nix build` commands.
const DEFAULT_BUILD_TIMEOUT: Duration = Duration::from_secs(600);

/// Default timeout for `nix-copy-closure` commands.
const DEFAULT_COPY_TIMEOUT: Duration = Duration::from_secs(300);

/// Tunable configuration for how the server invokes Nix: per-command timeouts
/// and a list of `nix.conf`-style options passed through as repeated
/// `--option <name> <value>` flags (e.g. extra substituters, trusted public
/// keys, or `allow-import-from-derivation`). Large or cache-dependent builds
/// that would otherwise fail opaquely can be tuned without a code change.
#[derive(Debug, Clone)]
pub struct NixOptions {
    pub eval_timeout: Duration,
    pub build_timeout: Duration,
    pub copy_timeout: Duration,
    /// `(name, value)` pairs rendered as `--option <name> <value>`.
    pub options: Vec<(String, String)>,
}

impl Default for NixOptions {
    fn default() -> Self {
        Self {
            eval_timeout: DEFAULT_EVAL_TIMEOUT,
            build_timeout: DEFAULT_BUILD_TIMEOUT,
            copy_timeout: DEFAULT_COPY_TIMEOUT,
            options: Vec::new(),
        }
    }
}

impl NixOptions {
    /// Build options from the environment. Timeouts come from
    /// `EKAFLEET_NIX_EVAL_TIMEOUT`, `EKAFLEET_NIX_BUILD_TIMEOUT`, and
    /// `EKAFLEET_NIX_COPY_TIMEOUT` (seconds; a value of 0 or an unparseable
    /// value keeps the default). Option passthrough comes from
    /// `EKAFLEET_NIX_OPTIONS`, a semicolon-separated list of `name=value`
    /// pairs, e.g. `substituters=https://cache.example.org;trusted-public-keys=key:...`.
    pub fn from_env() -> Self {
        let mut opts = Self::default();

        if let Some(d) = env_timeout("EKAFLEET_NIX_EVAL_TIMEOUT") {
            opts.eval_timeout = d;
        }
        if let Some(d) = env_timeout("EKAFLEET_NIX_BUILD_TIMEOUT") {
            opts.build_timeout = d;
        }
        if let Some(d) = env_timeout("EKAFLEET_NIX_COPY_TIMEOUT") {
            opts.copy_timeout = d;
        }
        if let Ok(raw) = std::env::var("EKAFLEET_NIX_OPTIONS") {
            opts.options = parse_options(&raw);
        }

        opts
    }

    /// Render the option passthrough as flat `--option <name> <value>` args.
    fn option_args(&self) -> Vec<String> {
        let mut args = Vec::with_capacity(self.options.len() * 3);
        for (name, value) in &self.options {
            args.push("--option".to_string());
            args.push(name.clone());
            args.push(value.clone());
        }
        args
    }
}

/// Read a positive, seconds-valued timeout from an environment variable.
/// Returns `None` when the variable is unset, unparseable, or zero.
fn env_timeout(var: &str) -> Option<Duration> {
    let secs: u64 = std::env::var(var).ok()?.trim().parse().ok()?;
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Parse a `name=value;name=value` option string into `(name, value)` pairs.
/// Whitespace around names/values is trimmed; entries without `=` or with an
/// empty name are skipped.
fn parse_options(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|entry| {
            let (name, value) = entry.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), value.trim().to_string()))
        })
        .collect()
}

/// Process-global Nix options, initialized once at server startup via
/// [`init_options`]. Falls back to defaults if never initialized (e.g. in
/// tests or the CLI).
static NIX_OPTIONS: OnceLock<NixOptions> = OnceLock::new();

/// Initialize the process-global Nix options. Idempotent: only the first call
/// wins, so this should run once during server startup.
pub fn init_options(opts: NixOptions) {
    let _ = NIX_OPTIONS.set(opts);
}

fn options() -> &'static NixOptions {
    NIX_OPTIONS.get_or_init(NixOptions::default)
}

#[derive(Debug, thiserror::Error)]
pub enum NixError {
    #[error("nix eval failed: {0}")]
    EvalFailed(String),
    #[error("nix build failed: {0}")]
    BuildFailed(String),
    #[error("nix-copy-closure failed: {0}")]
    CopyFailed(String),
    #[error("failed to parse nix output: {0}")]
    ParseError(String),
    #[error("nix command timed out: {0}")]
    Timeout(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Evaluate fleet.nix and return the parsed fleet configuration.
pub async fn eval_fleet(config_path: &Path) -> Result<FleetConfig, NixError> {
    let config_str = config_path
        .to_str()
        .ok_or_else(|| NixError::EvalFailed("invalid config path".into()))?;

    // Determine the flake attribute to evaluate
    let attr = if config_str.contains('#') {
        config_str.to_string()
    } else {
        format!("{config_str}#fleet")
    };

    let opts = options();
    let mut args = vec!["eval".to_string(), "--json".to_string(), attr];
    args.extend(opts.option_args());

    let fut = tokio::process::Command::new("nix")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let output = tokio::time::timeout(opts.eval_timeout, fut)
        .await
        .map_err(|_| {
            NixError::Timeout(format!(
                "nix eval timed out after {}s",
                opts.eval_timeout.as_secs()
            ))
        })??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NixError::EvalFailed(stderr.to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let config: FleetConfig =
        serde_json::from_str(&stdout).map_err(|e| NixError::ParseError(e.to_string()))?;

    tracing::info!(
        fleet = %config.name,
        services = config.services.len(),
        machines = config.machines.len(),
        "Fleet configuration evaluated"
    );

    Ok(config)
}

/// Build a Nix derivation and return the store path.
pub async fn build(flake_ref: &str) -> Result<String, NixError> {
    let opts = options();
    let mut args = vec![
        "build".to_string(),
        "--no-link".to_string(),
        "--print-out-paths".to_string(),
        flake_ref.to_string(),
    ];
    args.extend(opts.option_args());

    let fut = tokio::process::Command::new("nix")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let output = tokio::time::timeout(opts.build_timeout, fut)
        .await
        .map_err(|_| {
            NixError::Timeout(format!(
                "nix build timed out after {}s",
                opts.build_timeout.as_secs()
            ))
        })??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NixError::BuildFailed(stderr.to_string()));
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();

    tracing::info!(store_path = %store_path, "Nix build completed");
    Ok(store_path)
}

/// Copy a store path to a remote machine via nix-copy-closure.
pub async fn copy_closure(store_path: &str, target_host: &str) -> Result<(), NixError> {
    let opts = options();
    let fut = tokio::process::Command::new("nix-copy-closure")
        .args(["--to", target_host, store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let output = tokio::time::timeout(opts.copy_timeout, fut)
        .await
        .map_err(|_| {
            NixError::Timeout(format!(
                "nix-copy-closure timed out after {}s",
                opts.copy_timeout.as_secs()
            ))
        })??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NixError::CopyFailed(stderr.to_string()));
    }

    tracing::info!(
        store_path = %store_path,
        target = %target_host,
        "Closure copied"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_have_no_passthrough() {
        let opts = NixOptions::default();
        assert!(opts.option_args().is_empty());
        assert_eq!(opts.eval_timeout, DEFAULT_EVAL_TIMEOUT);
    }

    #[test]
    fn parse_options_parses_pairs() {
        let parsed = parse_options("substituters=https://c.example.org;trusted-public-keys=k:AA==");
        assert_eq!(
            parsed,
            vec![
                (
                    "substituters".to_string(),
                    "https://c.example.org".to_string()
                ),
                ("trusted-public-keys".to_string(), "k:AA==".to_string()),
            ]
        );
    }

    #[test]
    fn parse_options_trims_and_skips_malformed() {
        // Whitespace is trimmed; entries without '=' or with an empty name are
        // dropped rather than producing garbage options.
        let parsed = parse_options(" a = 1 ;bad;=novalue;b=2");
        assert_eq!(
            parsed,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn parse_options_empty_is_empty() {
        assert!(parse_options("").is_empty());
    }

    #[test]
    fn option_args_renders_repeated_option_flags() {
        let opts = NixOptions {
            options: vec![
                ("substituters".to_string(), "https://c".to_string()),
                ("cores".to_string(), "4".to_string()),
            ],
            ..Default::default()
        };
        assert_eq!(
            opts.option_args(),
            vec![
                "--option",
                "substituters",
                "https://c",
                "--option",
                "cores",
                "4"
            ]
        );
    }
}
