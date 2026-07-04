#![allow(dead_code)]

use std::path::Path;
use std::process::Stdio;

use crate::config::FleetConfig;

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

    let output = tokio::process::Command::new("nix")
        .args(["eval", "--json", &attr])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

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
    let output = tokio::process::Command::new("nix")
        .args(["build", "--no-link", "--print-out-paths", flake_ref])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

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
    let output = tokio::process::Command::new("nix-copy-closure")
        .args(["--to", target_host, store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

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
