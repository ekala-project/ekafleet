use std::path::{Path, PathBuf};
use std::process::Stdio;

/// EkaOS system activation — manages full OS-level deployments.
///
/// The caller provides:
/// - `toplevel`: the Nix store path of the system closure
///   (default derivation: `system.build.toplevel`)
/// - `activate_script`: path to the activation executable
///   (default: `"${toplevel}/bin/activate"`)
///
/// The activate script receives an action argument:
/// - `switch` — activate now + set as boot default
/// - `boot`   — set as boot default only
/// - `test`   — activate in current session only
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    #[error("toplevel path does not exist: {0}")]
    PathNotFound(String),
    #[error("activate script not found: {0}")]
    ActivateScriptNotFound(String),
    #[error("profile switch failed: {0}")]
    ProfileFailed(String),
    #[error("activation failed: {0}")]
    ActivationFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parameters for a system activation.
#[derive(Debug, Clone)]
pub struct ActivationParams {
    /// Store path of the system closure (system.build.toplevel output).
    pub toplevel: String,
    /// Path to the activate script. Defaults to `{toplevel}/bin/activate`.
    pub activate_script: Option<String>,
    /// What action to perform.
    pub action: ActivationAction,
}

impl ActivationParams {
    /// Resolve the activate script path — uses the explicit override or
    /// defaults to `{toplevel}/bin/activate`.
    pub fn resolve_activate_script(&self) -> PathBuf {
        match &self.activate_script {
            Some(script) => PathBuf::from(script),
            None => PathBuf::from(&self.toplevel).join("bin/activate"),
        }
    }
}

/// Result of a system activation.
#[derive(Debug)]
pub struct ActivationResult {
    pub toplevel: String,
    pub action: ActivationAction,
    pub previous_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationAction {
    /// Activate now and set as boot default.
    Switch,
    /// Set as boot default without activating now.
    Boot,
    /// Activate in current session only (don't change boot default).
    Test,
}

/// Activate an EkaOS system closure.
///
/// 1. Validates the toplevel store path exists
/// 2. Validates the activate script exists
/// 3. Sets the system profile (`nix-env --profile ... --set`)
/// 4. Runs the activate script with the requested action
pub async fn activate_system(
    params: &ActivationParams,
) -> Result<ActivationResult, ActivationError> {
    if params.toplevel.is_empty() {
        return Err(ActivationError::PathNotFound("(empty)".into()));
    }

    let toplevel = Path::new(&params.toplevel);

    // Validate toplevel exists
    if !toplevel.exists() {
        return Err(ActivationError::PathNotFound(params.toplevel.clone()));
    }

    // Resolve and validate activate script
    let activate_script = params.resolve_activate_script();
    if !activate_script.exists() {
        return Err(ActivationError::ActivateScriptNotFound(
            activate_script.display().to_string(),
        ));
    }

    // Check if already at this toplevel (skip if so)
    let current = current_system_path().await;
    if current.as_deref() == Some(params.toplevel.as_str()) {
        tracing::info!(toplevel = %params.toplevel, "System already at desired toplevel");
        return Ok(ActivationResult {
            toplevel: params.toplevel.clone(),
            action: params.action,
            previous_path: current,
        });
    }

    let previous_path = current;

    tracing::info!(
        toplevel = %params.toplevel,
        activate_script = %activate_script.display(),
        previous = ?previous_path,
        action = ?params.action,
        "Activating EkaOS system"
    );

    // Set the system profile
    set_system_profile(&params.toplevel).await?;

    // Run the activate script
    let action_str = match params.action {
        ActivationAction::Switch => "switch",
        ActivationAction::Boot => "boot",
        ActivationAction::Test => "test",
    };

    run_activate_script(&activate_script, action_str).await?;

    // Update /run/current-system symlink
    let current_link = PathBuf::from("/run/current-system");
    let _ = tokio::fs::remove_file(&current_link).await;
    tokio::fs::symlink(&params.toplevel, &current_link)
        .await
        .ok();

    tracing::info!(
        toplevel = %params.toplevel,
        action = ?params.action,
        "EkaOS system activated"
    );

    Ok(ActivationResult {
        toplevel: params.toplevel.clone(),
        action: params.action,
        previous_path,
    })
}

/// Rollback to the previous system generation.
pub async fn rollback(
    activate_script_override: Option<&str>,
) -> Result<ActivationResult, ActivationError> {
    let previous = previous_generation_path().await?;

    match previous {
        Some(path) => {
            let toplevel = path.to_string_lossy().to_string();
            tracing::info!(toplevel = %toplevel, "Rolling back to previous generation");

            let params = ActivationParams {
                toplevel,
                activate_script: activate_script_override.map(String::from),
                action: ActivationAction::Switch,
            };
            activate_system(&params).await
        }
        None => Err(ActivationError::ActivationFailed(
            "no previous generation available".into(),
        )),
    }
}

/// Get the current active system path.
pub async fn current_system_path() -> Option<String> {
    let current = PathBuf::from("/run/current-system");
    if current.exists() {
        tokio::fs::read_link(&current)
            .await
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    } else {
        tokio::fs::read_link(SYSTEM_PROFILE)
            .await
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }
}

/// Get the current system generation number.
pub async fn current_generation() -> Option<u64> {
    let profile_dir = Path::new(SYSTEM_PROFILE).parent()?;
    let mut max_gen = 0u64;

    if let Ok(mut entries) = tokio::fs::read_dir(profile_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(gen_str) = name_str
                .strip_prefix("system-")
                .and_then(|s| s.strip_suffix("-link"))
                && let Ok(n) = gen_str.parse::<u64>()
            {
                max_gen = max_gen.max(n);
            }
        }
    }

    if max_gen > 0 { Some(max_gen) } else { None }
}

/// Set the Nix system profile to point at a toplevel store path.
async fn set_system_profile(toplevel: &str) -> Result<(), ActivationError> {
    let output = tokio::process::Command::new("nix-env")
        .args(["--profile", SYSTEM_PROFILE, "--set", toplevel])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActivationError::ProfileFailed(stderr.trim().to_string()));
    }

    Ok(())
}

/// Execute the activate script with the given action.
async fn run_activate_script(script: &Path, action: &str) -> Result<(), ActivationError> {
    let output = tokio::process::Command::new(script)
        .arg(action)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ActivationError::ActivationFailed(format!(
            "{} {action} failed (exit {}): {stderr}\n{stdout}",
            script.display(),
            output.status,
        )));
    }

    Ok(())
}

/// Resolve the previous generation's store path from profile links.
async fn previous_generation_path() -> Result<Option<PathBuf>, ActivationError> {
    let current_gen = current_generation().await.unwrap_or(0);
    if current_gen <= 1 {
        return Ok(None);
    }

    let prev_link = PathBuf::from(format!(
        "/nix/var/nix/profiles/system-{}-link",
        current_gen - 1
    ));

    if prev_link.exists() {
        let target = tokio::fs::read_link(&prev_link).await?;
        Ok(Some(target))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_default_activate_script() {
        let params = ActivationParams {
            toplevel: "/nix/store/abc123-ekaos-system".into(),
            activate_script: None,
            action: ActivationAction::Switch,
        };
        assert_eq!(
            params.resolve_activate_script(),
            PathBuf::from("/nix/store/abc123-ekaos-system/bin/activate")
        );
    }

    #[test]
    fn resolve_custom_activate_script() {
        let params = ActivationParams {
            toplevel: "/nix/store/abc123-ekaos-system".into(),
            activate_script: Some("/nix/store/xyz-custom/bin/activate".into()),
            action: ActivationAction::Switch,
        };
        assert_eq!(
            params.resolve_activate_script(),
            PathBuf::from("/nix/store/xyz-custom/bin/activate")
        );
    }

    #[tokio::test]
    async fn empty_toplevel_fails() {
        let params = ActivationParams {
            toplevel: "".into(),
            activate_script: None,
            action: ActivationAction::Switch,
        };
        let result = activate_system(&params).await;
        assert!(matches!(result, Err(ActivationError::PathNotFound(_))));
    }

    #[tokio::test]
    async fn nonexistent_toplevel_fails() {
        let params = ActivationParams {
            toplevel: "/nix/store/nonexistent-path".into(),
            activate_script: None,
            action: ActivationAction::Switch,
        };
        let result = activate_system(&params).await;
        assert!(matches!(result, Err(ActivationError::PathNotFound(_))));
    }

    #[tokio::test]
    async fn missing_activate_script_fails() {
        let dir = tempfile::tempdir().unwrap();
        let params = ActivationParams {
            toplevel: dir.path().to_str().unwrap().into(),
            activate_script: None,
            action: ActivationAction::Switch,
        };
        let result = activate_system(&params).await;
        assert!(matches!(
            result,
            Err(ActivationError::ActivateScriptNotFound(_))
        ));
    }
}
