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
    /// Optional retention policy applied after a successful `Switch`/`Boot`.
    /// `None` leaves old generations untouched.
    pub retention: Option<GenerationRetention>,
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

/// Retention policy for old system profile generations.
///
/// After a successful activation, generations that fall outside this policy
/// are deleted so long-lived fleets do not accumulate generations forever and
/// fill the disk. The current generation is always kept regardless of policy.
#[derive(Debug, Clone, Copy)]
pub struct GenerationRetention {
    /// Keep at least this many of the most recent generations. `None` disables
    /// the count-based bound.
    pub keep_last: Option<u64>,
    /// Delete generations older than this many days. `None` disables the
    /// age-based bound.
    pub older_than_days: Option<u64>,
}

impl GenerationRetention {
    /// A conservative default: keep the last 10 generations, no age bound.
    pub const fn default_policy() -> Self {
        Self {
            keep_last: Some(10),
            older_than_days: None,
        }
    }

    /// Build a policy from environment overrides, falling back to the default.
    ///
    /// The NixOS module surfaces these as `Environment=` on the agent unit:
    ///   - `EKAFLEET_KEEP_GENERATIONS`      — keep the last N generations
    ///   - `EKAFLEET_KEEP_GENERATIONS_DAYS` — delete generations older than N days
    ///
    /// A value of `0` for the count disables the count bound. An unset/invalid
    /// value leaves that bound at its default.
    pub fn from_env() -> Self {
        let default = Self::default_policy();
        let keep_last = match std::env::var("EKAFLEET_KEEP_GENERATIONS") {
            Ok(v) => match v.trim().parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(n),
                Err(_) => default.keep_last,
            },
            Err(_) => default.keep_last,
        };
        let older_than_days = match std::env::var("EKAFLEET_KEEP_GENERATIONS_DAYS") {
            Ok(v) => match v.trim().parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(n),
                Err(_) => default.older_than_days,
            },
            Err(_) => default.older_than_days,
        };
        Self {
            keep_last,
            older_than_days,
        }
    }

    /// Whether the policy actually removes anything.
    fn is_noop(&self) -> bool {
        self.keep_last.is_none() && self.older_than_days.is_none()
    }
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

    // Prune old generations per the retention policy. Non-fatal: a pruning
    // failure must not fail an otherwise-successful activation.
    if let Some(policy) = params.retention
        && let Err(e) = prune_generations(policy).await
    {
        tracing::warn!(error = %e, "Generation pruning failed (activation still succeeded)");
    }

    Ok(ActivationResult {
        toplevel: params.toplevel.clone(),
        action: params.action,
        previous_path,
    })
}

/// Prune old system profile generations according to `policy`.
///
/// Uses `nix-env --profile <system> --delete-generations`, which accepts
/// `+N` (keep the last N generations, delete the rest) and `<N>d` (delete
/// generations older than N days).
///
/// The current generation is never deleted. On flakes-only installs where
/// `nix-env` is absent, falls back to `nix profile wipe-history` with the
/// matching `--older-than` bound (count-based pruning is not expressible there,
/// so only the age bound is applied in that case).
///
/// Returns without error when the policy is a no-op. Pruning failures are
/// surfaced as `ProfileFailed` but are non-fatal to activation (the caller
/// logs and continues).
pub async fn prune_generations(policy: GenerationRetention) -> Result<(), ActivationError> {
    if policy.is_noop() {
        return Ok(());
    }

    // Build the nix-env delete-generations selectors.
    let mut selectors: Vec<String> = Vec::new();
    if let Some(days) = policy.older_than_days {
        selectors.push(format!("{days}d"));
    }
    if let Some(keep) = policy.keep_last {
        selectors.push(format!("+{keep}"));
    }

    let mut args: Vec<&str> = vec!["--profile", SYSTEM_PROFILE, "--delete-generations"];
    for s in &selectors {
        args.push(s.as_str());
    }

    match run_profile_set("nix-env", &args).await {
        Ok(()) => {
            tracing::info!(?policy, "Pruned old system generations");
            Ok(())
        }
        Err(ActivationError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            // Flakes-only fallback: only the age bound is expressible.
            if let Some(days) = policy.older_than_days {
                let older = format!("{days}d");
                run_profile_set(
                    "nix",
                    &[
                        "profile",
                        "wipe-history",
                        "--profile",
                        SYSTEM_PROFILE,
                        "--older-than",
                        &older,
                    ],
                )
                .await?;
                tracing::info!(?policy, "Pruned old system generations via nix profile");
            } else {
                tracing::warn!(
                    "nix-env absent and no age bound set; count-based generation pruning skipped"
                );
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
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
                // Never prune during a rollback — the older generations are the
                // recovery targets we are relying on.
                retention: None,
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
///
/// Prefers `nix-env --profile ... --set` (present on channel-based and most
/// installs). On flakes-only installs where `nix-env` is not on `PATH`, falls
/// back to `nix profile install --profile ... <store-path>`, which the modern
/// `nix` CLI provides. This lets the agent activate on a non-NixOS host that
/// has only the flakes-enabled `nix` binary.
async fn set_system_profile(toplevel: &str) -> Result<(), ActivationError> {
    match run_profile_set("nix-env", &["--profile", SYSTEM_PROFILE, "--set", toplevel]).await {
        Ok(()) => Ok(()),
        Err(ActivationError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("nix-env not found; falling back to `nix profile` for system profile");
            run_profile_set(
                "nix",
                &["profile", "install", "--profile", SYSTEM_PROFILE, toplevel],
            )
            .await
        }
        Err(e) => Err(e),
    }
}

/// Run a profile-mutating subcommand, mapping a non-zero exit to `ProfileFailed`
/// and a missing binary to `Io(NotFound)` (so the caller can try a fallback).
async fn run_profile_set(program: &str, args: &[&str]) -> Result<(), ActivationError> {
    let output = tokio::process::Command::new(program)
        .args(args)
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
            retention: None,
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
            retention: None,
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
            retention: None,
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
            retention: None,
        };
        let result = activate_system(&params).await;
        assert!(matches!(result, Err(ActivationError::PathNotFound(_))));
    }

    #[tokio::test]
    async fn run_profile_set_reports_missing_binary_as_notfound() {
        // A nonexistent program must surface as Io(NotFound) so that
        // set_system_profile can trigger the `nix profile` fallback.
        let result = run_profile_set(
            "ekafleet-nonexistent-binary-xyz",
            &["--set", "/nix/store/x"],
        )
        .await;
        match result {
            Err(ActivationError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_profile_set_reports_nonzero_exit_as_profile_failed() {
        // `false` exits non-zero; must map to ProfileFailed, not Io.
        let result = run_profile_set("false", &[]).await;
        assert!(matches!(result, Err(ActivationError::ProfileFailed(_))));
    }

    #[test]
    fn retention_noop_detection() {
        assert!(
            GenerationRetention {
                keep_last: None,
                older_than_days: None,
            }
            .is_noop()
        );
        assert!(!GenerationRetention::default_policy().is_noop());
        assert!(
            !GenerationRetention {
                keep_last: None,
                older_than_days: Some(30),
            }
            .is_noop()
        );
    }

    #[test]
    fn default_retention_keeps_last_ten() {
        let p = GenerationRetention::default_policy();
        assert_eq!(p.keep_last, Some(10));
        assert_eq!(p.older_than_days, None);
    }

    #[tokio::test]
    async fn prune_noop_policy_is_ok_without_running_nix() {
        // A no-op policy must return Ok without invoking any tool, so it is
        // safe on hosts where nix-env is absent.
        let result = prune_generations(GenerationRetention {
            keep_last: None,
            older_than_days: None,
        })
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn missing_activate_script_fails() {
        let dir = tempfile::tempdir().unwrap();
        let params = ActivationParams {
            toplevel: dir.path().to_str().unwrap().into(),
            activate_script: None,
            action: ActivationAction::Switch,
            retention: None,
        };
        let result = activate_system(&params).await;
        assert!(matches!(
            result,
            Err(ActivationError::ActivateScriptNotFound(_))
        ));
    }
}
