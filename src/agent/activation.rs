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
/// A generation is deleted only when it falls outside *every* configured
/// bound: it is not among the `keep_last` most recent generations, and it is
/// older than `older_than_days`. The current generation is never deleted.
///
/// `nix-env --delete-generations` accepts a single `+N` or `Nd` selector, so
/// combining both bounds cannot be expressed as one selector (`10d +10` is
/// rejected with `invalid generation number '10d'`). Instead the generation
/// set is computed here from the profile links and passed to `nix-env` as
/// explicit generation numbers.
///
/// On flakes-only installs where `nix-env` is absent, falls back to
/// `nix profile wipe-history --older-than`, which only expresses the age bound.
/// That fallback is used only when no count bound is set, because applying the
/// age bound alone would delete generations the count bound must keep.
///
/// Returns without error when the policy is a no-op or nothing is outside the
/// policy. Pruning failures are surfaced as `ProfileFailed` but are non-fatal
/// to activation (the caller logs and continues).
pub async fn prune_generations(policy: GenerationRetention) -> Result<(), ActivationError> {
    if policy.is_noop() {
        return Ok(());
    }

    let profile = Path::new(SYSTEM_PROFILE);
    let (generations, current) = list_generations(profile).await?;
    let doomed = generations_to_delete(&generations, current, policy, std::time::SystemTime::now());
    if doomed.is_empty() {
        tracing::debug!(
            ?policy,
            "No system generations outside the retention policy"
        );
        return Ok(());
    }

    let args = delete_generations_args(SYSTEM_PROFILE, &doomed);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_profile_set("nix-env", &args).await {
        Ok(()) => {
            tracing::info!(?policy, deleted = ?doomed, "Pruned old system generations");
            Ok(())
        }
        Err(ActivationError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            match (policy.keep_last, policy.older_than_days) {
                (None, Some(days)) => {
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
                }
                _ => {
                    tracing::warn!(
                        ?policy,
                        "nix-env absent and `nix profile wipe-history` cannot express a count \
                         bound; generation pruning skipped"
                    );
                }
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

/// A system profile generation found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Generation {
    /// Generation number (`N` in `<profile>-N-link`).
    number: u64,
    /// When the generation link was created (its `lstat` mtime, as Nix uses).
    created: std::time::SystemTime,
}

/// Build the `nix-env` arguments that delete exactly `generations` from
/// `profile`. Each generation is passed as its own explicit number, which
/// `nix-env --delete-generations` accepts in any quantity.
fn delete_generations_args(profile: &str, generations: &[u64]) -> Vec<String> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--delete-generations".to_string(),
    ];
    args.extend(generations.iter().map(u64::to_string));
    args
}

/// Select the generations that fall outside `policy` and may be deleted.
///
/// A generation is kept if any of these hold:
///   - it is `current`;
///   - it is among the `keep_last` highest-numbered generations;
///   - it was created less than `older_than_days` days before `now`, or it is
///     the newest generation created before that cutoff (it was the active
///     generation at the cutoff, matching `nix-env --delete-generations Nd`).
///
/// An unset bound keeps nothing on its own. Returns generation numbers in
/// ascending order.
fn generations_to_delete(
    generations: &[Generation],
    current: Option<u64>,
    policy: GenerationRetention,
    now: std::time::SystemTime,
) -> Vec<u64> {
    if policy.is_noop() {
        return Vec::new();
    }

    let mut sorted: Vec<Generation> = generations.to_vec();
    sorted.sort_by_key(|g| std::cmp::Reverse(g.number)); // newest first

    let cutoff = policy
        .older_than_days
        .map(|days| now - std::time::Duration::from_secs(days.saturating_mul(86_400)));
    // The newest generation older than the cutoff stays, like `nix-env ... Nd`.
    let active_at_cutoff =
        cutoff.and_then(|cutoff| sorted.iter().find(|g| g.created < cutoff).map(|g| g.number));

    let mut doomed: Vec<u64> = sorted
        .iter()
        .enumerate()
        .filter(|(rank, g)| {
            let is_current = current == Some(g.number);
            let kept_by_count = policy.keep_last.is_some_and(|n| (*rank as u64) < n);
            let kept_by_age = cutoff
                .is_some_and(|cutoff| g.created >= cutoff || active_at_cutoff == Some(g.number));
            !is_current && !kept_by_count && !kept_by_age
        })
        .map(|(_, g)| g.number)
        .collect();
    doomed.sort_unstable();
    doomed
}

/// List the generations of `profile` and the generation it currently points at.
///
/// Generations are the `<name>-<N>-link` symlinks next to the profile. The
/// current generation is read from the profile symlink's target.
async fn list_generations(
    profile: &Path,
) -> Result<(Vec<Generation>, Option<u64>), ActivationError> {
    let (Some(dir), Some(name)) = (profile.parent(), profile.file_name()) else {
        return Ok((Vec::new(), None));
    };
    let prefix = format!("{}-", name.to_string_lossy());

    let mut generations = Vec::new();
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let Some(number) = parse_generation_link(&file_name.to_string_lossy(), &prefix) else {
            continue;
        };
        let created = tokio::fs::symlink_metadata(entry.path())
            .await?
            .modified()?;
        generations.push(Generation { number, created });
    }

    let current = tokio::fs::read_link(profile).await.ok().and_then(|target| {
        target
            .file_name()
            .and_then(|f| parse_generation_link(&f.to_string_lossy(), &prefix))
    });

    Ok((generations, current))
}

/// Parse `N` from a `<prefix>N-link` generation link name.
fn parse_generation_link(file_name: &str, prefix: &str) -> Option<u64> {
    file_name
        .strip_prefix(prefix)?
        .strip_suffix("-link")?
        .parse()
        .ok()
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

    fn gen_at(number: u64, now: std::time::SystemTime, days_ago: u64) -> Generation {
        Generation {
            number,
            created: now - std::time::Duration::from_secs(days_ago * 86_400),
        }
    }

    /// Ten generations, numbered 1..=10, generation N created (10 - N) * 3 days
    /// ago, so generation 10 is brand new and generation 1 is 27 days old.
    fn ten_generations(now: std::time::SystemTime) -> Vec<Generation> {
        (1..=10).map(|n| gen_at(n, now, (10 - n) * 3)).collect()
    }

    #[test]
    fn delete_args_pass_each_generation_explicitly() {
        let args = delete_generations_args("/nix/var/nix/profiles/system", &[1, 2, 7]);
        assert_eq!(
            args,
            [
                "--profile",
                "/nix/var/nix/profiles/system",
                "--delete-generations",
                "1",
                "2",
                "7",
            ]
        );
        // No `+N` / `Nd` selectors: nix-env only accepts one of those, alone.
        assert!(
            args[3..]
                .iter()
                .all(|a| a.chars().all(|c| c.is_ascii_digit()))
        );
    }

    #[test]
    fn count_bound_alone_keeps_last_n() {
        let now = std::time::SystemTime::now();
        let policy = GenerationRetention {
            keep_last: Some(3),
            older_than_days: None,
        };
        let doomed = generations_to_delete(&ten_generations(now), Some(10), policy, now);
        assert_eq!(doomed, [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn age_bound_alone_matches_nix_env_days_selector() {
        let now = std::time::SystemTime::now();
        let policy = GenerationRetention {
            keep_last: None,
            older_than_days: Some(10),
        };
        // Generations 7..=10 are 9, 6, 3 and 0 days old. Generation 6 (12 days)
        // was active at the cutoff and is kept, like `nix-env ... 10d`.
        let doomed = generations_to_delete(&ten_generations(now), Some(10), policy, now);
        assert_eq!(doomed, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn both_bounds_delete_only_outside_both() {
        let now = std::time::SystemTime::now();
        let gens = ten_generations(now);

        // Count keeps 8..=10; age keeps 6..=10. Union is 6..=10.
        let policy = GenerationRetention {
            keep_last: Some(3),
            older_than_days: Some(10),
        };
        assert_eq!(
            generations_to_delete(&gens, Some(10), policy, now),
            [1, 2, 3, 4, 5]
        );

        // Count keeps 4..=10; age keeps 9..=10 (8 is active at the cutoff, so
        // it is kept too). The count bound is the wider one here.
        let policy = GenerationRetention {
            keep_last: Some(7),
            older_than_days: Some(4),
        };
        assert_eq!(
            generations_to_delete(&gens, Some(10), policy, now),
            [1, 2, 3]
        );
    }

    #[test]
    fn current_generation_is_never_deleted() {
        let now = std::time::SystemTime::now();
        let policy = GenerationRetention {
            keep_last: Some(1),
            older_than_days: Some(1),
        };
        // The profile points at an old generation (e.g. after a rollback).
        let doomed = generations_to_delete(&ten_generations(now), Some(2), policy, now);
        assert!(!doomed.contains(&2));
        assert!(!doomed.contains(&10));
        // Generation 9 was active at the one-day cutoff, so the age bound keeps it.
        assert_eq!(doomed, [1, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn nothing_outside_policy_deletes_nothing() {
        let now = std::time::SystemTime::now();
        let policy = GenerationRetention {
            keep_last: Some(20),
            older_than_days: Some(1),
        };
        assert!(generations_to_delete(&ten_generations(now), Some(10), policy, now).is_empty());
        assert!(generations_to_delete(&[], None, policy, now).is_empty());
    }

    #[test]
    fn parse_generation_link_names() {
        assert_eq!(parse_generation_link("system-42-link", "system-"), Some(42));
        assert_eq!(parse_generation_link("system-link", "system-"), None);
        assert_eq!(parse_generation_link("system-x-link", "system-"), None);
        assert_eq!(parse_generation_link("other-3-link", "system-"), None);
        assert_eq!(parse_generation_link("system-3", "system-"), None);
    }

    #[tokio::test]
    async fn list_generations_reads_profile_links() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("system");
        for n in [1, 2, 5] {
            std::os::unix::fs::symlink(
                format!("/nix/store/fake-{n}"),
                dir.path().join(format!("system-{n}-link")),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink("system-5-link", &profile).unwrap();
        // Unrelated entries are ignored.
        std::fs::write(dir.path().join("system-9-link.tmp"), "").unwrap();
        std::os::unix::fs::symlink("/nix/store/x", dir.path().join("other-3-link")).unwrap();

        let (gens, current) = list_generations(&profile).await.unwrap();
        let mut numbers: Vec<u64> = gens.iter().map(|g| g.number).collect();
        numbers.sort_unstable();
        assert_eq!(numbers, [1, 2, 5]);
        assert_eq!(current, Some(5));
    }
}
