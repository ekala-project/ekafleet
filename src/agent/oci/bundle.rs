//! OCI runtime bundle generation for systemd-nspawn.
//!
//! Generates the `config.json` for an OCI bundle from an image's
//! container configuration and ekafleet service parameters.

use std::path::Path;

use serde::Serialize;

use super::manifest::ImageConfig;

/// The PATH of images that set none.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Service-level overrides of the image's process configuration.
#[derive(Debug, Clone, Default)]
pub struct ProcessOverrides {
    /// Replaces the image ENTRYPOINT (and drops its CMD unless `args` is set).
    pub entrypoint: Option<Vec<String>>,
    /// Replaces the image CMD.
    pub args: Option<Vec<String>>,
    /// Replaces the image working directory.
    pub working_dir: Option<String>,
    /// Added to (and overriding) the image environment, in order.
    pub env: Vec<(String, String)>,
}

/// The identity the container process runs as.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessUser {
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

/// The process a bundle runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub user: ProcessUser,
}

/// Combine the image configuration with service overrides, resolving the
/// image's `User` against the image's own `/etc/passwd` and `/etc/group`.
pub fn process_spec(
    image: &ImageConfig,
    overrides: &ProcessOverrides,
    rootfs: &Path,
) -> Result<ProcessSpec, BundleError> {
    let cc = image.config.as_ref();

    let (entrypoint, cmd) = match &overrides.entrypoint {
        // A new entrypoint does not inherit the image's arguments for the old one.
        Some(entrypoint) => (entrypoint.clone(), Vec::new()),
        None => (
            cc.and_then(|c| c.entrypoint.clone()).unwrap_or_default(),
            cc.and_then(|c| c.cmd.clone()).unwrap_or_default(),
        ),
    };
    let mut args = entrypoint;
    args.extend(overrides.args.clone().unwrap_or(cmd));
    if args.is_empty() {
        return Err(BundleError::NoEntrypoint);
    }

    let mut env: Vec<String> = cc.and_then(|c| c.env.clone()).unwrap_or_default();
    // Like other runtimes, give images that set no PATH the conventional one.
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.insert(0, format!("PATH={DEFAULT_PATH}"));
    }
    for (key, value) in &overrides.env {
        let prefix = format!("{key}=");
        env.retain(|e| !e.starts_with(&prefix));
        env.push(format!("{key}={value}"));
    }

    let cwd = overrides
        .working_dir
        .clone()
        .or_else(|| cc.and_then(|c| c.working_dir.clone()))
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "/".to_string());

    let user = resolve_user(rootfs, cc.and_then(|c| c.user.as_deref()).unwrap_or(""))?;
    Ok(ProcessSpec {
        args,
        env,
        cwd,
        user,
    })
}

/// Generate an OCI runtime bundle `config.json` for `process`.
///
/// The bundle directory must already contain a `rootfs/` subdirectory
/// with the unpacked image layers.
pub async fn write_bundle_config(
    bundle_dir: &Path,
    process: &ProcessSpec,
    extra_mounts: &[BindMount],
) -> Result<(), BundleError> {
    let mut mounts = default_mounts();
    for bind in extra_mounts {
        mounts.push(OciMount {
            destination: bind.container_path.clone(),
            source: Some(bind.host_path.clone()),
            type_: Some("bind".to_string()),
            options: Some(bind_options(bind.read_only)),
        });
    }

    let spec = OciSpec {
        oci_version: "1.0.0".to_string(),
        root: OciRoot {
            path: "rootfs".to_string(),
            readonly: false,
        },
        process: OciProcess {
            args: process.args.clone(),
            env: process.env.clone(),
            cwd: process.cwd.clone(),
            user: process.user.clone(),
            terminal: false,
            no_new_privileges: true,
            capabilities: Some(default_capabilities()),
        },
        mounts,
        linux: Some(OciLinux {
            namespaces: default_namespaces(),
            seccomp: Some(default_seccomp()),
        }),
    };

    let json = serde_json::to_vec_pretty(&spec)?;
    let path = bundle_dir.join("config.json");
    // Unchanged configs are left alone.
    if tokio::fs::read(&path).await.ok().as_deref() == Some(json.as_slice()) {
        return Ok(());
    }
    let tmp = bundle_dir.join("config.json.tmp");
    tokio::fs::write(&tmp, &json).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

/// A bind mount to inject into the container.
#[derive(Debug, Clone)]
pub struct BindMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("image has no entrypoint or cmd")]
    NoEntrypoint,
    #[error("image user {0:?} is not in the image's /etc/passwd")]
    UnknownUser(String),
    #[error("image group {0:?} is not in the image's /etc/group")]
    UnknownGroup(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Resolve an image `User` (`user`, `uid`, `user:group`, `uid:gid`), the way
/// container runtimes do: names are looked up in the image's own account
/// files; a user without a group runs with its primary group (0 for a uid
/// unknown to the image) plus the groups listing it as a member.
pub fn resolve_user(rootfs: &Path, user: &str) -> Result<ProcessUser, BundleError> {
    if user.is_empty() {
        return Ok(ProcessUser::default());
    }
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    let passwd = read_image_file(rootfs, "passwd");
    let groups = read_image_file(rootfs, "group");

    // passwd: name:x:uid:gid:...
    let account = passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let (name, uid, gid) = (fields.first()?, fields.get(2)?, fields.get(3)?);
        let (uid, gid) = (uid.parse::<u32>().ok()?, gid.parse::<u32>().ok()?);
        let matches = match user_part.parse::<u32>() {
            Ok(wanted) => uid == wanted,
            Err(_) => *name == user_part,
        };
        matches.then(|| (name.to_string(), uid, gid))
    });
    let (name, uid, primary_gid) = match (user_part.parse::<u32>(), account) {
        (_, Some(account)) => (Some(account.0), account.1, account.2),
        (Ok(uid), None) => (None, uid, 0),
        (Err(_), None) => return Err(BundleError::UnknownUser(user_part.to_string())),
    };

    // group: name:x:gid:member,member
    let group_entries: Vec<(String, u32, Vec<String>)> = groups
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let gid = fields.get(2)?.parse::<u32>().ok()?;
            let members = fields
                .get(3)
                .map(|m| {
                    m.split(',')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            Some((fields.first()?.to_string(), gid, members))
        })
        .collect();

    match group_part {
        Some(group) => {
            let gid = match group.parse::<u32>() {
                Ok(gid) => gid,
                Err(_) => group_entries
                    .iter()
                    .find(|(n, _, _)| n == group)
                    .map(|(_, gid, _)| *gid)
                    .ok_or_else(|| BundleError::UnknownGroup(group.to_string()))?,
            };
            Ok(ProcessUser {
                uid,
                gid,
                additional_gids: Vec::new(),
            })
        }
        None => {
            let mut additional_gids: Vec<u32> = match &name {
                Some(name) => group_entries
                    .iter()
                    .filter(|(_, gid, members)| *gid != primary_gid && members.contains(name))
                    .map(|(_, gid, _)| *gid)
                    .collect(),
                None => Vec::new(),
            };
            additional_gids.dedup();
            Ok(ProcessUser {
                uid,
                gid: primary_gid,
                additional_gids,
            })
        }
    }
}

/// Largest account file read from an image.
const MAX_ACCOUNT_FILE: u64 = 1 << 20;

/// The image's `/etc/<name>`, or empty when it is missing or not a regular
/// file in a real `/etc` directory (an image could point either at the host).
fn read_image_file(rootfs: &Path, name: &str) -> String {
    use std::io::Read;
    let etc = rootfs.join("etc");
    let real_dir = std::fs::symlink_metadata(&etc).is_ok_and(|m| m.is_dir());
    let path = etc.join(name);
    if !real_dir || !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
        return String::new();
    }
    let mut out = String::new();
    if let Ok(file) = std::fs::File::open(&path) {
        let _ = file.take(MAX_ACCOUNT_FILE).read_to_string(&mut out);
    }
    out
}

// ---------------------------------------------------------------------------
// OCI runtime spec subset (just enough for systemd-nspawn --oci-bundle)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciSpec {
    oci_version: String,
    root: OciRoot,
    process: OciProcess,
    mounts: Vec<OciMount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    linux: Option<OciLinux>,
}

#[derive(Serialize)]
struct OciRoot {
    path: String,
    readonly: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciProcess {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    user: ProcessUser,
    terminal: bool,
    no_new_privileges: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<OciCapabilities>,
}

#[derive(Serialize)]
struct OciMount {
    destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Vec<String>>,
}

#[derive(Serialize)]
struct OciLinux {
    namespaces: Vec<OciNamespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seccomp: Option<OciSeccomp>,
}

#[derive(Serialize)]
struct OciNamespace {
    #[serde(rename = "type")]
    type_: String,
}

/// OCI capabilities configuration.
#[derive(Serialize)]
struct OciCapabilities {
    bounding: Vec<String>,
    effective: Vec<String>,
    inheritable: Vec<String>,
    permitted: Vec<String>,
    ambient: Vec<String>,
}

/// OCI seccomp filter configuration.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciSeccomp {
    default_action: String,
    architectures: Vec<String>,
    syscalls: Vec<OciSyscallRule>,
}

#[derive(Serialize)]
struct OciSyscallRule {
    names: Vec<String>,
    action: String,
}

fn default_mounts() -> Vec<OciMount> {
    vec![
        OciMount {
            destination: "/proc".to_string(),
            source: Some("proc".to_string()),
            type_: Some("proc".to_string()),
            options: None,
        },
        OciMount {
            destination: "/dev".to_string(),
            source: Some("tmpfs".to_string()),
            type_: Some("tmpfs".to_string()),
            options: Some(vec![
                "nosuid".to_string(),
                "strictatime".to_string(),
                "mode=755".to_string(),
                "size=65536k".to_string(),
            ]),
        },
        OciMount {
            destination: "/sys".to_string(),
            source: Some("sysfs".to_string()),
            type_: Some("sysfs".to_string()),
            options: Some(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "ro".to_string(),
            ]),
        },
    ]
}

fn default_namespaces() -> Vec<OciNamespace> {
    ["pid", "ipc", "uts", "mount"]
        .into_iter()
        .map(|t| OciNamespace {
            type_: t.to_string(),
        })
        .collect()
}

/// Minimal capability set for hardened containers.
///
/// Drops all capabilities except the bare minimum needed for most services.
/// This follows the Docker/OCI default set minus the more dangerous ones
/// (e.g., NET_RAW, SYS_CHROOT).
fn default_capabilities() -> OciCapabilities {
    let caps: Vec<String> = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_KILL",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    OciCapabilities {
        bounding: caps.clone(),
        effective: caps.clone(),
        inheritable: caps.clone(),
        permitted: caps.clone(),
        ambient: caps,
    }
}

/// Default seccomp profile blocking dangerous syscalls.
///
/// Uses a default-allow policy with explicit blocks for syscalls that
/// enable privilege escalation or container escape. This mirrors the
/// Docker default seccomp profile's most critical restrictions.
fn default_seccomp() -> OciSeccomp {
    OciSeccomp {
        default_action: "SCMP_ACT_ALLOW".to_string(),
        architectures: vec![
            "SCMP_ARCH_X86_64".to_string(),
            "SCMP_ARCH_AARCH64".to_string(),
        ],
        syscalls: vec![OciSyscallRule {
            names: vec![
                "kexec_load".to_string(),
                "kexec_file_load".to_string(),
                "reboot".to_string(),
                "mount".to_string(),
                "umount2".to_string(),
                "pivot_root".to_string(),
                "swapon".to_string(),
                "swapoff".to_string(),
                "init_module".to_string(),
                "finit_module".to_string(),
                "delete_module".to_string(),
                "acct".to_string(),
                "settimeofday".to_string(),
                "clock_settime".to_string(),
                "add_key".to_string(),
                "request_key".to_string(),
                "keyctl".to_string(),
                "bpf".to_string(),
                "perf_event_open".to_string(),
                "unshare".to_string(),
                "setns".to_string(),
            ],
            action: "SCMP_ACT_ERRNO".to_string(),
        }],
    }
}

fn bind_options(read_only: bool) -> Vec<String> {
    let mut opts = vec!["bind".to_string()];
    if read_only {
        opts.push("ro".to_string());
    }
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent::oci::manifest::ContainerConfig;

    #[tokio::test]
    async fn generates_config_json() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path();
        tokio::fs::create_dir_all(bundle.join("rootfs"))
            .await
            .unwrap();

        let image_config = ImageConfig {
            config: Some(ContainerConfig {
                entrypoint: Some(vec!["/app/server".to_string()]),
                cmd: Some(vec!["--port".to_string(), "8080".to_string()]),
                env: Some(vec!["HOME=/app".to_string()]),
                working_dir: Some("/app".to_string()),
                user: None,
                labels: None,
            }),
            architecture: Some("amd64".to_string()),
            os: Some("linux".to_string()),
        };

        let overrides = ProcessOverrides {
            env: vec![(
                "SPIFFE_ENDPOINT_SOCKET".to_string(),
                "unix:///run/ekafleet/workload-api.sock".to_string(),
            )],
            ..Default::default()
        };
        let process = process_spec(&image_config, &overrides, &bundle.join("rootfs")).unwrap();

        let mounts = vec![BindMount {
            host_path: "/run/ekafleet/workload-api.sock".to_string(),
            container_path: "/run/ekafleet/workload-api.sock".to_string(),
            read_only: true,
        }];

        write_bundle_config(bundle, &process, &mounts)
            .await
            .unwrap();

        let config_str = tokio::fs::read_to_string(bundle.join("config.json"))
            .await
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(&config_str).unwrap();

        assert_eq!(config["ociVersion"], "1.0.0");
        assert_eq!(config["root"]["path"], "rootfs");

        let args = config["process"]["args"].as_array().unwrap();
        assert_eq!(args[0], "/app/server");
        assert_eq!(args[1], "--port");
        assert_eq!(args[2], "8080");

        let env = config["process"]["env"].as_array().unwrap();
        let env_strs: Vec<&str> = env.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(env_strs.contains(&"HOME=/app"));
        assert!(
            env_strs
                .iter()
                .any(|e| e.starts_with("SPIFFE_ENDPOINT_SOCKET="))
        );

        // Check bind mount present
        let mounts = config["mounts"].as_array().unwrap();
        let spiffe_mount = mounts
            .iter()
            .find(|m| m["destination"] == "/run/ekafleet/workload-api.sock");
        assert!(spiffe_mount.is_some());

        // Check hardening: noNewPrivileges
        assert_eq!(config["process"]["noNewPrivileges"], true);

        // Check hardening: capabilities are restricted
        let caps = &config["process"]["capabilities"];
        let bounding = caps["bounding"].as_array().unwrap();
        assert!(bounding.iter().any(|c| c == "CAP_NET_BIND_SERVICE"));
        // Dangerous caps should NOT be present
        let cap_strs: Vec<&str> = bounding.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(!cap_strs.contains(&"CAP_SYS_ADMIN"));
        assert!(!cap_strs.contains(&"CAP_NET_RAW"));
        assert!(!cap_strs.contains(&"CAP_SYS_PTRACE"));

        // Check hardening: seccomp profile present
        let seccomp = &config["linux"]["seccomp"];
        assert_eq!(seccomp["defaultAction"], "SCMP_ACT_ALLOW");
        let blocked = &seccomp["syscalls"][0];
        assert_eq!(blocked["action"], "SCMP_ACT_ERRNO");
        let blocked_names = blocked["names"].as_array().unwrap();
        let blocked_strs: Vec<&str> = blocked_names.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(blocked_strs.contains(&"kexec_load"));
        assert!(blocked_strs.contains(&"bpf"));
        assert!(blocked_strs.contains(&"unshare"));
    }

    #[test]
    fn no_entrypoint_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = process_spec(
            &ImageConfig::default(),
            &ProcessOverrides::default(),
            dir.path(),
        );
        assert!(matches!(result, Err(BundleError::NoEntrypoint)));
    }

    fn image(entrypoint: &[&str], cmd: &[&str], env: &[&str], user: Option<&str>) -> ImageConfig {
        let strings = |v: &[&str]| Some(v.iter().map(|s| s.to_string()).collect());
        ImageConfig {
            config: Some(ContainerConfig {
                entrypoint: strings(entrypoint),
                cmd: strings(cmd),
                env: strings(env),
                working_dir: Some("/app".to_string()),
                user: user.map(String::from),
                labels: None,
            }),
            architecture: None,
            os: None,
        }
    }

    #[test]
    fn service_overrides_replace_image_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let img = image(
            &["/bin/server"],
            &["--port", "80"],
            &["PATH=/bin", "MODE=image"],
            None,
        );
        let strings = |v: &[&str]| Some(v.iter().map(|s| s.to_string()).collect::<Vec<_>>());

        // Image defaults.
        let p = process_spec(&img, &ProcessOverrides::default(), dir.path()).unwrap();
        assert_eq!(p.args, ["/bin/server", "--port", "80"]);
        assert_eq!(p.cwd, "/app");
        assert_eq!(p.user, ProcessUser::default());

        // args replace CMD only.
        let p = process_spec(
            &img,
            &ProcessOverrides {
                args: strings(&["--port", "8080"]),
                ..Default::default()
            },
            dir.path(),
        )
        .unwrap();
        assert_eq!(p.args, ["/bin/server", "--port", "8080"]);

        // A new entrypoint drops the image CMD.
        let p = process_spec(
            &img,
            &ProcessOverrides {
                entrypoint: strings(&["/bin/sh", "-c"]),
                working_dir: Some("/srv".to_string()),
                env: vec![
                    ("MODE".to_string(), "service".to_string()),
                    ("EXTRA".to_string(), "1".to_string()),
                ],
                ..Default::default()
            },
            dir.path(),
        )
        .unwrap();
        assert_eq!(p.args, ["/bin/sh", "-c"]);
        assert_eq!(p.cwd, "/srv");
        assert_eq!(p.env, ["PATH=/bin", "MODE=service", "EXTRA=1"]);
    }

    fn rootfs_with_accounts(passwd: &str, group: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/passwd"), passwd).unwrap();
        std::fs::write(dir.path().join("etc/group"), group).unwrap();
        dir
    }

    #[test]
    fn image_users_resolve_against_the_image_account_files() {
        let root = rootfs_with_accounts(
            "root:x:0:0::/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n",
            "root:x:0:\napp:x:1000:\naudio:x:29:app,other\nstaff:x:50:\n",
        );
        let r = |user: &str| resolve_user(root.path(), user);
        let user = |uid, gid, additional_gids: Vec<u32>| ProcessUser {
            uid,
            gid,
            additional_gids,
        };

        assert_eq!(r("").unwrap(), user(0, 0, vec![]));
        assert_eq!(r("app").unwrap(), user(1000, 1000, vec![29]));
        assert_eq!(r("1000").unwrap(), user(1000, 1000, vec![29]));
        assert_eq!(r("app:staff").unwrap(), user(1000, 50, vec![]));
        assert_eq!(r("1000:7").unwrap(), user(1000, 7, vec![]));
        // A uid unknown to the image runs with group 0, as with Docker.
        assert_eq!(r("4242").unwrap(), user(4242, 0, vec![]));
        assert!(matches!(r("nobody"), Err(BundleError::UnknownUser(_))));
        assert!(matches!(r("app:wheel"), Err(BundleError::UnknownGroup(_))));
    }

    #[test]
    fn account_files_behind_symlinks_are_ignored() {
        let host = rootfs_with_accounts("app:x:1000:1000::/:/bin/sh\n", "");
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(host.path().join("etc"), root.path().join("etc")).unwrap();
        assert!(matches!(
            resolve_user(root.path(), "app"),
            Err(BundleError::UnknownUser(_))
        ));

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        std::os::unix::fs::symlink(
            host.path().join("etc/passwd"),
            root.path().join("etc/passwd"),
        )
        .unwrap();
        assert!(resolve_user(root.path(), "app").is_err());
    }

    #[tokio::test]
    async fn config_json_carries_the_user_and_is_rewritten_only_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let process = ProcessSpec {
            args: vec!["/bin/app".into()],
            env: vec![],
            cwd: "/".into(),
            user: ProcessUser {
                uid: 1000,
                gid: 1000,
                additional_gids: vec![29],
            },
        };
        write_bundle_config(dir.path(), &process, &[])
            .await
            .unwrap();
        let path = dir.path().join("config.json");
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            config["process"]["user"],
            serde_json::json!({"uid": 1000, "gid": 1000, "additionalGids": [29]})
        );

        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_bundle_config(dir.path(), &process, &[])
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
    }

    #[test]
    fn capabilities_sets_are_identical() {
        let caps = default_capabilities();
        assert_eq!(caps.bounding, caps.effective);
        assert_eq!(caps.bounding, caps.inheritable);
        assert_eq!(caps.bounding, caps.permitted);
        assert_eq!(caps.bounding, caps.ambient);
    }

    #[test]
    fn capabilities_minimal_set() {
        let caps = default_capabilities();
        let set = &caps.bounding;

        // Expected capabilities present
        assert!(set.contains(&"CAP_CHOWN".to_string()));
        assert!(set.contains(&"CAP_DAC_OVERRIDE".to_string()));
        assert!(set.contains(&"CAP_FSETID".to_string()));
        assert!(set.contains(&"CAP_FOWNER".to_string()));
        assert!(set.contains(&"CAP_SETGID".to_string()));
        assert!(set.contains(&"CAP_SETUID".to_string()));
        assert!(set.contains(&"CAP_SETFCAP".to_string()));
        assert!(set.contains(&"CAP_SETPCAP".to_string()));
        assert!(set.contains(&"CAP_NET_BIND_SERVICE".to_string()));
        assert!(set.contains(&"CAP_KILL".to_string()));
        assert_eq!(set.len(), 10);

        // Dangerous capabilities must NOT be present
        let dangerous = [
            "CAP_SYS_ADMIN",
            "CAP_NET_RAW",
            "CAP_SYS_PTRACE",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_BOOT",
            "CAP_SYS_TIME",
            "CAP_MKNOD",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
        ];
        for cap in dangerous {
            assert!(
                !set.contains(&cap.to_string()),
                "{cap} should not be in the capability set"
            );
        }
    }

    #[test]
    fn seccomp_blocks_dangerous_syscalls() {
        let seccomp = default_seccomp();
        assert_eq!(seccomp.default_action, "SCMP_ACT_ALLOW");
        assert!(
            seccomp
                .architectures
                .contains(&"SCMP_ARCH_X86_64".to_string())
        );
        assert!(
            seccomp
                .architectures
                .contains(&"SCMP_ARCH_AARCH64".to_string())
        );

        assert_eq!(seccomp.syscalls.len(), 1);
        let rule = &seccomp.syscalls[0];
        assert_eq!(rule.action, "SCMP_ACT_ERRNO");

        let blocked = &rule.names;
        let expected_blocked = [
            "kexec_load",
            "kexec_file_load",
            "reboot",
            "mount",
            "umount2",
            "pivot_root",
            "swapon",
            "swapoff",
            "init_module",
            "finit_module",
            "delete_module",
            "acct",
            "settimeofday",
            "clock_settime",
            "add_key",
            "request_key",
            "keyctl",
            "bpf",
            "perf_event_open",
            "unshare",
            "setns",
        ];
        for syscall in expected_blocked {
            assert!(
                blocked.contains(&syscall.to_string()),
                "{syscall} should be blocked by seccomp"
            );
        }
        assert_eq!(blocked.len(), expected_blocked.len());
    }

    #[test]
    fn default_namespaces_excludes_net_and_user() {
        let ns = default_namespaces();
        let types: Vec<&str> = ns.iter().map(|n| n.type_.as_str()).collect();

        // Must include
        assert!(types.contains(&"pid"));
        assert!(types.contains(&"ipc"));
        assert!(types.contains(&"uts"));
        assert!(types.contains(&"mount"));

        // Must NOT include (host networking, no rootless)
        assert!(!types.contains(&"net"));
        assert!(!types.contains(&"user"));
    }
}
