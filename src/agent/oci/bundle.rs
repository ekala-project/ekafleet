//! OCI runtime bundle generation for systemd-nspawn.
//!
//! Generates the `config.json` for an OCI bundle from an image's
//! container configuration and ekafleet service parameters.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use super::manifest::ImageConfig;

/// Generate an OCI runtime bundle `config.json` from an image config
/// and ekafleet service parameters.
///
/// The bundle directory must already contain a `rootfs/` subdirectory
/// with the unpacked image layers.
pub async fn write_bundle_config(
    bundle_dir: &Path,
    image_config: &ImageConfig,
    extra_env: &HashMap<String, String>,
    extra_mounts: &[BindMount],
) -> Result<(), BundleError> {
    let cc = image_config.config.as_ref();

    // Build environment
    let mut env: Vec<String> = cc.and_then(|c| c.env.clone()).unwrap_or_default();
    for (k, v) in extra_env {
        env.push(format!("{k}={v}"));
    }

    // Build args (entrypoint + cmd)
    let mut args: Vec<String> = cc.and_then(|c| c.entrypoint.clone()).unwrap_or_default();
    if let Some(cmd) = cc.and_then(|c| c.cmd.clone()) {
        args.extend(cmd);
    }
    if args.is_empty() {
        return Err(BundleError::NoEntrypoint);
    }

    // Working directory
    let cwd = cc
        .and_then(|c| c.working_dir.clone())
        .unwrap_or_else(|| "/".to_string());

    // Build mounts
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
            args,
            env,
            cwd,
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

    let json = serde_json::to_string_pretty(&spec)?;
    tokio::fs::write(bundle_dir.join("config.json"), json).await?;

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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
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

        let mut extra_env = HashMap::new();
        extra_env.insert(
            "SPIFFE_ENDPOINT_SOCKET".to_string(),
            "unix:///run/ekafleet/workload-api.sock".to_string(),
        );

        let mounts = vec![BindMount {
            host_path: "/run/ekafleet/workload-api.sock".to_string(),
            container_path: "/run/ekafleet/workload-api.sock".to_string(),
            read_only: true,
        }];

        write_bundle_config(bundle, &image_config, &extra_env, &mounts)
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

    #[tokio::test]
    async fn no_entrypoint_errors() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path();
        tokio::fs::create_dir_all(bundle.join("rootfs"))
            .await
            .unwrap();

        let image_config = ImageConfig::default();
        let result = write_bundle_config(bundle, &image_config, &HashMap::new(), &[]).await;
        assert!(result.is_err());
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
