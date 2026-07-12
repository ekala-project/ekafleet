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
        },
        mounts,
        linux: Some(OciLinux {
            namespaces: default_namespaces(),
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
struct OciProcess {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    terminal: bool,
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
}

#[derive(Serialize)]
struct OciNamespace {
    #[serde(rename = "type")]
    type_: String,
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
}
