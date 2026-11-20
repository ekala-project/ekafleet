//! Network policy enforcement with nftables.
//!
//! The agent keeps the latest [`PolicyUpdate`] from the server and renders
//! it into an `inet ekafleet` table of its own: one in the host namespace
//! for host-networked services, and one in each namespace network whose
//! services have a policy. Every rule only ever drops traffic: the chains
//! accept by default, so the host's own firewall (NixOS's) still decides
//! everything else, and services without a policy stay as reachable as
//! before.
//!
//! - **Ingress**: traffic to a protected service's ports from another node
//!   (over `wg-fleet`, or into its namespace network) is dropped unless its
//!   source is listed. Same-node traffic (loopback) is not filtered.
//! - **Egress**: packets sent by a service's processes, matched by its
//!   systemd unit's cgroup (`socket cgroupv2`), go through its rules in
//!   order; unmatched ones are dropped. Loopback and replies on established
//!   connections pass.
//!
//! nftables resolves a cgroup path when the rule is loaded, and a restarted
//! unit gets a new cgroup, so [`PolicyEnforcer::refresh`] re-renders
//! periodically and reloads whenever the set of cgroups changed. A
//! service's egress rules wait until its cgroup exists.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Stdio;

use tokio::sync::Mutex;

use crate::proto::{EgressPolicy, IngressPolicy, PolicyUpdate};

/// The table every rule lives in, in each network namespace.
const TABLE: &str = "ekafleet";

/// The mesh interface other nodes' traffic arrives on.
const MESH_IFACE: &str = "wg-fleet";

/// Where the unified cgroup hierarchy is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("nft command failed: {0}")]
    Command(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Applies the node's network policy.
#[derive(Default)]
pub struct PolicyEnforcer {
    state: Mutex<EnforcerState>,
}

#[derive(Default)]
struct EnforcerState {
    policy: PolicyUpdate,
    /// Whether the host table was loaded since the agent started (clearing
    /// rules a previous run left behind).
    host_loaded: bool,
    /// What was last loaded into each namespace (`None`: the host's): the
    /// ruleset and the cgroup inodes it resolved.
    applied: BTreeMap<Option<String>, (String, Vec<u64>)>,
}

/// A service's unit cgroup: path below [`CGROUP_ROOT`], depth, inode.
#[derive(Debug, Clone, PartialEq)]
pub struct Cgroup {
    pub path: String,
    pub level: usize,
    pub inode: u64,
}

impl PolicyEnforcer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the policy and apply it.
    pub async fn set(&self, policy: PolicyUpdate) {
        tracing::debug!(
            ingress = policy.ingress.len(),
            egress = policy.egress.len(),
            "Received network policy"
        );
        self.state.lock().await.policy = policy;
        self.refresh().await;
    }

    /// Render the current policy and load each namespace's rules that
    /// changed (including services whose cgroup appeared or was replaced).
    pub async fn refresh(&self) {
        let mut state = self.state.lock().await;
        let policy = state.policy.clone();
        let mut targets: BTreeMap<Option<String>, (Vec<&IngressPolicy>, Vec<&EgressPolicy>)> =
            BTreeMap::new();
        targets.entry(None).or_default();
        for p in &policy.ingress {
            targets
                .entry(namespace_of(&p.namespace))
                .or_default()
                .0
                .push(p);
        }
        for p in &policy.egress {
            targets
                .entry(namespace_of(&p.namespace))
                .or_default()
                .1
                .push(p);
        }
        // Namespaces that had rules and no longer do get an empty ruleset.
        let stale: Vec<Option<String>> = state
            .applied
            .keys()
            .filter(|ns| !targets.contains_key(*ns))
            .cloned()
            .collect();

        let mut loaded = Vec::new();
        for (namespace, (ingress, egress)) in targets
            .into_iter()
            .chain(stale.into_iter().map(|ns| (ns, (Vec::new(), Vec::new()))))
        {
            let cgroups: Vec<Option<Cgroup>> = egress
                .iter()
                .map(|p| service_cgroup(Path::new(CGROUP_ROOT), &p.service))
                .collect();
            let with_cgroups: Vec<(&EgressPolicy, &Cgroup)> = egress
                .iter()
                .zip(&cgroups)
                .filter_map(|(p, c)| c.as_ref().map(|c| (*p, c)))
                .collect();
            for (policy, cgroup) in egress.iter().zip(&cgroups) {
                if cgroup.is_none() {
                    tracing::debug!(service = %policy.service, "No cgroup yet; egress rules wait for it");
                }
            }
            let ruleset = render(namespace.is_some(), &ingress, &with_cgroups);
            let inodes: Vec<u64> = with_cgroups.iter().map(|(_, c)| c.inode).collect();
            let unchanged = match state.applied.get(&namespace) {
                Some(applied) => *applied == (ruleset.clone(), inodes.clone()),
                // Nothing loaded: an empty ruleset changes nothing, except
                // on the host once, for a previous run's leftovers.
                None => ruleset == empty_ruleset() && (namespace.is_some() || state.host_loaded),
            };
            if unchanged {
                continue;
            }
            loaded.push((namespace, ruleset, inodes));
        }
        for (namespace, ruleset, inodes) in loaded {
            let netns = namespace
                .as_ref()
                .map(|ns| format!("/run/netns/ekafleet-{ns}"));
            if let Some(path) = &netns
                && !Path::new(path).exists()
            {
                // Not set up yet (or gone with its rules): retry later.
                state.applied.remove(&namespace);
                continue;
            }
            match apply_ruleset(netns.as_deref(), &ruleset).await {
                Ok(()) => {
                    tracing::info!(namespace = ?namespace, "Network policy applied");
                    if namespace.is_none() {
                        state.host_loaded = true;
                    }
                    if ruleset == empty_ruleset() {
                        state.applied.remove(&namespace);
                    } else {
                        state.applied.insert(namespace, (ruleset, inodes));
                    }
                }
                Err(e) => {
                    tracing::error!(namespace = ?namespace, error = %e, "Network policy not applied");
                }
            }
        }
    }
}

fn namespace_of(namespace: &str) -> Option<String> {
    (!crate::agent::netns::is_default_namespace(namespace)).then(|| namespace.to_string())
}

/// The cgroup of the unit running `service`, in the default slice or the
/// one units with resource controls use.
pub fn service_cgroup(root: &Path, service: &str) -> Option<Cgroup> {
    use std::os::unix::fs::MetadataExt;
    if crate::ca::validate_identity_name(service).is_err() {
        return None;
    }
    let unit = format!("ekafleet-{service}.service");
    ["system.slice", "system.slice/system-ekafleet.slice"]
        .iter()
        .find_map(|slice| {
            let path = format!("{slice}/{unit}");
            let meta = std::fs::metadata(root.join(&path)).ok()?;
            meta.is_dir().then(|| Cgroup {
                level: path.split('/').count(),
                path,
                inode: meta.ino(),
            })
        })
}

/// A ruleset that removes the table.
fn empty_ruleset() -> String {
    format!("table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// A comment naming a service (names are validated; this keeps any other
/// character out of the ruleset).
fn comment(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
        .take(128)
        .collect()
}

fn ports(ports: &[u32]) -> Option<String> {
    let ports: BTreeSet<u16> = ports
        .iter()
        .filter_map(|p| u16::try_from(*p).ok().filter(|p| *p != 0))
        .collect();
    (!ports.is_empty()).then(|| {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    })
}

/// The ruleset replacing the table in one namespace, atomically. Addresses
/// and CIDRs that do not parse are left out (a source that does not parse
/// is not allowed).
pub fn render(
    namespaced: bool,
    ingress: &[&IngressPolicy],
    egress: &[(&EgressPolicy, &Cgroup)],
) -> String {
    if ingress.is_empty() && egress.is_empty() {
        return empty_ruleset();
    }
    let mut out = empty_ruleset();
    out.push_str(&format!("table inet {TABLE} {{\n"));

    out.push_str(
        "    chain ingress {\n        type filter hook input priority filter - 1; policy accept;\n",
    );
    if namespaced {
        out.push_str("        iif \"lo\" accept\n");
    }
    for policy in ingress {
        let Some(ports) = ports(&policy.ports) else {
            continue;
        };
        let to = if namespaced {
            match policy.dest_ip.parse::<Ipv4Addr>() {
                Ok(ip) => format!("ip daddr {ip}"),
                Err(_) => continue,
            }
        } else {
            format!("iifname \"{MESH_IFACE}\"")
        };
        let sources: BTreeSet<Ipv4Addr> = policy
            .allowed_sources
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let except = if sources.is_empty() {
            String::new()
        } else {
            format!(
                " ip saddr != {{ {} }}",
                sources
                    .iter()
                    .map(Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        out.push_str(&format!(
            "        {to} meta l4proto {{ tcp, udp }} th dport {{ {ports} }}{except} drop comment \"{}\"\n",
            comment(&policy.service)
        ));
    }
    out.push_str("    }\n");

    out.push_str(
        "    chain egress {\n        type filter hook output priority filter - 1; policy accept;\n",
    );
    if !egress.is_empty() {
        out.push_str("        oif \"lo\" accept\n        ct state established,related accept\n");
    }
    for (policy, cgroup) in egress {
        let path: String = cgroup
            .path
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '\\'))
            .collect();
        let socket = format!("socket cgroupv2 level {} \"{path}\"", cgroup.level);
        let name = comment(&policy.service);
        for rule in &policy.rules {
            let Ok((addr, len)) = crate::config::parse_ipv4_cidr(&rule.dest_cidr) else {
                continue;
            };
            let dport = match ports(&rule.dest_ports) {
                Some(ports) => format!(" meta l4proto {{ tcp, udp }} th dport {{ {ports} }}"),
                None if rule.dest_ports.is_empty() => String::new(),
                // Only invalid ports: matching every port would widen it.
                None => continue,
            };
            let verdict = if rule.allow { "accept" } else { "drop" };
            out.push_str(&format!(
                "        {socket} ip daddr {addr}/{len}{dport} {verdict} comment \"{name}\"\n"
            ));
        }
        out.push_str(&format!(
            "        {socket} drop comment \"{name} default\"\n"
        ));
    }
    out.push_str("    }\n}\n");
    out
}

/// Load `ruleset` with `nft -f -`, inside the network namespace at `netns`
/// if given. `nsenter` switches only the network namespace, so cgroup paths
/// still resolve against the host's cgroup mount.
pub(crate) async fn apply_ruleset(netns: Option<&str>, ruleset: &str) -> Result<(), NftError> {
    use tokio::io::AsyncWriteExt;

    let mut command = match netns {
        Some(netns) => {
            let mut c = tokio::process::Command::new("nsenter");
            c.arg(format!("--net={netns}")).args(["nft", "-f", "-"]);
            c
        }
        None => {
            let mut c = tokio::process::Command::new("nft");
            c.args(["-f", "-"]);
            c
        }
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(ruleset.as_bytes()).await?;
    }
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(NftError::Command(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::EgressRuleSpec;

    fn ingress(service: &str, dest_ip: &str, ports: &[u32], sources: &[&str]) -> IngressPolicy {
        IngressPolicy {
            service: service.into(),
            namespace: String::new(),
            dest_ip: dest_ip.into(),
            ports: ports.to_vec(),
            allowed_sources: sources.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn host_rules_drop_mesh_traffic_from_unlisted_sources() {
        let db = ingress(
            "db",
            "",
            &[5432, 5433, 0, 70000],
            &["10.100.0.4", "10.100.0.2", "junk\""],
        );
        let closed = ingress("cache", "", &[6379], &[]);
        let ruleset = render(false, &[&db, &closed], &[]);
        assert!(ruleset.starts_with("table inet ekafleet\ndelete table inet ekafleet\n"));
        assert!(
            ruleset.contains(
                "iifname \"wg-fleet\" meta l4proto { tcp, udp } th dport { 5432, 5433 } \
             ip saddr != { 10.100.0.2, 10.100.0.4 } drop comment \"db\""
            ),
            "{ruleset}"
        );
        // No caller anywhere: nothing from other nodes gets in.
        assert!(ruleset.contains(
            "iifname \"wg-fleet\" meta l4proto { tcp, udp } th dport { 6379 } drop comment \"cache\""
        ), "{ruleset}");
        assert!(!ruleset.contains("junk"));
        assert!(ruleset.contains("policy accept"));
        assert!(!ruleset.contains("policy drop"));
    }

    #[test]
    fn namespace_rules_match_the_replica_and_let_local_traffic_through() {
        let cache = ingress("cache", "10.200.0.2", &[6379], &["10.200.0.3"]);
        let ruleset = render(true, &[&cache], &[]);
        assert!(ruleset.contains("iif \"lo\" accept"));
        assert!(
            ruleset.contains(
                "ip daddr 10.200.0.2 meta l4proto { tcp, udp } th dport { 6379 } \
             ip saddr != { 10.200.0.3 } drop comment \"cache\""
            ),
            "{ruleset}"
        );
    }

    #[test]
    fn egress_rules_match_the_unit_cgroup_and_drop_the_rest() {
        let policy = EgressPolicy {
            service: "db".into(),
            namespace: String::new(),
            rules: vec![
                EgressRuleSpec {
                    dest_cidr: "10.0.0.0/8".into(),
                    dest_ports: vec![443],
                    allow: true,
                },
                EgressRuleSpec {
                    dest_cidr: "10.9.9.9".into(),
                    dest_ports: vec![],
                    allow: false,
                },
                EgressRuleSpec {
                    dest_cidr: "nope".into(),
                    dest_ports: vec![],
                    allow: true,
                },
                EgressRuleSpec {
                    dest_cidr: "0.0.0.0/0".into(),
                    dest_ports: vec![0],
                    allow: true,
                },
            ],
        };
        let cgroup = Cgroup {
            path: "system.slice/ekafleet-db.service".into(),
            level: 2,
            inode: 7,
        };
        let ruleset = render(false, &[], &[(&policy, &cgroup)]);
        let socket = "socket cgroupv2 level 2 \"system.slice/ekafleet-db.service\"";
        let lines: Vec<&str> = ruleset
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("socket"))
            .collect();
        assert_eq!(
            lines,
            [
                format!(
                    "{socket} ip daddr 10.0.0.0/8 meta l4proto {{ tcp, udp }} th dport {{ 443 }} accept comment \"db\""
                ),
                format!("{socket} ip daddr 10.9.9.9/32 drop comment \"db\""),
                format!("{socket} drop comment \"db default\""),
            ]
        );
        assert!(ruleset.contains("oif \"lo\" accept"));
        assert!(ruleset.contains("ct state established,related accept"));
    }

    #[test]
    fn nothing_to_enforce_removes_the_table() {
        assert_eq!(render(false, &[], &[]), empty_ruleset());
    }

    #[test]
    fn unit_cgroups_are_found_in_either_slice() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        assert!(service_cgroup(root.path(), "db").is_none());
        let dir = root
            .path()
            .join("system.slice/system-ekafleet.slice/ekafleet-db.service");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            service_cgroup(root.path(), "db"),
            Some(Cgroup {
                path: "system.slice/system-ekafleet.slice/ekafleet-db.service".into(),
                level: 3,
                inode: std::fs::metadata(&dir).unwrap().ino(),
            })
        );
        assert!(service_cgroup(root.path(), "../etc").is_none());
    }
}
