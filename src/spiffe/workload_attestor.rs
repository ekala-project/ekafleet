/// Workload attestor for the SPIFFE Workload API.
///
/// Maps a connecting process (identified by PID from Unix socket peer credentials)
/// to an ekafleet service name. This allows the Workload API to determine which
/// SVID to serve to a given caller.
///
/// Attestation is **cgroup-based only**. The service name is derived from the
/// process's systemd cgroup membership (`/proc/<pid>/cgroup`), which is set by
/// the kernel when the supervisor launches the unit and cannot be forged by the
/// workload itself.
///
/// A previous version also honored an `EKAFLEET_SERVICE` environment variable as
/// a fallback. That was removed because a process can set any environment
/// variable it likes, so it could claim to be any service and be issued that
/// service's SVID — a privilege-escalation / identity-spoofing hole. Environment
/// is an attacker-controlled input and must never be used as an identity source.
///
/// Determine which ekafleet service a PID belongs to.
/// Returns None if the PID is not part of any managed service.
pub async fn attest_pid(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{pid}/cgroup");
    let content = tokio::fs::read_to_string(&cgroup_path).await.ok()?;
    attest_from_cgroup_content(&content)
}

/// Extract the ekafleet service name from the contents of `/proc/<pid>/cgroup`.
///
/// The unit is expected to appear as a full path segment named
/// `ekafleet-<name>.service` (as written by the supervisor), e.g.
/// `0::/system.slice/ekafleet-web.service`. Matching on a path segment (rather
/// than a loose substring) avoids being fooled by an unrelated path component
/// that merely contains the text `ekafleet-`.
fn attest_from_cgroup_content(content: &str) -> Option<String> {
    for line in content.lines() {
        // Cgroup v2: "0::/system.slice/ekafleet-myapp.service"
        // Cgroup v1: "1:name=systemd:/system.slice/ekafleet-myapp.service"
        // The path is the last ':'-separated field.
        let path = line.rsplit(':').next().unwrap_or(line);
        for segment in path.split('/') {
            if let Some(name) = segment
                .strip_prefix("ekafleet-")
                .and_then(|s| s.strip_suffix(".service"))
                && !name.is_empty()
            {
                return Some(name.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cgroup_v2_line() {
        let content = "0::/system.slice/ekafleet-web-server.service";
        assert_eq!(
            attest_from_cgroup_content(content),
            Some("web-server".to_string())
        );
    }

    #[test]
    fn parse_cgroup_v1_line() {
        let content = "1:name=systemd:/system.slice/ekafleet-api.service";
        assert_eq!(attest_from_cgroup_content(content), Some("api".to_string()));
    }

    #[test]
    fn nested_slice_path_is_parsed() {
        let content = "0::/system.slice/some.slice/ekafleet-db.service";
        assert_eq!(attest_from_cgroup_content(content), Some("db".to_string()));
    }

    #[test]
    fn unrelated_cgroup_returns_none() {
        let content = "0::/user.slice/user-1000.slice/session-3.scope";
        assert_eq!(attest_from_cgroup_content(content), None);
    }

    #[test]
    fn substring_match_does_not_forge_identity() {
        // A path component that merely contains "ekafleet-" as a substring but
        // is not a distinct `ekafleet-<name>.service` segment must not match,
        // so an unprivileged process cannot craft a cgroup-looking path to
        // impersonate a service.
        let content = "0::/system.slice/notekafleet-evil.service.d/foo";
        assert_eq!(attest_from_cgroup_content(content), None);
    }

    #[tokio::test]
    async fn unknown_pid_returns_none() {
        // PID 999999999 should not exist
        let result = attest_pid(999999999).await;
        assert!(result.is_none());
    }
}
