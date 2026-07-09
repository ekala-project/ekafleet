/// Workload attestor for the SPIFFE Workload API.
///
/// Maps a connecting process (identified by PID from Unix socket peer credentials)
/// to an ekafleet service name. This allows the Workload API to determine which
/// SVID to serve to a given caller.
///
/// Attestation strategies (tried in order):
///   1. Check `/proc/<pid>/cgroup` for `ekafleet-<name>.service` unit
///   2. Check `/proc/<pid>/environ` for `EKAFLEET_SERVICE=<name>` env var
///
/// Determine which ekafleet service a PID belongs to.
/// Returns None if the PID is not part of any managed service.
pub async fn attest_pid(pid: u32) -> Option<String> {
    // Strategy 1: Parse systemd cgroup for ekafleet unit name
    if let Some(name) = attest_from_cgroup(pid).await {
        return Some(name);
    }

    // Strategy 2: Check environment variable
    if let Some(name) = attest_from_environ(pid).await {
        return Some(name);
    }

    None
}

/// Extract service name from /proc/<pid>/cgroup.
/// Looks for cgroup paths containing "ekafleet-<name>.service".
async fn attest_from_cgroup(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{pid}/cgroup");
    let content = tokio::fs::read_to_string(&cgroup_path).await.ok()?;

    for line in content.lines() {
        // Cgroup v2 format: "0::/system.slice/ekafleet-myapp.service"
        // Cgroup v1 format: "1:name=systemd:/system.slice/ekafleet-myapp.service"
        if let Some(pos) = line.find("ekafleet-") {
            let after_prefix = &line[pos + "ekafleet-".len()..];
            if let Some(end) = after_prefix.find(".service") {
                let name = &after_prefix[..end];
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }

    None
}

/// Extract service name from /proc/<pid>/environ.
/// Looks for EKAFLEET_SERVICE=<name> in the null-delimited environ file.
async fn attest_from_environ(pid: u32) -> Option<String> {
    let environ_path = format!("/proc/{pid}/environ");
    let content = tokio::fs::read(&environ_path).await.ok()?;

    // Environment variables are null-terminated
    let prefix = b"EKAFLEET_SERVICE=";
    for var in content.split(|&b| b == 0) {
        if var.starts_with(prefix) {
            let value = &var[prefix.len()..];
            let name = String::from_utf8_lossy(value);
            if !name.is_empty() {
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
        // Simulate cgroup parsing logic
        let line = "0::/system.slice/ekafleet-web-server.service";
        let pos = line.find("ekafleet-").unwrap();
        let after = &line[pos + "ekafleet-".len()..];
        let end = after.find(".service").unwrap();
        let name = &after[..end];
        assert_eq!(name, "web-server");
    }

    #[test]
    fn parse_cgroup_v1_line() {
        let line = "1:name=systemd:/system.slice/ekafleet-api.service";
        let pos = line.find("ekafleet-").unwrap();
        let after = &line[pos + "ekafleet-".len()..];
        let end = after.find(".service").unwrap();
        let name = &after[..end];
        assert_eq!(name, "api");
    }

    #[test]
    fn parse_environ_entry() {
        let prefix = b"EKAFLEET_SERVICE=";
        let var = b"EKAFLEET_SERVICE=my-app";
        assert!(var.starts_with(prefix));
        let value = &var[prefix.len()..];
        assert_eq!(std::str::from_utf8(value).unwrap(), "my-app");
    }

    #[tokio::test]
    async fn unknown_pid_returns_none() {
        // PID 999999999 should not exist
        let result = attest_pid(999999999).await;
        assert!(result.is_none());
    }
}
