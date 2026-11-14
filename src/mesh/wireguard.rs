use std::net::Ipv4Addr;
use std::process::Stdio;

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("wg command failed: {0}")]
    Command(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid mesh assignment: {0}")]
    Assignment(String),
    #[error("node identity unusable for the mesh: {0}")]
    Identity(String),
    #[error(transparent)]
    Advert(#[from] super::advert::AdvertError),
}

/// Manages the kernel WireGuard interface for mesh networking.
///
/// The private key is generated per interface lifetime, handed to `wg` on
/// stdin (never argv) and kept only in `Zeroizing` memory; a restarted
/// agent generates a new one and re-advertises.
pub struct WireguardManager {
    interface: String,
    private_key: Zeroizing<String>,
    listen_port: u16,
    /// Address and prefix length, once the interface is up.
    address: Option<(Ipv4Addr, u8)>,
    public_key: String,
}

impl WireguardManager {
    pub fn new(interface: &str, listen_port: u16) -> Self {
        Self {
            interface: interface.to_string(),
            private_key: Zeroizing::new(String::new()),
            listen_port,
            address: None,
            public_key: String::new(),
        }
    }

    /// Why this host cannot run the mesh, if it cannot: the interface needs
    /// root (CAP_NET_ADMIN) and the `wg` and `ip` tools.
    pub fn unavailable_reason() -> Option<String> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return Some("the agent is not running as root".into());
        }
        let missing: Vec<&str> = ["wg", "ip"]
            .into_iter()
            .filter(|tool| !on_path(tool))
            .collect();
        if !missing.is_empty() {
            return Some(format!("{} not found on PATH", missing.join(" and ")));
        }
        None
    }

    /// Bring the interface up with `ip/prefix_len` and a fresh key pair.
    /// Returns `false` (and changes nothing) if it is already up with that
    /// address. An interface left over from an earlier run is replaced.
    pub async fn initialize(&mut self, ip: Ipv4Addr, prefix_len: u8) -> Result<bool, WgError> {
        if self.address == Some((ip, prefix_len)) {
            return Ok(false);
        }
        // A stale interface (agent restart) keeps an unknown key and peers.
        let _ = run_cmd("ip", &["link", "del", &self.interface]).await;
        self.address = None;

        let output = tokio::process::Command::new("wg")
            .arg("genkey")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            return Err(WgError::Command("genkey failed".into()));
        }
        let stdout = Zeroizing::new(output.stdout);
        self.private_key = Zeroizing::new(String::from_utf8_lossy(&stdout).trim().to_string());

        run_cmd("ip", &["link", "add", &self.interface, "type", "wireguard"]).await?;

        // Set private key via stdin (avoid exposing key in process args)
        {
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new("wg")
                .args([
                    "set",
                    &self.interface,
                    "private-key",
                    "/dev/stdin",
                    "listen-port",
                    &self.listen_port.to_string(),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(WgError::Io)?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(self.private_key.as_bytes()).await?;
            }

            let output = child.wait_with_output().await?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(WgError::Command(format!(
                    "wg set private-key → {}",
                    stderr.trim()
                )));
            }
        }

        let ip_cidr = format!("{ip}/{prefix_len}");
        run_cmd("ip", &["addr", "add", &ip_cidr, "dev", &self.interface]).await?;
        run_cmd("ip", &["link", "set", &self.interface, "up"]).await?;
        self.public_key = self.read_public_key().await?;
        self.address = Some((ip, prefix_len));

        tracing::info!(
            interface = %self.interface,
            ip = %ip,
            port = self.listen_port,
            "WireGuard interface initialized"
        );

        Ok(true)
    }

    async fn read_public_key(&self) -> Result<String, WgError> {
        let output = tokio::process::Command::new("wg")
            .args(["show", &self.interface, "public-key"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            return Err(WgError::Command("show public-key failed".into()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// This node's WireGuard public key (empty until initialized).
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Add or update a WireGuard peer.
    pub async fn set_peer(
        &self,
        public_key: &str,
        endpoint: &str,
        allowed_ip: &str,
    ) -> Result<(), WgError> {
        run_cmd(
            "wg",
            &[
                "set",
                &self.interface,
                "peer",
                public_key,
                "endpoint",
                endpoint,
                "allowed-ips",
                allowed_ip,
                "persistent-keepalive",
                "25",
            ],
        )
        .await?;

        tracing::debug!(
            peer = %public_key,
            endpoint = %endpoint,
            allowed_ip = %allowed_ip,
            "Peer configured"
        );

        Ok(())
    }

    /// Remove a WireGuard peer.
    pub async fn remove_peer(&self, public_key: &str) -> Result<(), WgError> {
        run_cmd(
            "wg",
            &["set", &self.interface, "peer", public_key, "remove"],
        )
        .await
    }

    /// This node's mesh address, once the interface is up.
    pub fn mesh_ip(&self) -> Option<Ipv4Addr> {
        self.address.map(|(ip, _)| ip)
    }

    /// Whether `ip` lies in this node's mesh network.
    pub fn in_mesh_network(&self, ip: Ipv4Addr) -> bool {
        self.address.is_some_and(|(own, prefix_len)| {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix_len))
                .unwrap_or(0);
            u32::from(own) & mask == u32::from(ip) & mask
        })
    }

    /// Tear down the WireGuard interface.
    pub async fn teardown(&mut self) -> Result<(), WgError> {
        run_cmd("ip", &["link", "del", &self.interface]).await?;
        self.address = None;
        tracing::info!(interface = %self.interface, "WireGuard interface removed");
        Ok(())
    }
}

/// Whether an executable named `tool` is in a `PATH` directory.
fn on_path(tool: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            std::fs::metadata(dir.join(tool))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), WgError> {
    let output = tokio::process::Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WgError::Command(format!(
            "{} {} → {}",
            cmd,
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_network_membership_follows_the_prefix() {
        let mut wg = WireguardManager::new("wg-test", 51820);
        assert!(!wg.in_mesh_network(Ipv4Addr::new(10, 100, 0, 2)));
        wg.address = Some((Ipv4Addr::new(10, 100, 0, 1), 16));
        assert!(wg.in_mesh_network(Ipv4Addr::new(10, 100, 7, 2)));
        assert!(!wg.in_mesh_network(Ipv4Addr::new(10, 101, 0, 2)));
        assert_eq!(wg.mesh_ip(), Some(Ipv4Addr::new(10, 100, 0, 1)));
    }

    #[test]
    fn tools_are_found_on_path() {
        assert!(on_path("sh"));
        assert!(!on_path("definitely-not-a-real-tool-ekafleet"));
    }
}
