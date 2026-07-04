use std::net::Ipv4Addr;
use std::process::Stdio;

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("wg command failed: {0}")]
    Command(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Manages the kernel WireGuard interface for mesh networking.
/// The private key is wrapped in `Zeroizing` to ensure it is
/// cleared from memory when dropped.
pub struct WireguardManager {
    interface: String,
    private_key: Zeroizing<String>,
    listen_port: u16,
    mesh_ip: Ipv4Addr,
}

impl WireguardManager {
    pub fn new(interface: &str, listen_port: u16) -> Self {
        Self {
            interface: interface.to_string(),
            private_key: Zeroizing::new(String::new()),
            listen_port,
            mesh_ip: Ipv4Addr::new(10, 100, 0, 1),
        }
    }

    /// Initialize the WireGuard interface.
    /// Generates keypair if needed, creates the interface, assigns IP.
    pub async fn initialize(&mut self, node_index: u16) -> Result<(), WgError> {
        // Assign mesh IP: 10.100.{index}.1
        self.mesh_ip = Ipv4Addr::new(
            10,
            100,
            node_index.to_be_bytes()[0],
            node_index.to_be_bytes()[1],
        );

        // Generate private key
        let output = tokio::process::Command::new("wg")
            .arg("genkey")
            .stdout(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            return Err(WgError::Command("genkey failed".into()));
        }

        self.private_key =
            Zeroizing::new(String::from_utf8_lossy(&output.stdout).trim().to_string());

        // Create interface
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

        // Assign IP
        let ip_cidr = format!("{}/16", self.mesh_ip);
        run_cmd("ip", &["addr", "add", &ip_cidr, "dev", &self.interface]).await?;

        // Bring up
        run_cmd("ip", &["link", "set", &self.interface, "up"]).await?;

        tracing::info!(
            interface = %self.interface,
            ip = %self.mesh_ip,
            port = self.listen_port,
            "WireGuard interface initialized"
        );

        Ok(())
    }

    /// Get the public key for this node's WireGuard interface.
    pub async fn public_key(&self) -> Result<String, WgError> {
        let output = tokio::process::Command::new("wg")
            .args(["show", &self.interface, "public-key"])
            .stdout(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            return Err(WgError::Command("show public-key failed".into()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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

    /// Get the mesh IP for this node.
    pub fn mesh_ip(&self) -> Ipv4Addr {
        self.mesh_ip
    }

    /// Tear down the WireGuard interface.
    pub async fn teardown(&self) -> Result<(), WgError> {
        run_cmd("ip", &["link", "del", &self.interface]).await?;
        tracing::info!(interface = %self.interface, "WireGuard interface removed");
        Ok(())
    }
}

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), WgError> {
    let output = tokio::process::Command::new(cmd)
        .args(args)
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
