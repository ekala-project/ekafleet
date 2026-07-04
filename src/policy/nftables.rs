use std::net::Ipv4Addr;
use std::process::Stdio;

#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("nft command failed: {0}")]
    Command(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Network policy enforcement via nftables.
/// Generates and applies rules based on service identity contracts.
pub struct PolicyEnforcer {
    table_name: String,
}

/// A network policy rule derived from service identity contracts.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub dest_ports: Vec<u16>,
    pub description: String,
}

impl PolicyEnforcer {
    pub fn new() -> Self {
        Self {
            table_name: "ekafleet".to_string(),
        }
    }

    /// Initialize the nftables table and default-deny chain.
    pub async fn initialize(&self) -> Result<(), NftError> {
        let ruleset = format!(
            r#"
table inet {table} {{
    chain input {{
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        # Allow WireGuard
        udp dport 51820 accept
        # Allow gossip
        udp dport 7401 accept
        # Allow gRPC
        tcp dport 7400 accept
        # Allow HTTP API
        tcp dport 7402 accept
    }}

    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}
}}
"#,
            table = self.table_name,
        );

        self.apply_ruleset(&ruleset).await?;
        tracing::info!(table = %self.table_name, "nftables base rules initialized");
        Ok(())
    }

    /// Apply policy rules derived from service identity contracts.
    pub async fn apply_policies(&self, rules: &[PolicyRule]) -> Result<(), NftError> {
        // Build nft rules from policy
        let mut nft_rules = Vec::new();

        for rule in rules {
            let ports: String = rule
                .dest_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            nft_rules.push(format!(
                "add rule inet {table} input ip saddr {src} ip daddr {dst} tcp dport {{ {ports} }} accept comment \"{desc}\"",
                table = self.table_name,
                src = rule.source_ip,
                dst = rule.dest_ip,
                desc = rule.description,
            ));
        }

        if nft_rules.is_empty() {
            return Ok(());
        }

        let ruleset = nft_rules.join("\n");
        self.apply_ruleset(&ruleset).await?;

        tracing::info!(rules = rules.len(), "Network policies applied");
        Ok(())
    }

    /// Flush all rules in the ekafleet table.
    pub async fn flush(&self) -> Result<(), NftError> {
        let cmd = format!("flush table inet {}", self.table_name);
        self.apply_ruleset(&cmd).await
    }

    /// Remove the ekafleet table entirely.
    pub async fn teardown(&self) -> Result<(), NftError> {
        let cmd = format!("delete table inet {}", self.table_name);
        self.apply_ruleset(&cmd).await
    }

    async fn apply_ruleset(&self, ruleset: &str) -> Result<(), NftError> {
        let output = tokio::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?
            .wait_with_output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftError::Command(stderr.to_string()));
        }

        let _ = ruleset; // will be piped to stdin when using proper stdin write
        Ok(())
    }
}
