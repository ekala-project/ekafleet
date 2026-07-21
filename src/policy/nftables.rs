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

/// A DNAT port-forwarding rule for inbound traffic to namespace services.
#[derive(Debug, Clone)]
pub struct PortForwardRule {
    /// External port on the host interface.
    pub external_port: u16,
    /// Internal namespace IP to forward to.
    pub internal_ip: Ipv4Addr,
    /// Internal port (usually same as external).
    pub internal_port: u16,
    /// Protocol: "tcp" or "udp".
    pub protocol: String,
    /// Human-readable description.
    pub description: String,
}

/// An egress network policy rule controlling outbound traffic from a service.
#[derive(Debug, Clone)]
pub struct EgressRule {
    pub source_ip: Ipv4Addr,
    pub dest_cidr: String,
    pub dest_ports: Vec<u16>,
    pub action: EgressAction,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressAction {
    Allow,
    Deny,
}

impl Default for PolicyEnforcer {
    fn default() -> Self {
        Self::new()
    }
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
        # Allow VXLAN namespace overlay (cross-node, arrives via WireGuard)
        iifname "wg-fleet" udp dport 4789 accept
    }}

    chain output {{
        type filter hook output priority 0; policy accept;
        ct state established,related accept
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

            // Sanitize description to prevent nftables comment injection
            let desc: String = rule
                .description
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
                .take(128)
                .collect();

            nft_rules.push(format!(
                "add rule inet {table} input ip saddr {src} ip daddr {dst} tcp dport {{ {ports} }} accept comment \"{desc}\"",
                table = self.table_name,
                src = rule.source_ip,
                dst = rule.dest_ip,
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

    /// Apply egress rules controlling outbound traffic from services.
    pub async fn apply_egress(&self, rules: &[EgressRule]) -> Result<(), NftError> {
        let mut nft_rules = Vec::new();

        for rule in rules {
            let action = match rule.action {
                EgressAction::Allow => "accept",
                EgressAction::Deny => "drop",
            };

            let desc: String = rule
                .description
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
                .take(128)
                .collect();

            if rule.dest_ports.is_empty() {
                nft_rules.push(format!(
                    "add rule inet {table} output ip saddr {src} ip daddr {dst} {action} comment \"{desc}\"",
                    table = self.table_name,
                    src = rule.source_ip,
                    dst = rule.dest_cidr,
                ));
            } else {
                let ports: String = rule
                    .dest_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                nft_rules.push(format!(
                    "add rule inet {table} output ip saddr {src} ip daddr {dst} tcp dport {{ {ports} }} {action} comment \"{desc}\"",
                    table = self.table_name,
                    src = rule.source_ip,
                    dst = rule.dest_cidr,
                ));
            }
        }

        if nft_rules.is_empty() {
            return Ok(());
        }

        let ruleset = nft_rules.join("\n");
        self.apply_ruleset(&ruleset).await?;

        tracing::info!(rules = rules.len(), "Egress policies applied");
        Ok(())
    }

    /// Initialize namespace NAT rules: masquerade for outbound traffic from
    /// customer workload subnets (10.200.0.0/16) and optional DNAT port-forwarding
    /// rules for inbound traffic.
    pub async fn apply_namespace_nat(
        &self,
        port_forwards: &[PortForwardRule],
    ) -> Result<(), NftError> {
        let mut rules = String::new();

        // Masquerade: customer workload subnets → outbound internet
        rules.push_str(&format!(
            r#"
table inet {table} {{
    chain ekafleet_postrouting {{
        type nat hook postrouting priority 100;
        ip saddr 10.200.0.0/16 masquerade
    }}
"#,
            table = self.table_name,
        ));

        // DNAT: inbound port-forwarding to namespace services
        if !port_forwards.is_empty() {
            rules.push_str(
                r#"
    chain ekafleet_prerouting {
        type nat hook prerouting priority -100;
"#,
            );

            for pf in port_forwards {
                let desc: String = pf
                    .description
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
                    .take(128)
                    .collect();

                let proto = if pf.protocol == "udp" { "udp" } else { "tcp" };
                rules.push_str(&format!(
                    "        {proto} dport {ext} dnat to {ip}:{int} comment \"{desc}\"\n",
                    ext = pf.external_port,
                    ip = pf.internal_ip,
                    int = pf.internal_port,
                ));
            }

            rules.push_str("    }\n");
        }

        rules.push_str("}\n");

        self.apply_ruleset(&rules).await?;
        tracing::info!(
            port_forwards = port_forwards.len(),
            "Namespace NAT rules applied"
        );
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

    /// Generate policy rules as nftables commands without applying them.
    /// Useful for testing rule generation and sanitization.
    #[cfg(test)]
    fn generate_rules(&self, rules: &[PolicyRule]) -> Vec<String> {
        let mut nft_rules = Vec::new();
        for rule in rules {
            let ports: String = rule
                .dest_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            let desc: String = rule
                .description
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
                .take(128)
                .collect();

            nft_rules.push(format!(
                "add rule inet {table} input ip saddr {src} ip daddr {dst} tcp dport {{ {ports} }} accept comment \"{desc}\"",
                table = self.table_name,
                src = rule.source_ip,
                dst = rule.dest_ip,
            ));
        }
        nft_rules
    }

    async fn apply_ruleset(&self, ruleset: &str) -> Result<(), NftError> {
        use tokio::io::AsyncWriteExt;

        let mut child = tokio::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ruleset.as_bytes()).await?;
            // Drop stdin to close the pipe so nft sees EOF
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftError::Command(stderr.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(desc: &str) -> PolicyRule {
        PolicyRule {
            source_ip: Ipv4Addr::new(10, 100, 1, 1),
            dest_ip: Ipv4Addr::new(10, 100, 2, 1),
            dest_ports: vec![8080, 8443],
            description: desc.to_string(),
        }
    }

    #[test]
    fn sanitize_removes_dangerous_chars_from_description() {
        let enforcer = PolicyEnforcer::new();
        let rules = enforcer.generate_rules(&[rule("allow web\" ; drop table")]);

        assert_eq!(rules.len(), 1);
        // Extract just the comment content between the comment delimiters
        let comment_start = rules[0].find("comment \"").unwrap() + 9;
        let comment_end = rules[0].rfind('"').unwrap();
        let comment = &rules[0][comment_start..comment_end];

        // The sanitized description must not contain quotes or semicolons
        assert!(!comment.contains('"'), "quotes must be stripped");
        assert!(!comment.contains(';'), "semicolons must be stripped");
        // But should still contain the safe words
        assert!(comment.contains("allow"), "safe words should remain");
        assert!(comment.contains("web"), "safe words should remain");
    }

    #[test]
    fn sanitize_preserves_safe_characters() {
        let enforcer = PolicyEnforcer::new();
        let rules = enforcer.generate_rules(&[rule("allow frontend-to-backend_v2")]);

        assert!(rules[0].contains("allow frontend-to-backend_v2"));
    }

    #[test]
    fn sanitize_truncates_long_descriptions() {
        let enforcer = PolicyEnforcer::new();
        let long_desc = "a".repeat(256);
        let rules = enforcer.generate_rules(&[rule(&long_desc)]);

        // Extract the comment content
        let comment_start = rules[0].find("comment \"").unwrap() + 9;
        let comment_end = rules[0].rfind('"').unwrap();
        let comment = &rules[0][comment_start..comment_end];

        assert!(
            comment.len() <= 128,
            "description must be truncated to 128 chars"
        );
    }

    #[test]
    fn rule_generation_with_multiple_ports() {
        let enforcer = PolicyEnforcer::new();
        let r = PolicyRule {
            source_ip: Ipv4Addr::new(10, 0, 0, 1),
            dest_ip: Ipv4Addr::new(10, 0, 0, 2),
            dest_ports: vec![80, 443, 8080],
            description: "web traffic".into(),
        };
        let rules = enforcer.generate_rules(&[r]);

        assert!(rules[0].contains("80, 443, 8080"));
        assert!(rules[0].contains("10.0.0.1"));
        assert!(rules[0].contains("10.0.0.2"));
    }

    #[test]
    fn empty_rules_produces_empty_output() {
        let enforcer = PolicyEnforcer::new();
        let rules = enforcer.generate_rules(&[]);
        assert!(rules.is_empty());
    }

    #[test]
    fn port_forward_rule_fields() {
        let pf = PortForwardRule {
            external_port: 25565,
            internal_ip: Ipv4Addr::new(10, 200, 1, 2),
            internal_port: 25565,
            protocol: "tcp".into(),
            description: "customer-a-minecraft".into(),
        };
        assert_eq!(pf.external_port, 25565);
        assert_eq!(pf.internal_ip, Ipv4Addr::new(10, 200, 1, 2));
    }

    #[test]
    fn shell_metacharacters_stripped() {
        let enforcer = PolicyEnforcer::new();
        let dangerous_descs = vec![
            "$(rm -rf /)",
            "`whoami`",
            "foo\nbar",
            "a && b",
            "a || b",
            "a | b",
            "a > /etc/passwd",
            "a < /dev/null",
        ];

        for desc in dangerous_descs {
            let rules = enforcer.generate_rules(&[rule(desc)]);
            let rule_str = &rules[0];

            assert!(!rule_str.contains('$'), "$ must be stripped from: {desc}");
            assert!(
                !rule_str.contains('`'),
                "backtick must be stripped from: {desc}"
            );
            assert!(!rule_str.contains('&'), "& must be stripped from: {desc}");
            assert!(!rule_str.contains('|'), "| must be stripped from: {desc}");
            assert!(!rule_str.contains('>'), "> must be stripped from: {desc}");
            assert!(!rule_str.contains('<'), "< must be stripped from: {desc}");
        }
    }
}
