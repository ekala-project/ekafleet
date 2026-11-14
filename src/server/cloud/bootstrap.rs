#![allow(dead_code)]

/// Generate a cloud-init user-data script that bootstraps an ekafleet agent.
///
/// The generated script:
/// 1. Writes the CA certificate to `/etc/ekafleet/ca.pem`
/// 2. Writes the one-time join token to a root-only file (never argv, where
///    any local user could read it from /proc)
/// 3. Starts the agent as `node_name`, the name the token is bound to
pub fn generate_user_data(
    server_addr: &str,
    node_name: &str,
    join_token: &str,
    ca_cert_pem: &str,
) -> String {
    // Use a bash script wrapped in cloud-init compatible format.
    // NixOS cloud-init will execute this as a user-data script.
    format!(
        r#"#!/bin/bash
set -euo pipefail

# Write CA certificate for TLS verification
mkdir -p /etc/ekafleet
cat > /etc/ekafleet/ca.pem <<'EKAFLEET_CA_CERT'
{ca_cert_pem}
EKAFLEET_CA_CERT

# One-time join token, readable by root only
(umask 077; printf '%s' '{join_token}' > /etc/ekafleet/join-token)

# Start ekafleet agent
exec ekafleet agent \
  --join {server_addr} \
  --node-name {node_name} \
  --join-token-file /etc/ekafleet/join-token \
  --ca-cert /etc/ekafleet/ca.pem \
  --data-dir /var/lib/ekafleet
"#
    )
}

/// Base64-encode user-data for cloud providers that require it (e.g., AWS).
pub fn encode_user_data(user_data: &str) -> String {
    // Simple base64 encoding without pulling in a crate.
    // Uses the standard base64 alphabet.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = user_data.as_bytes();
    let mut output = Vec::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        output.push(ALPHABET[((triple >> 18) & 0x3F) as usize]);
        output.push(ALPHABET[((triple >> 12) & 0x3F) as usize]);

        if chunk.len() > 1 {
            output.push(ALPHABET[((triple >> 6) & 0x3F) as usize]);
        } else {
            output.push(b'=');
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[(triple & 0x3F) as usize]);
        } else {
            output.push(b'=');
        }
    }

    String::from_utf8(output).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_data_contains_server_addr() {
        let ud = generate_user_data("10.0.0.1:7400", "workers-1a2b", "abc123", "PEM-DATA");
        assert!(ud.contains("--join 10.0.0.1:7400"));
        assert!(ud.contains("--node-name workers-1a2b"));
        assert!(ud.contains("--join-token-file /etc/ekafleet/join-token"));
        assert!(!ud.contains("--join-token abc123"));
        assert!(ud.contains("printf '%s' 'abc123' > /etc/ekafleet/join-token"));
        assert!(ud.contains("PEM-DATA"));
    }

    #[test]
    fn base64_encode_roundtrip() {
        let input = "Hello, world!";
        let encoded = encode_user_data(input);
        assert_eq!(encoded, "SGVsbG8sIHdvcmxkIQ==");
    }
}
