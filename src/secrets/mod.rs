pub mod db_driver;
pub mod dynamic;
pub mod injector;
pub mod key_derivation;
pub mod store;
pub mod transit;
pub mod versioned;

/// Where the agent keeps decrypted static secrets: one directory per service
/// on tmpfs, bind-mounted read-only at [`SERVICE_SECRETS_DIR`] in the unit.
pub const AGENT_SECRETS_DIR: &str = "/run/ekafleet/secrets";

/// Where a service sees its static secrets.
pub const SERVICE_SECRETS_DIR: &str = "/run/secrets";

/// Longest accepted secret value (64 KiB).
pub const MAX_SECRET_SIZE: usize = 64 * 1024;

/// Check a secret or service name used as a file name on agents: 1–128 of
/// `[A-Za-z0-9._-]`, not starting with a dot.
pub fn validate_name(kind: &str, name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 128 {
        return Err(format!("{kind} name must be 1-128 characters"));
    }
    if name.starts_with('.') {
        return Err(format!("{kind} name '{name}' must not start with '.'"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "{kind} name '{name}' may only contain letters, digits, '.', '_' and '-'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_name;

    #[test]
    fn names_are_safe_file_names() {
        for ok in ["api-key", "DB_PASSWORD", "tls.key", "a"] {
            assert!(validate_name("secret", ok).is_ok(), "{ok}");
        }
        let long = "x".repeat(129);
        for bad in ["", ".hidden", "..", "a/b", "a b", "ä", long.as_str()] {
            assert!(validate_name("secret", bad).is_err(), "{bad}");
        }
    }
}
