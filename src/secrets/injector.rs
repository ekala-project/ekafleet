use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Agent-side secret injection.
/// Writes decrypted secrets to files accessible by the target service.
pub struct SecretInjector {
    secrets_dir: PathBuf,
    /// service_name → secret_name → version
    injected: HashMap<String, HashMap<String, u64>>,
}

impl SecretInjector {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            secrets_dir: data_dir.join("secrets"),
            injected: HashMap::new(),
        }
    }

    /// Inject a secret for a service. Writes to a file and returns the path.
    pub async fn inject(
        &mut self,
        service_name: &str,
        secret_name: &str,
        value: &[u8],
        version: u64,
    ) -> Result<PathBuf, std::io::Error> {
        // Check if already at this version
        if let Some(svc) = self.injected.get(service_name) {
            if svc.get(secret_name) == Some(&version) {
                let path = self.secret_path(service_name, secret_name);
                return Ok(path);
            }
        }

        let dir = self.secrets_dir.join(service_name);
        tokio::fs::create_dir_all(&dir).await?;

        let path = dir.join(secret_name);

        // TODO: decrypt the value before writing (currently stored plaintext)
        tokio::fs::write(&path, value).await?;

        // Set restrictive permissions (owner read-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o400);
            tokio::fs::set_permissions(&path, perms).await?;
        }

        self.injected
            .entry(service_name.to_string())
            .or_default()
            .insert(secret_name.to_string(), version);

        tracing::info!(
            service = %service_name,
            secret = %secret_name,
            version,
            path = %path.display(),
            "Secret injected"
        );

        Ok(path)
    }

    /// Remove all secrets for a service.
    pub async fn remove_service(&mut self, service_name: &str) -> Result<(), std::io::Error> {
        let dir = self.secrets_dir.join(service_name);
        if dir.exists() {
            tokio::fs::remove_dir_all(&dir).await?;
        }
        self.injected.remove(service_name);
        Ok(())
    }

    fn secret_path(&self, service_name: &str, secret_name: &str) -> PathBuf {
        self.secrets_dir.join(service_name).join(secret_name)
    }
}
