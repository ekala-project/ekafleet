use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

const NONCE_LEN: usize = 12;

/// Agent-side secret injection.
/// Decrypts secrets received from the server and writes plaintext
/// to files with restrictive permissions accessible by the target service.
pub struct SecretInjector {
    secrets_dir: PathBuf,
    /// service_name → secret_name → version
    injected: HashMap<String, HashMap<String, u64>>,
    key: Arc<LessSafeKey>,
}

impl SecretInjector {
    pub fn new(data_dir: &Path, encryption_key: &[u8; 32]) -> Self {
        let unbound =
            UnboundKey::new(&AES_256_GCM, encryption_key).expect("valid 256-bit key required");
        let key = LessSafeKey::new(unbound);

        Self {
            secrets_dir: data_dir.join("secrets"),
            injected: HashMap::new(),
            key: Arc::new(key),
        }
    }

    /// Decrypt a sealed value (nonce || ciphertext || tag).
    fn decrypt(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        if sealed.len() < NONCE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed data too short",
            ));
        }

        let (nonce_bytes, ciphertext_and_tag) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid nonce"))?;

        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "decryption failed")
            })?;

        Ok(plaintext.to_vec())
    }

    /// Inject a secret for a service. Decrypts and writes to a file, returns the path.
    pub async fn inject(
        &mut self,
        service_name: &str,
        secret_name: &str,
        encrypted_value: &[u8],
        version: u64,
    ) -> Result<PathBuf, std::io::Error> {
        // Check if already at this version
        if let Some(svc) = self.injected.get(service_name)
            && svc.get(secret_name) == Some(&version)
        {
            let path = self.secret_path(service_name, secret_name);
            return Ok(path);
        }

        let dir = self.secrets_dir.join(service_name);
        tokio::fs::create_dir_all(&dir).await?;

        let path = dir.join(secret_name);

        // Decrypt before writing to disk
        let plaintext = self.decrypt(encrypted_value)?;
        tokio::fs::write(&path, &plaintext).await?;

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
            "Secret injected (decrypted)"
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
