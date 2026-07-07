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

        // If the file already exists with read-only permissions, make it writable first
        #[cfg(unix)]
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&path, perms).await?;
        }

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

    /// Update the encryption key (e.g., when the server distributes the fleet key).
    pub fn update_key(&mut self, new_key: &[u8; 32]) {
        let unbound =
            UnboundKey::new(&AES_256_GCM, new_key).expect("valid 256-bit key required");
        self.key = Arc::new(LessSafeKey::new(unbound));
        tracing::info!("Secret injector encryption key updated");
    }

    fn secret_path(&self, service_name: &str, secret_name: &str) -> PathBuf {
        self.secrets_dir.join(service_name).join(secret_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    /// Encrypt a value the same way SecretStore does, for test input.
    fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        use ring::aead::{AES_256_GCM, Aad, Nonce, UnboundKey};
        use ring::rand::{SecureRandom, SystemRandom};

        let unbound = UnboundKey::new(&AES_256_GCM, key).unwrap();
        let sealing_key = LessSafeKey::new(unbound);
        let rng = SystemRandom::new();

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .unwrap();

        let mut sealed = Vec::with_capacity(NONCE_LEN + in_out.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&in_out);
        sealed
    }

    #[tokio::test]
    async fn inject_decrypts_and_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        let mut injector = SecretInjector::new(dir.path(), &key);

        let encrypted = encrypt_value(&key, b"database-password");
        let path = injector
            .inject("my-service", "db_pass", &encrypted, 1)
            .await
            .unwrap();

        let contents = tokio::fs::read(&path).await.unwrap();
        assert_eq!(contents, b"database-password");
    }

    #[tokio::test]
    async fn inject_sets_restrictive_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        let mut injector = SecretInjector::new(dir.path(), &key);

        let encrypted = encrypt_value(&key, b"secret");
        let path = injector.inject("svc", "key", &encrypted, 1).await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(
                perms.mode() & 0o777,
                0o400,
                "secret file must be owner-read-only"
            );
        }
    }

    #[tokio::test]
    async fn inject_is_idempotent_for_same_version() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        let mut injector = SecretInjector::new(dir.path(), &key);

        let encrypted = encrypt_value(&key, b"value");
        let path1 = injector.inject("svc", "key", &encrypted, 1).await.unwrap();
        let path2 = injector.inject("svc", "key", &encrypted, 1).await.unwrap();

        assert_eq!(path1, path2);
    }

    #[tokio::test]
    async fn inject_updates_on_new_version() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        let mut injector = SecretInjector::new(dir.path(), &key);

        let enc1 = encrypt_value(&key, b"v1");
        let enc2 = encrypt_value(&key, b"v2");

        injector.inject("svc", "key", &enc1, 1).await.unwrap();
        let path = injector.inject("svc", "key", &enc2, 2).await.unwrap();

        let contents = tokio::fs::read(&path).await.unwrap();
        assert_eq!(contents, b"v2");
    }

    #[tokio::test]
    async fn wrong_key_fails_to_inject() {
        let dir = tempfile::tempdir().unwrap();
        let encrypted = encrypt_value(&[0xAA; 32], b"secret");

        let mut injector = SecretInjector::new(dir.path(), &[0xBB; 32]);
        let result = injector.inject("svc", "key", &encrypted, 1).await;

        assert!(
            result.is_err(),
            "decryption with wrong key must fail during injection"
        );
    }

    #[tokio::test]
    async fn remove_service_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        let mut injector = SecretInjector::new(dir.path(), &key);

        let encrypted = encrypt_value(&key, b"secret");
        let path = injector.inject("svc", "key", &encrypted, 1).await.unwrap();
        assert!(path.exists());

        injector.remove_service("svc").await.unwrap();
        assert!(!path.exists());
    }
}
