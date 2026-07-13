use std::collections::HashMap;
use std::sync::Arc;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::RwLock;

const NONCE_LEN: usize = 12; // AES-256-GCM nonce size

/// Server-side encrypted secret storage.
/// Secrets are encrypted at rest with AES-256-GCM and scoped to specific services.
#[derive(Clone)]
pub struct SecretStore {
    inner: Arc<RwLock<StoreState>>,
    key: Arc<LessSafeKey>,
    /// Raw key bytes retained for HKDF derivation and re-encryption.
    raw_key: Arc<[u8; 32]>,
    rng: Arc<SystemRandom>,
}

struct StoreState {
    /// service_name → secret_name → encrypted value + metadata
    secrets: HashMap<String, HashMap<String, SecretEntry>>,
}

#[derive(Clone)]
struct SecretEntry {
    /// Nonce (12 bytes) || ciphertext || tag (16 bytes)
    sealed: Vec<u8>,
    version: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

impl SecretStore {
    /// Create a new SecretStore with the given 256-bit encryption key.
    pub fn new(encryption_key: &[u8; 32]) -> Self {
        let unbound =
            UnboundKey::new(&AES_256_GCM, encryption_key).expect("valid 256-bit key required");
        let key = LessSafeKey::new(unbound);

        Self {
            inner: Arc::new(RwLock::new(StoreState {
                secrets: HashMap::new(),
            })),
            key: Arc::new(key),
            raw_key: Arc::new(*encryption_key),
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Returns the raw encryption key bytes (for HKDF derivation / re-encryption).
    pub fn raw_key(&self) -> &[u8; 32] {
        &self.raw_key
    }

    /// Encrypt plaintext value using AES-256-GCM.
    /// Returns nonce || ciphertext || tag.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| SecretStoreError::Encrypt)?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| SecretStoreError::Encrypt)?;

        // Prepend nonce to ciphertext+tag
        let mut sealed = Vec::with_capacity(NONCE_LEN + in_out.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&in_out);
        Ok(sealed)
    }

    /// Decrypt a sealed value (nonce || ciphertext || tag).
    fn decrypt(&self, sealed: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        if sealed.len() < NONCE_LEN {
            return Err(SecretStoreError::Decrypt);
        }

        let (nonce_bytes, ciphertext_and_tag) = sealed.split_at(NONCE_LEN);
        let nonce =
            Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| SecretStoreError::Decrypt)?;

        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| SecretStoreError::Decrypt)?;

        Ok(plaintext.to_vec())
    }

    /// Store or update a secret for a service.
    /// The value is encrypted before storage.
    pub async fn put(
        &self,
        service_name: &str,
        secret_name: &str,
        value: &[u8],
    ) -> Result<u64, SecretStoreError> {
        let sealed = self.encrypt(value)?;

        let mut state = self.inner.write().await;
        let service_secrets = state.secrets.entry(service_name.to_string()).or_default();

        let version = service_secrets
            .get(secret_name)
            .map(|e| e.version + 1)
            .unwrap_or(1);

        service_secrets.insert(secret_name.to_string(), SecretEntry { sealed, version });

        tracing::info!(
            service = %service_name,
            secret = %secret_name,
            version,
            "Secret stored (encrypted)"
        );

        Ok(version)
    }

    /// Get a decrypted secret for a service. Returns (plaintext, version).
    pub async fn get(
        &self,
        service_name: &str,
        secret_name: &str,
    ) -> Result<Option<(Vec<u8>, u64)>, SecretStoreError> {
        let state = self.inner.read().await;
        match state
            .secrets
            .get(service_name)
            .and_then(|svc| svc.get(secret_name))
        {
            Some(entry) => {
                let plaintext = self.decrypt(&entry.sealed)?;
                Ok(Some((plaintext, entry.version)))
            }
            None => Ok(None),
        }
    }

    /// Delete a secret.
    pub async fn delete(&self, service_name: &str, secret_name: &str) -> bool {
        let mut state = self.inner.write().await;
        if let Some(svc) = state.secrets.get_mut(service_name) {
            svc.remove(secret_name).is_some()
        } else {
            false
        }
    }

    /// List all secrets for a service (names only).
    pub async fn list(&self, service_name: &str) -> Vec<(String, u64)> {
        let state = self.inner.read().await;
        state
            .secrets
            .get(service_name)
            .map(|svc| {
                svc.iter()
                    .map(|(name, entry)| (name.clone(), entry.version))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all encrypted secrets that should be pushed to a node for its assigned services.
    /// Returns sealed (encrypted) values for transit — the agent decrypts on receipt.
    pub async fn secrets_for_services(
        &self,
        service_names: &[String],
    ) -> Vec<(String, String, Vec<u8>, u64)> {
        let state = self.inner.read().await;
        let mut result = Vec::new();

        for svc_name in service_names {
            if let Some(svc_secrets) = state.secrets.get(svc_name) {
                for (secret_name, entry) in svc_secrets {
                    result.push((
                        svc_name.clone(),
                        secret_name.clone(),
                        entry.sealed.clone(),
                        entry.version,
                    ));
                }
            }
        }

        result
    }

    /// Get secrets for a specific agent, re-encrypted with a per-agent derived key.
    ///
    /// Secrets are stored encrypted with the fleet master key. This method
    /// re-encrypts each secret under the agent's HKDF-derived key so the
    /// fleet master key never reaches agents.
    pub async fn secrets_for_agent(
        &self,
        service_names: &[String],
        agent_spiffe_id: &str,
    ) -> Vec<(String, String, Vec<u8>, u64)> {
        let agent_key =
            super::key_derivation::derive_agent_key(self.raw_key.as_ref(), agent_spiffe_id);
        let entries = self.secrets_for_services(service_names).await;
        let mut result = Vec::with_capacity(entries.len());

        for (svc, name, sealed, version) in entries {
            match super::key_derivation::reencrypt(self.raw_key.as_ref(), &agent_key, &sealed) {
                Ok(reencrypted) => result.push((svc, name, reencrypted, version)),
                Err(e) => {
                    tracing::error!(
                        service = %svc,
                        secret = %name,
                        error = %e,
                        "Failed to re-encrypt secret for agent"
                    );
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let store = SecretStore::new(&test_key());
        let plaintext = b"my-database-password";

        store.put("svc1", "db_pass", plaintext).await.unwrap();
        let (retrieved, version) = store.get("svc1", "db_pass").await.unwrap().unwrap();

        assert_eq!(retrieved, plaintext);
        assert_eq!(version, 1);
    }

    #[tokio::test]
    async fn secrets_are_not_stored_as_plaintext() {
        let store = SecretStore::new(&test_key());
        let plaintext = b"super-secret-value";

        store.put("svc1", "secret", plaintext).await.unwrap();

        // Access the internal sealed data directly
        let state = store.inner.read().await;
        let entry = state.secrets.get("svc1").unwrap().get("secret").unwrap();

        // The sealed data must NOT contain the plaintext
        assert_ne!(entry.sealed, plaintext.to_vec());
        // And must be longer than plaintext (nonce + tag overhead)
        assert!(entry.sealed.len() > plaintext.len());
    }

    #[tokio::test]
    async fn different_encryptions_produce_different_ciphertext() {
        let store = SecretStore::new(&test_key());
        let plaintext = b"same-value";

        // Encrypt twice — nonces should differ, producing different ciphertext
        let sealed1 = store.encrypt(plaintext).unwrap();
        let sealed2 = store.encrypt(plaintext).unwrap();

        assert_ne!(
            sealed1, sealed2,
            "identical plaintext must produce different ciphertext (unique nonces)"
        );
    }

    #[tokio::test]
    async fn wrong_key_cannot_decrypt() {
        let store1 = SecretStore::new(&[0xAA; 32]);
        let store2 = SecretStore::new(&[0xBB; 32]);

        let sealed = store1.encrypt(b"secret").unwrap();
        let result = store2.decrypt(&sealed);

        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_decryption() {
        let store = SecretStore::new(&test_key());
        let mut sealed = store.encrypt(b"secret").unwrap();

        // Flip a byte in the ciphertext (after the nonce)
        let idx = NONCE_LEN + 1;
        sealed[idx] ^= 0xFF;

        let result = store.decrypt(&sealed);
        assert!(
            result.is_err(),
            "tampered ciphertext must fail authentication"
        );
    }

    #[tokio::test]
    async fn version_increments_on_update() {
        let store = SecretStore::new(&test_key());

        let v1 = store.put("svc", "key", b"val1").await.unwrap();
        let v2 = store.put("svc", "key", b"val2").await.unwrap();
        let v3 = store.put("svc", "key", b"val3").await.unwrap();

        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
        assert_eq!(v3, 3);

        let (val, version) = store.get("svc", "key").await.unwrap().unwrap();
        assert_eq!(val, b"val3");
        assert_eq!(version, 3);
    }

    #[tokio::test]
    async fn secrets_scoped_per_service() {
        let store = SecretStore::new(&test_key());

        store.put("svc-a", "password", b"alpha").await.unwrap();
        store.put("svc-b", "password", b"beta").await.unwrap();

        let a = store.get("svc-a", "password").await.unwrap().unwrap();
        let b = store.get("svc-b", "password").await.unwrap().unwrap();

        assert_eq!(a.0, b"alpha");
        assert_eq!(b.0, b"beta");

        // svc-c has no secrets
        assert!(store.get("svc-c", "password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_removes_secret() {
        let store = SecretStore::new(&test_key());
        store.put("svc", "key", b"val").await.unwrap();

        assert!(store.delete("svc", "key").await);
        assert!(store.get("svc", "key").await.unwrap().is_none());

        // Deleting non-existent returns false
        assert!(!store.delete("svc", "key").await);
    }

    #[tokio::test]
    async fn list_returns_names_and_versions() {
        let store = SecretStore::new(&test_key());
        store.put("svc", "a", b"1").await.unwrap();
        store.put("svc", "b", b"2").await.unwrap();
        store.put("svc", "a", b"3").await.unwrap(); // version 2

        let mut list = store.list("svc").await;
        list.sort_by_key(|(name, _)| name.clone());

        assert_eq!(list.len(), 2);
        assert_eq!(list[0], ("a".to_string(), 2));
        assert_eq!(list[1], ("b".to_string(), 1));
    }

    #[tokio::test]
    async fn secrets_for_services_returns_encrypted_data() {
        let store = SecretStore::new(&test_key());
        store.put("svc-a", "key1", b"val1").await.unwrap();
        store.put("svc-b", "key2", b"val2").await.unwrap();
        store.put("svc-c", "key3", b"val3").await.unwrap();

        let result = store
            .secrets_for_services(&["svc-a".into(), "svc-c".into()])
            .await;

        assert_eq!(result.len(), 2);
        // The returned values should be sealed (encrypted), not plaintext
        for (_, _, sealed, _) in &result {
            assert!(
                sealed.len() > NONCE_LEN,
                "sealed data must include nonce + ciphertext + tag"
            );
        }
    }

    #[tokio::test]
    async fn truncated_ciphertext_fails() {
        let store = SecretStore::new(&test_key());
        // Too short to contain a nonce
        assert!(store.decrypt(&[0u8; 5]).is_err());
        // Empty
        assert!(store.decrypt(&[]).is_err());
    }
}
