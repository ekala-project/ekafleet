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
            rng: Arc::new(SystemRandom::new()),
        }
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
}
