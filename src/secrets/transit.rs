#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::RwLock;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Transit encryption engine providing named encryption keys for
/// application-level encrypt/decrypt operations (encryption as a service).
#[derive(Clone)]
pub struct TransitEngine {
    inner: Arc<RwLock<TransitState>>,
    rng: Arc<SystemRandom>,
}

struct TransitState {
    keys: HashMap<String, NamedKey>,
}

struct NamedKey {
    key: LessSafeKey,
}

#[derive(Debug, thiserror::Error)]
pub enum TransitError {
    #[error("key '{0}' not found")]
    KeyNotFound(String),
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("random generation failed")]
    RngFailure,
}

impl Default for TransitEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TransitEngine {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TransitState {
                keys: HashMap::new(),
            })),
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Create a new named encryption key (AES-256-GCM).
    pub async fn create_key(&self, name: &str) -> Result<(), TransitError> {
        let mut key_bytes = [0u8; KEY_LEN];
        self.rng
            .fill(&mut key_bytes)
            .map_err(|_| TransitError::RngFailure)?;

        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| TransitError::EncryptionFailed)?;
        let key = LessSafeKey::new(unbound);

        let mut state = self.inner.write().await;
        state.keys.insert(name.to_string(), NamedKey { key });

        tracing::info!(key_name = %name, "Transit encryption key created");
        Ok(())
    }

    /// Encrypt plaintext with a named key. Returns nonce || ciphertext || tag.
    pub async fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<Vec<u8>, TransitError> {
        let state = self.inner.read().await;
        let named_key = state
            .keys
            .get(key_name)
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| TransitError::RngFailure)?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        named_key
            .key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| TransitError::EncryptionFailed)?;

        let mut sealed = Vec::with_capacity(NONCE_LEN + in_out.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&in_out);
        Ok(sealed)
    }

    /// Decrypt ciphertext with a named key. Expects nonce || ciphertext || tag.
    pub async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TransitError> {
        if ciphertext.len() < NONCE_LEN {
            return Err(TransitError::DecryptionFailed);
        }

        let state = self.inner.read().await;
        let named_key = state
            .keys
            .get(key_name)
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))?;

        let (nonce_bytes, ct_and_tag) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| TransitError::DecryptionFailed)?;

        let mut in_out = ct_and_tag.to_vec();
        let plaintext = named_key
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| TransitError::DecryptionFailed)?;

        Ok(plaintext.to_vec())
    }

    /// List all named keys.
    pub async fn list_keys(&self) -> Vec<String> {
        let state = self.inner.read().await;
        state.keys.keys().cloned().collect()
    }

    /// Delete a named key. Returns true if the key existed.
    pub async fn delete_key(&self, name: &str) -> bool {
        let mut state = self.inner.write().await;
        let removed = state.keys.remove(name).is_some();
        if removed {
            tracing::info!(key_name = %name, "Transit encryption key deleted");
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let engine = TransitEngine::new();
        engine.create_key("my-key").await.unwrap();

        let plaintext = b"hello, world!";
        let ciphertext = engine.encrypt("my-key", plaintext).await.unwrap();
        let decrypted = engine.decrypt("my-key", &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn encrypt_with_unknown_key_fails() {
        let engine = TransitEngine::new();

        let result = engine.encrypt("nonexistent", b"data").await;
        assert!(matches!(result, Err(TransitError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn decrypt_with_unknown_key_fails() {
        let engine = TransitEngine::new();

        let result = engine.decrypt("nonexistent", &[0u8; 32]).await;
        assert!(matches!(result, Err(TransitError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn different_keys_cannot_decrypt_each_other() {
        let engine = TransitEngine::new();
        engine.create_key("key-a").await.unwrap();
        engine.create_key("key-b").await.unwrap();

        let ciphertext = engine.encrypt("key-a", b"secret").await.unwrap();
        let result = engine.decrypt("key-b", &ciphertext).await;

        assert!(matches!(result, Err(TransitError::DecryptionFailed)));
    }

    #[tokio::test]
    async fn list_keys_returns_all() {
        let engine = TransitEngine::new();
        engine.create_key("alpha").await.unwrap();
        engine.create_key("beta").await.unwrap();

        let mut keys = engine.list_keys().await;
        keys.sort();
        assert_eq!(keys, vec!["alpha", "beta"]);
    }

    #[tokio::test]
    async fn delete_key_removes_it() {
        let engine = TransitEngine::new();
        engine.create_key("ephemeral").await.unwrap();

        assert!(engine.delete_key("ephemeral").await);
        assert!(!engine.delete_key("ephemeral").await);
        assert!(engine.list_keys().await.is_empty());
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let engine = TransitEngine::new();
        engine.create_key("k").await.unwrap();

        let mut ct = engine.encrypt("k", b"data").await.unwrap();
        ct[NONCE_LEN + 1] ^= 0xFF;

        let result = engine.decrypt("k", &ct).await;
        assert!(matches!(result, Err(TransitError::DecryptionFailed)));
    }
}
