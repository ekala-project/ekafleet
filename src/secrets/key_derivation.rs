use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{self, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

const NONCE_LEN: usize = 12;

/// Derive a per-agent encryption key from the fleet master key using HKDF-SHA256.
///
/// The derived key is unique per agent, so compromising one agent's key does not
/// expose secrets encrypted for other agents. The fleet master key never leaves
/// the server.
pub fn derive_agent_key(fleet_master_key: &[u8], agent_spiffe_id: &str) -> [u8; 32] {
    let salt = hkdf::Salt::new(HKDF_SHA256, b"ekafleet-agent-key-v1");
    let prk = salt.extract(fleet_master_key);
    let info = [agent_spiffe_id.as_bytes()];
    let okm = prk
        .expand(&info, HKDF_SHA256)
        .expect("HKDF expand with valid length");
    let mut key = [0u8; 32];
    okm.fill(&mut key).expect("32-byte output fits SHA-256");
    key
}

/// Re-encrypt a sealed value (encrypted with `src_key`) under a different key (`dst_key`).
///
/// The AAD is used for both decryption and re-encryption, preserving the
/// binding to the secret's service/name context across the key transition.
///
/// Used by the server to re-encrypt secrets from the fleet master key to a
/// per-agent derived key before distribution.
pub fn reencrypt(
    src_key: &[u8; 32],
    dst_key: &[u8; 32],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ReencryptError> {
    // Decrypt with source key
    if sealed.len() < NONCE_LEN {
        return Err(ReencryptError);
    }
    let (nonce_bytes, ciphertext_and_tag) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| ReencryptError)?;
    let src_unbound = UnboundKey::new(&AES_256_GCM, src_key).map_err(|_| ReencryptError)?;
    let src_aead = LessSafeKey::new(src_unbound);
    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext = src_aead
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| ReencryptError)?;
    let plaintext = plaintext.to_vec();

    // Re-encrypt with destination key (same AAD preserves context binding)
    let rng = SystemRandom::new();
    let mut new_nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut new_nonce_bytes).map_err(|_| ReencryptError)?;
    let new_nonce = Nonce::assume_unique_for_key(new_nonce_bytes);
    let dst_unbound = UnboundKey::new(&AES_256_GCM, dst_key).map_err(|_| ReencryptError)?;
    let dst_aead = LessSafeKey::new(dst_unbound);
    let mut out = plaintext;
    dst_aead
        .seal_in_place_append_tag(new_nonce, Aad::from(aad), &mut out)
        .map_err(|_| ReencryptError)?;

    let mut result = Vec::with_capacity(NONCE_LEN + out.len());
    result.extend_from_slice(&new_nonce_bytes);
    result.extend_from_slice(&out);
    Ok(result)
}

#[derive(Debug)]
pub struct ReencryptError;

impl std::fmt::Display for ReencryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "re-encryption failed")
    }
}

impl std::error::Error for ReencryptError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet_key() -> [u8; 32] {
        [0xAB; 32]
    }

    const TEST_AAD: &[u8] = b"test-svc\x00db-pass";

    /// Helper: encrypt plaintext with the given key and AAD (same as SecretStore).
    fn encrypt_with(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let unbound = UnboundKey::new(&AES_256_GCM, key).unwrap();
        let aead = LessSafeKey::new(unbound);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        aead.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .unwrap();
        let mut sealed = Vec::with_capacity(NONCE_LEN + in_out.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&in_out);
        sealed
    }

    /// Helper: decrypt sealed data with the given key and AAD.
    fn decrypt_with(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Vec<u8> {
        let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).unwrap();
        let unbound = UnboundKey::new(&AES_256_GCM, key).unwrap();
        let aead = LessSafeKey::new(unbound);
        let mut in_out = ct.to_vec();
        let pt = aead
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .unwrap();
        pt.to_vec()
    }

    #[test]
    fn derived_keys_are_deterministic() {
        let k1 = derive_agent_key(&fleet_key(), "spiffe://fleet.internal/agent/node-1");
        let k2 = derive_agent_key(&fleet_key(), "spiffe://fleet.internal/agent/node-1");
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_agents_get_different_keys() {
        let k1 = derive_agent_key(&fleet_key(), "spiffe://fleet.internal/agent/node-1");
        let k2 = derive_agent_key(&fleet_key(), "spiffe://fleet.internal/agent/node-2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_fleet_keys_produce_different_derived_keys() {
        let k1 = derive_agent_key(&[0xAA; 32], "spiffe://fleet.internal/agent/node-1");
        let k2 = derive_agent_key(&[0xBB; 32], "spiffe://fleet.internal/agent/node-1");
        assert_ne!(k1, k2);
    }

    #[test]
    fn derived_key_is_32_bytes() {
        let k = derive_agent_key(&fleet_key(), "spiffe://fleet.internal/agent/node-1");
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn reencrypt_preserves_plaintext() {
        let src = fleet_key();
        let dst = derive_agent_key(&src, "spiffe://fleet.internal/agent/node-1");
        let plaintext = b"my-database-password";

        let sealed_src = encrypt_with(&src, plaintext, TEST_AAD);
        let sealed_dst = reencrypt(&src, &dst, &sealed_src, TEST_AAD).unwrap();

        let recovered = decrypt_with(&dst, &sealed_dst, TEST_AAD);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn reencrypt_output_not_decryptable_with_src_key() {
        let src = fleet_key();
        let dst = derive_agent_key(&src, "spiffe://fleet.internal/agent/node-1");
        let sealed_src = encrypt_with(&src, b"secret", TEST_AAD);

        let sealed_dst = reencrypt(&src, &dst, &sealed_src, TEST_AAD).unwrap();

        // The re-encrypted value must NOT be decryptable with the source key
        let unbound = UnboundKey::new(&AES_256_GCM, &src).unwrap();
        let aead = LessSafeKey::new(unbound);
        let (nonce_bytes, ct) = sealed_dst.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).unwrap();
        let mut in_out = ct.to_vec();
        let result = aead.open_in_place(nonce, Aad::from(TEST_AAD), &mut in_out);
        assert!(
            result.is_err(),
            "re-encrypted data must not be decryptable with the original fleet key"
        );
    }

    #[test]
    fn reencrypt_fails_on_truncated_input() {
        let src = fleet_key();
        let dst = [0xCC; 32];
        assert!(reencrypt(&src, &dst, &[0u8; 5], TEST_AAD).is_err());
        assert!(reencrypt(&src, &dst, &[], TEST_AAD).is_err());
    }

    #[test]
    fn reencrypt_fails_on_tampered_input() {
        let src = fleet_key();
        let dst = [0xCC; 32];
        let mut sealed = encrypt_with(&src, b"secret", TEST_AAD);
        // Flip a byte in the ciphertext
        sealed[NONCE_LEN + 1] ^= 0xFF;
        assert!(reencrypt(&src, &dst, &sealed, TEST_AAD).is_err());
    }

    #[test]
    fn reencrypt_fails_with_wrong_aad() {
        let src = fleet_key();
        let dst = derive_agent_key(&src, "spiffe://fleet.internal/agent/node-1");
        let sealed = encrypt_with(&src, b"secret", b"svc-a\x00key");
        // Try to re-encrypt with different AAD — must fail (integrity check)
        assert!(reencrypt(&src, &dst, &sealed, b"svc-b\x00key").is_err());
    }
}
