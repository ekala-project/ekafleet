//! Transit encryption: named, versioned AES-256-GCM keys held by the
//! server, so services can encrypt data without holding a key.
//!
//! Ciphertext is `ekafleet:v<version>:<base64(nonce || ciphertext || tag)>`,
//! authenticated with the key name and version, so a value only decrypts
//! with the key (and version) that produced it. Rotating a key adds a
//! version; new values use the latest and old ones still decrypt.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
const PREFIX: &str = "ekafleet:v";

/// Largest plaintext accepted (1 MiB).
pub const MAX_PLAINTEXT: usize = 1024 * 1024;

/// Scope transit key material is sealed under in the secret store; no
/// service may be named like it.
pub const SEAL_SCOPE: &str = "_transit";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitError {
    #[error("ciphertext is not an ekafleet transit value")]
    Malformed,
    #[error("key version {0} does not exist")]
    UnknownVersion(u32),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("random generation failed")]
    RngFailure,
}

/// A fresh random key.
pub fn generate_key() -> Result<Zeroizing<[u8; KEY_LEN]>, TransitError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    SystemRandom::new()
        .fill(key.as_mut())
        .map_err(|_| TransitError::RngFailure)?;
    Ok(key)
}

/// Name under which version `version` of key `name` is sealed.
pub fn seal_name(name: &str, version: u32) -> String {
    format!("{name}/v{version}")
}

fn aad(name: &str, version: u32) -> Vec<u8> {
    format!("ekafleet-transit\0{name}\0{version}").into_bytes()
}

fn cipher(key: &[u8]) -> Result<LessSafeKey, TransitError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| TransitError::EncryptionFailed)
}

/// Encrypt `plaintext` with version `version` of key `name`.
pub fn encrypt(
    name: &str,
    version: u32,
    key: &[u8],
    plaintext: &[u8],
) -> Result<String, TransitError> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| TransitError::RngFailure)?;
    let mut sealed = plaintext.to_vec();
    cipher(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(name, version)),
            &mut sealed,
        )
        .map_err(|_| TransitError::EncryptionFailed)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    Ok(format!("{PREFIX}{version}:{}", STANDARD.encode(out)))
}

/// The key version a ciphertext was made with.
pub fn version_of(ciphertext: &str) -> Result<u32, TransitError> {
    let (version, _) = split(ciphertext)?;
    Ok(version)
}

fn split(ciphertext: &str) -> Result<(u32, &str), TransitError> {
    let rest = ciphertext
        .trim()
        .strip_prefix(PREFIX)
        .ok_or(TransitError::Malformed)?;
    let (version, body) = rest.split_once(':').ok_or(TransitError::Malformed)?;
    let version = version.parse().map_err(|_| TransitError::Malformed)?;
    if version == 0 {
        return Err(TransitError::Malformed);
    }
    Ok((version, body))
}

/// Decrypt a value made with key `name`; `key` is the version it names.
pub fn decrypt(
    name: &str,
    key: &[u8],
    ciphertext: &str,
) -> Result<Zeroizing<Vec<u8>>, TransitError> {
    let (version, body) = split(ciphertext)?;
    let raw = STANDARD.decode(body).map_err(|_| TransitError::Malformed)?;
    if raw.len() < NONCE_LEN {
        return Err(TransitError::Malformed);
    }
    let (nonce, sealed) = raw.split_at(NONCE_LEN);
    let nonce =
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| TransitError::DecryptionFailed)?;
    let mut buf = Zeroizing::new(sealed.to_vec());
    let plaintext = cipher(key)?
        .open_in_place(nonce, Aad::from(aad(name, version)), &mut buf)
        .map_err(|_| TransitError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_decrypt_only_with_their_key_and_version() {
        let k1 = generate_key().unwrap();
        let k2 = generate_key().unwrap();
        let ct = encrypt("orders", 1, k1.as_ref(), b"card 4242").unwrap();
        assert!(ct.starts_with("ekafleet:v1:"));
        assert_eq!(version_of(&ct), Ok(1));
        assert_eq!(
            &**decrypt("orders", k1.as_ref(), &ct).unwrap(),
            b"card 4242"
        );

        // Another key, another key name, or a relabelled version fail.
        assert_eq!(
            decrypt("orders", k2.as_ref(), &ct).unwrap_err(),
            TransitError::DecryptionFailed
        );
        assert_eq!(
            decrypt("users", k1.as_ref(), &ct).unwrap_err(),
            TransitError::DecryptionFailed
        );
        let relabelled = ct.replacen("ekafleet:v1:", "ekafleet:v2:", 1);
        assert_eq!(
            decrypt("orders", k1.as_ref(), &relabelled).unwrap_err(),
            TransitError::DecryptionFailed
        );
    }

    #[test]
    fn malformed_values_are_rejected() {
        let key = generate_key().unwrap();
        for bad in [
            "",
            "vault:v1:abc",
            "ekafleet:v0:AAAA",
            "ekafleet:vx:AAAA",
            "ekafleet:v1",
            "ekafleet:v1:!!!",
            "ekafleet:v1:AAAA",
        ] {
            assert_eq!(
                decrypt("k", key.as_ref(), bad).unwrap_err(),
                TransitError::Malformed,
                "{bad}"
            );
        }
        let mut ct = encrypt("k", 3, key.as_ref(), b"data").unwrap();
        ct.pop();
        ct.push(if ct.ends_with('A') { 'B' } else { 'A' });
        assert!(decrypt("k", key.as_ref(), &ct).is_err());
    }
}
