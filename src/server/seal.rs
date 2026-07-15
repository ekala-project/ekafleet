//! At-rest sealing for sensitive key material (CA private key, fleet master key).
//!
//! Sealing wraps a secret under a key-encryption key (KEK) derived from an
//! operator-supplied passphrase via PBKDF2-HMAC-SHA256, then encrypts with
//! AES-256-GCM. The on-disk envelope is self-describing:
//!
//! ```text
//! magic "EKAFSEAL" | version u8 | iterations u32-be | salt[16] | nonce[12] | ciphertext+tag
//! ```
//!
//! The passphrase is taken from the `EKAFLEET_SEAL_PASSPHRASE` environment
//! variable. When it is absent the caller may choose to fall back to plaintext
//! persistence (with a warning) so that development and existing deployments
//! keep working; production is expected to set the passphrase.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"EKAFSEAL";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// PBKDF2 iteration count. Tuned for a balance of startup cost and brute-force
/// resistance on the derived KEK; recorded in the envelope for forward compat.
const DEFAULT_ITERATIONS: u32 = 600_000;

/// Environment variable that supplies the sealing passphrase.
pub const PASSPHRASE_ENV: &str = "EKAFLEET_SEAL_PASSPHRASE";

#[derive(Debug)]
pub enum SealError {
    Crypto,
    Format(String),
    BadPassphrase,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Crypto => write!(f, "cryptographic operation failed"),
            SealError::Format(m) => write!(f, "malformed sealed envelope: {m}"),
            SealError::BadPassphrase => {
                write!(f, "unable to unseal — wrong passphrase or corrupt data")
            }
        }
    }
}

impl std::error::Error for SealError {}

/// Read the sealing passphrase from the environment, if configured.
pub fn passphrase_from_env() -> Option<Zeroizing<String>> {
    match std::env::var(PASSPHRASE_ENV) {
        Ok(p) if !p.is_empty() => Some(Zeroizing::new(p)),
        _ => None,
    }
}

/// Returns true if the given bytes look like a sealed envelope.
pub fn is_sealed(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

fn derive_kek(passphrase: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; KEY_LEN]> {
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    let iters = NonZeroU32::new(iterations).unwrap_or(NonZeroU32::new(DEFAULT_ITERATIONS).unwrap());
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        salt,
        passphrase,
        kek.as_mut(),
    );
    kek
}

/// Seal `plaintext` under a KEK derived from `passphrase`.
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, SealError> {
    let rng = SystemRandom::new();

    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt).map_err(|_| SealError::Crypto)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).map_err(|_| SealError::Crypto)?;

    let kek = derive_kek(passphrase.as_bytes(), &salt, DEFAULT_ITERATIONS);
    let unbound = UnboundKey::new(&AES_256_GCM, kek.as_ref()).map_err(|_| SealError::Crypto)?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| SealError::Crypto)?;

    let mut out = Vec::with_capacity(MAGIC.len() + 1 + 4 + SALT_LEN + NONCE_LEN + buf.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&DEFAULT_ITERATIONS.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Unseal an envelope produced by [`seal`].
pub fn unseal(sealed: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let header_len = MAGIC.len() + 1 + 4 + SALT_LEN + NONCE_LEN;
    if sealed.len() < header_len {
        return Err(SealError::Format("truncated header".into()));
    }
    if &sealed[..MAGIC.len()] != MAGIC {
        return Err(SealError::Format("bad magic".into()));
    }
    let mut pos = MAGIC.len();
    let version = sealed[pos];
    pos += 1;
    if version != VERSION {
        return Err(SealError::Format(format!("unsupported version {version}")));
    }
    let iterations = u32::from_be_bytes(sealed[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let salt = &sealed[pos..pos + SALT_LEN];
    pos += SALT_LEN;
    let nonce_bytes: [u8; NONCE_LEN] = sealed[pos..pos + NONCE_LEN].try_into().unwrap();
    pos += NONCE_LEN;
    let ciphertext = &sealed[pos..];

    let kek = derive_kek(passphrase.as_bytes(), salt, iterations);
    let unbound = UnboundKey::new(&AES_256_GCM, kek.as_ref()).map_err(|_| SealError::Crypto)?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| SealError::BadPassphrase)?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// Persist `plaintext` to `path`, sealing it when a passphrase is configured.
///
/// When no passphrase is set, writes plaintext and logs a warning so operators
/// are aware the material is unprotected at rest. File permissions are set to
/// `0o600` on Unix regardless.
pub async fn write_maybe_sealed(
    path: &std::path::Path,
    plaintext: &[u8],
    what: &str,
) -> anyhow::Result<()> {
    let bytes = match passphrase_from_env() {
        Some(pass) => seal(plaintext, &pass).map_err(|e| anyhow::anyhow!("{e}"))?,
        None => {
            tracing::warn!(
                what,
                env = PASSPHRASE_ENV,
                "{what} is being written UNSEALED (plaintext at rest). \
                 Set {PASSPHRASE_ENV} to encrypt sensitive key material."
            );
            plaintext.to_vec()
        }
    };
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, &bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(path, perms).await?;
    }
    Ok(())
}

/// Read `path`, unsealing it when it is a sealed envelope.
///
/// Plaintext (legacy) files are returned as-is. A sealed file requires the
/// passphrase to be configured; otherwise an error is returned so the operator
/// notices rather than silently failing to start.
pub async fn read_maybe_sealed(path: &std::path::Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let data = tokio::fs::read(path).await?;
    if is_sealed(&data) {
        let pass = passphrase_from_env().ok_or_else(|| {
            anyhow::anyhow!(
                "{} is sealed but {PASSPHRASE_ENV} is not set",
                path.display()
            )
        })?;
        unseal(&data, &pass)
            .map_err(|e| anyhow::anyhow!("failed to unseal {}: {e}", path.display()))
    } else {
        Ok(Zeroizing::new(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let secret = b"top-secret-ca-key-material";
        let sealed = seal(secret, "correct horse battery staple").unwrap();
        assert!(is_sealed(&sealed));
        assert_ne!(&sealed[..], &secret[..]);
        let opened = unseal(&sealed, "correct horse battery staple").unwrap();
        assert_eq!(&opened[..], secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let sealed = seal(b"data", "right").unwrap();
        let err = unseal(&sealed, "wrong").unwrap_err();
        assert!(matches!(err, SealError::BadPassphrase));
    }

    #[test]
    fn plaintext_is_not_detected_as_sealed() {
        assert!(!is_sealed(b"-----BEGIN PRIVATE KEY-----"));
        assert!(!is_sealed(b""));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(b"data", "pw").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(unseal(&sealed, "pw").is_err());
    }
}
