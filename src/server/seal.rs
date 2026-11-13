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
//! variable, or read from the file named by `EKAFLEET_SEAL_PASSPHRASE_FILE`
//! (e.g. a systemd credential, which keeps the secret out of the unit's
//! environment block). When neither is set the caller may fall back to
//! plaintext persistence (with a warning) so that development keeps working;
//! production is expected to configure a passphrase.

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

/// Environment variable naming a file that holds the sealing passphrase.
pub const PASSPHRASE_FILE_ENV: &str = "EKAFLEET_SEAL_PASSPHRASE_FILE";

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
///
/// A configured but unreadable or empty passphrase file is an error, never
/// "no passphrase": silently falling back would write key material unsealed.
pub fn passphrase_from_env() -> anyhow::Result<Option<Zeroizing<String>>> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV)
        && !p.is_empty()
    {
        return Ok(Some(Zeroizing::new(p)));
    }
    let Some(path) = std::env::var_os(PASSPHRASE_FILE_ENV).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    passphrase_from_file(std::path::Path::new(&path)).map(Some)
}

/// Read a passphrase file, dropping one trailing newline.
fn passphrase_from_file(path: &std::path::Path) -> anyhow::Result<Zeroizing<String>> {
    let mut pass = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("cannot read seal passphrase file {}: {e}", path.display())
    })?);
    if pass.ends_with('\n') {
        pass.pop();
        if pass.ends_with('\r') {
            pass.pop();
        }
    }
    if pass.is_empty() {
        anyhow::bail!("seal passphrase file {} is empty", path.display());
    }
    Ok(pass)
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
/// are aware the material is unprotected at rest. The file is replaced
/// atomically and created with mode `0o600`, so it is never readable by other
/// users, not even transiently.
pub async fn write_maybe_sealed(
    path: &std::path::Path,
    plaintext: &[u8],
    what: &str,
) -> anyhow::Result<()> {
    let bytes = match passphrase_from_env()? {
        Some(pass) => Zeroizing::new(seal(plaintext, &pass).map_err(|e| anyhow::anyhow!("{e}"))?),
        None => {
            tracing::warn!(
                what,
                env = PASSPHRASE_ENV,
                "{what} is being written UNSEALED (plaintext at rest). \
                 Set {PASSPHRASE_ENV} or {PASSPHRASE_FILE_ENV} to encrypt sensitive key material."
            );
            Zeroizing::new(plaintext.to_vec())
        }
    };
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    crate::fsutil::write_atomic(path, &bytes, 0o600).await?;
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
        let pass = passphrase_from_env()?.ok_or_else(|| {
            anyhow::anyhow!(
                "{} is sealed but neither {PASSPHRASE_ENV} nor {PASSPHRASE_FILE_ENV} is set",
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
    fn passphrase_file_strips_one_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pass");
        std::fs::write(&path, "s3cret\n").unwrap();
        assert_eq!(passphrase_from_file(&path).unwrap().as_str(), "s3cret");
        std::fs::write(&path, "s3cret \r\n").unwrap();
        assert_eq!(passphrase_from_file(&path).unwrap().as_str(), "s3cret ");
    }

    #[test]
    fn empty_or_missing_passphrase_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pass");
        assert!(passphrase_from_file(&path).is_err());
        std::fs::write(&path, "\n").unwrap();
        assert!(passphrase_from_file(&path).is_err());
    }

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
