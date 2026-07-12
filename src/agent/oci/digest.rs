//! OCI content-addressable digest verification.
//!
//! Implements the `<algorithm>:<hex>` digest format used throughout the
//! OCI Distribution and Image specifications.

use std::fmt;
use std::str::FromStr;

use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

/// A verified OCI digest in the form `sha256:<hex>`.
#[derive(Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest {
    hex: String,
}

impl Digest {
    /// The digest algorithm prefix.
    const ALGO: &str = "sha256";

    /// Compute the SHA-256 digest of `data`.
    pub fn from_bytes(data: &[u8]) -> Self {
        let d = ring::digest::digest(&SHA256, data);
        let hex = hex_encode(d.as_ref());
        Self { hex }
    }

    /// Return the hex-encoded hash (without the `sha256:` prefix).
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Return the full `sha256:<hex>` string.
    pub fn as_str(&self) -> String {
        format!("{}:{}", Self::ALGO, self.hex)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Digest({}:{})",
            Self::ALGO,
            &self.hex[..12.min(self.hex.len())]
        )
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::ALGO, self.hex)
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> Self {
        d.as_str()
    }
}

impl TryFrom<String> for Digest {
    type Error = DigestError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("sha256:")
            .ok_or(DigestError::UnsupportedAlgorithm)?;

        if rest.len() != 64 {
            return Err(DigestError::InvalidLength);
        }
        if !rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DigestError::InvalidHex);
        }

        Ok(Self {
            hex: rest.to_string(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("unsupported digest algorithm (only sha256 supported)")]
    UnsupportedAlgorithm,
    #[error("invalid digest length (expected 64 hex chars)")]
    InvalidLength,
    #[error("invalid hex encoding")]
    InvalidHex,
}

/// Streaming digest verifier that checks downloaded content against an expected digest.
pub struct DigestVerifier {
    ctx: Context,
    expected: Digest,
    bytes_written: u64,
}

impl DigestVerifier {
    pub fn new(expected: Digest) -> Self {
        Self {
            ctx: Context::new(&SHA256),
            expected,
            bytes_written: 0,
        }
    }

    /// Feed a chunk of data into the verifier.
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
        self.bytes_written += data.len() as u64;
    }

    /// Total bytes fed so far.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Finalize and verify the digest. Returns `Ok(())` if the digest
    /// matches, or `Err` with the computed digest if it does not.
    pub fn finish(self) -> Result<Digest, DigestMismatch> {
        let computed_raw = self.ctx.finish();
        let computed = Digest {
            hex: hex_encode(computed_raw.as_ref()),
        };
        if computed == self.expected {
            Ok(computed)
        } else {
            Err(DigestMismatch {
                expected: self.expected,
                computed,
            })
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("digest mismatch: expected {expected}, computed {computed}")]
pub struct DigestMismatch {
    pub expected: Digest,
    pub computed: Digest,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_digest() {
        let d = Digest::from_bytes(b"hello world");
        let s = d.as_str();
        let parsed: Digest = s.parse().unwrap();
        assert_eq!(d, parsed);
    }

    #[test]
    fn known_sha256() {
        let d = Digest::from_bytes(b"hello world");
        assert_eq!(
            d.hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn parse_valid() {
        let s = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let d: Digest = s.parse().unwrap();
        assert_eq!(d.to_string(), s);
    }

    #[test]
    fn parse_invalid_algo() {
        assert!("md5:abc123".parse::<Digest>().is_err());
    }

    #[test]
    fn parse_invalid_length() {
        assert!("sha256:abcdef".parse::<Digest>().is_err());
    }

    #[test]
    fn parse_invalid_hex() {
        let bad = format!("sha256:{}", "g".repeat(64));
        assert!(bad.parse::<Digest>().is_err());
    }

    #[test]
    fn verifier_success() {
        let expected = Digest::from_bytes(b"test data");
        let mut v = DigestVerifier::new(expected);
        v.update(b"test ");
        v.update(b"data");
        assert!(v.finish().is_ok());
    }

    #[test]
    fn verifier_failure() {
        let wrong = Digest::from_bytes(b"wrong");
        let mut v = DigestVerifier::new(wrong);
        v.update(b"test data");
        let err = v.finish().unwrap_err();
        assert_ne!(err.expected, err.computed);
    }

    #[test]
    fn serde_round_trip() {
        let d = Digest::from_bytes(b"serde test");
        let json = serde_json::to_string(&d).unwrap();
        let parsed: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, parsed);
    }
}
