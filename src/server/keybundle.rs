//! The key bundle: the keys every server of one cluster must share, sealed
//! under a passphrase so they can be carried to a new server
//! (`ekafleet keys export` on an existing server, `ekafleet keys import` on
//! the new one before its first boot).
//!
//! It holds the fleet key (secrets and transit keys are sealed under it),
//! the binary cache signing key (agents trust one cache key), and the root
//! CA key and certificate plus the JWT-SVID signing key (every server's
//! SVIDs chain to one root). Keys a server keeps to itself stay out of it:
//! the Raft storage key, the intermediate CA (minted from the root on first
//! boot) and the server ID.
//!
//! The bundle is sealed with [`seal`] (PBKDF2 + AES-256-GCM); imported keys
//! are written as the server writes its own: 0600, and sealed at rest when
//! a seal passphrase is configured.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::seal;

/// Format version of the sealed bundle.
const VERSION: u32 = 1;
/// Shortest passphrase accepted to seal a bundle.
pub const MIN_PASSPHRASE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum KeyBundleError {
    #[error("{} is missing; start this server once to create its keys", .0.display())]
    Missing(PathBuf),
    #[error("a fleet key rotation is in progress; export once it has finished")]
    RotationInProgress,
    #[error("the bundle passphrase must be at least {MIN_PASSPHRASE_LEN} characters")]
    WeakPassphrase,
    #[error("cannot open the key bundle (wrong passphrase or not a bundle): {0}")]
    Unseal(#[from] seal::SealError),
    #[error("malformed key bundle: {0}")]
    Malformed(String),
    #[error("the bundle is for trust domain {bundle}, not {expected}")]
    WrongDomain { bundle: String, expected: String },
    #[error(
        "{} differs from the bundle's {what}: this server already has its own keys. \
         Move its data directory aside to join it to the cluster",
        .path.display()
    )]
    Conflict { path: PathBuf, what: &'static str },
    #[error("{0}")]
    Io(#[from] anyhow::Error),
}

/// Which keys to import: a server running its CA in a separate
/// `ekafleet ca-signer` imports [`Scope::Server`] into its own data
/// directory and [`Scope::Ca`] into the signer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scope {
    /// The fleet key and the binary cache signing key.
    Server,
    /// The root CA and the JWT-SVID signing key.
    Ca,
    /// Both, for a server with an embedded CA.
    All,
}

impl Scope {
    fn includes(self, part: &Part) -> bool {
        self == Scope::All || self == part.scope
    }
}

struct Part {
    file: &'static str,
    scope: Scope,
    what: &'static str,
    /// Not secret: written 0644 and never sealed.
    public: bool,
    /// Rotated on a running cluster: a different copy on an existing server
    /// is newer, not a conflict.
    rotates: bool,
}

const FLEET_KEY: &str = "fleet-key";

const PARTS: &[Part] = &[
    Part {
        file: FLEET_KEY,
        scope: Scope::Server,
        what: "fleet encryption key",
        public: false,
        rotates: true,
    },
    Part {
        file: super::cache::CACHE_KEY,
        scope: Scope::Server,
        what: "binary cache signing key",
        public: false,
        rotates: false,
    },
    Part {
        file: crate::ca::persist::ROOT_KEY,
        scope: Scope::Ca,
        what: "CA private key",
        public: false,
        rotates: false,
    },
    Part {
        file: crate::ca::persist::ROOT_CERT,
        scope: Scope::Ca,
        what: "CA certificate",
        public: true,
        rotates: false,
    },
    Part {
        file: crate::ca::persist::JWT_KEY,
        scope: Scope::Ca,
        what: "JWT-SVID signing key",
        public: false,
        rotates: false,
    },
];

#[derive(Serialize, Deserialize)]
struct Bundle {
    version: u32,
    domain: String,
    /// File name → base64 contents (unsealed).
    files: BTreeMap<String, String>,
}

impl Drop for Bundle {
    fn drop(&mut self) {
        for contents in self.files.values_mut() {
            contents.zeroize();
        }
    }
}

async fn read_part(path: &Path, part: &Part) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if part.public {
        Ok(Zeroizing::new(tokio::fs::read(path).await?))
    } else {
        seal::read_maybe_sealed(path).await
    }
}

/// Seal the shared keys of the server in `data_dir` (and its CA in
/// `ca_dir`, when separate) under `passphrase`.
pub async fn export(
    data_dir: &Path,
    ca_dir: Option<&Path>,
    domain: &str,
    passphrase: &str,
) -> Result<Vec<u8>, KeyBundleError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(KeyBundleError::WeakPassphrase);
    }
    if data_dir.join(super::secrets::NEXT_FLEET_KEY_FILE).exists() {
        return Err(KeyBundleError::RotationInProgress);
    }
    let mut bundle = Bundle {
        version: VERSION,
        domain: domain.to_string(),
        files: BTreeMap::new(),
    };
    for part in PARTS {
        let dir = match part.scope {
            Scope::Ca => ca_dir.unwrap_or(data_dir),
            _ => data_dir,
        };
        let path = dir.join(part.file);
        if !path.exists() {
            return Err(KeyBundleError::Missing(path));
        }
        let contents = read_part(&path, part).await?;
        bundle
            .files
            .insert(part.file.to_string(), B64.encode(&*contents));
    }
    let json = Zeroizing::new(
        serde_json::to_vec(&bundle).map_err(|e| KeyBundleError::Malformed(e.to_string()))?,
    );
    Ok(seal::seal(&json, passphrase)?)
}

/// What [`import`] did with each key.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub written: Vec<&'static str>,
    /// Already present and identical, or a newer rotated copy.
    pub kept: Vec<&'static str>,
}

/// Write the keys of `scope` from the sealed `bundle` into `data_dir`.
///
/// Idempotent, so it can run before every start: keys already present are
/// kept when identical (or, for the rotating fleet key, newer). A
/// different CA or cache key means the server already made its own, and
/// is refused rather than overwritten.
pub async fn import(
    bundle: &[u8],
    passphrase: &str,
    data_dir: &Path,
    scope: Scope,
    expected_domain: Option<&str>,
) -> Result<ImportReport, KeyBundleError> {
    let json = seal::unseal(bundle, passphrase)?;
    let bundle: Bundle =
        serde_json::from_slice(&json).map_err(|e| KeyBundleError::Malformed(e.to_string()))?;
    if bundle.version != VERSION {
        return Err(KeyBundleError::Malformed(format!(
            "unsupported bundle version {}",
            bundle.version
        )));
    }
    if let Some(expected) = expected_domain
        && expected != bundle.domain
    {
        return Err(KeyBundleError::WrongDomain {
            bundle: bundle.domain.clone(),
            expected: expected.to_string(),
        });
    }

    // Decode and check everything before writing anything.
    let mut parts = Vec::new();
    for part in PARTS.iter().filter(|p| scope.includes(p)) {
        let encoded = bundle
            .files
            .get(part.file)
            .ok_or_else(|| KeyBundleError::Malformed(format!("no {}", part.what)))?;
        let contents = Zeroizing::new(
            B64.decode(encoded)
                .map_err(|e| KeyBundleError::Malformed(format!("{}: {e}", part.what)))?,
        );
        validate(part, &contents, &bundle.domain)?;
        let path = data_dir.join(part.file);
        let existing = if path.exists() {
            Some(read_part(&path, part).await?)
        } else {
            None
        };
        match existing {
            Some(existing) if *existing == *contents || part.rotates => {
                parts.push((part, path, None));
            }
            Some(_) => {
                return Err(KeyBundleError::Conflict {
                    path,
                    what: part.what,
                });
            }
            None => parts.push((part, path, Some(contents))),
        }
    }

    tokio::fs::create_dir_all(data_dir)
        .await
        .map_err(anyhow::Error::from)?;
    let mut report = ImportReport::default();
    for (part, path, contents) in parts {
        let Some(contents) = contents else {
            report.kept.push(part.what);
            continue;
        };
        if part.public {
            crate::fsutil::write_atomic(&path, &contents, 0o644)
                .await
                .map_err(anyhow::Error::from)?;
        } else {
            seal::write_maybe_sealed(&path, &contents, part.what).await?;
        }
        tracing::info!(what = part.what, path = %path.display(), "Imported from the key bundle");
        report.written.push(part.what);
    }
    Ok(report)
}

/// Refuse a bundle part the server could not load.
fn validate(part: &Part, contents: &[u8], domain: &str) -> Result<(), KeyBundleError> {
    let bad = |e: String| KeyBundleError::Malformed(format!("{}: {e}", part.what));
    match part.file {
        FLEET_KEY => {
            let hex = std::str::from_utf8(contents).map_err(|e| bad(e.to_string()))?;
            let hex = hex.trim();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad("not a 256-bit hex key".into()));
            }
        }
        super::cache::CACHE_KEY => {
            super::cache::BinaryCache::from_pkcs8(contents, domain)
                .map_err(|e| bad(e.to_string()))?;
        }
        crate::ca::persist::JWT_KEY => {
            crate::ca::jwt::JwtSigner::from_pkcs8(contents).map_err(|e| bad(e.to_string()))?;
        }
        _ => {
            let pem = std::str::from_utf8(contents).map_err(|e| bad(e.to_string()))?;
            if !pem.contains("-----BEGIN ") {
                return Err(bad("not PEM".into()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery";

    /// The keys a server creates on its first start.
    async fn first_boot(dir: &Path) {
        super::super::get_or_create_fleet_key(dir).await.unwrap();
        super::super::cache::BinaryCache::open(dir, "fleet.test")
            .await
            .unwrap();
        crate::ca::persist::open_ca(dir, "fleet.test")
            .await
            .unwrap();
        crate::ca::persist::open_jwt_signer(dir).await.unwrap();
    }

    #[tokio::test]
    async fn a_new_server_shares_the_clusters_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (dir.path().join("s1"), dir.path().join("s2"));
        first_boot(&first).await;
        let bundle = export(&first, None, "fleet.test", PASS).await.unwrap();
        assert!(seal::is_sealed(&bundle));

        let report = import(&bundle, PASS, &second, Scope::All, Some("fleet.test"))
            .await
            .unwrap();
        assert_eq!(report.written.len(), PARTS.len());
        // The second server boots with the same root, JWT, cache and fleet keys.
        first_boot(&second).await;
        let (a, b) = (
            crate::ca::persist::open_ca(&first, "fleet.test")
                .await
                .unwrap(),
            crate::ca::persist::open_ca(&second, "fleet.test")
                .await
                .unwrap(),
        );
        assert_eq!(
            a.root_certificate_pem().await,
            b.root_certificate_pem().await
        );
        assert_ne!(
            a.intermediate_certificate_pem().await,
            b.intermediate_certificate_pem().await,
            "each server mints its own intermediate"
        );
        for file in [FLEET_KEY, super::super::cache::CACHE_KEY] {
            let part = PARTS.iter().find(|p| p.file == file).unwrap();
            assert_eq!(
                *read_part(&first.join(file), part).await.unwrap(),
                *read_part(&second.join(file), part).await.unwrap()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(second.join(FLEET_KEY))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Again (every start): nothing to write.
        let again = import(&bundle, PASS, &second, Scope::All, None)
            .await
            .unwrap();
        assert!(again.written.is_empty());
        assert_eq!(again.kept.len(), PARTS.len());
    }

    #[tokio::test]
    async fn bundles_are_split_between_a_server_and_its_ca_signer() {
        let dir = tempfile::tempdir().unwrap();
        let (server, ca) = (dir.path().join("server"), dir.path().join("ca"));
        super::super::get_or_create_fleet_key(&server)
            .await
            .unwrap();
        super::super::cache::BinaryCache::open(&server, "fleet.test")
            .await
            .unwrap();
        // The CA keys live with the signer: exporting needs its directory.
        let missing = export(&server, None, "fleet.test", PASS).await;
        assert!(matches!(missing, Err(KeyBundleError::Missing(_))));
        crate::ca::persist::open_ca(&ca, "fleet.test")
            .await
            .unwrap();
        crate::ca::persist::open_jwt_signer(&ca).await.unwrap();
        let bundle = export(&server, Some(&ca), "fleet.test", PASS)
            .await
            .unwrap();

        let (server2, ca2) = (dir.path().join("server2"), dir.path().join("ca2"));
        import(&bundle, PASS, &server2, Scope::Server, None)
            .await
            .unwrap();
        import(&bundle, PASS, &ca2, Scope::Ca, None).await.unwrap();
        assert!(server2.join(FLEET_KEY).exists());
        assert!(!server2.join(crate::ca::persist::ROOT_KEY).exists());
        assert!(ca2.join(crate::ca::persist::ROOT_KEY).exists());
        assert!(!ca2.join(FLEET_KEY).exists());
    }

    #[tokio::test]
    async fn bad_bundles_and_existing_keys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (first, other) = (dir.path().join("s1"), dir.path().join("other"));
        first_boot(&first).await;
        assert!(matches!(
            export(&first, None, "fleet.test", "short").await,
            Err(KeyBundleError::WeakPassphrase)
        ));
        let bundle = export(&first, None, "fleet.test", PASS).await.unwrap();

        let target = dir.path().join("s2");
        assert!(matches!(
            import(&bundle, "wrong passphrase!", &target, Scope::All, None).await,
            Err(KeyBundleError::Unseal(_))
        ));
        assert!(matches!(
            import(&bundle, PASS, &target, Scope::All, Some("other.test")).await,
            Err(KeyBundleError::WrongDomain { .. })
        ));
        assert!(matches!(
            import(b"not a bundle", PASS, &target, Scope::All, None).await,
            Err(KeyBundleError::Unseal(_))
        ));
        assert!(!target.exists(), "nothing written on failure");

        // A server that already booted on its own keeps its keys.
        first_boot(&other).await;
        let conflict = import(&bundle, PASS, &other, Scope::All, None).await;
        assert!(
            matches!(conflict, Err(KeyBundleError::Conflict { .. })),
            "{conflict:?}"
        );

        // An unfinished fleet key rotation is not exported.
        std::fs::write(first.join(super::super::secrets::NEXT_FLEET_KEY_FILE), b"x").unwrap();
        assert!(matches!(
            export(&first, None, "fleet.test", PASS).await,
            Err(KeyBundleError::RotationInProgress)
        ));
    }

    #[tokio::test]
    async fn a_rotated_fleet_key_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (dir.path().join("s1"), dir.path().join("s2"));
        first_boot(&first).await;
        let bundle = export(&first, None, "fleet.test", PASS).await.unwrap();
        import(&bundle, PASS, &second, Scope::All, None)
            .await
            .unwrap();
        let rotated = "ab".repeat(32);
        std::fs::write(second.join(FLEET_KEY), &rotated).unwrap();
        let report = import(&bundle, PASS, &second, Scope::All, None)
            .await
            .unwrap();
        assert!(report.written.is_empty());
        assert_eq!(
            std::fs::read_to_string(second.join(FLEET_KEY)).unwrap(),
            rotated
        );
    }
}
