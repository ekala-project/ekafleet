//! The server's binary cache for service closures.
//!
//! At apply time the server builds every store path a service configuration
//! refers to (see [`super::nix::build_closures`]). Agents fetch those
//! closures from here over their authenticated gRPC connection: the agent
//! runs a short-lived loopback HTTP bridge and points `nix copy --from` at
//! it, so Nix itself downloads only what is missing and verifies every path
//! against the narinfo signature and NAR hash.
//!
//! Each narinfo is signed with an Ed25519 key (`ring`), sealed at rest like
//! the CA keys. Its public half travels to agents in `DesiredState`. An agent
//! may only fetch paths in the closure of the store paths assigned to it.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::server::seal;

/// File holding the (possibly sealed) PKCS#8 cache signing key.
const CACHE_KEY: &str = "cache-signing-key.pk8";

/// Size of the NAR chunks streamed to agents.
const CHUNK_SIZE: usize = 64 * 1024;

const STORE_DIR: &str = "/nix/store";

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache signing key: {0}")]
    Key(String),
    #[error("{0} failed: {1}")]
    Nix(&'static str, String),
    #[error("unexpected nix output: {0}")]
    Parse(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Store metadata for one path, as needed for its narinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    pub path: String,
    /// `sha256:<nix32>`.
    pub nar_hash: String,
    pub nar_size: u64,
    pub deriver: Option<String>,
    /// Full store paths, sorted.
    pub references: Vec<String>,
}

impl PathInfo {
    /// The string Nix signs and verifies for a path
    /// (`1;<path>;<narHash>;<narSize>;<refs>`).
    pub fn fingerprint(&self) -> String {
        format!(
            "1;{};{};{};{}",
            self.path,
            self.nar_hash,
            self.nar_size,
            self.references.join(",")
        )
    }
}

/// The 32-character hash part of a store path (`/nix/store/<hash>-name`).
pub fn hash_part(path: &str) -> Option<&str> {
    let base = path.strip_prefix(STORE_DIR)?.strip_prefix('/')?;
    let hash = base.get(..32)?;
    (base.as_bytes().get(32) == Some(&b'-') && is_nix32(hash)).then_some(hash)
}

/// The base name of a store path (`<hash>-name`).
fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

const NIX32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

fn is_nix32(s: &str) -> bool {
    s.bytes().all(|b| NIX32.contains(&b))
}

/// Encode bytes in Nix's base-32 alphabet and bit order.
pub fn nix32(bytes: &[u8]) -> String {
    let len = (bytes.len() * 8).div_ceil(5);
    (0..len)
        .rev()
        .map(|n| {
            let b = n * 5;
            let (i, j) = (b / 8, b % 8);
            let lo = u16::from(bytes[i]) >> j;
            let hi = bytes.get(i + 1).map_or(0, |&x| u16::from(x) << (8 - j));
            NIX32[usize::from((lo | hi) & 0x1f)] as char
        })
        .collect()
}

/// Normalise a hash from `nix-store --dump-db` (base-16 SHA-256, or an
/// already prefixed `sha256:` hash) to `sha256:<nix32>`.
fn normalise_hash(raw: &str) -> Result<String, CacheError> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix("sha256:") {
        if rest.len() == 52 && is_nix32(rest) {
            return Ok(raw.to_string());
        }
        return normalise_hash(rest);
    }
    if raw.len() != 64 {
        return Err(CacheError::Parse(format!("unrecognised NAR hash {raw}")));
    }
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| CacheError::Parse(format!("unrecognised NAR hash {raw}")))?;
    Ok(format!("sha256:{}", nix32(&bytes)))
}

/// Parse `nix-store --dump-db` registration output: for each path its
/// path, NAR hash, NAR size, deriver, reference count and references.
pub fn parse_dump_db(out: &str) -> Result<Vec<PathInfo>, CacheError> {
    let mut lines = out.lines();
    let mut infos = Vec::new();
    let short = || CacheError::Parse("truncated nix-store --dump-db output".into());
    while let Some(path) = lines.next() {
        if path.is_empty() {
            continue;
        }
        let nar_hash = normalise_hash(lines.next().ok_or_else(short)?)?;
        let nar_size = lines
            .next()
            .ok_or_else(short)?
            .trim()
            .parse()
            .map_err(|_| CacheError::Parse(format!("bad NAR size for {path}")))?;
        let deriver = lines.next().ok_or_else(short)?.trim();
        let count: usize = lines
            .next()
            .ok_or_else(short)?
            .trim()
            .parse()
            .map_err(|_| CacheError::Parse(format!("bad reference count for {path}")))?;
        let mut references = (0..count)
            .map(|_| lines.next().map(str::to_string).ok_or_else(short))
            .collect::<Result<Vec<_>, _>>()?;
        references.sort();
        infos.push(PathInfo {
            path: path.to_string(),
            nar_hash,
            nar_size,
            deriver: (!deriver.is_empty()).then(|| deriver.to_string()),
            references,
        });
    }
    Ok(infos)
}

async fn nix_store(args: &[&str], paths: &[String]) -> Result<String, CacheError> {
    let output = tokio::process::Command::new("nix-store")
        .args(args)
        .args(paths)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    if !output.status.success() {
        let what = if args.contains(&"--dump-db") {
            "nix-store --dump-db"
        } else {
            "nix-store --query"
        };
        return Err(CacheError::Nix(
            what,
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Default)]
struct Index {
    /// Root store path → hash parts of every path in its closure.
    closures: HashMap<String, Arc<HashSet<String>>>,
    /// Hash part → metadata.
    infos: HashMap<String, Arc<PathInfo>>,
}

/// Signed, node-scoped binary cache over the server's local Nix store.
#[derive(Clone)]
pub struct BinaryCache {
    key: Arc<Ed25519KeyPair>,
    key_name: String,
    index: Arc<RwLock<Index>>,
}

impl BinaryCache {
    /// Load the signing key from `data_dir`, generating and persisting
    /// (sealed, 0600) one on first boot. A key that exists but cannot be read
    /// or unsealed is an error, never a reason to replace it: agents would
    /// stop trusting the cache.
    pub async fn open(data_dir: &Path, domain: &str) -> anyhow::Result<Self> {
        let path = data_dir.join(CACHE_KEY);
        let pkcs8 = if path.exists() {
            seal::read_maybe_sealed(&path).await?
        } else {
            let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| CacheError::Key("key generation failed".into()))?;
            let pkcs8 = Zeroizing::new(doc.as_ref().to_vec());
            tokio::fs::create_dir_all(data_dir).await?;
            seal::write_maybe_sealed(&path, &pkcs8, "binary cache signing key").await?;
            pkcs8
        };
        let cache = Self::from_pkcs8(&pkcs8, domain)?;
        tracing::info!(public_key = %cache.public_key(), "Binary cache signing key loaded");
        Ok(cache)
    }

    pub fn from_pkcs8(pkcs8: &[u8], domain: &str) -> Result<Self, CacheError> {
        let key = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| CacheError::Key(format!("invalid key: {e}")))?;
        Ok(Self {
            key: Arc::new(key),
            key_name: format!("ekafleet-{domain}-1"),
            index: Arc::default(),
        })
    }

    /// The public key in Nix's `name:base64` format, for
    /// `trusted-public-keys`.
    pub fn public_key(&self) -> String {
        format!(
            "{}:{}",
            self.key_name,
            B64.encode(self.key.public_key().as_ref())
        )
    }

    /// Sign `info` and render its narinfo. The NAR is served uncompressed.
    pub fn narinfo(&self, info: &PathInfo) -> String {
        let hash = hash_part(&info.path).unwrap_or_default();
        let sig = B64.encode(self.key.sign(info.fingerprint().as_bytes()).as_ref());
        let refs: Vec<&str> = info.references.iter().map(|r| base_name(r)).collect();
        let mut out = format!(
            "StorePath: {}\nURL: nar/{hash}.nar\nCompression: none\nNarHash: {}\nNarSize: {}\nReferences: {}\n",
            info.path,
            info.nar_hash,
            info.nar_size,
            refs.join(" ")
        );
        if let Some(deriver) = &info.deriver {
            out.push_str(&format!("Deriver: {}\n", base_name(deriver)));
        }
        out.push_str(&format!("Sig: {}:{sig}\n", self.key_name));
        out
    }

    /// The closure of `root` as hash parts, computing and indexing it on
    /// first use. Store paths are immutable, so the result never goes stale.
    async fn closure(&self, root: &str) -> Result<Arc<HashSet<String>>, CacheError> {
        if let Some(closure) = self.index.read().await.closures.get(root) {
            return Ok(closure.clone());
        }
        let requisites = nix_store(&["--query", "--requisites"], &[root.to_string()]).await?;
        let paths: Vec<String> = requisites.lines().map(str::to_string).collect();
        let missing: Vec<String> = {
            let index = self.index.read().await;
            paths
                .iter()
                .filter(|p| hash_part(p).is_some_and(|h| !index.infos.contains_key(h)))
                .cloned()
                .collect()
        };
        let infos = if missing.is_empty() {
            Vec::new()
        } else {
            parse_dump_db(&nix_store(&["--dump-db"], &missing).await?)?
        };
        let closure: Arc<HashSet<String>> = Arc::new(
            paths
                .iter()
                .filter_map(|p| hash_part(p).map(str::to_string))
                .collect(),
        );
        let mut index = self.index.write().await;
        for info in infos {
            if let Some(hash) = hash_part(&info.path) {
                index.infos.insert(hash.to_string(), Arc::new(info));
            }
        }
        index.closures.insert(root.to_string(), closure.clone());
        Ok(closure)
    }

    /// The path with hash part `hash` if it lies in the closure of one of
    /// `roots`, which are the store paths assigned to the requesting node.
    pub async fn authorize(
        &self,
        roots: &[String],
        hash: &str,
    ) -> Result<Option<Arc<PathInfo>>, CacheError> {
        if hash.len() != 32 || !is_nix32(hash) {
            return Ok(None);
        }
        for root in roots {
            if hash_part(root).is_none() {
                continue;
            }
            if self.closure(root).await?.contains(hash) {
                return Ok(self.index.read().await.infos.get(hash).cloned());
            }
        }
        Ok(None)
    }

    /// Stream the NAR serialisation of `path` in chunks.
    pub fn dump(path: &str) -> tokio::sync::mpsc::Receiver<Result<Vec<u8>, CacheError>> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let path = path.to_string();
        tokio::spawn(async move {
            let child = tokio::process::Command::new("nix-store")
                .args(["--dump", &path])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn();
            let mut child = match child {
                Ok(child) => child,
                Err(e) => {
                    let _ = tx.send(Err(e.into())).await;
                    return;
                }
            };
            let Some(mut stdout) = child.stdout.take() else {
                return;
            };
            loop {
                let mut buf = vec![0u8; CHUNK_SIZE];
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.truncate(n);
                        if tx.send(Ok(buf)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e.into())).await;
                        return;
                    }
                }
            }
            match child.wait_with_output().await {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    let _ = tx
                        .send(Err(CacheError::Nix(
                            "nix-store --dump",
                            String::from_utf8_lossy(&out.stderr).trim().to_string(),
                        )))
                        .await;
                }
                Err(e) => {
                    let _ = tx.send(Err(e.into())).await;
                }
            }
        });
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "/nix/store/lcxc2z1h2g8wq8dxfpizy1di85kyxnqx-hello-2.12.3";
    const GLIBC: &str = "/nix/store/0d8g8n0a11v6f5m2h416ajyxmnkwc3md-glibc-2.42-67";

    #[test]
    fn nix32_matches_nix() {
        // `nix-store -q --hash` of the same path printed this.
        assert_eq!(
            normalise_hash("82ab2c557df3a6b49dd7103861cd4339919d1afb70fd80718543b4eb29d8e1d8")
                .unwrap(),
            "sha256:1n71v0lypd23hmqq1zbhzcd9v49r8g6n2f0hsyfv99pkgmajraw2"
        );
        let prefixed = "sha256:1n71v0lypd23hmqq1zbhzcd9v49r8g6n2f0hsyfv99pkgmajraw2";
        assert_eq!(normalise_hash(prefixed).unwrap(), prefixed);
        assert!(normalise_hash("abc").is_err());
    }

    #[test]
    fn hash_part_requires_a_store_path() {
        assert_eq!(hash_part(HELLO), Some("lcxc2z1h2g8wq8dxfpizy1di85kyxnqx"));
        assert_eq!(hash_part("/tmp/lcxc2z1h2g8wq8dxfpizy1di85kyxnqx-x"), None);
        assert_eq!(hash_part("/nix/store/short-x"), None);
        // 'e' is not in the nix32 alphabet.
        assert_eq!(
            hash_part("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-x"),
            None
        );
    }

    #[test]
    fn dump_db_is_parsed() {
        let out = format!(
            "{HELLO}\n82ab2c557df3a6b49dd7103861cd4339919d1afb70fd80718543b4eb29d8e1d8\n279624\n\
             /nix/store/a41gq8gxdhd2haqk5ij6ak4ybwmignrp-hello-2.12.3.drv\n2\n{HELLO}\n{GLIBC}\n\
             {GLIBC}\n82ab2c557df3a6b49dd7103861cd4339919d1afb70fd80718543b4eb29d8e1d8\n10\n\n0\n"
        );
        let infos = parse_dump_db(&out).unwrap();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].references, [GLIBC, HELLO], "sorted");
        assert_eq!(infos[0].nar_size, 279624);
        assert_eq!(infos[1].deriver, None);
        assert!(parse_dump_db(&format!("{HELLO}\nabc\n")).is_err());
    }

    #[test]
    fn narinfo_signature_verifies_against_the_public_key() {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let cache = BinaryCache::from_pkcs8(doc.as_ref(), "fleet.internal").unwrap();
        let info = PathInfo {
            path: HELLO.into(),
            nar_hash: "sha256:1n71v0lypd23hmqq1zbhzcd9v49r8g6n2f0hsyfv99pkgmajraw2".into(),
            nar_size: 279624,
            deriver: Some("/nix/store/a41gq8gxdhd2haqk5ij6ak4ybwmignrp-hello-2.12.3.drv".into()),
            references: vec![GLIBC.into(), HELLO.into()],
        };
        let narinfo = cache.narinfo(&info);
        assert!(narinfo.contains("URL: nar/lcxc2z1h2g8wq8dxfpizy1di85kyxnqx.nar\n"));
        assert!(narinfo.contains(
            "References: 0d8g8n0a11v6f5m2h416ajyxmnkwc3md-glibc-2.42-67 \
             lcxc2z1h2g8wq8dxfpizy1di85kyxnqx-hello-2.12.3\n"
        ));
        assert!(narinfo.contains("Deriver: a41gq8gxdhd2haqk5ij6ak4ybwmignrp-hello-2.12.3.drv\n"));

        let (name, public) = cache
            .public_key()
            .split_once(':')
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap();
        assert_eq!(name, "ekafleet-fleet.internal-1");
        let sig = narinfo
            .lines()
            .find_map(|l| l.strip_prefix("Sig: "))
            .and_then(|s| s.strip_prefix(&format!("{name}:")))
            .unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            B64.decode(public).unwrap(),
        )
        .verify(info.fingerprint().as_bytes(), &B64.decode(sig).unwrap())
        .unwrap();
        assert_eq!(
            info.fingerprint(),
            format!(
                "1;{HELLO};sha256:1n71v0lypd23hmqq1zbhzcd9v49r8g6n2f0hsyfv99pkgmajraw2;279624;{GLIBC},{HELLO}"
            )
        );
    }

    #[tokio::test]
    async fn key_is_persisted_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let first = BinaryCache::open(dir.path(), "fleet.internal")
            .await
            .unwrap();
        let second = BinaryCache::open(dir.path(), "fleet.internal")
            .await
            .unwrap();
        assert_eq!(first.public_key(), second.public_key());
        std::fs::write(dir.path().join(CACHE_KEY), b"garbage").unwrap();
        assert!(
            BinaryCache::open(dir.path(), "fleet.internal")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn paths_outside_assigned_closures_are_refused() {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let cache = BinaryCache::from_pkcs8(doc.as_ref(), "fleet.internal").unwrap();
        // Malformed hashes and non-store roots never reach nix.
        assert!(cache.authorize(&[], "x").await.unwrap().is_none());
        assert!(
            cache
                .authorize(&["/etc/passwd".into()], "lcxc2z1h2g8wq8dxfpizy1di85kyxnqx")
                .await
                .unwrap()
                .is_none()
        );
    }
}
