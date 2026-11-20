//! TLS of ingress routes.
//!
//! The agent writes each TLS route's certificate chain and private key
//! (from `_fleet` secrets) to [`TLS_DIR`] as `<route>.crt` and
//! `<route>.key`. The key is readable by root and the proxy's group only.
//! The proxy serves them by SNI on its TLS listener, and asks clients for
//! a certificate chaining to the fleet CA, which routes with allowed
//! callers require.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use super::routes::RoutesFile;

/// Where the agent writes, and the proxy reads, route certificates.
pub const TLS_DIR: &str = "/run/ekafleet/ingress-tls";

/// The group the proxy runs in, which may read route keys.
pub const PROXY_GROUP: &str = "ekafleet-ingress-tls";

#[derive(Debug, thiserror::Error)]
pub enum IngressTlsError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("route {route}: {reason}")]
    Certificate { route: String, reason: String },
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Parse a certificate chain and private key.
fn certified_key(route: &str, cert: &[u8], key: &[u8]) -> Result<CertifiedKey, IngressTlsError> {
    let invalid = |reason: String| IngressTlsError::Certificate {
        route: route.to_string(),
        reason,
    };
    let chain = crate::ca::pki::pem_certs(&mut &cert[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(format!("certificate: {e}")))?;
    if chain.is_empty() {
        return Err(invalid("no certificate".into()));
    }
    let key = crate::ca::pki::pem_private_key(&mut &key[..])
        .map_err(|e| invalid(format!("key: {e}")))?
        .ok_or_else(|| invalid("no private key".into()))?;
    let key = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| invalid(format!("key: {e}")))?;
    let certified = CertifiedKey::new(chain, key);
    certified
        .keys_match()
        .map_err(|e| invalid(format!("key does not match the certificate: {e}")))?;
    Ok(certified)
}

/// The gid of `name`, if the group exists.
pub fn group_id(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, correctly sized buffer.
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut group,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    (rc == 0 && !result.is_null()).then_some(group.gr_gid)
}

/// Agent side: the route certificates in a directory.
pub struct CertDir {
    dir: PathBuf,
    /// Group that may read keys; without, only root may.
    group: Option<u32>,
}

impl CertDir {
    pub fn new(dir: &Path, group: Option<u32>) -> Self {
        Self {
            dir: dir.to_path_buf(),
            group,
        }
    }

    fn io(path: &Path) -> impl FnOnce(std::io::Error) -> IngressTlsError + '_ {
        move |source| IngressTlsError::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    async fn prepare_dir(&self) -> Result<(), IngressTlsError> {
        use std::os::unix::fs::PermissionsExt;
        let io = Self::io(&self.dir);
        tokio::fs::create_dir_all(&self.dir).await.map_err(io)?;
        let mode = if self.group.is_some() { 0o750 } else { 0o700 };
        std::os::unix::fs::chown(&self.dir, None, self.group).map_err(Self::io(&self.dir))?;
        tokio::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(Self::io(&self.dir))
    }

    /// Check and write `route`'s certificate chain and key. Returns a
    /// digest of both, which changes when either does.
    pub async fn write(
        &self,
        route: &str,
        cert: &[u8],
        key: Zeroizing<Vec<u8>>,
    ) -> Result<String, IngressTlsError> {
        certified_key(route, cert, &key)?;
        self.prepare_dir().await?;
        let cert_path = self.dir.join(format!("{route}.crt"));
        let key_path = self.dir.join(format!("{route}.key"));
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(cert);
        digest.update(&key);
        let digest: String = digest.finish().as_ref()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if tokio::fs::read(&cert_path).await.is_ok_and(|c| c == cert)
            && tokio::fs::read(&key_path)
                .await
                .is_ok_and(|k| Zeroizing::new(k)[..] == key[..])
        {
            return Ok(digest);
        }
        let key_mode = if self.group.is_some() { 0o640 } else { 0o600 };
        crate::fsutil::write_atomic(&key_path, &key, key_mode)
            .await
            .map_err(Self::io(&key_path))?;
        std::os::unix::fs::chown(&key_path, None, self.group).map_err(Self::io(&key_path))?;
        crate::fsutil::write_atomic(&cert_path, cert, 0o644)
            .await
            .map_err(Self::io(&cert_path))?;
        Ok(digest)
    }

    /// Delete the files of routes not in `keep`.
    pub async fn retain(&self, keep: &HashSet<String>) -> Result<(), IngressTlsError> {
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(IngressTlsError::Io {
                    path: self.dir.clone(),
                    source,
                });
            }
        };
        while let Some(entry) = entries.next_entry().await.map_err(Self::io(&self.dir))? {
            let path = entry.path();
            let route = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if !keep.contains(route) {
                tokio::fs::remove_file(&path)
                    .await
                    .map_err(Self::io(&path))?;
            }
        }
        Ok(())
    }
}

/// Proxy side: the certificates served by SNI, and the client verifier.
#[derive(Clone)]
pub struct IngressTls {
    dir: PathBuf,
    acceptor: Arc<std::sync::RwLock<TlsAcceptor>>,
}

#[derive(Debug, Default)]
struct Certificates {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    /// For `*` routes, and clients sending no (or an unknown) SNI name.
    fallback: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        hello
            .server_name()
            .and_then(|name| self.by_host.get(&name.to_ascii_lowercase()))
            .or(self.fallback.as_ref())
            .cloned()
    }
}

impl IngressTls {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            acceptor: Arc::new(std::sync::RwLock::new(Self::build(
                Certificates::default(),
                "",
            ))),
        }
    }

    fn build(certificates: Certificates, client_ca: &str) -> TlsAcceptor {
        // Clients may present a fleet SVID; routes with allowed callers
        // refuse those that do not.
        let verifier = match crate::server::federation::roots_from_pem(client_ca) {
            Ok(roots) => WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                .allow_unauthenticated()
                .build()
                .map_err(|e| tracing::warn!(error = %e, "Ingress client CA unusable"))
                .ok(),
            Err(_) => None,
        }
        .unwrap_or_else(WebPkiClientVerifier::no_client_auth);
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(certificates));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    /// Serve the certificates of `routes`' TLS routes. A route whose files
    /// are missing or invalid is left out (and logged).
    pub async fn load(&self, routes: &RoutesFile) {
        let mut certificates = Certificates::default();
        for route in routes.routes.iter().filter(|r| r.tls.is_some()) {
            let cert_path = self.dir.join(format!("{}.crt", route.name));
            let key_path = self.dir.join(format!("{}.key", route.name));
            let loaded = async {
                let cert = tokio::fs::read(&cert_path)
                    .await
                    .map_err(CertDir::io(&cert_path))?;
                let key = Zeroizing::new(
                    tokio::fs::read(&key_path)
                        .await
                        .map_err(CertDir::io(&key_path))?,
                );
                certified_key(&route.name, &cert, &key)
            }
            .await;
            match loaded {
                Ok(key) => {
                    let key = Arc::new(key);
                    if route.host == "*" {
                        certificates.fallback = Some(key);
                    } else {
                        certificates.by_host.insert(route.host.clone(), key);
                    }
                }
                Err(e) => {
                    tracing::error!(route = %route.name, error = %e, "Cannot load route certificate")
                }
            }
        }
        if certificates.fallback.is_none() {
            // A client without SNI still gets a certificate, if any.
            certificates.fallback = certificates.by_host.values().next().cloned();
        }
        let acceptor = Self::build(certificates, &routes.client_ca);
        *self.acceptor.write().unwrap_or_else(|e| e.into_inner()) = acceptor;
    }

    /// The acceptor for new connections.
    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
