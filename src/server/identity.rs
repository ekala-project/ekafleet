//! The server's own SVID (`spiffe://<domain>/server/<id>`).
//!
//! It is short-lived like every other SVID, so it is renewed two thirds of
//! the way through its lifetime. TLS listeners resolve the certificate
//! through [`ServerIdentity`] on every handshake, so connections made after a
//! renewal get the new certificate without a restart.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::ca::CaSigner;

/// Shortest wait before a renewal, and between failed attempts.
const MIN_RENEW_WAIT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("issuing the server SVID: {0}")]
    Issue(#[from] crate::ca::root::CaError),
    #[error("server SVID PEM: {0}")]
    Pem(String),
}

struct Current {
    key: Arc<CertifiedKey>,
    /// Certificate chain followed by the private key.
    pem: Zeroizing<String>,
    issued_at: u64,
    expires_at: u64,
}

/// The current server SVID, shared by every TLS listener and client.
#[derive(Clone)]
pub struct ServerIdentity {
    current: Arc<RwLock<Current>>,
}

impl std::fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerIdentity").finish_non_exhaustive()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Parse a combined chain + key PEM.
fn certified_key(pem: &str) -> Result<Arc<CertifiedKey>, IdentityError> {
    let chain = rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| IdentityError::Pem(e.to_string()))?;
    if chain.is_empty() {
        return Err(IdentityError::Pem("no certificate".into()));
    }
    let key = rustls_pemfile::private_key(&mut pem.as_bytes())
        .map_err(|e| IdentityError::Pem(e.to_string()))?
        .ok_or_else(|| IdentityError::Pem("no private key".into()))?;
    let signing_key = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| IdentityError::Pem(e.to_string()))?;
    Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
}

impl Current {
    fn from_pem(pem: Zeroizing<String>, expires_at: u64) -> Result<Self, IdentityError> {
        Ok(Self {
            key: certified_key(&pem)?,
            pem,
            issued_at: now(),
            expires_at,
        })
    }

    async fn issue(ca: &dyn CaSigner, server_id: &str) -> Result<Self, IdentityError> {
        let (pem, _chain, expires_at) = ca.issue_server_svid(server_id).await?;
        let pem =
            Zeroizing::new(String::from_utf8(pem).map_err(|e| IdentityError::Pem(e.to_string()))?);
        Self::from_pem(pem, expires_at)
    }
}

impl ServerIdentity {
    /// Build from an issued combined chain + key PEM.
    pub fn from_pem(pem: Zeroizing<String>, expires_at: u64) -> Result<Self, IdentityError> {
        Ok(Self::wrap(Current::from_pem(pem, expires_at)?))
    }

    fn wrap(current: Current) -> Self {
        Self {
            current: Arc::new(RwLock::new(current)),
        }
    }

    /// Issue a new server SVID for `server_id`.
    pub async fn issue(ca: &dyn CaSigner, server_id: &str) -> Result<Self, IdentityError> {
        Ok(Self::wrap(Current::issue(ca, server_id).await?))
    }

    /// The current chain + key PEM.
    pub fn pem(&self) -> Zeroizing<String> {
        let current = self.current.read().unwrap_or_else(|e| e.into_inner());
        current.pem.clone()
    }

    /// The current certificate and signing key.
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        let current = self.current.read().unwrap_or_else(|e| e.into_inner());
        current.key.clone()
    }

    pub fn expires_at(&self) -> u64 {
        let current = self.current.read().unwrap_or_else(|e| e.into_inner());
        current.expires_at
    }

    /// How long to wait before renewing, at `now`.
    fn renew_in(&self, now: u64) -> Duration {
        let current = self.current.read().unwrap_or_else(|e| e.into_inner());
        let lifetime = current.expires_at.saturating_sub(current.issued_at);
        let renew_at = current.issued_at + lifetime * 2 / 3;
        Duration::from_secs(renew_at.saturating_sub(now)).max(MIN_RENEW_WAIT)
    }

    fn replace(&self, renewed: Current) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = renewed;
    }

    /// Renew the SVID until `shutdown`.
    pub fn spawn_renewal(
        &self,
        ca: Arc<dyn CaSigner>,
        server_id: String,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let identity = self.clone();
        tokio::spawn(async move {
            let mut wait = identity.renew_in(now());
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(wait) => {}
                }
                match Current::issue(ca.as_ref(), &server_id).await {
                    Ok(renewed) => {
                        identity.replace(renewed);
                        tracing::info!(
                            server_id = %server_id,
                            expires_at = identity.expires_at(),
                            "Server SVID renewed"
                        );
                        wait = identity.renew_in(now());
                    }
                    Err(e) => {
                        tracing::error!(server_id = %server_id, error = %e, "Server SVID renewal failed");
                        wait = MIN_RENEW_WAIT;
                    }
                }
            }
        })
    }
}

impl ResolvesServerCert for ServerIdentity {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key())
    }
}

/// Servers present their SVID as the client certificate too (Raft).
impl rustls::client::ResolvesClientCert for ServerIdentity {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaSigner;
    use crate::ca::signer::DirectCaSigner;

    async fn signer() -> Arc<dyn CaSigner> {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::ca::persist::open_ca(dir.path(), "fleet.test")
            .await
            .unwrap();
        let jwt = crate::ca::persist::open_jwt_signer(dir.path())
            .await
            .unwrap();
        Arc::new(DirectCaSigner::new(root, jwt))
    }

    #[tokio::test]
    async fn renewal_waits_two_thirds_of_the_lifetime() {
        let ca = signer().await;
        let identity = ServerIdentity::issue(ca.as_ref(), "s1").await.unwrap();
        let (issued, expires) = {
            let c = identity.current.read().unwrap();
            (c.issued_at, c.expires_at)
        };
        let lifetime = expires - issued;
        assert!(lifetime > 0);
        let wait = identity.renew_in(issued).as_secs();
        assert!(
            (lifetime * 2 / 3).abs_diff(wait) <= 1,
            "{wait} of {lifetime}"
        );
        // Overdue: retry soon rather than spin.
        assert_eq!(identity.renew_in(expires + 10), MIN_RENEW_WAIT);
    }

    #[tokio::test]
    async fn replace_swaps_the_resolved_certificate() {
        let ca = signer().await;
        let identity = ServerIdentity::issue(ca.as_ref(), "s1").await.unwrap();
        let before = identity.certified_key().cert[0].clone();
        let pem_before = identity.pem();
        identity.replace(Current::issue(ca.as_ref(), "s1").await.unwrap());
        assert_ne!(identity.certified_key().cert[0], before);
        assert_ne!(*identity.pem(), *pem_before);
        let id = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_der(
            identity.certified_key().cert[0].as_ref(),
        );
        assert_eq!(id.as_deref(), Some("spiffe://fleet.test/server/s1"));
    }
}
