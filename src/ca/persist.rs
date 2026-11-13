//! Loading and persisting CA key material.
//!
//! Shared by the in-process CA (`ekafleet server`) and the standalone
//! `ekafleet ca-signer` daemon so both protect keys identically: private keys
//! are sealed at rest when `EKAFLEET_SEAL_PASSPHRASE` is set (see
//! [`crate::server::seal`]) and always written atomically with mode 0600.

use std::path::Path;

use zeroize::Zeroizing;

use super::jwt::JwtSigner;
use super::root::RootCa;
use crate::server::seal;

const ROOT_KEY: &str = "ca-key.pem";
const ROOT_CERT: &str = "ca-cert.pem";
const INT_KEY: &str = "ca-intermediate-key.pem";
const INT_CERT: &str = "ca-intermediate-cert.pem";
const JWT_KEY: &str = "jwt-signing-key.pk8";

/// Read a (possibly sealed) private key PEM and its certificate. Returns
/// `None` when either file is absent.
async fn read_pair(
    data_dir: &Path,
    key: &str,
    cert: &str,
) -> anyhow::Result<Option<(Zeroizing<String>, String)>> {
    let key_path = data_dir.join(key);
    let cert_path = data_dir.join(cert);
    if !key_path.exists() || !cert_path.exists() {
        return Ok(None);
    }
    let key_bytes = seal::read_maybe_sealed(&key_path).await?;
    let key_pem = Zeroizing::new(
        String::from_utf8(key_bytes.to_vec())
            .map_err(|_| anyhow::anyhow!("{} is not valid UTF-8 PEM", key_path.display()))?,
    );
    let cert_pem = tokio::fs::read_to_string(&cert_path).await?;
    Ok(Some((key_pem, cert_pem)))
}

/// Load the CA from `data_dir`, generating a root on first boot and minting
/// a fresh intermediate when the stored one is missing or near expiry, and
/// persist whatever changed.
///
/// A key file that exists but cannot be read or unsealed is an error rather
/// than a reason to silently mint a new root, which would invalidate every
/// identity in the fleet.
pub async fn open_ca(data_dir: &Path, domain: &str) -> anyhow::Result<RootCa> {
    let ca = RootCa::new(domain);
    let root = read_pair(data_dir, ROOT_KEY, ROOT_CERT).await?;
    let intermediate = read_pair(data_dir, INT_KEY, INT_CERT).await?;

    ca.initialize_with_intermediate(
        root.as_ref().map(|(k, _)| k.as_str()),
        root.as_ref().map(|(_, c)| c.as_str()),
        intermediate.as_ref().map(|(k, _)| k.as_str()),
        intermediate.as_ref().map(|(_, c)| c.as_str()),
    )
    .await?;

    tokio::fs::create_dir_all(data_dir).await?;

    if root.is_none()
        && let (Some(key_pem), Some(cert_pem)) =
            (ca.root_key_pem().await, ca.root_certificate_pem().await)
    {
        let key_pem = Zeroizing::new(key_pem);
        seal::write_maybe_sealed(
            &data_dir.join(ROOT_KEY),
            key_pem.as_bytes(),
            "CA private key",
        )
        .await?;
        crate::fsutil::write_atomic(&data_dir.join(ROOT_CERT), cert_pem.as_bytes(), 0o644).await?;
        tracing::info!("CA key and certificate persisted to disk");
    }

    persist_intermediate_if_changed(
        &ca,
        data_dir,
        intermediate.as_ref().map(|(_, c)| c.as_str()),
    )
    .await?;

    Ok(ca)
}

/// Load the JWT-SVID signing key from `data_dir`, generating and persisting
/// (sealed, 0600) one on first boot. As with the CA keys, an existing key
/// that cannot be read or unsealed is an error, never a reason to replace it.
pub async fn open_jwt_signer(data_dir: &Path) -> anyhow::Result<JwtSigner> {
    let path = data_dir.join(JWT_KEY);
    if path.exists() {
        let pkcs8 = seal::read_maybe_sealed(&path).await?;
        return Ok(JwtSigner::from_pkcs8(&pkcs8)?);
    }
    let (signer, pkcs8) = JwtSigner::generate()?;
    tokio::fs::create_dir_all(data_dir).await?;
    seal::write_maybe_sealed(&path, &pkcs8, "JWT-SVID signing key").await?;
    tracing::info!(kid = %signer.kid(), "JWT-SVID signing key generated and persisted");
    Ok(signer)
}

/// Persist the CA's current intermediate when it differs from `stored_cert`
/// (first boot, or rotation on expiry).
pub async fn persist_intermediate_if_changed(
    ca: &RootCa,
    data_dir: &Path,
    stored_cert: Option<&str>,
) -> anyhow::Result<()> {
    if let (Some(int_key), Some(int_cert)) = (
        ca.intermediate_key_pem().await,
        ca.intermediate_certificate_pem().await,
    ) && stored_cert != Some(int_cert.as_str())
    {
        let int_key = Zeroizing::new(int_key);
        seal::write_maybe_sealed(
            &data_dir.join(INT_KEY),
            int_key.as_bytes(),
            "intermediate CA key",
        )
        .await?;
        crate::fsutil::write_atomic(&data_dir.join(INT_CERT), int_cert.as_bytes(), 0o644).await?;
        tracing::info!("Intermediate CA key and certificate persisted to disk");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reopen_loads_the_same_ca() {
        let dir = tempfile::tempdir().unwrap();
        let first = open_ca(dir.path(), "test.internal").await.unwrap();
        let root = first.root_certificate_pem().await.unwrap();
        let int = first.intermediate_certificate_pem().await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for key in [ROOT_KEY, INT_KEY] {
                let mode = std::fs::metadata(dir.path().join(key))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{key}");
            }
        }

        let second = open_ca(dir.path(), "test.internal").await.unwrap();
        assert_eq!(second.root_certificate_pem().await.unwrap(), root);
        assert_eq!(second.intermediate_certificate_pem().await.unwrap(), int);
    }

    #[tokio::test]
    async fn jwt_signer_is_persisted_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let first = open_jwt_signer(dir.path()).await.unwrap();
        let second = open_jwt_signer(dir.path()).await.unwrap();
        assert_eq!(first.kid(), second.kid());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(JWT_KEY))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        std::fs::write(dir.path().join(JWT_KEY), b"EKAFSEAL\x01garbage").unwrap();
        assert!(open_jwt_signer(dir.path()).await.is_err());
    }

    #[tokio::test]
    async fn unreadable_root_key_is_an_error_not_a_new_root() {
        let dir = tempfile::tempdir().unwrap();
        open_ca(dir.path(), "test.internal").await.unwrap();
        // A sealed envelope that cannot be opened (no passphrase configured
        // in tests) must not be replaced by a freshly generated root.
        std::fs::write(dir.path().join(ROOT_KEY), b"EKAFSEAL\x01garbage").unwrap();
        assert!(open_ca(dir.path(), "test.internal").await.is_err());
    }
}
