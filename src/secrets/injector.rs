//! Agent-side static secret files.
//!
//! Values arrive sealed under the key the server derived for this agent and
//! are written, decrypted, to `<dir>/<service>/<name>` (mode 0400, on tmpfs
//! under [`super::AGENT_SECRETS_DIR`]); the service's unit bind-mounts its
//! directory read-only at `/run/secrets`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum SecretInjectorError {
    #[error("no fleet key received yet")]
    NoKey,
    #[error("secret does not decrypt with this agent's key")]
    Decrypt,
    #[error("{0}")]
    InvalidName(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct SecretInjector {
    secrets_dir: PathBuf,
    key: Option<LessSafeKey>,
}

impl SecretInjector {
    /// An injector writing under `secrets_dir`, with no key until
    /// [`Self::update_key`].
    pub fn new(secrets_dir: &Path) -> Self {
        Self {
            secrets_dir: secrets_dir.to_path_buf(),
            key: None,
        }
    }

    /// Install the key the server derived for this agent.
    pub fn update_key(&mut self, key: &[u8; 32]) {
        let unbound = UnboundKey::new(&AES_256_GCM, key).expect("valid 256-bit key required");
        self.key = Some(LessSafeKey::new(unbound));
        tracing::info!("Secret injector encryption key updated");
    }

    /// Decrypt a sealed value (nonce || ciphertext || tag) bound to `aad`.
    fn decrypt(
        &self,
        sealed: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecretInjectorError> {
        let key = self.key.as_ref().ok_or(SecretInjectorError::NoKey)?;
        if sealed.len() < NONCE_LEN {
            return Err(SecretInjectorError::Decrypt);
        }
        let (nonce_bytes, ciphertext_and_tag) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| SecretInjectorError::Decrypt)?;
        let mut in_out = Zeroizing::new(ciphertext_and_tag.to_vec());
        let len = key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| SecretInjectorError::Decrypt)?
            .len();
        in_out.truncate(len);
        Ok(in_out)
    }

    /// The directory holding a service's secret files.
    pub fn service_dir(&self, service_name: &str) -> PathBuf {
        self.secrets_dir.join(service_name)
    }

    fn path(&self, service_name: &str, secret_name: &str) -> Result<PathBuf, SecretInjectorError> {
        super::validate_name("service", service_name).map_err(SecretInjectorError::InvalidName)?;
        super::validate_name("secret", secret_name).map_err(SecretInjectorError::InvalidName)?;
        Ok(self.service_dir(service_name).join(secret_name))
    }

    /// Decrypt and write a secret. Returns whether the file changed.
    pub async fn inject(
        &self,
        service_name: &str,
        secret_name: &str,
        sealed: &[u8],
    ) -> Result<bool, SecretInjectorError> {
        let path = self.path(service_name, secret_name)?;
        let plaintext =
            self.decrypt(sealed, &super::store::secret_aad(service_name, secret_name))?;
        if let Ok(current) = tokio::fs::read(&path).await {
            let current = Zeroizing::new(current);
            if *current == *plaintext {
                return Ok(false);
            }
        }
        create_private_dir(&self.secrets_dir).await?;
        create_private_dir(&self.service_dir(service_name)).await?;
        // Written whole under a temporary name and renamed into place, so the
        // service never reads a partial value. Secret names cannot start
        // with a dot, so the temporary name never collides with one.
        let tmp = self
            .service_dir(service_name)
            .join(format!(".{secret_name}.tmp"));
        let _ = tokio::fs::remove_file(&tmp).await;
        write_read_only(&tmp, plaintext).await?;
        tokio::fs::rename(&tmp, &path).await?;
        tracing::info!(service = %service_name, secret = %secret_name, "Secret written");
        Ok(true)
    }

    /// Remove one secret's file. Returns whether it existed.
    pub async fn remove(
        &self,
        service_name: &str,
        secret_name: &str,
    ) -> Result<bool, SecretInjectorError> {
        let path = self.path(service_name, secret_name)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                tracing::info!(service = %service_name, secret = %secret_name, "Secret removed");
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether every one of `names` has a file for `service_name`.
    pub fn has_all(&self, service_name: &str, names: &[String]) -> bool {
        names.iter().all(|name| {
            self.path(service_name, name)
                .is_ok_and(|path| path.is_file())
        })
    }

    /// Delete the files of services and secrets not in `declared`
    /// (service → secret names), keeping the directories of declared
    /// services (they are bind-mounted into running units).
    pub async fn retain(
        &self,
        declared: &HashMap<String, Vec<String>>,
    ) -> Result<(), SecretInjectorError> {
        let mut services = match tokio::fs::read_dir(&self.secrets_dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        while let Some(service) = services.next_entry().await? {
            let name = service.file_name().to_string_lossy().into_owned();
            let Some(keep) = declared.get(&name) else {
                tokio::fs::remove_dir_all(service.path()).await?;
                tracing::info!(service = %name, "Secrets of unassigned service removed");
                continue;
            };
            let keep: HashSet<&str> = keep.iter().map(String::as_str).collect();
            let mut files = tokio::fs::read_dir(service.path()).await?;
            while let Some(file) = files.next_entry().await? {
                let file_name = file.file_name().to_string_lossy().into_owned();
                if !keep.contains(file_name.as_str()) {
                    tokio::fs::remove_file(file.path()).await?;
                    tracing::info!(service = %name, secret = %file_name, "Undeclared secret removed");
                }
            }
        }
        Ok(())
    }
}

async fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await
}

/// Create `path` with mode 0400 from the start and write `contents`.
async fn write_read_only(path: &Path, contents: Zeroizing<Vec<u8>>) -> std::io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)?;
        file.write_all(&contents)
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0xAB; 32];

    fn injector(dir: &Path) -> SecretInjector {
        let mut injector = SecretInjector::new(dir);
        injector.update_key(&KEY);
        injector
    }

    /// Seal a value the way the server does for this agent.
    fn seal(key: &[u8; 32], service: &str, secret: &str, plaintext: &[u8]) -> Vec<u8> {
        crate::secrets::store::SecretStore::new(key)
            .seal(service, secret, plaintext)
            .unwrap()
    }

    #[tokio::test]
    async fn inject_writes_a_read_only_file_once_per_value() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let injector = injector(dir.path());

        let v1 = seal(&KEY, "web", "db_pass", b"one");
        assert!(injector.inject("web", "db_pass", &v1).await.unwrap());
        let path = dir.path().join("web/db_pass");
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o400);
        let dir_mode = std::fs::metadata(dir.path().join("web"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);

        // The same value again (e.g. after a reconnect) changes nothing.
        let again = seal(&KEY, "web", "db_pass", b"one");
        assert!(!injector.inject("web", "db_pass", &again).await.unwrap());

        let v2 = seal(&KEY, "web", "db_pass", b"two");
        assert!(injector.inject("web", "db_pass", &v2).await.unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(injector.has_all("web", &["db_pass".into()]));
        assert!(!injector.has_all("web", &["db_pass".into(), "other".into()]));
    }

    #[tokio::test]
    async fn values_open_only_with_the_right_key_and_binding() {
        let dir = tempfile::tempdir().unwrap();
        let sealed = seal(&KEY, "web", "key", b"secret");

        assert!(matches!(
            SecretInjector::new(dir.path())
                .inject("web", "key", &sealed)
                .await,
            Err(SecretInjectorError::NoKey)
        ));
        let mut other = SecretInjector::new(dir.path());
        other.update_key(&[0xBB; 32]);
        assert!(matches!(
            other.inject("web", "key", &sealed).await,
            Err(SecretInjectorError::Decrypt)
        ));
        // Bound to its service and name.
        let injector = injector(dir.path());
        assert!(matches!(
            injector.inject("api", "key", &sealed).await,
            Err(SecretInjectorError::Decrypt)
        ));
        assert!(matches!(
            injector.inject("web", "../key", &sealed).await,
            Err(SecretInjectorError::InvalidName(_))
        ));
        assert!(!dir.path().join("web").exists());
    }

    #[tokio::test]
    async fn retain_and_remove_drop_stale_files() {
        let dir = tempfile::tempdir().unwrap();
        let injector = injector(dir.path());
        for (service, secret) in [("web", "a"), ("web", "b"), ("old", "c")] {
            let sealed = seal(&KEY, service, secret, b"v");
            injector.inject(service, secret, &sealed).await.unwrap();
        }

        injector
            .retain(&[("web".to_string(), vec!["a".to_string()])].into())
            .await
            .unwrap();
        assert!(dir.path().join("web/a").exists());
        assert!(!dir.path().join("web/b").exists());
        assert!(!dir.path().join("old").exists());

        assert!(injector.remove("web", "a").await.unwrap());
        assert!(!injector.remove("web", "a").await.unwrap());
        // The directory stays: a running unit has it mounted.
        assert!(dir.path().join("web").is_dir());
    }
}
