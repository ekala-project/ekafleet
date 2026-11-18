//! Dynamic database credentials: a fresh database user per service secret,
//! created through a secret engine's admin connection and dropped when it
//! is replaced or no longer declared.
//!
//! The server issues the credentials and delivers them like a static secret,
//! as JSON (`{"username", "password", "url"}`) at `/run/secrets/<name>`.

use std::future::Future;
use std::pin::Pin;

use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use super::db_driver::{self, DbDriverError, Permissions, RoleTemplate};

/// Lease length when a secret doesn't set `ttl` (one day).
pub const DEFAULT_TTL: u64 = 86_400;

/// Shortest accepted lease (five minutes).
pub const MIN_TTL: u64 = 300;

/// Roles a dynamic secret may ask for.
pub const ROLES: &[&str] = &["readonly", "readwrite", "admin"];

#[derive(Debug, thiserror::Error)]
pub enum DynamicSecretError {
    #[error("unknown role '{0}' (expected readonly, readwrite or admin)")]
    UnknownRole(String),
    #[error("random generation failed")]
    RngFailure,
    #[error("invalid admin connection URL: {0}")]
    InvalidUrl(String),
    #[error(transparent)]
    Db(#[from] DbDriverError),
}

/// The privileges `role` grants.
pub fn role_permissions(role: &str) -> Result<Permissions, DynamicSecretError> {
    match role {
        "readonly" => Ok(Permissions::ReadOnly),
        "readwrite" => Ok(Permissions::ReadWrite),
        "admin" => Ok(Permissions::Admin),
        _ => Err(DynamicSecretError::UnknownRole(role.to_string())),
    }
}

/// Credentials of one issued database user.
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
    /// Connection URL for the service, with the credentials embedded.
    pub url: Zeroizing<String>,
}

impl Credentials {
    /// A new random user for the database `database` on the server that
    /// `admin_url` points at.
    pub fn generate(admin_url: &str, database: &str) -> Result<Self, DynamicSecretError> {
        let username = format!("ek_{}", random_hex(6)?);
        let password = Zeroizing::new(random_hex(24)?);
        let url = service_url(admin_url, &username, &password, database)?;
        Ok(Self {
            username,
            password,
            url,
        })
    }

    /// The JSON the service reads.
    pub fn to_json(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            serde_json::json!({
                "username": self.username,
                "password": self.password.as_str(),
                "url": self.url.as_str(),
            })
            .to_string()
            .into_bytes(),
        )
    }
}

fn random_hex(bytes: usize) -> Result<String, DynamicSecretError> {
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| DynamicSecretError::RngFailure)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// `admin_url` with its credentials and database replaced, keeping the
/// scheme, host, port and query (e.g. `sslmode`).
fn service_url(
    admin_url: &str,
    username: &str,
    password: &str,
    database: &str,
) -> Result<Zeroizing<String>, DynamicSecretError> {
    let invalid = || DynamicSecretError::InvalidUrl("expected scheme://user:pass@host/db".into());
    db_driver::detect_engine(admin_url)?;
    let (scheme, rest) = admin_url.split_once("://").ok_or_else(invalid)?;
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host.is_empty() {
        return Err(invalid());
    }
    let query = tail.find('?').map_or("", |i| &tail[i..]);
    Ok(Zeroizing::new(format!(
        "{scheme}://{username}:{password}@{host}/{database}{query}"
    )))
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Creates and drops database users. [`Databases`] talks to real servers;
/// tests substitute their own.
pub trait CredentialBackend: Send + Sync {
    /// Create `username` with `role`'s privileges on `database`, valid until
    /// `valid_until` (Unix seconds).
    fn provision<'a>(
        &'a self,
        admin_url: &'a str,
        credentials: &'a Credentials,
        database: &'a str,
        role: &'a str,
        valid_until: u64,
    ) -> BoxFuture<'a, Result<(), DynamicSecretError>>;

    /// Drop `username`, ending its sessions.
    fn revoke<'a>(
        &'a self,
        admin_url: &'a str,
        username: &'a str,
    ) -> BoxFuture<'a, Result<(), DynamicSecretError>>;
}

/// PostgreSQL and MySQL servers, through [`db_driver`].
pub struct Databases;

impl CredentialBackend for Databases {
    fn provision<'a>(
        &'a self,
        admin_url: &'a str,
        credentials: &'a Credentials,
        database: &'a str,
        role: &'a str,
        valid_until: u64,
    ) -> BoxFuture<'a, Result<(), DynamicSecretError>> {
        Box::pin(async move {
            let engine = db_driver::detect_engine(admin_url)?;
            let template = RoleTemplate {
                database: database.to_string(),
                permissions: role_permissions(role)?,
            };
            db_driver::provision_credentials(
                &engine,
                admin_url,
                &credentials.username,
                &credentials.password,
                &template,
                valid_until,
            )
            .await?;
            Ok(())
        })
    }

    fn revoke<'a>(
        &'a self,
        admin_url: &'a str,
        username: &'a str,
    ) -> BoxFuture<'a, Result<(), DynamicSecretError>> {
        Box::pin(async move {
            let engine = db_driver::detect_engine(admin_url)?;
            db_driver::revoke_credentials(&engine, admin_url, username).await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_point_at_the_admin_host_and_service_database() {
        let creds = Credentials::generate(
            "postgres://admin:p%40ss@db.internal:5432/postgres?sslmode=require",
            "shop",
        )
        .unwrap();
        assert!(creds.username.starts_with("ek_") && creds.username.len() == 15);
        assert_eq!(creds.password.len(), 48);
        assert_eq!(
            creds.url.as_str(),
            format!(
                "postgres://{}:{}@db.internal:5432/shop?sslmode=require",
                creds.username,
                creds.password.as_str()
            )
        );
        let json: serde_json::Value = serde_json::from_slice(&creds.to_json()).unwrap();
        assert_eq!(json["username"], creds.username.as_str());
        assert_eq!(json["url"], creds.url.as_str());

        let mysql = Credentials::generate("mysql://root@10.0.0.5", "app").unwrap();
        assert!(mysql.url.starts_with("mysql://ek_"));
        assert!(mysql.url.ends_with("@10.0.0.5/app"));

        assert!(Credentials::generate("redis://x@y/0", "app").is_err());
        assert!(Credentials::generate("postgres://admin@/x", "app").is_err());
        assert_ne!(
            Credentials::generate("mysql://r@h", "a").unwrap().username,
            mysql.username
        );
    }

    #[test]
    fn roles_are_exact() {
        for role in ROLES {
            assert!(role_permissions(role).is_ok());
        }
        assert!(role_permissions("rw").is_err());
        assert!(role_permissions("superuser").is_err());
    }
}
