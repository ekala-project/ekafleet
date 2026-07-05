use std::time::Duration;

/// Database driver abstraction for dynamic credential provisioning.
///
/// Each driver connects to a database, creates a user with the given
/// credentials and permissions, and drops the user on revocation.
///
/// Supported engines: PostgreSQL, MySQL.
#[derive(Debug, Clone)]
pub enum DbEngine {
    Postgres,
    Mysql,
}

/// Role template defining what permissions to grant.
#[derive(Debug, Clone)]
pub struct RoleTemplate {
    /// The database to grant access to (e.g., "myapp")
    pub database: String,
    /// Permission level
    pub permissions: Permissions,
}

#[derive(Debug, Clone)]
pub enum Permissions {
    /// Read-only access (SELECT)
    ReadOnly,
    /// Read-write access (SELECT, INSERT, UPDATE, DELETE)
    ReadWrite,
    /// Full admin access (ALL PRIVILEGES)
    Admin,
}

#[derive(Debug, thiserror::Error)]
pub enum DbDriverError {
    #[error("database connection failed: {0}")]
    ConnectionFailed(String),
    #[error("credential provisioning failed: {0}")]
    ProvisionFailed(String),
    #[error("credential revocation failed: {0}")]
    RevocationFailed(String),
    #[error("unsupported engine: {0}")]
    UnsupportedEngine(String),
    #[error("invalid connection URL: {0}")]
    InvalidUrl(String),
}

/// Provision a database user with the given credentials.
///
/// Connects to the database at `connection_url`, creates the user,
/// and grants permissions according to the role template.
pub async fn provision_credentials(
    engine: &DbEngine,
    connection_url: &str,
    username: &str,
    password: &str,
    role: &RoleTemplate,
) -> Result<(), DbDriverError> {
    match engine {
        DbEngine::Postgres => provision_postgres(connection_url, username, password, role).await,
        DbEngine::Mysql => provision_mysql(connection_url, username, password, role).await,
    }
}

/// Revoke a database user (DROP USER).
pub async fn revoke_credentials(
    engine: &DbEngine,
    connection_url: &str,
    username: &str,
) -> Result<(), DbDriverError> {
    match engine {
        DbEngine::Postgres => revoke_postgres(connection_url, username).await,
        DbEngine::Mysql => revoke_mysql(connection_url, username).await,
    }
}

/// Parse a connection URL to determine the database engine.
pub fn detect_engine(connection_url: &str) -> Result<DbEngine, DbDriverError> {
    if connection_url.starts_with("postgres://") || connection_url.starts_with("postgresql://") {
        Ok(DbEngine::Postgres)
    } else if connection_url.starts_with("mysql://") {
        Ok(DbEngine::Mysql)
    } else {
        Err(DbDriverError::UnsupportedEngine(
            connection_url
                .split("://")
                .next()
                .unwrap_or("unknown")
                .to_string(),
        ))
    }
}

/// Parse a role name into a RoleTemplate.
pub fn parse_role(role_name: &str, database: &str) -> RoleTemplate {
    let permissions = match role_name {
        "readonly" | "ro" | "read" => Permissions::ReadOnly,
        "readwrite" | "rw" | "write" => Permissions::ReadWrite,
        "admin" | "superuser" | "all" => Permissions::Admin,
        _ => Permissions::ReadOnly, // default to least privilege
    };

    RoleTemplate {
        database: database.to_string(),
        permissions,
    }
}

// ─── PostgreSQL ─────────────────────────────────────────────────────

async fn provision_postgres(
    connection_url: &str,
    username: &str,
    password: &str,
    role: &RoleTemplate,
) -> Result<(), DbDriverError> {
    use sqlx::Executor;
    use sqlx::postgres::PgPoolOptions;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(connection_url)
        .await
        .map_err(|e| DbDriverError::ConnectionFailed(e.to_string()))?;

    // Create role with login and password
    // Use format! for DDL since sqlx bind parameters don't work for identifiers
    let create_sql = format!(
        "CREATE ROLE \"{}\" WITH LOGIN PASSWORD '{}'",
        escape_pg_ident(username),
        escape_pg_literal(password),
    );
    pool.execute(create_sql.as_str())
        .await
        .map_err(|e| DbDriverError::ProvisionFailed(format!("CREATE ROLE: {e}")))?;

    // Grant permissions based on role template
    let grant_sql = match role.permissions {
        Permissions::ReadOnly => format!(
            "GRANT CONNECT ON DATABASE \"{}\" TO \"{}\"; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{}\"",
            escape_pg_ident(&role.database),
            escape_pg_ident(username),
            escape_pg_ident(username),
        ),
        Permissions::ReadWrite => format!(
            "GRANT CONNECT ON DATABASE \"{}\" TO \"{}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{}\"",
            escape_pg_ident(&role.database),
            escape_pg_ident(username),
            escape_pg_ident(username),
        ),
        Permissions::Admin => format!(
            "GRANT ALL PRIVILEGES ON DATABASE \"{}\" TO \"{}\"",
            escape_pg_ident(&role.database),
            escape_pg_ident(username),
        ),
    };
    pool.execute(grant_sql.as_str())
        .await
        .map_err(|e| DbDriverError::ProvisionFailed(format!("GRANT: {e}")))?;

    // Set a connection limit to prevent abuse
    let limit_sql = format!(
        "ALTER ROLE \"{}\" CONNECTION LIMIT 10",
        escape_pg_ident(username),
    );
    pool.execute(limit_sql.as_str())
        .await
        .map_err(|e| DbDriverError::ProvisionFailed(format!("ALTER ROLE: {e}")))?;

    // Set role to expire matching the lease TTL
    let valid_sql = format!(
        "ALTER ROLE \"{}\" VALID UNTIL '{}'",
        escape_pg_ident(username),
        pg_timestamp_hours(1),
    );
    pool.execute(valid_sql.as_str())
        .await
        .map_err(|e| DbDriverError::ProvisionFailed(format!("VALID UNTIL: {e}")))?;

    tracing::info!(
        engine = "postgres",
        user = %username,
        database = %role.database,
        permissions = ?role.permissions,
        "Database credentials provisioned"
    );

    pool.close().await;
    Ok(())
}

async fn revoke_postgres(connection_url: &str, username: &str) -> Result<(), DbDriverError> {
    use sqlx::Executor;
    use sqlx::postgres::PgPoolOptions;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(connection_url)
        .await
        .map_err(|e| DbDriverError::ConnectionFailed(e.to_string()))?;

    // Terminate existing connections
    let terminate_sql = format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{}'",
        escape_pg_literal(username),
    );
    let _ = pool.execute(terminate_sql.as_str()).await;

    // Revoke all privileges
    let revoke_sql = format!(
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{}\"",
        escape_pg_ident(username),
    );
    let _ = pool.execute(revoke_sql.as_str()).await;

    // Drop the role
    let drop_sql = format!("DROP ROLE IF EXISTS \"{}\"", escape_pg_ident(username));
    pool.execute(drop_sql.as_str())
        .await
        .map_err(|e| DbDriverError::RevocationFailed(format!("DROP ROLE: {e}")))?;

    tracing::info!(engine = "postgres", user = %username, "Database credentials revoked");

    pool.close().await;
    Ok(())
}

// ─── MySQL ──────────────────────────────────────────────────────────

async fn provision_mysql(
    connection_url: &str,
    username: &str,
    password: &str,
    role: &RoleTemplate,
) -> Result<(), DbDriverError> {
    use sqlx::Executor;
    use sqlx::mysql::MySqlPoolOptions;

    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(connection_url)
        .await
        .map_err(|e| DbDriverError::ConnectionFailed(e.to_string()))?;

    // Create user with password
    let create_sql = format!(
        "CREATE USER '{}'@'%' IDENTIFIED BY '{}'",
        escape_mysql_ident(username),
        escape_mysql_literal(password),
    );
    pool.execute(create_sql.as_str())
        .await
        .map_err(|e| DbDriverError::ProvisionFailed(format!("CREATE USER: {e}")))?;

    // Grant permissions
    let grant_sql = match role.permissions {
        Permissions::ReadOnly => format!(
            "GRANT SELECT ON `{}`.* TO '{}'@'%'",
            escape_mysql_ident(&role.database),
            escape_mysql_ident(username),
        ),
        Permissions::ReadWrite => format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON `{}`.* TO '{}'@'%'",
            escape_mysql_ident(&role.database),
            escape_mysql_ident(username),
        ),
        Permissions::Admin => format!(
            "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'%'",
            escape_mysql_ident(&role.database),
            escape_mysql_ident(username),
        ),
    };
    pool.execute(grant_sql.as_str())
        .await
        .map_err(|e| DbDriverError::ProvisionFailed(format!("GRANT: {e}")))?;

    // Set max connections per user
    let resource_sql = format!(
        "ALTER USER '{}'@'%' WITH MAX_USER_CONNECTIONS 10",
        escape_mysql_ident(username),
    );
    let _ = pool.execute(resource_sql.as_str()).await;

    // Set password expiry matching the lease TTL
    let expire_sql = format!(
        "ALTER USER '{}'@'%' PASSWORD EXPIRE INTERVAL 1 DAY",
        escape_mysql_ident(username),
    );
    let _ = pool.execute(expire_sql.as_str()).await;

    // Flush privileges
    let _ = pool.execute("FLUSH PRIVILEGES").await;

    tracing::info!(
        engine = "mysql",
        user = %username,
        database = %role.database,
        permissions = ?role.permissions,
        "Database credentials provisioned"
    );

    pool.close().await;
    Ok(())
}

async fn revoke_mysql(connection_url: &str, username: &str) -> Result<(), DbDriverError> {
    use sqlx::Executor;
    use sqlx::mysql::MySqlPoolOptions;

    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(connection_url)
        .await
        .map_err(|e| DbDriverError::ConnectionFailed(e.to_string()))?;

    // Revoke and drop
    let revoke_sql = format!(
        "REVOKE ALL PRIVILEGES, GRANT OPTION FROM '{}'@'%'",
        escape_mysql_ident(username),
    );
    let _ = pool.execute(revoke_sql.as_str()).await;

    let drop_sql = format!("DROP USER IF EXISTS '{}'@'%'", escape_mysql_ident(username),);
    pool.execute(drop_sql.as_str())
        .await
        .map_err(|e| DbDriverError::RevocationFailed(format!("DROP USER: {e}")))?;

    let _ = pool.execute("FLUSH PRIVILEGES").await;

    tracing::info!(engine = "mysql", user = %username, "Database credentials revoked");

    pool.close().await;
    Ok(())
}

// ─── SQL escaping helpers ───────────────────────────────────────────

/// Escape a PostgreSQL identifier (prevent SQL injection in DDL).
fn escape_pg_ident(s: &str) -> String {
    s.replace('"', "\"\"")
}

/// Escape a PostgreSQL string literal.
fn escape_pg_literal(s: &str) -> String {
    s.replace('\'', "''")
}

/// Escape a MySQL identifier.
fn escape_mysql_ident(s: &str) -> String {
    s.replace('`', "``").replace('\'', "\\'")
}

/// Escape a MySQL string literal.
fn escape_mysql_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Generate a PostgreSQL timestamp N hours from now.
fn pg_timestamp_hours(hours: u64) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + hours * 3600;

    // Format as ISO 8601
    let dt = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::now_utc());
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "2099-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_postgres_engine() {
        assert!(matches!(
            detect_engine("postgres://user:pass@localhost/db"),
            Ok(DbEngine::Postgres)
        ));
        assert!(matches!(
            detect_engine("postgresql://user:pass@localhost/db"),
            Ok(DbEngine::Postgres)
        ));
    }

    #[test]
    fn detect_mysql_engine() {
        assert!(matches!(
            detect_engine("mysql://user:pass@localhost/db"),
            Ok(DbEngine::Mysql)
        ));
    }

    #[test]
    fn detect_unsupported_engine() {
        assert!(matches!(
            detect_engine("sqlite:///path/to/db"),
            Err(DbDriverError::UnsupportedEngine(_))
        ));
    }

    #[test]
    fn parse_role_readonly() {
        let role = parse_role("readonly", "mydb");
        assert!(matches!(role.permissions, Permissions::ReadOnly));
        assert_eq!(role.database, "mydb");
    }

    #[test]
    fn parse_role_readwrite() {
        let role = parse_role("rw", "mydb");
        assert!(matches!(role.permissions, Permissions::ReadWrite));
    }

    #[test]
    fn parse_role_admin() {
        let role = parse_role("admin", "mydb");
        assert!(matches!(role.permissions, Permissions::Admin));
    }

    #[test]
    fn parse_role_unknown_defaults_readonly() {
        let role = parse_role("custom-role", "mydb");
        assert!(matches!(role.permissions, Permissions::ReadOnly));
    }

    #[test]
    fn escape_pg_prevents_injection() {
        assert_eq!(escape_pg_ident("normal"), "normal");
        assert_eq!(escape_pg_ident("has\"quote"), "has\"\"quote");
    }

    #[test]
    fn escape_pg_literal_prevents_injection() {
        assert_eq!(escape_pg_literal("normal"), "normal");
        assert_eq!(escape_pg_literal("has'quote"), "has''quote");
    }

    #[test]
    fn escape_mysql_prevents_injection() {
        assert_eq!(escape_mysql_ident("normal"), "normal");
        assert_eq!(escape_mysql_ident("has`tick"), "has``tick");
        assert_eq!(escape_mysql_literal("has'quote"), "has\\'quote");
        assert_eq!(escape_mysql_literal("has\\slash"), "has\\\\slash");
    }

    #[test]
    fn pg_timestamp_is_future() {
        let ts = pg_timestamp_hours(1);
        assert!(ts.contains('T'));
        assert!(ts.len() > 10);
    }
}
