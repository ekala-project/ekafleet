use super::*;

#[tokio::test]
async fn register_engine_detects_type() {
    let engine = DynamicSecretsEngine::new();
    engine
        .register_engine("pg", "postgres://admin:pass@localhost:5432/admin", "myapp")
        .await
        .unwrap();

    let state = engine.inner.read().await;
    assert!(matches!(state.engines["pg"].db_engine, DbEngine::Postgres));
}

#[tokio::test]
async fn register_mysql_engine() {
    let engine = DynamicSecretsEngine::new();
    engine
        .register_engine("my", "mysql://root:pass@localhost:3306/admin", "myapp")
        .await
        .unwrap();

    let state = engine.inner.read().await;
    assert!(matches!(state.engines["my"].db_engine, DbEngine::Mysql));
}

#[tokio::test]
async fn register_unsupported_engine_fails() {
    let engine = DynamicSecretsEngine::new();
    let result = engine
        .register_engine("sq", "sqlite:///tmp/db.sqlite", "myapp")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn generate_credentials_produces_unique_material() {
    let engine = DynamicSecretsEngine::new();
    engine
        .register_engine("pg", "postgres://admin:pass@localhost:5432/admin", "myapp")
        .await
        .unwrap();

    // Will fail to connect to DB but should still generate credentials
    let l1 = engine
        .generate_credentials("pg", "readonly", "my-service", None)
        .await
        .unwrap();
    let l2 = engine
        .generate_credentials("pg", "readonly", "my-service", None)
        .await
        .unwrap();

    assert_ne!(l1.credentials.username, l2.credentials.username);
    assert_ne!(l1.credentials.password, l2.credentials.password);
    assert_ne!(l1.lease_id, l2.lease_id);
    assert!(
        !l1.provisioned,
        "should not be provisioned when DB unreachable"
    );
}

#[tokio::test]
async fn generate_credentials_includes_connection_url() {
    let engine = DynamicSecretsEngine::new();
    engine
        .register_engine(
            "pg",
            "postgres://admin:pass@db.example.com:5432/admin",
            "myapp",
        )
        .await
        .unwrap();

    let lease = engine
        .generate_credentials("pg", "rw", "my-service", None)
        .await
        .unwrap();

    let conn_url = lease.credentials.connection_url.unwrap();
    assert!(conn_url.starts_with("postgres://"));
    assert!(conn_url.contains("db.example.com:5432"));
    assert!(conn_url.contains("myapp"));
    assert!(conn_url.contains(&lease.credentials.username));
}

#[tokio::test]
async fn generate_fails_for_unknown_engine() {
    let engine = DynamicSecretsEngine::new();
    let result = engine
        .generate_credentials("nonexistent", "role", "svc", None)
        .await;
    assert!(matches!(result, Err(DynamicSecretError::EngineNotFound(_))));
}

#[tokio::test]
async fn revoke_lease_removes_it() {
    let engine = DynamicSecretsEngine::new();
    engine
        .register_engine("pg", "postgres://admin:pass@localhost:5432/admin", "myapp")
        .await
        .unwrap();

    let lease = engine
        .generate_credentials("pg", "admin", "svc", None)
        .await
        .unwrap();

    assert_eq!(engine.active_leases().await.len(), 1);
    engine.revoke_lease(&lease.lease_id).await.unwrap();
    assert_eq!(engine.active_leases().await.len(), 0);
}

#[tokio::test]
async fn revoke_nonexistent_lease_fails() {
    let engine = DynamicSecretsEngine::new();
    let result = engine.revoke_lease("no/such/lease").await;
    assert!(matches!(result, Err(DynamicSecretError::LeaseNotFound(_))));
}

#[tokio::test]
async fn custom_ttl() {
    let engine = DynamicSecretsEngine::new();
    engine
        .register_engine("pg", "postgres://admin:pass@localhost/db", "mydb")
        .await
        .unwrap();

    let lease = engine
        .generate_credentials("pg", "ro", "svc", Some(LeaseTtl { seconds: 300 }))
        .await
        .unwrap();

    let now = now_epoch();
    assert!(lease.expires_at >= now + 299);
    assert!(lease.expires_at <= now + 301);
}

#[test]
fn build_service_url_postgres() {
    let url = build_service_url(
        "postgres://admin:secret@db.host:5432/admindb",
        "v-svc-ro-abc123",
        "randompass",
        "myapp",
    );
    assert_eq!(
        url,
        "postgres://v-svc-ro-abc123:randompass@db.host:5432/myapp"
    );
}

#[test]
fn build_service_url_mysql() {
    let url = build_service_url(
        "mysql://root:pass@db.host:3306/admin",
        "v-svc-rw-def456",
        "pw",
        "myapp",
    );
    assert_eq!(url, "mysql://v-svc-rw-def456:pw@db.host:3306/myapp");
}
