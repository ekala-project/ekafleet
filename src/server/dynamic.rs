//! Issues, renews and revokes dynamic database credentials.
//!
//! For every `type = "dynamic"` secret in the applied configuration, the
//! lease manager keeps one database user: it creates it through the secret
//! engine's admin connection, stores the credentials (sealed under the fleet
//! key) as the secret's value so they reach the service like a static
//! secret, and replaces the user two thirds of the way through its lease.
//! Replaced users are dropped when their password expires, by which time
//! the services have restarted with the new credentials; users of secrets
//! no longer declared are dropped at once.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::api::FleetKeyState;
use super::events::{EventCategory, EventLevel, EventStore};
use super::state::FleetState;
use crate::config::{FleetConfig, SecretEngineConfig};
use crate::raft::state::{DynamicLease, FleetStateMachine};
use crate::secrets::FLEET_SCOPE;
use crate::secrets::dynamic::{CredentialBackend, Credentials};
use crate::secrets::store::SecretStore;

/// How often leases are checked when nothing wakes the manager sooner.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(30);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A dynamic secret the configuration declares.
struct Wanted<'a> {
    engine_name: &'a str,
    engine: &'a SecretEngineConfig,
    role: &'a str,
    ttl: u64,
}

fn wanted(config: &FleetConfig) -> BTreeMap<(String, String), Wanted<'_>> {
    let mut out = BTreeMap::new();
    for (service, cfg) in &config.services {
        for (name, secret) in &cfg.secrets {
            if !secret.is_dynamic() {
                continue;
            }
            let (Some(engine_name), Some(role)) =
                (secret.engine.as_deref(), secret.role.as_deref())
            else {
                continue;
            };
            let Some(engine) = config.secret_engines.get(engine_name) else {
                continue;
            };
            out.insert(
                (service.clone(), name.clone()),
                Wanted {
                    engine_name,
                    engine,
                    role,
                    ttl: secret.ttl(),
                },
            );
        }
    }
    out
}

#[derive(Clone)]
pub struct LeaseManager {
    pub raft_state: FleetStateMachine,
    pub state: FleetState,
    pub events: EventStore,
    pub fleet_key: Arc<RwLock<FleetKeyState>>,
    pub secret_store: Arc<RwLock<SecretStore>>,
    pub backend: Arc<dyn CredentialBackend>,
}

impl LeaseManager {
    /// Check leases every [`CHECK_INTERVAL`] and whenever assignments or
    /// secrets change, until `shutdown`.
    pub fn spawn(self, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        let wake = self.state.assignments_changed();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CHECK_INTERVAL);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => {}
                    _ = wake.notified() => {}
                }
                self.run(now()).await;
            }
        })
    }

    /// Bring leases in line with the configuration as of `now`: issue
    /// missing and due credentials, retire undeclared ones, and drop retired
    /// users that are due. Returns how many credentials were issued.
    pub async fn run(&self, now: u64) -> usize {
        let config = self
            .raft_state
            .current_config()
            .await
            .and_then(|r| r.config().ok());
        let mut issued = 0;
        if let Some(config) = &config {
            let wanted = wanted(config);
            self.retire_undeclared(&wanted, now).await;
            let leases = self.raft_state.dynamic_leases().await;
            for ((service, name), want) in &wanted {
                let lease = leases.get(service).and_then(|s| s.get(name));
                let due = lease.is_none_or(|lease| {
                    lease.engine != want.engine_name
                        || lease.role != want.role
                        || now >= lease.renew_at()
                });
                if due && self.issue(service, name, want, lease, now).await {
                    issued += 1;
                }
            }
        }
        self.drop_retired(config.as_ref(), now).await;
        if issued > 0 {
            self.state.assignments_changed().trigger();
        }
        issued
    }

    async fn retire_undeclared(&self, wanted: &BTreeMap<(String, String), Wanted<'_>>, now: u64) {
        for (service, names) in self.raft_state.dynamic_leases().await {
            for name in names.keys() {
                if wanted.contains_key(&(service.clone(), name.clone())) {
                    continue;
                }
                match self
                    .raft_state
                    .retire_dynamic_secret(&service, name, now)
                    .await
                {
                    Ok(_) => {
                        tracing::info!(service = %service, secret = %name, "Dynamic secret no longer declared; revoking its user");
                    }
                    Err(e) => {
                        tracing::error!(service = %service, secret = %name, error = %e, "Failed to retire a dynamic secret");
                    }
                }
            }
        }
    }

    /// The admin connection URL of `engine`, if its fleet secret is set.
    async fn admin_url(&self, engine: &SecretEngineConfig) -> Option<Zeroizing<String>> {
        let stored = self.raft_state.secrets().await;
        let (sealed, _) = stored
            .get(FLEET_SCOPE)
            .and_then(|s| s.get(&engine.admin_url_secret))?;
        let opened = self
            .secret_store
            .read()
            .await
            .open(FLEET_SCOPE, &engine.admin_url_secret, sealed)
            .map_err(|e| tracing::error!(secret = %engine.admin_url_secret, error = %e, "Cannot open a secret engine's admin URL"))
            .ok()?;
        String::from_utf8(opened.to_vec())
            .map(|url| Zeroizing::new(url.trim().to_string()))
            .ok()
    }

    async fn issue(
        &self,
        service: &str,
        name: &str,
        want: &Wanted<'_>,
        current: Option<&DynamicLease>,
        now: u64,
    ) -> bool {
        let Some(admin_url) = self.admin_url(want.engine).await else {
            tracing::warn!(
                service = %service,
                secret = %name,
                engine = %want.engine_name,
                "Cannot issue a dynamic secret: set the engine's admin URL with \
                 `ekafleet secret set {FLEET_SCOPE} {}`",
                want.engine.admin_url_secret
            );
            return false;
        };
        let credentials = match Credentials::generate(&admin_url, &want.engine.database) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(engine = %want.engine_name, error = %e, "Cannot issue a dynamic secret");
                return false;
            }
        };
        let lease = DynamicLease {
            engine: want.engine_name.to_string(),
            role: want.role.to_string(),
            username: credentials.username.clone(),
            issued_at: now,
            expires_at: now + want.ttl,
        };
        if let Err(e) = self
            .backend
            .provision(
                &admin_url,
                &credentials,
                &want.engine.database,
                want.role,
                lease.expires_at,
            )
            .await
        {
            tracing::error!(service = %service, secret = %name, engine = %want.engine_name, error = %e, "Failed to create a database user");
            self.events
                .emit_kind(
                    "secret.dynamic.failed",
                    EventLevel::Error,
                    EventCategory::SecretRotation,
                    Some(service),
                    None,
                    &format!(
                        "could not issue {name} from engine {}: {e}",
                        want.engine_name
                    ),
                )
                .await;
            return false;
        }

        // Sealed and stored under the fleet key lock, so a rotation can't
        // miss the new value.
        let stored = {
            let _fleet_key = self.fleet_key.read().await;
            let sealed = self
                .secret_store
                .read()
                .await
                .seal(service, name, &credentials.to_json());
            match sealed {
                Ok(sealed) => self
                    .raft_state
                    .issue_dynamic_secret(service, name, sealed, lease.clone())
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        };
        let version = match stored {
            Ok(version) => version,
            Err(e) => {
                tracing::error!(service = %service, secret = %name, error = %e, "Failed to store dynamic credentials; dropping the user");
                if let Err(e) = self.backend.revoke(&admin_url, &credentials.username).await {
                    tracing::error!(user = %credentials.username, error = %e, "Failed to drop an unused database user");
                }
                return false;
            }
        };
        let verb = if current.is_some() {
            "renewed"
        } else {
            "issued"
        };
        tracing::info!(
            service = %service,
            secret = %name,
            engine = %want.engine_name,
            user = %lease.username,
            version,
            expires_at = lease.expires_at,
            "Dynamic secret {verb}"
        );
        self.events
            .emit_kind(
                &format!("secret.dynamic.{verb}"),
                EventLevel::Info,
                EventCategory::SecretRotation,
                Some(service),
                None,
                &format!(
                    "{name}: user {} from engine {} (version {version})",
                    lease.username, want.engine_name
                ),
            )
            .await;
        true
    }

    async fn drop_retired(&self, config: Option<&FleetConfig>, now: u64) {
        for user in self.raft_state.retired_users().await {
            if user.drop_at > now {
                continue;
            }
            let engine = config.and_then(|c| c.secret_engines.get(&user.engine));
            let Some(engine) = engine else {
                // The database's admin connection is gone with the engine;
                // the password still expires on its own.
                tracing::warn!(engine = %user.engine, user = %user.username, "Secret engine removed; its retired user can't be dropped and expires on its own");
                self.forget(&user.engine, &user.username).await;
                continue;
            };
            let Some(admin_url) = self.admin_url(engine).await else {
                tracing::warn!(engine = %user.engine, user = %user.username, "Cannot drop a retired database user: the engine's admin URL is not set");
                continue;
            };
            match self.backend.revoke(&admin_url, &user.username).await {
                Ok(()) => {
                    tracing::info!(engine = %user.engine, user = %user.username, "Retired database user dropped");
                    self.forget(&user.engine, &user.username).await;
                }
                Err(e) => {
                    tracing::warn!(engine = %user.engine, user = %user.username, error = %e, "Failed to drop a retired database user; will retry");
                }
            }
        }
    }

    async fn forget(&self, engine: &str, username: &str) {
        if let Err(e) = self.raft_state.forget_retired_user(engine, username).await {
            tracing::error!(engine = %engine, user = %username, error = %e, "Failed to forget a retired database user");
        }
    }
}

#[allow(clippy::result_large_err)] // tonic::Status, as in every gRPC handler
mod rpc {
    use tonic::{Request, Status};

    use super::super::api::FleetControlService;
    use super::super::audit::{AuditAction, AuditOutcome};
    use super::super::rbac::{Permission, require_permission};
    use super::now;
    use crate::proto::{
        DynamicLeaseInfo, ListDynamicLeasesRequest, ListDynamicLeasesResponse, RetiredUserInfo,
        RevokeDynamicSecretRequest, RevokeDynamicSecretResponse,
    };

    impl FleetControlService {
        pub(in crate::server) async fn handle_list_dynamic_leases(
            &self,
            request: Request<ListDynamicLeasesRequest>,
        ) -> Result<ListDynamicLeasesResponse, Status> {
            require_permission(&request, Permission::Read)?;
            let filter = request.get_ref().service_name.clone();
            if !filter.is_empty() {
                self.require_service_access(&request, &filter).await?;
            }
            let visible = self.visible_services(&request).await;
            let leases = self
                .raft_state
                .dynamic_leases()
                .await
                .into_iter()
                .filter(|(service, _)| filter.is_empty() || *service == filter)
                .filter(|(service, _)| visible.as_ref().is_none_or(|v| v.contains(service)))
                .flat_map(|(service, names)| {
                    names
                        .into_iter()
                        .map(move |(name, lease)| DynamicLeaseInfo {
                            service_name: service.clone(),
                            secret_name: name,
                            renew_at: lease.renew_at(),
                            engine: lease.engine,
                            role: lease.role,
                            username: lease.username,
                            issued_at: lease.issued_at,
                            expires_at: lease.expires_at,
                        })
                })
                .collect();
            let retired = if visible.is_none() && filter.is_empty() {
                self.raft_state
                    .retired_users()
                    .await
                    .into_iter()
                    .map(|u| RetiredUserInfo {
                        engine: u.engine,
                        username: u.username,
                        drop_at: u.drop_at,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            Ok(ListDynamicLeasesResponse { leases, retired })
        }

        pub(in crate::server) async fn handle_revoke_dynamic_secret(
            &self,
            request: Request<RevokeDynamicSecretRequest>,
        ) -> Result<RevokeDynamicSecretResponse, Status> {
            require_permission(&request, Permission::ManageSecrets)?;
            let req = request.get_ref();
            for (kind, name) in [("service", &req.service_name), ("secret", &req.secret_name)] {
                crate::secrets::validate_name(kind, name).map_err(Status::invalid_argument)?;
            }
            self.require_service_access(&request, &req.service_name)
                .await?;
            let revoked = self
                .raft_state
                .retire_dynamic_secret(&req.service_name, &req.secret_name, now())
                .await
                .map_err(|e| Status::internal(format!("failed to revoke: {e}")))?;
            self.audit(
                &request,
                AuditAction::SecretWrite,
                &format!("{}/{}", req.service_name, req.secret_name),
                if revoked {
                    "revoke dynamic user"
                } else {
                    "revoke (no lease)"
                },
                AuditOutcome::Success,
            )
            .await;
            if revoked {
                tracing::info!(service = %req.service_name, secret = %req.secret_name, "Dynamic secret revoked; issuing a new user");
                // Wakes the lease manager, which drops the user and issues
                // another, and the publisher.
                self.state.assignments_changed().trigger();
            }
            Ok(RevokeDynamicSecretResponse { revoked })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::raft::state::Command;
    use crate::secrets::dynamic::DynamicSecretError;

    const FLEET_KEY: [u8; 32] = [7; 32];

    /// Records users created and dropped; fails while `down`.
    #[derive(Default)]
    struct FakeDb {
        created: Mutex<Vec<(String, String, u64)>>,
        dropped: Mutex<Vec<String>>,
        down: std::sync::atomic::AtomicBool,
    }

    type Fut<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), DynamicSecretError>> + Send + 'a>,
    >;

    impl FakeDb {
        fn check(&self) -> Result<(), DynamicSecretError> {
            if self.down.load(std::sync::atomic::Ordering::SeqCst) {
                Err(
                    crate::secrets::db_driver::DbDriverError::ConnectionFailed("down".into())
                        .into(),
                )
            } else {
                Ok(())
            }
        }
        fn created(&self) -> Vec<String> {
            self.created
                .lock()
                .unwrap()
                .iter()
                .map(|c| c.0.clone())
                .collect()
        }
        fn dropped(&self) -> Vec<String> {
            self.dropped.lock().unwrap().clone()
        }
    }

    impl CredentialBackend for FakeDb {
        fn provision<'a>(
            &'a self,
            admin_url: &'a str,
            credentials: &'a Credentials,
            database: &'a str,
            role: &'a str,
            valid_until: u64,
        ) -> Fut<'a> {
            Box::pin(async move {
                self.check()?;
                assert_eq!(admin_url, "postgres://admin:pw@db:5432/postgres");
                assert_eq!(database, "shop");
                self.created.lock().unwrap().push((
                    credentials.username.clone(),
                    role.to_string(),
                    valid_until,
                ));
                Ok(())
            })
        }

        fn revoke<'a>(&'a self, _admin_url: &'a str, username: &'a str) -> Fut<'a> {
            Box::pin(async move {
                self.check()?;
                self.dropped.lock().unwrap().push(username.to_string());
                Ok(())
            })
        }
    }

    async fn apply(raft: &FleetStateMachine, services: serde_json::Value) {
        let config = serde_json::json!({
            "name": "test",
            "domain": "fleet.test",
            "secretEngines": {"pg": {"adminUrlSecret": "pg-admin", "database": "shop"}},
            "services": services,
        });
        raft.apply_config(Command::ApplyConfig {
            flake_ref: ".".into(),
            config_json: config.to_string(),
            applied_at: 1,
            applied_by: "test".into(),
            rollback_of: None,
            closures: Default::default(),
            images: Default::default(),
        })
        .await
        .unwrap();
    }

    fn web(ttl: u64) -> serde_json::Value {
        serde_json::json!({"web": {
            "command": "/bin/web",
            "secrets": {"db": {"type": "dynamic", "engine": "pg", "role": "readwrite", "ttl": ttl}},
        }})
    }

    fn manager(raft: &FleetStateMachine, db: &Arc<FakeDb>) -> LeaseManager {
        LeaseManager {
            raft_state: raft.clone(),
            state: FleetState::new(),
            events: EventStore::new(),
            fleet_key: Arc::new(RwLock::new(FleetKeyState {
                key: Zeroizing::new(FLEET_KEY.to_vec()),
                version: 1,
            })),
            secret_store: Arc::new(RwLock::new(SecretStore::new(&FLEET_KEY))),
            backend: db.clone(),
        }
    }

    async fn set_admin_url(raft: &FleetStateMachine) {
        let sealed = SecretStore::new(&FLEET_KEY)
            .seal(
                FLEET_SCOPE,
                "pg-admin",
                b"postgres://admin:pw@db:5432/postgres\n",
            )
            .unwrap();
        raft.put_secret(FLEET_SCOPE, "pg-admin", sealed)
            .await
            .unwrap();
    }

    async fn delivered(raft: &FleetStateMachine) -> serde_json::Value {
        let (sealed, _) = raft.secrets().await["web"]["db"].clone();
        let json = SecretStore::new(&FLEET_KEY)
            .open("web", "db", &sealed)
            .unwrap();
        serde_json::from_slice(&json).unwrap()
    }

    #[tokio::test]
    async fn credentials_are_issued_renewed_and_old_users_dropped() {
        let raft = FleetStateMachine::new();
        let db = Arc::new(FakeDb::default());
        let leases = manager(&raft, &db);
        apply(&raft, web(900)).await;

        // Nothing is issued until the engine's admin URL is set.
        assert_eq!(leases.run(1000).await, 0);
        set_admin_url(&raft).await;
        assert_eq!(leases.run(1000).await, 1);
        let first = db.created();
        assert_eq!(first.len(), 1);
        assert_eq!(db.created.lock().unwrap()[0].1, "readwrite");
        assert_eq!(db.created.lock().unwrap()[0].2, 1900);
        let json = delivered(&raft).await;
        assert_eq!(json["username"], first[0].as_str());
        assert!(json["url"].as_str().unwrap().ends_with("@db:5432/shop"));

        // Not due yet; then renewed two thirds of the way through.
        assert_eq!(leases.run(1599).await, 0);
        assert_eq!(leases.run(1600).await, 1);
        let users = db.created();
        assert_eq!(users.len(), 2);
        assert_eq!(delivered(&raft).await["username"], users[1].as_str());
        assert_eq!(raft.secrets().await["web"]["db"].1, 2);
        // The first user lives until its password expires, then is dropped.
        assert!(db.dropped().is_empty());
        leases.run(1899).await;
        assert!(db.dropped().is_empty());
        leases.run(1900).await;
        assert_eq!(db.dropped(), [first[0].clone()]);
        assert!(raft.retired_users().await.is_empty());
    }

    #[tokio::test]
    async fn undeclared_secrets_lose_their_user_at_once() {
        let raft = FleetStateMachine::new();
        let db = Arc::new(FakeDb::default());
        let leases = manager(&raft, &db);
        set_admin_url(&raft).await;
        apply(&raft, web(900)).await;
        leases.run(1000).await;
        let user = db.created()[0].clone();

        apply(&raft, serde_json::json!({"web": {"command": "/bin/web"}})).await;
        assert_eq!(leases.run(1010).await, 0);
        assert_eq!(db.dropped(), [user]);
        assert!(!raft.secrets().await.contains_key("web"));
        assert!(raft.dynamic_leases().await.is_empty());
    }

    #[tokio::test]
    async fn role_changes_reissue_and_failures_retry() {
        let raft = FleetStateMachine::new();
        let db = Arc::new(FakeDb::default());
        let leases = manager(&raft, &db);
        set_admin_url(&raft).await;
        apply(&raft, web(900)).await;
        leases.run(1000).await;

        let mut readonly = web(900);
        readonly["web"]["secrets"]["db"]["role"] = "readonly".into();
        apply(&raft, readonly).await;
        db.down.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(leases.run(1010).await, 0);
        // The old credentials stay in place while the database is down.
        assert_eq!(raft.dynamic_leases().await["web"]["db"].role, "readwrite");

        db.down.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(leases.run(1020).await, 1);
        assert_eq!(raft.dynamic_leases().await["web"]["db"].role, "readonly");
        assert_eq!(db.created.lock().unwrap()[1].1, "readonly");
    }

    #[tokio::test]
    async fn retired_users_of_removed_engines_are_forgotten() {
        let raft = FleetStateMachine::new();
        let db = Arc::new(FakeDb::default());
        let leases = manager(&raft, &db);
        set_admin_url(&raft).await;
        apply(&raft, web(900)).await;
        leases.run(1000).await;

        let config = serde_json::json!({"name": "test", "domain": "fleet.test"});
        raft.apply_config(Command::ApplyConfig {
            flake_ref: ".".into(),
            config_json: config.to_string(),
            applied_at: 2,
            applied_by: "test".into(),
            rollback_of: None,
            closures: Default::default(),
            images: Default::default(),
        })
        .await
        .unwrap();
        leases.run(1010).await;
        assert!(db.dropped().is_empty());
        assert!(raft.retired_users().await.is_empty());
    }

    #[tokio::test]
    async fn dynamic_secrets_refuse_writes_and_revoke_to_reissue() {
        use crate::proto::{
            DeleteSecretRequest, ListDynamicLeasesRequest, RevokeDynamicSecretRequest,
            SetSecretRequest,
        };
        use crate::server::rbac::Role;
        use tonic::Request;

        let raft = FleetStateMachine::new();
        let db = Arc::new(FakeDb::default());
        set_admin_url(&raft).await;
        apply(&raft, web(900)).await;
        let svc = crate::server::api::FleetControlService::new(
            FleetState::new(),
            "fleet.test",
            crate::attestation::join_token::JoinTokenStore::new(),
            raft.clone(),
            crate::server::cloud::instance_tracker::InstanceTracker::new(raft.clone()),
            "127.0.0.1:0",
            EventStore::new(),
            crate::server::rbac::TokenStore::new(),
            tempfile::tempdir().unwrap().keep(),
        );
        fn admin<T>(msg: T) -> Request<T> {
            let mut req = Request::new(msg);
            req.extensions_mut().insert(Role::Admin);
            req
        }
        let err = svc
            .handle_set_secret(admin(SetSecretRequest {
                service_name: "web".into(),
                secret_name: "db".into(),
                value: b"x".to_vec(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let err = svc
            .handle_delete_secret(admin(DeleteSecretRequest {
                service_name: "web".into(),
                secret_name: "db".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        let leases = manager(&raft, &db);
        leases.run(1000).await;
        let listed = svc
            .handle_list_dynamic_leases(admin(ListDynamicLeasesRequest {
                service_name: String::new(),
            }))
            .await
            .unwrap();
        assert_eq!(listed.leases.len(), 1);
        assert_eq!(listed.leases[0].renew_at, 1600);
        let first = listed.leases[0].username.clone();

        let revoke = || {
            admin(RevokeDynamicSecretRequest {
                service_name: "web".into(),
                secret_name: "db".into(),
            })
        };
        assert!(
            svc.handle_revoke_dynamic_secret(revoke())
                .await
                .unwrap()
                .revoked
        );
        // The next pass drops the revoked user and issues another.
        assert_eq!(leases.run(now()).await, 1);
        assert_eq!(db.dropped(), std::slice::from_ref(&first));
        assert_ne!(raft.dynamic_leases().await["web"]["db"].username, first);
    }
}
