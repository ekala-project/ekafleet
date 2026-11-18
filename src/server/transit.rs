//! Transit encryption RPCs.
//!
//! Keys belong to a namespace. Operators manage them with `ManageSecrets`
//! and use them with `Transit`; namespace-scoped tokens only reach their
//! namespace's keys. Workloads authenticate with their service SVID and may
//! only use the keys their service lists in `transitKeys`, in its own
//! namespace. Key material never leaves the server.

#![allow(clippy::result_large_err)] // tonic::Status, as in every gRPC handler

use tonic::{Request, Status};
use zeroize::Zeroizing;

use super::api::FleetControlService;
use super::audit::{AuditAction, AuditOutcome};
use super::rbac::{PeerIdentity, Permission, effective_namespace, namespace_scope};
use crate::proto::{
    CreateTransitKeyRequest, DeleteTransitKeyRequest, DeleteTransitKeyResponse,
    ListTransitKeysRequest, ListTransitKeysResponse, RotateTransitKeyRequest,
    TransitDecryptRequest, TransitDecryptResponse, TransitEncryptRequest, TransitEncryptResponse,
    TransitKeyInfo,
};
use crate::raft::state::TransitKey;
use crate::secrets::transit::{self, SEAL_SCOPE, seal_name};

fn info(name: &str, key: &TransitKey) -> TransitKeyInfo {
    TransitKeyInfo {
        name: name.to_string(),
        namespace: key.namespace.clone(),
        latest_version: key.versions.len() as u32,
    }
}

fn check_name(name: &str) -> Result<(), Status> {
    crate::secrets::validate_name("transit key", name).map_err(Status::invalid_argument)
}

impl FleetControlService {
    /// The key `name`, if the caller may use it with `perm`.
    async fn authorized_transit_key<T>(
        &self,
        request: &Request<T>,
        perm: Permission,
        name: &str,
    ) -> Result<TransitKey, Status> {
        super::rbac::require_permission(request, perm)?;
        check_name(name)?;
        let not_found = || Status::not_found(format!("no transit key '{name}'"));
        let key = self.raft_state.transit_key(name).await;

        if let Some(peer) = request.extensions().get::<PeerIdentity>()
            && let Some(service) = peer.service_name(&self.domain)
        {
            let config = self
                .raft_state
                .current_config()
                .await
                .and_then(|r| r.config().ok());
            let svc = config.as_ref().and_then(|c| c.services.get(service));
            let allowed = svc.is_some_and(|svc| svc.transit_keys.iter().any(|k| k == name))
                && key
                    .as_ref()
                    .zip(svc)
                    .is_some_and(|(key, svc)| key.namespace == effective_namespace(&svc.namespace));
            if !allowed {
                return Err(Status::permission_denied(format!(
                    "service '{service}' may not use transit key '{name}'"
                )));
            }
        }
        let key = key.ok_or_else(not_found)?;
        if let Some(ns) = namespace_scope(request)
            && key.namespace != ns
        {
            // Indistinguishable from a missing key to other namespaces.
            return Err(not_found());
        }
        Ok(key)
    }

    /// Open version `version` of key `name`.
    async fn open_transit_key(
        &self,
        name: &str,
        key: &TransitKey,
        version: u32,
    ) -> Result<Zeroizing<Vec<u8>>, Status> {
        let sealed = version
            .checked_sub(1)
            .and_then(|i| key.versions.get(i as usize))
            .ok_or_else(|| {
                Status::invalid_argument(format!("transit key '{name}' has no version {version}"))
            })?;
        let store = self.secret_store.read().await;
        store
            .open(SEAL_SCOPE, &seal_name(name, version), sealed)
            .map_err(|e| Status::internal(format!("transit key {name} v{version}: {e}")))
    }

    async fn seal_new_transit_key(&self, name: &str, version: u32) -> Result<Vec<u8>, Status> {
        let material = transit::generate_key().map_err(|e| Status::internal(e.to_string()))?;
        let store = self.secret_store.read().await;
        store
            .seal(SEAL_SCOPE, &seal_name(name, version), material.as_ref())
            .map_err(|e| Status::internal(e.to_string()))
    }

    pub(super) async fn handle_create_transit_key(
        &self,
        request: Request<CreateTransitKeyRequest>,
    ) -> Result<TransitKeyInfo, Status> {
        super::rbac::require_permission(&request, Permission::ManageSecrets)?;
        let req = request.get_ref();
        check_name(&req.name)?;
        let scope = namespace_scope(&request);
        let namespace = match (req.namespace.as_str(), scope) {
            ("", Some(scope)) => scope.to_string(),
            ("", None) => effective_namespace("").to_string(),
            (ns, Some(scope)) if ns != scope => {
                return Err(Status::permission_denied(format!(
                    "token is scoped to namespace '{scope}'"
                )));
            }
            (ns, _) => effective_namespace(ns).to_string(),
        };
        crate::config::validate_namespace_name(&namespace).map_err(Status::invalid_argument)?;
        // Under the fleet key lock, so a rotation can't miss the new key.
        let created = {
            let _fleet_key = self.fleet_key.read().await;
            let key = TransitKey {
                namespace,
                versions: vec![self.seal_new_transit_key(&req.name, 1).await?],
            };
            let created = self
                .raft_state
                .create_transit_key(&req.name, key.clone())
                .await
                .map_err(|e| Status::internal(format!("failed to store transit key: {e}")))?;
            created.then_some(key)
        };
        let Some(key) = created else {
            return Err(Status::already_exists(format!(
                "transit key '{}' exists",
                req.name
            )));
        };
        self.audit(
            &request,
            AuditAction::TransitKey,
            &req.name,
            &format!("create in namespace {}", key.namespace),
            AuditOutcome::Success,
        )
        .await;
        tracing::info!(key = %req.name, namespace = %key.namespace, "Transit key created");
        Ok(info(&req.name, &key))
    }

    pub(super) async fn handle_rotate_transit_key(
        &self,
        request: Request<RotateTransitKeyRequest>,
    ) -> Result<TransitKeyInfo, Status> {
        let name = request.get_ref().name.clone();
        let key = self
            .authorized_transit_key(&request, Permission::ManageSecrets, &name)
            .await?;
        let version = {
            let _fleet_key = self.fleet_key.read().await;
            let next = key.versions.len() as u32 + 1;
            let sealed = self.seal_new_transit_key(&name, next).await?;
            self.raft_state
                .add_transit_key_version(&name, sealed)
                .await
                .map_err(|e| Status::internal(format!("failed to store transit key: {e}")))?
                .ok_or_else(|| Status::not_found(format!("no transit key '{name}'")))?
        };
        self.audit(
            &request,
            AuditAction::TransitKey,
            &name,
            &format!("rotate to version {version}"),
            AuditOutcome::Success,
        )
        .await;
        tracing::info!(key = %name, version, "Transit key rotated");
        Ok(TransitKeyInfo {
            name,
            namespace: key.namespace,
            latest_version: version,
        })
    }

    pub(super) async fn handle_list_transit_keys(
        &self,
        request: Request<ListTransitKeysRequest>,
    ) -> Result<ListTransitKeysResponse, Status> {
        super::rbac::require_permission(&request, Permission::Read)?;
        let scope = namespace_scope(&request);
        let keys = self
            .raft_state
            .transit_keys()
            .await
            .iter()
            .filter(|(_, key)| scope.is_none_or(|ns| key.namespace == ns))
            .map(|(name, key)| info(name, key))
            .collect();
        Ok(ListTransitKeysResponse { keys })
    }

    pub(super) async fn handle_delete_transit_key(
        &self,
        request: Request<DeleteTransitKeyRequest>,
    ) -> Result<DeleteTransitKeyResponse, Status> {
        let name = request.get_ref().name.clone();
        self.authorized_transit_key(&request, Permission::ManageSecrets, &name)
            .await?;
        let deleted = self
            .raft_state
            .delete_transit_key(&name)
            .await
            .map_err(|e| Status::internal(format!("failed to delete transit key: {e}")))?;
        self.audit(
            &request,
            AuditAction::TransitKey,
            &name,
            "delete",
            AuditOutcome::Success,
        )
        .await;
        tracing::warn!(key = %name, "Transit key deleted; values encrypted with it are lost");
        Ok(DeleteTransitKeyResponse { deleted })
    }

    pub(super) async fn handle_transit_encrypt(
        &self,
        request: Request<TransitEncryptRequest>,
    ) -> Result<TransitEncryptResponse, Status> {
        let name = request.get_ref().key_name.clone();
        if request.get_ref().plaintext.len() > transit::MAX_PLAINTEXT {
            return Err(Status::invalid_argument(format!(
                "plaintext exceeds {} bytes",
                transit::MAX_PLAINTEXT
            )));
        }
        let key = self
            .authorized_transit_key(&request, Permission::Transit, &name)
            .await?;
        let version = key.versions.len() as u32;
        let material = self.open_transit_key(&name, &key, version).await?;
        let plaintext = Zeroizing::new(request.into_inner().plaintext);
        let ciphertext = transit::encrypt(&name, version, &material, &plaintext)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(TransitEncryptResponse { ciphertext })
    }

    pub(super) async fn handle_transit_decrypt(
        &self,
        request: Request<TransitDecryptRequest>,
    ) -> Result<TransitDecryptResponse, Status> {
        let name = request.get_ref().key_name.clone();
        let key = self
            .authorized_transit_key(&request, Permission::Transit, &name)
            .await?;
        let ciphertext = &request.get_ref().ciphertext;
        let version =
            transit::version_of(ciphertext).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let material = self.open_transit_key(&name, &key, version).await?;
        let plaintext = transit::decrypt(&name, &material, ciphertext)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(TransitDecryptResponse {
            plaintext: plaintext.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::state::{Command, FleetStateMachine};
    use crate::server::rbac::{RequestNamespace, Role, TokenIdentity};

    async fn service() -> FleetControlService {
        let raft = FleetStateMachine::new();
        let config = serde_json::json!({
            "name": "test",
            "domain": "fleet.test",
            "services": {
                "web": {"command": "/bin/web", "transitKeys": ["orders"]},
                "shop": {"command": "/bin/shop", "namespace": "shop", "transitKeys": ["carts"]},
                "batch": {"command": "/bin/batch"},
            },
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
        FleetControlService::new(
            crate::server::state::FleetState::new(),
            "fleet.test",
            crate::attestation::join_token::JoinTokenStore::new(),
            raft.clone(),
            crate::server::cloud::instance_tracker::InstanceTracker::new(raft),
            "127.0.0.1:0",
            crate::server::events::EventStore::new(),
            crate::server::rbac::TokenStore::new(),
            tempfile::tempdir().unwrap().keep(),
        )
    }

    fn as_token<T>(msg: T, namespace: Option<&str>) -> Request<T> {
        let mut req = Request::new(msg);
        let role = if namespace.is_some() {
            Role::Operator
        } else {
            Role::Admin
        };
        req.extensions_mut().insert(role);
        if let Some(ns) = namespace {
            req.extensions_mut().insert(RequestNamespace(ns.into()));
        }
        req.extensions_mut().insert(TokenIdentity {
            id: "token:test".into(),
            description: String::new(),
            role,
            namespace: namespace.map(str::to_string),
        });
        req
    }

    fn as_service<T>(msg: T, service: &str) -> Request<T> {
        let peer = PeerIdentity::from_spiffe_id(
            "fleet.test",
            format!("spiffe://fleet.test/service/{service}"),
        )
        .unwrap();
        let mut req = Request::new(msg);
        req.extensions_mut().insert(peer.role);
        req.extensions_mut().insert(peer);
        req
    }

    fn encrypt(key: &str, plaintext: &[u8]) -> TransitEncryptRequest {
        TransitEncryptRequest {
            key_name: key.into(),
            plaintext: plaintext.to_vec(),
        }
    }

    fn decrypt(key: &str, ciphertext: &str) -> TransitDecryptRequest {
        TransitDecryptRequest {
            key_name: key.into(),
            ciphertext: ciphertext.into(),
        }
    }

    async fn create(svc: &FleetControlService, name: &str, namespace: &str) {
        svc.handle_create_transit_key(as_token(
            CreateTransitKeyRequest {
                name: name.into(),
                namespace: namespace.into(),
            },
            None,
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rotated_keys_keep_decrypting_old_values() {
        let svc = service().await;
        create(&svc, "orders", "").await;
        let v1 = svc
            .handle_transit_encrypt(as_token(encrypt("orders", b"card"), None))
            .await
            .unwrap()
            .ciphertext;
        assert!(v1.starts_with("ekafleet:v1:"));

        let rotated = svc
            .handle_rotate_transit_key(as_token(
                RotateTransitKeyRequest {
                    name: "orders".into(),
                },
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            (rotated.namespace.as_str(), rotated.latest_version),
            ("default", 2)
        );
        let v2 = svc
            .handle_transit_encrypt(as_token(encrypt("orders", b"card"), None))
            .await
            .unwrap()
            .ciphertext;
        assert!(v2.starts_with("ekafleet:v2:"));
        for ct in [&v1, &v2] {
            let plain = svc
                .handle_transit_decrypt(as_token(decrypt("orders", ct), None))
                .await
                .unwrap()
                .plaintext;
            assert_eq!(plain, b"card");
        }

        // A value made with another key doesn't open under this one.
        create(&svc, "other", "").await;
        let err = svc
            .handle_transit_decrypt(as_token(decrypt("other", &v1), None))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let dup = svc
            .handle_create_transit_key(as_token(
                CreateTransitKeyRequest {
                    name: "orders".into(),
                    namespace: String::new(),
                },
                None,
            ))
            .await
            .unwrap_err();
        assert_eq!(dup.code(), tonic::Code::AlreadyExists);

        let too_big = svc
            .handle_transit_encrypt(as_token(
                encrypt("orders", &vec![0; transit::MAX_PLAINTEXT + 1]),
                None,
            ))
            .await
            .unwrap_err();
        assert_eq!(too_big.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn workloads_use_only_their_declared_keys_in_their_namespace() {
        let svc = service().await;
        create(&svc, "orders", "").await;
        create(&svc, "carts", "shop").await;
        create(&svc, "payroll", "").await;

        let ct = svc
            .handle_transit_encrypt(as_service(encrypt("orders", b"x"), "web"))
            .await
            .unwrap()
            .ciphertext;
        let plain = svc
            .handle_transit_decrypt(as_service(decrypt("orders", &ct), "web"))
            .await
            .unwrap()
            .plaintext;
        assert_eq!(plain, b"x");
        svc.handle_transit_encrypt(as_service(encrypt("carts", b"x"), "shop"))
            .await
            .unwrap();

        // Undeclared keys, other services' keys, unknown services, and
        // management are all refused.
        for (key, service) in [
            ("payroll", "web"),
            ("carts", "web"),
            ("orders", "batch"),
            ("orders", "ghost"),
            ("missing", "web"),
        ] {
            let err = svc
                .handle_transit_encrypt(as_service(encrypt(key, b"x"), service))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied, "{service} {key}");
        }
        let err = svc
            .handle_rotate_transit_key(as_service(
                RotateTransitKeyRequest {
                    name: "orders".into(),
                },
                "web",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let err = svc
            .handle_list_transit_keys(as_service(ListTransitKeysRequest {}, "web"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn workloads_lose_a_key_in_another_namespace() {
        // `web` declares `orders`, but the key lives in namespace `shop`.
        let svc = service().await;
        create(&svc, "orders", "shop").await;
        let err = svc
            .handle_transit_encrypt(as_service(encrypt("orders", b"x"), "web"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn scoped_tokens_reach_only_their_namespace() {
        let svc = service().await;
        create(&svc, "orders", "").await;
        let scoped_create = |name: &str, namespace: &str| {
            as_token(
                CreateTransitKeyRequest {
                    name: name.into(),
                    namespace: namespace.into(),
                },
                Some("shop"),
            )
        };
        // Keys a scoped token creates land in its namespace, and no other.
        let created = svc
            .handle_create_transit_key(scoped_create("carts", ""))
            .await
            .unwrap();
        assert_eq!(created.namespace, "shop");
        let err = svc
            .handle_create_transit_key(scoped_create("ledger", "default"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let err = svc
            .handle_rotate_transit_key(as_token(
                RotateTransitKeyRequest {
                    name: "orders".into(),
                },
                Some("shop"),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        let listed = svc
            .handle_list_transit_keys(as_token(ListTransitKeysRequest {}, Some("shop")))
            .await
            .unwrap()
            .keys;
        assert_eq!(
            listed.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(),
            ["carts"]
        );
        svc.handle_transit_encrypt(as_token(encrypt("carts", b"x"), Some("shop")))
            .await
            .unwrap();
        let err = svc
            .handle_transit_encrypt(as_token(encrypt("orders", b"x"), Some("shop")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn deleted_keys_stop_decrypting() {
        let svc = service().await;
        create(&svc, "orders", "").await;
        let ct = svc
            .handle_transit_encrypt(as_token(encrypt("orders", b"x"), None))
            .await
            .unwrap()
            .ciphertext;
        let deleted = svc
            .handle_delete_transit_key(as_token(
                DeleteTransitKeyRequest {
                    name: "orders".into(),
                },
                None,
            ))
            .await
            .unwrap();
        assert!(deleted.deleted);
        let err = svc
            .handle_transit_decrypt(as_token(decrypt("orders", &ct), None))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }
}
