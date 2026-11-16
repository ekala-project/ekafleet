//! Auditing refused requests.
//!
//! Requests are refused in many places: the gRPC interceptor (missing or
//! unknown credentials, an unacceptable SPIFFE ID), every handler's RBAC
//! and namespace checks, and the HTTP API's middleware. Rather than
//! instrumenting each, [`AuditDenials`] wraps the gRPC service and records
//! every response whose status is UNAUTHENTICATED or PERMISSION_DENIED,
//! attributed to the caller's token id or SPIFFE ID (never the token
//! itself) and its address.

use std::net::IpAddr;
use std::task::{Context, Poll};

use tonic::codegen::{BoxFuture, Service, http};
use tonic::server::NamedService;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

use super::audit::{AuditAction, AuditLog, AuditOutcome};
use super::rbac::{TokenStore, extract_bearer_token, token_id};

/// The caller of a refused request, as recorded in the audit log.
pub fn actor(
    token_store: &TokenStore,
    authorization: Option<&str>,
    peer_leaf_der: Option<&[u8]>,
) -> String {
    if let Some(der) = peer_leaf_der {
        return crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_der(der)
            .unwrap_or_else(|| "mtls:no-spiffe-id".into());
    }
    let Some(token) = authorization.and_then(|h| extract_bearer_token(Some(h))) else {
        return "anonymous".into();
    };
    match token_store.authenticate_identity(token) {
        Some((_, identity)) => identity.actor(),
        // Unknown, expired or revoked: its id still links attempts.
        None => format!("{} (unknown)", token_id(token)),
    }
}

/// Audit action and outcome for a refused gRPC status code.
fn classify(code: tonic::Code) -> Option<AuditAction> {
    match code {
        tonic::Code::Unauthenticated => Some(AuditAction::Authenticate),
        tonic::Code::PermissionDenied => Some(AuditAction::Access),
        _ => None,
    }
}

/// Audit action for a refused HTTP status.
pub fn classify_http(status: http::StatusCode) -> Option<AuditAction> {
    match status {
        http::StatusCode::UNAUTHORIZED => Some(AuditAction::Authenticate),
        http::StatusCode::FORBIDDEN => Some(AuditAction::Access),
        _ => None,
    }
}

/// "reason (from <ip>)"
pub fn detail(reason: &str, remote: Option<IpAddr>) -> String {
    match remote {
        Some(ip) => format!("{reason} (from {ip})"),
        None => reason.to_string(),
    }
}

/// Wraps a gRPC service and audits its refused requests.
#[derive(Clone)]
pub struct AuditDenials<S> {
    inner: S,
    audit: AuditLog,
    token_store: TokenStore,
}

impl<S> AuditDenials<S> {
    pub fn new(inner: S, audit: AuditLog, token_store: TokenStore) -> Self {
        Self {
            inner,
            audit,
            token_store,
        }
    }
}

impl<S: NamedService> NamedService for AuditDenials<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, B, ResB> Service<http::Request<B>> for AuditDenials<S>
where
    S: Service<http::Request<B>, Response = http::Response<ResB>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
    ResB: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        // Only what attribution needs, taken before the request moves on.
        let path = req.uri().path().to_string();
        let authorization = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let tls = req
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .cloned();
        let remote = tls
            .as_ref()
            .and_then(|t| t.get_ref().remote_addr())
            .or_else(|| {
                req.extensions()
                    .get::<TcpConnectInfo>()
                    .and_then(|t| t.remote_addr())
            })
            .map(|a| a.ip());

        // The ready service handles this call; a fresh clone takes its place.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let audit = self.audit.clone();
        let token_store = self.token_store.clone();
        Box::pin(async move {
            let response = inner.call(req).await?;
            let status = tonic::Status::from_header_map(response.headers());
            if let Some(status) = status
                && let Some(action) = classify(status.code())
            {
                let certs = tls.as_ref().and_then(|t| t.peer_certs());
                let leaf = certs.as_ref().and_then(|c| c.first()).map(|c| c.as_ref());
                let actor = actor(&token_store, authorization.as_deref(), leaf);
                audit
                    .record(
                        &actor,
                        action,
                        &path,
                        &detail(status.message(), remote),
                        AuditOutcome::Denied,
                    )
                    .await;
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::rbac::Role;

    #[tokio::test]
    async fn actors_never_reveal_tokens() {
        let store = TokenStore::new();
        store.register("s3cret-admin", Role::Admin, "ci").await;
        let known = actor(&store, Some("Bearer s3cret-admin"), None);
        assert!(
            known.starts_with("token:") && known.contains("(ci)"),
            "{known}"
        );
        let unknown = actor(&store, Some("Bearer guess"), None);
        assert!(unknown.ends_with("(unknown)") && !unknown.contains("guess"));
        assert_eq!(actor(&store, None, None), "anonymous");
        assert_eq!(actor(&store, Some("Basic x"), None), "anonymous");
        assert_eq!(actor(&store, None, Some(b"not der")), "mtls:no-spiffe-id");
    }

    #[test]
    fn refusals_are_classified() {
        assert_eq!(
            classify(tonic::Code::Unauthenticated),
            Some(AuditAction::Authenticate)
        );
        assert_eq!(
            classify(tonic::Code::PermissionDenied),
            Some(AuditAction::Access)
        );
        assert_eq!(classify(tonic::Code::NotFound), None);
        assert_eq!(
            classify_http(http::StatusCode::FORBIDDEN),
            Some(AuditAction::Access)
        );
        assert_eq!(classify_http(http::StatusCode::OK), None);
        assert_eq!(
            detail("nope", Some("10.0.0.1".parse().unwrap())),
            "nope (from 10.0.0.1)"
        );
    }

    #[tokio::test]
    async fn denied_responses_are_audited_and_others_are_not() {
        use super::super::audit::AuditQuery;
        let audit = AuditLog::new();
        let tokens = TokenStore::new();
        tokens.register("viewer-token", Role::Viewer, "dash").await;
        let stub = tower::service_fn(|req: http::Request<()>| async move {
            let status = if req.uri().path().ends_with("/Apply") {
                tonic::Status::permission_denied("Viewer role does not have Deploy permission")
            } else {
                tonic::Status::not_found("no such node")
            };
            let mut response = http::Response::new(());
            status.add_header(response.headers_mut()).unwrap();
            Ok::<_, std::convert::Infallible>(response)
        });
        let mut service = AuditDenials::new(stub, audit.clone(), tokens);
        for path in ["/fleet.FleetControl/Apply", "/fleet.FleetControl/GetNode"] {
            let req = http::Request::builder()
                .uri(path)
                .header("authorization", "Bearer viewer-token")
                .body(())
                .unwrap();
            service.call(req).await.unwrap();
        }
        let entries = audit.query(&AuditQuery::default()).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].action, AuditAction::Access);
        assert_eq!(entries[0].resource, "/fleet.FleetControl/Apply");
        assert!(entries[0].actor.contains("(dash)"), "{}", entries[0].actor);
        assert!(!entries[0].actor.contains("viewer-token"));
        assert_eq!(entries[0].outcome, AuditOutcome::Denied);
    }
}
