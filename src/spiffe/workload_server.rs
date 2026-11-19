use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::spiffe::jwt_broker::JwtBrokerError;
use crate::spiffe::workload_api::WorkloadManager;
use crate::spiffe::workload_attestor;
use crate::workload_proto::spiffe_workload_api_server::SpiffeWorkloadApi;
use crate::workload_proto::{
    JwtBundlesRequest, JwtBundlesResponse, Jwtsvid, JwtsvidRequest, JwtsvidResponse,
    ValidateJwtsvidRequest, ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse,
    X509svid, X509svidRequest, X509svidResponse,
};

/// Metadata header every Workload API call must carry (SPIFFE Workload API
/// spec §5.1). It guards against a remote attacker tricking a local client
/// (e.g. through SSRF) into calling the API.
pub const SECURITY_HEADER: &str = "workload.spiffe.io";

/// SPIFFE Workload API service implementation.
///
/// Serves X.509-SVIDs and trust bundles to workloads over a Unix domain
/// socket. Every call is attested: the caller's PID comes from the socket
/// peer credentials and is mapped to an ekafleet service via its cgroup.
pub struct WorkloadApiService {
    workload_mgr: Arc<WorkloadManager>,
}

impl WorkloadApiService {
    pub fn new(workload_mgr: Arc<WorkloadManager>) -> Self {
        Self { workload_mgr }
    }

    /// Extract the caller's PID from the kernel-provided Unix socket peer
    /// credentials (`SO_PEERCRED`).
    ///
    /// The PID must come from the connection itself, never from request
    /// metadata: a client controls its own headers and could otherwise claim
    /// the PID of any other workload and be issued that workload's SVID.
    fn caller_pid<T>(request: &Request<T>) -> Option<u32> {
        request
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            .and_then(|info| info.peer_cred)
            .and_then(|cred| cred.pid())
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|&pid| pid > 0)
    }

    /// Check the security header, then attest the calling workload: resolve
    /// its PID from the socket peer credentials and map it to an ekafleet
    /// service via its cgroup.
    #[allow(clippy::result_large_err)]
    async fn attest_caller<T>(request: &Request<T>) -> Result<String, Status> {
        let header_ok = request
            .metadata()
            .get(SECURITY_HEADER)
            .and_then(|v| v.to_str().ok())
            == Some("true");
        if !header_ok {
            return Err(Status::invalid_argument(
                "security header missing from request",
            ));
        }
        let pid = Self::caller_pid(request).ok_or_else(|| {
            Status::unauthenticated("unable to identify caller from socket peer credentials")
        })?;
        workload_attestor::attest_pid(pid).await.ok_or_else(|| {
            Status::permission_denied(format!(
                "PID {pid} does not belong to any ekafleet-managed service"
            ))
        })
    }
}

/// Trust domain ID used as the key of bundle maps (`spiffe://<domain>`).
fn trust_domain_id(domain: &str) -> String {
    format!("spiffe://{domain}")
}

/// Decode every certificate in `pem` to DER.
fn pem_certs_der(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .map(|c| c.map(|c| c.to_vec()).map_err(|e| e.to_string()))
        .collect()
}

/// Decode a PKCS#8 private key PEM to DER.
fn pem_pkcs8_der(pem: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    match rustls_pemfile::private_key(&mut reader) {
        Ok(Some(rustls_pki_types::PrivateKeyDer::Pkcs8(key))) => {
            Ok(zeroize::Zeroizing::new(key.secret_pkcs8_der().to_vec()))
        }
        Ok(Some(_)) => Err("SVID key is not PKCS#8".into()),
        Ok(None) => Err("no private key in SVID key PEM".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// DER bundles of federated trust domains, keyed by trust domain ID.
/// A bundle that does not parse is left out rather than failing the
/// response for the local domain.
async fn federated_x509(mgr: &WorkloadManager) -> HashMap<String, Vec<u8>> {
    let mut bundles = HashMap::new();
    for (domain, bundle) in mgr.federated_bundles().await {
        match pem_certs_der(&bundle.x509_pem) {
            Ok(certs) if !certs.is_empty() => {
                bundles.insert(trust_domain_id(&domain), certs.concat());
            }
            Ok(_) => tracing::warn!(trust_domain = %domain, "Federated bundle has no certificates"),
            Err(e) => {
                tracing::warn!(trust_domain = %domain, error = %e, "Federated bundle does not parse")
            }
        }
    }
    bundles
}

/// Build the X509SVIDResponse for `service`, or `None` until it has both an
/// SVID and a trust bundle.
async fn x509_svid_response(
    mgr: &WorkloadManager,
    service: &str,
) -> Result<Option<X509svidResponse>, String> {
    let (Some(svid), Some(bundle_pem)) = (mgr.get_svid(service).await, mgr.trust_bundle().await)
    else {
        return Ok(None);
    };
    let bundle = pem_certs_der(&bundle_pem)?;
    // Leaf first, then any chain certificates that are not trust anchors.
    let mut chain = pem_certs_der(&svid.cert_pem)?;
    if chain.is_empty() {
        return Err("SVID certificate PEM contains no certificate".into());
    }
    chain.truncate(1);
    chain.extend(
        pem_certs_der(&svid.chain_pem)?
            .into_iter()
            .filter(|c| !bundle.contains(c)),
    );
    let key = pem_pkcs8_der(&svid.key_pem)?;
    Ok(Some(X509svidResponse {
        svids: vec![X509svid {
            spiffe_id: svid.spiffe_id,
            x509_svid: chain.concat(),
            x509_svid_key: key.to_vec(),
            bundle: bundle.concat(),
            hint: String::new(),
        }],
        crl: vec![],
        federated_bundles: federated_x509(mgr).await,
    }))
}

async fn x509_bundles_response(
    mgr: &WorkloadManager,
) -> Result<Option<X509BundlesResponse>, String> {
    let Some(bundle_pem) = mgr.trust_bundle().await else {
        return Ok(None);
    };
    let domain = mgr.trust_domain_str().await.unwrap_or_default();
    let bundle = pem_certs_der(&bundle_pem)?.concat();
    let mut bundles = federated_x509(mgr).await;
    bundles.insert(trust_domain_id(&domain), bundle);
    Ok(Some(X509BundlesResponse {
        crl: vec![],
        bundles,
    }))
}

async fn jwt_bundles_response(mgr: &WorkloadManager) -> Result<Option<JwtBundlesResponse>, String> {
    let Some(jwks) = mgr.jwt_bundle().await else {
        return Ok(None);
    };
    let domain = mgr.trust_domain_str().await.unwrap_or_default();
    let mut bundles: HashMap<String, Vec<u8>> = mgr
        .federated_bundles()
        .await
        .into_iter()
        .filter(|(_, b)| !b.jwks.is_empty())
        .map(|(d, b)| (trust_domain_id(&d), b.jwks.into_bytes()))
        .collect();
    bundles.insert(trust_domain_id(&domain), jwks.into_bytes());
    Ok(Some(JwtBundlesResponse { bundles }))
}

/// Convert JSON to a protobuf `Value` (for `ValidateJWTSVIDResponse.claims`).
fn json_to_prost(value: serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(b),
        serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or_default()),
        serde_json::Value::String(s) => Kind::StringValue(s),
        serde_json::Value::Array(list) => Kind::ListValue(prost_types::ListValue {
            values: list.into_iter().map(json_to_prost).collect(),
        }),
        serde_json::Value::Object(map) => Kind::StructValue(json_object_to_struct(map)),
    };
    prost_types::Value { kind: Some(kind) }
}

fn json_object_to_struct(map: serde_json::Map<String, serde_json::Value>) -> prost_types::Struct {
    prost_types::Struct {
        fields: map
            .into_iter()
            .map(|(k, v)| (k, json_to_prost(v)))
            .collect(),
    }
}

/// Validate a JWT-SVID against the local JWT bundle (`ValidateJWTSVID`).
#[allow(clippy::result_large_err)]
async fn validate_jwt_svid(
    mgr: &WorkloadManager,
    audience: &str,
    token: &str,
) -> Result<ValidateJwtsvidResponse, Status> {
    if audience.is_empty() {
        return Err(Status::invalid_argument("audience must be specified"));
    }
    if token.is_empty() {
        return Err(Status::invalid_argument("svid must be specified"));
    }
    let bundle = mgr
        .jwt_bundle()
        .await
        .ok_or_else(|| Status::unavailable("no JWT bundle received from the server yet"))?;
    let domain = mgr.trust_domain_str().await.unwrap_or_default();
    let verified = crate::ca::jwt::verify_jwt_svid(token, &bundle, &domain, audience)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    Ok(ValidateJwtsvidResponse {
        spiffe_id: verified.spiffe_id,
        claims: Some(json_object_to_struct(verified.claims)),
    })
}

type WorkloadStream<T> = Pin<Box<ReceiverStream<Result<T, Status>>>>;

/// Stream `build()` to the client: once as soon as it yields a value, then
/// again on every change notification whose result differs from the last
/// one sent. Ends when the client disconnects or a build fails.
fn spawn_change_stream<T, F, Fut>(mgr: Arc<WorkloadManager>, build: F) -> WorkloadStream<T>
where
    T: PartialEq + Clone + Send + 'static,
    F: Fn(Arc<WorkloadManager>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Option<T>, String>> + Send,
{
    let (tx, rx) = mpsc::channel(4);
    let mut changes = mgr.subscribe();
    tokio::spawn(async move {
        let mut last: Option<T> = None;
        loop {
            changes.mark_unchanged();
            match build(mgr.clone()).await {
                Ok(Some(resp)) if last.as_ref() != Some(&resp) => {
                    if tx.send(Ok(resp.clone())).await.is_err() {
                        return;
                    }
                    last = Some(resp);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Workload API: failed to build response");
                    let _ = tx.send(Err(Status::internal(e))).await;
                    return;
                }
            }
            tokio::select! {
                _ = tx.closed() => return,
                changed = changes.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Box::pin(ReceiverStream::new(rx))
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for WorkloadApiService {
    type FetchX509SVIDStream = WorkloadStream<X509svidResponse>;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let service_name = Self::attest_caller(&request).await?;
        tracing::info!(service = %service_name, "Workload API: FetchX509SVID");

        let stream = spawn_change_stream(self.workload_mgr.clone(), move |mgr| {
            let service = service_name.clone();
            async move { x509_svid_response(&mgr, &service).await }
        });
        Ok(Response::new(stream))
    }

    type FetchX509BundlesStream = WorkloadStream<X509BundlesResponse>;

    async fn fetch_x509_bundles(
        &self,
        request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        Self::attest_caller(&request).await?;
        let stream = spawn_change_stream(self.workload_mgr.clone(), |mgr| async move {
            x509_bundles_response(&mgr).await
        });
        Ok(Response::new(stream))
    }

    async fn fetch_jwtsvid(
        &self,
        request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        let service_name = Self::attest_caller(&request).await?;
        let req = request.into_inner();
        if req.audience.is_empty() {
            return Err(Status::invalid_argument("audience must be specified"));
        }
        let domain = self
            .workload_mgr
            .trust_domain_str()
            .await
            .unwrap_or_default();
        let spiffe_id = crate::ca::SvidSubject::Service(service_name.clone()).spiffe_id(&domain);
        // A workload may only ask for its own identity.
        if !req.spiffe_id.is_empty() && req.spiffe_id != spiffe_id {
            return Err(Status::permission_denied(format!(
                "caller is {spiffe_id}, not {}",
                req.spiffe_id
            )));
        }
        tracing::info!(service = %service_name, audience = ?req.audience, "Workload API: FetchJWTSVID");

        let token = self
            .workload_mgr
            .jwt_broker()
            .fetch(&service_name, &req.audience)
            .await
            .map_err(|e| match e {
                JwtBrokerError::Refused(msg) => Status::permission_denied(msg),
                other => Status::unavailable(other.to_string()),
            })?;
        Ok(Response::new(JwtsvidResponse {
            svids: vec![Jwtsvid {
                spiffe_id,
                svid: token,
                hint: String::new(),
            }],
        }))
    }

    async fn validate_jwtsvid(
        &self,
        request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Self::attest_caller(&request).await?;
        let req = request.into_inner();
        validate_jwt_svid(&self.workload_mgr, &req.audience, &req.svid)
            .await
            .map(Response::new)
    }

    type FetchJWTBundlesStream = WorkloadStream<JwtBundlesResponse>;

    async fn fetch_jwt_bundles(
        &self,
        request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        Self::attest_caller(&request).await?;
        let stream = spawn_change_stream(self.workload_mgr.clone(), |mgr| async move {
            jwt_bundles_response(&mgr).await
        });
        Ok(Response::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spiffe::workload_api::FederatedBundle;

    /// A real CA chain and an SVID issued from a CSR, as the agent holds them.
    async fn issued_svid(mgr: &WorkloadManager) {
        let ca = crate::ca::root::RootCa::new("test.internal");
        ca.initialize(None, None).await.unwrap();
        let csr = crate::ca::csr::generate_service_csr("test.internal", "web").unwrap();
        let (cert, chain, expires_at) = ca
            .sign_csr(
                &csr.csr_der,
                &crate::ca::SvidSubject::Service("web".into()),
                None,
            )
            .await
            .unwrap();
        let root = ca.root_certificate_pem().await.unwrap();
        mgr.set_trust_bundle(&root).await.unwrap();
        mgr.install_svid_split(
            "web",
            std::str::from_utf8(&cert).unwrap(),
            &csr.keypair.serialize_pem(),
            std::str::from_utf8(&chain).unwrap(),
            expires_at,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn x509_svid_response_is_der_leaf_then_intermediate() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");
        assert!(x509_svid_response(&mgr, "web").await.unwrap().is_none());
        issued_svid(&mgr).await;

        let resp = x509_svid_response(&mgr, "web").await.unwrap().unwrap();
        let svid = &resp.svids[0];
        assert_eq!(svid.spiffe_id, "spiffe://test.internal/service/web");

        // x509_svid: leaf followed by the intermediate (not the root).
        let (rest, leaf) = x509_parser::parse_x509_certificate(&svid.x509_svid).unwrap();
        let (rest, intermediate) = x509_parser::parse_x509_certificate(rest).unwrap();
        assert!(rest.is_empty());
        assert!(!leaf.is_ca());
        assert!(intermediate.is_ca());
        assert_eq!(leaf.issuer(), intermediate.subject());

        // bundle: the root alone, DER.
        let (rest, root) = x509_parser::parse_x509_certificate(&svid.bundle).unwrap();
        assert!(rest.is_empty());
        assert_eq!(intermediate.issuer(), root.subject());

        // key: PKCS#8 DER matching the leaf.
        let key = rcgen::KeyPair::try_from(svid.x509_svid_key.as_slice()).unwrap();
        assert_eq!(
            leaf.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );
    }

    #[tokio::test]
    async fn x509_bundles_keyed_by_trust_domain_id() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");
        assert!(x509_bundles_response(&mgr).await.unwrap().is_none());
        issued_svid(&mgr).await;
        let resp = x509_bundles_response(&mgr).await.unwrap().unwrap();
        let bundle = resp.bundles.get("spiffe://test.internal").unwrap();
        x509_parser::parse_x509_certificate(bundle).unwrap();
    }

    #[tokio::test]
    async fn federated_bundles_are_served_alongside_the_local_one() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");
        issued_svid(&mgr).await;
        let peer = rcgen::generate_simple_self_signed(vec!["peer".into()]).unwrap();
        mgr.set_federated_bundles(
            [
                (
                    "peer.test".to_string(),
                    FederatedBundle {
                        x509_pem: peer.cert.pem(),
                        jwks: r#"{"keys":[]}"#.into(),
                    },
                ),
                (
                    "broken.test".to_string(),
                    FederatedBundle {
                        x509_pem: "junk".into(),
                        jwks: String::new(),
                    },
                ),
            ]
            .into(),
        )
        .await;

        let bundles = x509_bundles_response(&mgr).await.unwrap().unwrap().bundles;
        let mut keys: Vec<_> = bundles.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["spiffe://peer.test", "spiffe://test.internal"]);
        assert_eq!(bundles["spiffe://peer.test"], peer.cert.der().to_vec());

        let svid = x509_svid_response(&mgr, "web").await.unwrap().unwrap();
        assert_eq!(
            svid.federated_bundles.keys().collect::<Vec<_>>(),
            ["spiffe://peer.test"]
        );

        mgr.set_jwt_bundle(r#"{"keys":[1]}"#).await;
        let jwt = jwt_bundles_response(&mgr).await.unwrap().unwrap().bundles;
        assert_eq!(jwt["spiffe://peer.test"], br#"{"keys":[]}"#);
        assert_eq!(jwt.len(), 2);
    }

    #[tokio::test]
    async fn jwt_bundle_and_validation_use_the_pushed_jwks() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = WorkloadManager::new(dir.path(), "test.internal");
        let (signer, _) = crate::ca::jwt::JwtSigner::generate().unwrap();
        let (token, _) = signer
            .sign(
                "spiffe://test.internal/service/web",
                &["db".to_string()],
                crate::ca::jwt::JWT_SVID_TTL,
            )
            .unwrap();

        assert!(jwt_bundles_response(&mgr).await.unwrap().is_none());
        assert_eq!(
            validate_jwt_svid(&mgr, "db", &token)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );

        mgr.set_jwt_bundle(&signer.jwks()).await;
        let bundles = jwt_bundles_response(&mgr).await.unwrap().unwrap();
        assert_eq!(
            bundles.bundles["spiffe://test.internal"],
            signer.jwks().into_bytes()
        );

        let resp = validate_jwt_svid(&mgr, "db", &token).await.unwrap();
        assert_eq!(resp.spiffe_id, "spiffe://test.internal/service/web");
        let claims = resp.claims.unwrap();
        assert_eq!(
            claims.fields["sub"].kind,
            Some(prost_types::value::Kind::StringValue(
                "spiffe://test.internal/service/web".into()
            ))
        );

        for (aud, tok) in [("other", token.as_str()), ("", token.as_str()), ("db", "")] {
            assert_eq!(
                validate_jwt_svid(&mgr, aud, tok).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
    }
}
