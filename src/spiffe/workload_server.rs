use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::spiffe::workload_api::WorkloadManager;
use crate::spiffe::workload_attestor;
use crate::workload_proto::spiffe_workload_api_server::SpiffeWorkloadApi;
use crate::workload_proto::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svid, X509svidRequest,
    X509svidResponse,
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
        federated_bundles: Default::default(),
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
    Ok(Some(X509BundlesResponse {
        crl: vec![],
        bundles: [(trust_domain_id(&domain), bundle)].into(),
    }))
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
        Self::attest_caller(&request).await?;
        Err(Status::unimplemented("JWT-SVIDs are not supported"))
    }

    async fn validate_jwtsvid(
        &self,
        request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Self::attest_caller(&request).await?;
        Err(Status::unimplemented("JWT-SVIDs are not supported"))
    }

    type FetchJWTBundlesStream = WorkloadStream<JwtBundlesResponse>;

    async fn fetch_jwt_bundles(
        &self,
        request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        Self::attest_caller(&request).await?;
        Err(Status::unimplemented("JWT-SVIDs are not supported"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
