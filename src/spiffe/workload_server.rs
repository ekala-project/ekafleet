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

/// SPIFFE Workload API service implementation.
///
/// Serves X.509-SVIDs and trust bundles to workloads over a Unix domain socket.
/// Identifies callers via Unix socket peer credentials (PID → service name).
pub struct WorkloadApiService {
    workload_mgr: Arc<WorkloadManager>,
}

impl WorkloadApiService {
    pub fn new(workload_mgr: Arc<WorkloadManager>) -> Self {
        Self { workload_mgr }
    }

    /// Extract the caller's PID from request metadata.
    fn extract_peer_pid<T>(request: &Request<T>) -> Option<u32> {
        request
            .metadata()
            .get("x-ekafleet-peer-pid")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
    }
}

type WorkloadStream<T> = Pin<Box<ReceiverStream<Result<T, Status>>>>;

#[tonic::async_trait]
impl SpiffeWorkloadApi for WorkloadApiService {
    type FetchX509SVIDStream = WorkloadStream<X509svidResponse>;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        // Identify the caller
        let pid = Self::extract_peer_pid(&request)
            .ok_or_else(|| Status::unauthenticated("unable to identify caller PID"))?;

        let service_name = workload_attestor::attest_pid(pid).await.ok_or_else(|| {
            Status::permission_denied(format!(
                "PID {pid} does not belong to any ekafleet-managed service"
            ))
        })?;

        tracing::info!(
            pid,
            service = %service_name,
            "Workload API: FetchX509SVID"
        );

        let (tx, rx) = mpsc::channel(4);
        let mgr = self.workload_mgr.clone();

        // Send current SVID immediately, then watch for renewals
        tokio::spawn(async move {
            loop {
                if let Some((cert_pem, key_pem, _chain_pem, _expires_at)) =
                    mgr.get_svid(&service_name).await
                {
                    let spiffe_id = mgr.spiffe_id(&service_name).await.unwrap_or_default();
                    let trust_bundle = mgr.trust_bundle().await.unwrap_or_default();

                    let response = X509svidResponse {
                        svids: vec![X509svid {
                            spiffe_id,
                            x509_svid: cert_pem.into_bytes(),
                            x509_svid_key: key_pem.into_bytes(),
                            bundle: trust_bundle.into_bytes(),
                        }],
                    };

                    if tx.send(Ok(response)).await.is_err() {
                        break;
                    }
                }

                // Wait before checking for renewal (poll interval)
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type FetchX509BundlesStream = WorkloadStream<X509BundlesResponse>;

    async fn fetch_x509_bundles(
        &self,
        _request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        let (tx, rx) = mpsc::channel(4);
        let mgr = self.workload_mgr.clone();

        tokio::spawn(async move {
            loop {
                if let Some(bundle_pem) = mgr.trust_bundle().await {
                    let trust_domain = mgr
                        .trust_domain_str()
                        .await
                        .unwrap_or_else(|| "fleet.internal".to_string());

                    let mut bundles = std::collections::HashMap::new();
                    bundles.insert(trust_domain, bundle_pem.into_bytes());

                    let response = X509BundlesResponse { bundles };

                    if tx.send(Ok(response)).await.is_err() {
                        break;
                    }
                }

                // Poll for bundle updates
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn fetch_jwtsvid(
        &self,
        _request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        Err(Status::unimplemented(
            "JWT-SVID support is not yet implemented",
        ))
    }

    async fn validate_jwtsvid(
        &self,
        _request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Err(Status::unimplemented(
            "JWT-SVID validation is not yet implemented",
        ))
    }

    type FetchJWTBundlesStream = WorkloadStream<JwtBundlesResponse>;

    async fn fetch_jwt_bundles(
        &self,
        _request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        Err(Status::unimplemented(
            "JWT bundle support is not yet implemented",
        ))
    }
}
