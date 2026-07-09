use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::spiffe::workload_api::WorkloadManager;
use crate::spiffe::workload_attestor;
use crate::workload_proto::spiffe_workload_api_server::SpiffeWorkloadApi;
use crate::workload_proto::{
    JwtBundlesRequest, JwtBundlesResponse, Jwtsvid, JwtsvidClaims, JwtsvidRequest, JwtsvidResponse,
    ValidateJwtsvidRequest, ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse,
    X509svid, X509svidRequest, X509svidResponse,
};

/// SPIFFE Workload API service implementation.
///
/// Serves X.509-SVIDs and trust bundles to workloads over a Unix domain socket.
/// Identifies callers via Unix socket peer credentials (PID → service name).
pub struct WorkloadApiService {
    workload_mgr: Arc<WorkloadManager>,
    /// HMAC key for JWT-SVID signing (derived from fleet key).
    jwt_signing_key: Arc<ring::hmac::Key>,
}

impl WorkloadApiService {
    pub fn new(workload_mgr: Arc<WorkloadManager>, jwt_key_material: &[u8]) -> Self {
        let jwt_signing_key = Arc::new(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            jwt_key_material,
        ));
        Self {
            workload_mgr,
            jwt_signing_key,
        }
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
        request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        let req = request.into_inner();

        // Determine the SPIFFE ID: either from the request or from the caller's workload
        let spiffe_id = if req.spiffe_id.is_empty() {
            // No explicit SPIFFE ID — this is an error for now
            return Err(Status::invalid_argument(
                "spiffe_id is required in JWTSVIDRequest",
            ));
        } else {
            req.spiffe_id.clone()
        };

        if req.audience.is_empty() {
            return Err(Status::invalid_argument(
                "at least one audience is required",
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ttl = 3600u64; // 1 hour

        // Build JWT claims as JSON
        let aud_json: Vec<String> = req.audience.iter().map(|a| format!("\"{a}\"")).collect();
        let claims_json = format!(
            r#"{{"sub":"{}","aud":[{}],"iat":{},"exp":{}}}"#,
            spiffe_id,
            aud_json.join(","),
            now,
            now + ttl,
        );

        // Base64url encode header and payload
        let header = base64url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let payload = base64url_encode(claims_json.as_bytes());
        let signing_input = format!("{header}.{payload}");

        // Sign with HMAC-SHA256
        let tag = ring::hmac::sign(&self.jwt_signing_key, signing_input.as_bytes());
        let signature = base64url_encode(tag.as_ref());

        let jwt = format!("{signing_input}.{signature}");

        tracing::info!(spiffe_id = %spiffe_id, "JWT-SVID issued");

        Ok(Response::new(JwtsvidResponse {
            svids: vec![Jwtsvid {
                spiffe_id,
                svid: jwt,
            }],
        }))
    }

    async fn validate_jwtsvid(
        &self,
        request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        let req = request.into_inner();

        if req.svid.is_empty() {
            return Err(Status::invalid_argument("svid is required"));
        }

        // Split JWT into parts
        let parts: Vec<&str> = req.svid.split('.').collect();
        if parts.len() != 3 {
            return Err(Status::invalid_argument("invalid JWT format"));
        }

        // Verify signature
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        ring::hmac::verify(
            &self.jwt_signing_key,
            signing_input.as_bytes(),
            &base64url_decode(parts[2])
                .map_err(|_| Status::invalid_argument("invalid base64url in signature"))?,
        )
        .map_err(|_| Status::unauthenticated("invalid JWT signature"))?;

        // Decode payload
        let payload_bytes = base64url_decode(parts[1])
            .map_err(|_| Status::invalid_argument("invalid base64url in payload"))?;
        let payload_str = String::from_utf8(payload_bytes)
            .map_err(|_| Status::invalid_argument("invalid UTF-8 in payload"))?;

        // Parse claims (simple JSON parsing without a full serde dependency)
        let claims: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|_| Status::invalid_argument("invalid JSON in JWT payload"))?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64())
            && now > exp
        {
            return Err(Status::unauthenticated("JWT has expired"));
        }

        // Check audience
        if !req.audience.is_empty() {
            let token_aud = claims
                .get("aud")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !token_aud.iter().any(|a| a == &req.audience) {
                return Err(Status::unauthenticated("audience mismatch"));
            }
        }

        let spiffe_id = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // Build claims map for response
        let mut claims_map = std::collections::HashMap::new();
        if let Some(obj) = claims.as_object() {
            for (k, v) in obj {
                claims_map.insert(k.clone(), v.to_string().trim_matches('"').to_string());
            }
        }

        Ok(Response::new(ValidateJwtsvidResponse {
            spiffe_id,
            claims: Some(JwtsvidClaims { claims: claims_map }),
        }))
    }

    type FetchJWTBundlesStream = WorkloadStream<JwtBundlesResponse>;

    async fn fetch_jwt_bundles(
        &self,
        _request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        let (tx, rx) = mpsc::channel(4);
        let mgr = self.workload_mgr.clone();
        let key = self.jwt_signing_key.clone();

        tokio::spawn(async move {
            loop {
                let trust_domain = mgr
                    .trust_domain_str()
                    .await
                    .unwrap_or_else(|| "fleet.internal".to_string());

                // Build a minimal JWKS indicating the signing algorithm.
                // The actual symmetric key is not exposed in the bundle
                // (clients validate via the ValidateJWTSVID RPC instead).
                let _ = &key; // retain reference to keep task alive
                let jwks = r#"{"keys":[{"kty":"oct","alg":"HS256","kid":"fleet-jwt-key-1"}]}"#;

                let mut bundles = std::collections::HashMap::new();
                bundles.insert(trust_domain, jwks.as_bytes().to_vec());

                let response = JwtBundlesResponse { bundles };
                if tx.send(Ok(response)).await.is_err() {
                    break;
                }

                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Base64url encode without padding (per JWT/JWS spec RFC 7515).
fn base64url_encode(data: &[u8]) -> String {
    let mut encoded = String::new();
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut i = 0;
    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        encoded.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        encoded.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        encoded.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        encoded.push(TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let remaining = data.len() - i;
    if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        encoded.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        encoded.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        encoded.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
    } else if remaining == 1 {
        let n = (data[i] as u32) << 16;
        encoded.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        encoded.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
    }
    encoded
}

/// Base64url decode without padding.
fn base64url_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    fn decode_char(c: u8) -> Result<u32, &'static str> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err("invalid base64url character"),
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let n = (decode_char(bytes[i])? << 18)
            | (decode_char(bytes[i + 1])? << 12)
            | (decode_char(bytes[i + 2])? << 6)
            | decode_char(bytes[i + 3])?;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    let remaining = bytes.len() - i;
    if remaining == 3 {
        let n = (decode_char(bytes[i])? << 18)
            | (decode_char(bytes[i + 1])? << 12)
            | (decode_char(bytes[i + 2])? << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    } else if remaining == 2 {
        let n = (decode_char(bytes[i])? << 18) | (decode_char(bytes[i + 1])? << 12);
        out.push((n >> 16) as u8);
    }
    Ok(out)
}
