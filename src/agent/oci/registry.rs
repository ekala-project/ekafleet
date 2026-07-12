//! OCI Distribution Spec registry client.
//!
//! Provides manifest fetching and blob downloading from any OCI-compliant
//! registry, with automatic token-based authentication.

use std::sync::Arc;

use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::RwLock;

use super::auth::{BearerChallenge, Credentials, TokenResponse};
use super::digest::{Digest, DigestVerifier};
use super::manifest::{ACCEPT_MANIFESTS, ManifestKind};
use super::reference::ImageReference;

/// An OCI registry client that handles authentication and content verification.
pub struct RegistryClient {
    http: Client<hyper_util::client::legacy::connect::HttpConnector, http_body_util::Full<Bytes>>,
    credentials: Credentials,
    /// Cached bearer tokens keyed by scope string.
    tokens: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("manifest not found: {0}")]
    NotFound(String),
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
    #[error("response body error: {0}")]
    Body(String),
    #[error("registry returned HTTP {status}: {message}")]
    Status { status: u16, message: String },
}

/// Result of fetching a manifest, including the raw bytes for digest verification.
pub struct ManifestResponse {
    /// Parsed manifest (single or index).
    pub kind: ManifestKind,
    /// Raw manifest bytes (for computing digest).
    pub raw: Vec<u8>,
    /// Digest of the raw manifest content.
    pub digest: Digest,
    /// Content-Type returned by the registry.
    pub media_type: String,
}

/// Result of fetching a blob.
pub struct BlobResponse {
    /// Raw blob content.
    pub data: Vec<u8>,
    /// Verified digest of the content.
    pub digest: Digest,
}

impl RegistryClient {
    /// Create a new registry client with the given credentials.
    pub fn new(credentials: Credentials) -> Self {
        let http = Client::builder(TokioExecutor::new()).build_http();
        Self {
            http,
            credentials,
            tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Fetch a manifest (or image index) for the given image reference.
    pub async fn fetch_manifest(
        &self,
        image: &ImageReference,
    ) -> Result<ManifestResponse, RegistryError> {
        let reference = image.api_reference();
        let url = format!(
            "https://{}/v2/{}/manifests/{reference}",
            image.registry, image.repository
        );
        let scope = format!("repository:{}:pull", image.repository);

        let accept = ACCEPT_MANIFESTS.join(", ");
        let body = self.authenticated_get(&url, &scope, Some(&accept)).await?;

        let media_type = body.media_type.clone();
        let raw = body.data;
        let digest = Digest::from_bytes(&raw);

        // If the reference specified a digest, verify it matches.
        if let Some(expected) = &image.digest {
            if &digest != expected {
                return Err(RegistryError::DigestMismatch {
                    expected: expected.to_string(),
                    actual: digest.to_string(),
                });
            }
        }

        let kind = ManifestKind::from_json(&media_type, &raw)
            .map_err(|e| RegistryError::ManifestParse(e.to_string()))?;

        Ok(ManifestResponse {
            kind,
            raw,
            digest,
            media_type,
        })
    }

    /// Fetch a blob by digest (e.g. config or layer).
    pub async fn fetch_blob(
        &self,
        image: &ImageReference,
        expected_digest: &Digest,
    ) -> Result<BlobResponse, RegistryError> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            image.registry, image.repository, expected_digest
        );
        let scope = format!("repository:{}:pull", image.repository);

        let body = self.authenticated_get(&url, &scope, None).await?;

        // Verify digest
        let mut verifier = DigestVerifier::new(expected_digest.clone());
        verifier.update(&body.data);
        let digest = verifier
            .finish()
            .map_err(|e| RegistryError::DigestMismatch {
                expected: e.expected.to_string(),
                actual: e.computed.to_string(),
            })?;

        Ok(BlobResponse {
            data: body.data,
            digest,
        })
    }

    /// Check if a manifest exists (HEAD request). Returns the digest if found.
    pub async fn head_manifest(
        &self,
        image: &ImageReference,
    ) -> Result<Option<Digest>, RegistryError> {
        let reference = image.api_reference();
        let url = format!(
            "https://{}/v2/{}/manifests/{reference}",
            image.registry, image.repository
        );
        let scope = format!("repository:{}:pull", image.repository);

        let token = self.get_token(&image.registry, &scope).await?;

        let accept = ACCEPT_MANIFESTS.join(", ");
        let req = hyper::Request::builder()
            .method("HEAD")
            .uri(&url)
            .header("Accept", &accept);

        let req = if let Some(t) = &token {
            req.header("Authorization", format!("Bearer {t}"))
        } else {
            req
        };

        let req = req
            .body(http_body_util::Full::new(Bytes::new()))
            .map_err(|e| RegistryError::Http(e.to_string()))?;

        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| RegistryError::Http(e.to_string()))?;

        match resp.status().as_u16() {
            200 => {
                // Parse digest from Docker-Content-Digest header
                if let Some(dcd) = resp.headers().get("docker-content-digest") {
                    let digest: Digest = dcd
                        .to_str()
                        .map_err(|e| RegistryError::Http(e.to_string()))?
                        .parse()
                        .map_err(|e: super::digest::DigestError| {
                            RegistryError::Http(e.to_string())
                        })?;
                    Ok(Some(digest))
                } else {
                    // No digest header; we'd need a full GET to compute it
                    Ok(None)
                }
            }
            404 => Ok(None),
            status => Err(RegistryError::Status {
                status,
                message: "HEAD manifest failed".to_string(),
            }),
        }
    }

    /// Perform an authenticated GET request, handling 401 → token exchange.
    async fn authenticated_get(
        &self,
        url: &str,
        scope: &str,
        accept: Option<&str>,
    ) -> Result<AuthenticatedResponse, RegistryError> {
        // Try with cached token first
        let token = self.get_token_cached(scope).await;
        let resp = self.do_get(url, token.as_deref(), accept).await?;

        if resp.status == 401 {
            // Parse Www-Authenticate and exchange for a token
            let challenge = resp
                .www_authenticate
                .as_deref()
                .and_then(BearerChallenge::parse)
                .ok_or_else(|| {
                    RegistryError::Auth("missing or unparseable Www-Authenticate header".into())
                })?;

            let token = self.exchange_token(&challenge, Some(scope)).await?;

            // Cache the token
            self.tokens
                .write()
                .await
                .insert(scope.to_string(), token.clone());

            // Retry with new token
            let resp = self.do_get(url, Some(&token), accept).await?;

            if resp.status != 200 {
                return Err(RegistryError::Status {
                    status: resp.status,
                    message: String::from_utf8_lossy(&resp.data).into_owned(),
                });
            }
            Ok(resp)
        } else if resp.status == 200 {
            Ok(resp)
        } else if resp.status == 404 {
            Err(RegistryError::NotFound(url.to_string()))
        } else {
            Err(RegistryError::Status {
                status: resp.status,
                message: String::from_utf8_lossy(&resp.data).into_owned(),
            })
        }
    }

    async fn do_get(
        &self,
        url: &str,
        bearer_token: Option<&str>,
        accept: Option<&str>,
    ) -> Result<AuthenticatedResponse, RegistryError> {
        let mut builder = hyper::Request::builder().method("GET").uri(url);

        if let Some(accept) = accept {
            builder = builder.header("Accept", accept);
        }
        if let Some(token) = bearer_token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        } else if let Credentials::Basic { username, password } = &self.credentials {
            let encoded = base64_encode(&format!("{username}:{password}"));
            builder = builder.header("Authorization", format!("Basic {encoded}"));
        }

        let req = builder
            .body(http_body_util::Full::new(Bytes::new()))
            .map_err(|e| RegistryError::Http(e.to_string()))?;

        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| RegistryError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let media_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .map_err(|e| RegistryError::Body(e.to_string()))?
            .to_bytes()
            .to_vec();

        Ok(AuthenticatedResponse {
            status,
            data: body,
            www_authenticate: www_auth,
            media_type,
        })
    }

    /// Exchange credentials for a bearer token at the token endpoint.
    async fn exchange_token(
        &self,
        challenge: &BearerChallenge,
        scope: Option<&str>,
    ) -> Result<String, RegistryError> {
        let url = challenge.token_url(scope);

        let mut builder = hyper::Request::builder().method("GET").uri(&url);

        if let Credentials::Basic { username, password } = &self.credentials {
            let encoded = base64_encode(&format!("{username}:{password}"));
            builder = builder.header("Authorization", format!("Basic {encoded}"));
        }

        let req = builder
            .body(http_body_util::Full::new(Bytes::new()))
            .map_err(|e| RegistryError::Http(e.to_string()))?;

        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| RegistryError::Auth(format!("token exchange HTTP error: {e}")))?;

        if resp.status() != 200 {
            return Err(RegistryError::Auth(format!(
                "token endpoint returned HTTP {}",
                resp.status()
            )));
        }

        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .map_err(|e| RegistryError::Body(e.to_string()))?
            .to_bytes();

        let token_resp: TokenResponse = serde_json::from_slice(&body)
            .map_err(|e| RegistryError::Auth(format!("token response parse error: {e}")))?;

        Ok(token_resp.token)
    }

    /// Try to get a token from an initial unauthenticated request to the registry.
    async fn get_token(
        &self,
        registry: &str,
        scope: &str,
    ) -> Result<Option<String>, RegistryError> {
        // Check cache first
        if let Some(token) = self.get_token_cached(scope).await {
            return Ok(Some(token));
        }

        // Probe the registry to get the auth challenge
        let probe_url = format!("https://{registry}/v2/");
        let resp = self.do_get(&probe_url, None, None).await?;

        if resp.status == 200 {
            // No auth needed
            return Ok(None);
        }

        if resp.status == 401 {
            if let Some(challenge) = resp
                .www_authenticate
                .as_deref()
                .and_then(BearerChallenge::parse)
            {
                let token = self.exchange_token(&challenge, Some(scope)).await?;
                self.tokens
                    .write()
                    .await
                    .insert(scope.to_string(), token.clone());
                return Ok(Some(token));
            }
        }

        Ok(None)
    }

    async fn get_token_cached(&self, scope: &str) -> Option<String> {
        self.tokens.read().await.get(scope).cloned()
    }
}

struct AuthenticatedResponse {
    status: u16,
    data: Vec<u8>,
    www_authenticate: Option<String>,
    media_type: String,
}

/// Minimal base64 encoder (standard alphabet, with padding).
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let bytes = input.as_bytes();
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode("hello"), "aGVsbG8=");
        assert_eq!(base64_encode("user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_encode(""), "");
        assert_eq!(base64_encode("a"), "YQ==");
        assert_eq!(base64_encode("ab"), "YWI=");
        assert_eq!(base64_encode("abc"), "YWJj");
    }

    #[test]
    fn creates_with_anonymous() {
        let _client = RegistryClient::new(Credentials::Anonymous);
    }

    #[test]
    fn creates_with_basic() {
        let _client = RegistryClient::new(Credentials::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        });
    }
}
