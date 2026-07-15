//! OCI registry authentication.
//!
//! Implements the Docker v2 token-based authentication flow:
//!   1. Client hits registry API → gets 401 with `Www-Authenticate: Bearer realm=...`
//!   2. Client exchanges credentials at the token endpoint
//!   3. Client uses returned bearer token for subsequent requests

use std::collections::HashMap;

use serde::Deserialize;

/// Credentials for authenticating with an OCI registry.
#[derive(Debug, Clone, Default)]
pub enum Credentials {
    /// No authentication (anonymous access).
    #[default]
    Anonymous,
    /// HTTP Basic authentication (username + password/token).
    Basic { username: String, password: String },
}

/// Parsed `Www-Authenticate: Bearer` challenge from a 401 response.
#[derive(Debug, Clone)]
pub struct BearerChallenge {
    /// Token endpoint URL.
    pub realm: String,
    /// Registry service identifier.
    pub service: Option<String>,
    /// Access scope (e.g. `repository:library/alpine:pull`).
    pub scope: Option<String>,
}

impl BearerChallenge {
    /// Parse the `Www-Authenticate` header value.
    ///
    /// Expected format: `Bearer realm="...",service="...",scope="..."`
    pub fn parse(header: &str) -> Option<Self> {
        let rest = header.strip_prefix("Bearer ")?;
        let params = parse_params(rest);

        let realm = params.get("realm")?.to_string();
        let service = params.get("service").map(|s| s.to_string());
        let scope = params.get("scope").map(|s| s.to_string());

        Some(Self {
            realm,
            service,
            scope,
        })
    }

    /// Build the token request URL with query parameters.
    pub fn token_url(&self, scope_override: Option<&str>) -> String {
        let mut url = self.realm.clone();
        let mut sep = if url.contains('?') { '&' } else { '?' };

        if let Some(svc) = &self.service {
            url.push(sep);
            url.push_str("service=");
            url.push_str(svc);
            sep = '&';
        }

        let scope = scope_override.or(self.scope.as_deref());
        if let Some(s) = scope {
            url.push(sep);
            url.push_str("scope=");
            url.push_str(s);
        }

        url
    }
}

/// Response from a token endpoint.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Bearer token (or `access_token` in older implementations).
    #[serde(alias = "access_token")]
    pub token: String,
}

/// Parse `key="value",key2="value2"` parameter strings.
fn parse_params(s: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let mut rest = s;

    while !rest.is_empty() {
        rest = rest.trim_start_matches([',', ' ']);
        let Some(eq_pos) = rest.find('=') else {
            break;
        };
        let key = rest[..eq_pos].trim();
        rest = &rest[eq_pos + 1..];

        let value = if rest.starts_with('"') {
            rest = &rest[1..];
            let end = rest.find('"').unwrap_or(rest.len());
            let val = &rest[..end];
            rest = &rest[(end + 1).min(rest.len())..];
            val
        } else {
            let end = rest.find([',', ' ']).unwrap_or(rest.len());
            let val = &rest[..end];
            rest = &rest[end..];
            val
        };

        params.insert(key.to_string(), value.to_string());
    }

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bearer_challenge() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        let challenge = BearerChallenge::parse(header).unwrap();
        assert_eq!(challenge.realm, "https://auth.docker.io/token");
        assert_eq!(challenge.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:library/alpine:pull")
        );
    }

    #[test]
    fn parse_minimal_challenge() {
        let header = r#"Bearer realm="https://ghcr.io/token""#;
        let challenge = BearerChallenge::parse(header).unwrap();
        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(challenge.service, None);
    }

    #[test]
    fn non_bearer_returns_none() {
        assert!(BearerChallenge::parse("Basic realm=\"foo\"").is_none());
    }

    #[test]
    fn token_url_with_all_params() {
        let challenge = BearerChallenge {
            realm: "https://auth.example.com/token".to_string(),
            service: Some("registry.example.com".to_string()),
            scope: Some("repository:myorg/myapp:pull".to_string()),
        };
        let url = challenge.token_url(None);
        assert!(url.contains("service=registry.example.com"));
        assert!(url.contains("scope=repository:myorg/myapp:pull"));
    }

    #[test]
    fn token_url_scope_override() {
        let challenge = BearerChallenge {
            realm: "https://auth.example.com/token".to_string(),
            service: None,
            scope: Some("repository:old:pull".to_string()),
        };
        let url = challenge.token_url(Some("repository:new:pull"));
        assert!(url.contains("scope=repository:new:pull"));
        assert!(!url.contains("scope=repository:old:pull"));
    }

    #[test]
    fn parse_params_basic() {
        let params = parse_params(r#"realm="https://example.com",service="svc""#);
        assert_eq!(params.get("realm").unwrap(), "https://example.com");
        assert_eq!(params.get("service").unwrap(), "svc");
    }

    #[test]
    fn anonymous_is_default() {
        assert!(matches!(Credentials::default(), Credentials::Anonymous));
    }
}
