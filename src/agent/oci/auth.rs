//! OCI registry authentication.
//!
//! Implements the Docker v2 token-based authentication flow:
//!   1. Client hits registry API → gets 401 with `Www-Authenticate: Bearer realm=...`
//!   2. Client exchanges credentials at the token endpoint
//!   3. Client uses returned bearer token for subsequent requests

use std::collections::HashMap;

use serde::Deserialize;
use zeroize::Zeroizing;

/// Credentials for authenticating with an OCI registry.
#[derive(Clone, Default)]
pub enum Credentials {
    /// No authentication (anonymous access).
    #[default]
    Anonymous,
    /// HTTP Basic authentication (username + password/token).
    Basic {
        username: String,
        password: Zeroizing<String>,
    },
    /// An OAuth2 refresh token (`identitytoken` in a Docker config),
    /// exchanged at the registry's token endpoint.
    IdentityToken(Zeroizing<String>),
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::Basic { username, .. } => write!(f, "Basic({username})"),
            Self::IdentityToken(_) => f.write_str("IdentityToken"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("registry credentials are not a valid Docker config.json: {0}")]
    InvalidConfig(String),
}

/// Pick the credentials for `registry` from a Docker `config.json` (as
/// written by `docker login`): `auths` keyed by registry host, each with
/// `auth` (base64 `user:password`), `username`/`password`, or
/// `identitytoken`. Registries without an entry are accessed anonymously.
pub fn docker_config_credentials(json: &[u8], registry: &str) -> Result<Credentials, AuthError> {
    use base64::Engine;

    #[derive(Deserialize)]
    struct Config {
        #[serde(default)]
        auths: HashMap<String, Entry>,
    }
    #[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    struct Entry {
        #[serde(default)]
        auth: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        identitytoken: Option<String>,
    }

    let config: Config =
        serde_json::from_slice(json).map_err(|e| AuthError::InvalidConfig(e.to_string()))?;
    // Docker Hub's entry is keyed by its legacy index URL.
    let hub = matches!(
        registry,
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
    );
    let entry = config.auths.iter().find_map(|(key, entry)| {
        let host = key
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default();
        let matches = host == registry
            || (hub
                && matches!(
                    host,
                    "docker.io" | "index.docker.io" | "registry-1.docker.io"
                ));
        matches.then_some(entry)
    });
    let Some(entry) = entry else {
        return Ok(Credentials::Anonymous);
    };
    if let Some(token) = &entry.identitytoken
        && !token.is_empty()
    {
        return Ok(Credentials::IdentityToken(Zeroizing::new(token.clone())));
    }
    if let Some(auth) = &entry.auth
        && !auth.is_empty()
    {
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(auth.trim())
                .map_err(|e| AuthError::InvalidConfig(format!("auth for {registry}: {e}")))?,
        );
        let decoded = std::str::from_utf8(&decoded)
            .map_err(|_| AuthError::InvalidConfig(format!("auth for {registry} is not UTF-8")))?;
        let (username, password) = decoded.split_once(':').ok_or_else(|| {
            AuthError::InvalidConfig(format!("auth for {registry} is not user:password"))
        })?;
        return Ok(Credentials::Basic {
            username: username.to_string(),
            password: Zeroizing::new(password.to_string()),
        });
    }
    match (&entry.username, &entry.password) {
        (Some(username), Some(password)) => Ok(Credentials::Basic {
            username: username.clone(),
            password: Zeroizing::new(password.clone()),
        }),
        _ => Err(AuthError::InvalidConfig(format!(
            "entry for {registry} has no auth, username/password or identitytoken"
        ))),
    }
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
    fn docker_config_entries_are_matched_by_host() {
        let json = br#"{"auths": {
            "https://index.docker.io/v1/": {"auth": "aHViOnNlY3JldA=="},
            "registry.internal:5000": {"username": "u", "password": "p"},
            "acr.example.com": {"identitytoken": "refresh"}
        }}"#;
        let basic = |c: Credentials| match c {
            Credentials::Basic { username, password } => (username, password.to_string()),
            other => panic!("expected basic credentials, got {other:?}"),
        };
        assert_eq!(
            basic(docker_config_credentials(json, "docker.io").unwrap()),
            ("hub".into(), "secret".into())
        );
        assert_eq!(
            basic(docker_config_credentials(json, "registry.internal:5000").unwrap()),
            ("u".into(), "p".into())
        );
        assert!(matches!(
            docker_config_credentials(json, "acr.example.com").unwrap(),
            Credentials::IdentityToken(t) if t.as_str() == "refresh"
        ));
        assert!(matches!(
            docker_config_credentials(json, "ghcr.io").unwrap(),
            Credentials::Anonymous
        ));
        assert!(docker_config_credentials(b"user:pass", "ghcr.io").is_err());
        // Debug output never shows the secret.
        let shown = format!(
            "{:?}",
            docker_config_credentials(json, "docker.io").unwrap()
        );
        assert!(!shown.contains("secret"), "{shown}");
    }

    #[test]
    fn anonymous_is_default() {
        assert!(matches!(Credentials::default(), Credentials::Anonymous));
    }
}
