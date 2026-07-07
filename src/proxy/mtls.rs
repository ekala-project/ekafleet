use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Validates SPIFFE peer identities against service identity contracts.
///
/// When a service makes a request through the mesh proxy, the proxy
/// extracts the caller's SPIFFE ID from the client certificate and
/// checks it against the target service's `allowedCallers` list.
///
/// This enforces the service-to-service authorization policy defined
/// in the fleet configuration's `identity` block.
#[derive(Clone)]
pub struct SpiffeAuthorizer {
    inner: Arc<RwLock<AuthzState>>,
}

struct AuthzState {
    /// trust_domain for SPIFFE ID construction
    trust_domain: String,
    /// target_service → list of allowed caller SPIFFE IDs
    policies: HashMap<String, Vec<String>>,
}

impl SpiffeAuthorizer {
    pub fn new(trust_domain: &str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AuthzState {
                trust_domain: trust_domain.to_string(),
                policies: HashMap::new(),
            })),
        }
    }

    /// Update authorization policies from service identity contracts.
    ///
    /// For each service, `allowed_callers` is the list of service names
    /// that are permitted to call it. These are converted to SPIFFE IDs
    /// for matching against peer certificates.
    pub async fn update_policies(&self, service_policies: &HashMap<String, Vec<String>>) {
        let mut state = self.inner.write().await;
        state.policies.clear();

        for (target_service, allowed_callers) in service_policies {
            let spiffe_callers: Vec<String> = allowed_callers
                .iter()
                .map(|caller| format!("spiffe://{}/service/{}", state.trust_domain, caller))
                .collect();

            state
                .policies
                .insert(target_service.clone(), spiffe_callers);
        }

        tracing::info!(
            services = state.policies.len(),
            "SPIFFE authorization policies updated"
        );
    }

    /// Check if a caller with the given SPIFFE ID is authorized to
    /// access the target service.
    ///
    /// Returns `Ok(())` if authorized, `Err` with reason if denied.
    pub async fn authorize(
        &self,
        caller_spiffe_id: &str,
        target_service: &str,
    ) -> Result<(), AuthzError> {
        let state = self.inner.read().await;

        let allowed = match state.policies.get(target_service) {
            Some(callers) => callers,
            None => {
                // No policy defined — deny by default
                return Err(AuthzError::NoPolicyDefined {
                    target: target_service.to_string(),
                });
            }
        };

        // Empty allowed list means no callers are permitted
        if allowed.is_empty() {
            return Err(AuthzError::Denied {
                caller: caller_spiffe_id.to_string(),
                target: target_service.to_string(),
            });
        }

        if allowed.contains(&caller_spiffe_id.to_string()) {
            Ok(())
        } else {
            Err(AuthzError::Denied {
                caller: caller_spiffe_id.to_string(),
                target: target_service.to_string(),
            })
        }
    }

    /// Extract a SPIFFE ID from a PEM certificate's SAN URI.
    pub fn extract_spiffe_id_from_pem(cert_pem: &str) -> Option<String> {
        let cert_start = cert_pem.find("-----BEGIN CERTIFICATE-----")?;
        let cert_end =
            cert_pem.find("-----END CERTIFICATE-----")? + "-----END CERTIFICATE-----".len();
        let pem_block = &cert_pem[cert_start..cert_end];

        let mut reader = std::io::BufReader::new(pem_block.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let der = certs.first()?;

        Self::extract_spiffe_id_from_der(der)
    }

    /// Extract a SPIFFE ID from a DER-encoded certificate's SAN URI.
    pub fn extract_spiffe_id_from_der(der: &[u8]) -> Option<String> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;

        // Look for URI SANs starting with "spiffe://"
        for ext in cert.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::URI(uri) = name
                        && uri.starts_with("spiffe://")
                    {
                        return Some(uri.to_string());
                    }
                }
            }
        }

        None
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("no SPIFFE authorization policy defined for service '{target}'")]
    NoPolicyDefined { target: String },
    #[error("caller '{caller}' is not authorized to access service '{target}'")]
    Denied { caller: String, target: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authorized_caller_allowed() {
        let authz = SpiffeAuthorizer::new("fleet.internal");
        let mut policies = HashMap::new();
        policies.insert(
            "backend".to_string(),
            vec!["frontend".to_string(), "api-gw".to_string()],
        );
        authz.update_policies(&policies).await;

        let result = authz
            .authorize("spiffe://fleet.internal/service/frontend", "backend")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn unauthorized_caller_denied() {
        let authz = SpiffeAuthorizer::new("fleet.internal");
        let mut policies = HashMap::new();
        policies.insert("backend".to_string(), vec!["frontend".to_string()]);
        authz.update_policies(&policies).await;

        let result = authz
            .authorize("spiffe://fleet.internal/service/malicious", "backend")
            .await;
        assert!(matches!(result, Err(AuthzError::Denied { .. })));
    }

    #[tokio::test]
    async fn unknown_target_denied() {
        let authz = SpiffeAuthorizer::new("fleet.internal");
        let policies = HashMap::new();
        authz.update_policies(&policies).await;

        let result = authz
            .authorize("spiffe://fleet.internal/service/anyone", "nonexistent")
            .await;
        assert!(matches!(result, Err(AuthzError::NoPolicyDefined { .. })));
    }

    #[tokio::test]
    async fn empty_allowed_callers_denies_all() {
        let authz = SpiffeAuthorizer::new("fleet.internal");
        let mut policies = HashMap::new();
        policies.insert("isolated-svc".to_string(), vec![]);
        authz.update_policies(&policies).await;

        let result = authz
            .authorize("spiffe://fleet.internal/service/anyone", "isolated-svc")
            .await;
        assert!(matches!(result, Err(AuthzError::Denied { .. })));
    }

    #[tokio::test]
    async fn wrong_trust_domain_denied() {
        let authz = SpiffeAuthorizer::new("fleet.internal");
        let mut policies = HashMap::new();
        policies.insert("backend".to_string(), vec!["frontend".to_string()]);
        authz.update_policies(&policies).await;

        // Different trust domain
        let result = authz
            .authorize("spiffe://evil.external/service/frontend", "backend")
            .await;
        assert!(matches!(result, Err(AuthzError::Denied { .. })));
    }

    #[tokio::test]
    async fn policy_update_replaces_previous() {
        let authz = SpiffeAuthorizer::new("fleet.internal");

        let mut policies1 = HashMap::new();
        policies1.insert("svc".to_string(), vec!["old-caller".to_string()]);
        authz.update_policies(&policies1).await;

        let mut policies2 = HashMap::new();
        policies2.insert("svc".to_string(), vec!["new-caller".to_string()]);
        authz.update_policies(&policies2).await;

        let old = authz
            .authorize("spiffe://fleet.internal/service/old-caller", "svc")
            .await;
        assert!(matches!(old, Err(AuthzError::Denied { .. })));

        let new = authz
            .authorize("spiffe://fleet.internal/service/new-caller", "svc")
            .await;
        assert!(new.is_ok());
    }
}
