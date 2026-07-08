#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// SPIFFE trust domain federation — establishes trust between separate
/// trust domains so services in different clusters can authenticate
/// each other via mTLS without sharing a single CA.
#[derive(Clone)]
pub struct TrustDomainFederation {
    /// Foreign trust domain → CA bundle PEM
    foreign_bundles: Arc<RwLock<HashMap<String, String>>>,
    /// Local trust domain name
    local_domain: String,
}

impl TrustDomainFederation {
    pub fn new(local_domain: &str) -> Self {
        Self {
            foreign_bundles: Arc::new(RwLock::new(HashMap::new())),
            local_domain: local_domain.to_string(),
        }
    }

    /// Register a foreign trust domain's CA bundle.
    /// After registration, SVIDs from this trust domain will be accepted
    /// during mTLS verification.
    pub async fn add_trust_domain(&self, domain: &str, ca_bundle_pem: &str) {
        self.foreign_bundles
            .write()
            .await
            .insert(domain.to_string(), ca_bundle_pem.to_string());
        tracing::info!(
            domain = %domain,
            local = %self.local_domain,
            "Foreign trust domain registered for SPIFFE federation"
        );
    }

    /// Remove a foreign trust domain.
    pub async fn remove_trust_domain(&self, domain: &str) -> bool {
        self.foreign_bundles.write().await.remove(domain).is_some()
    }

    /// Get the CA bundle for a foreign trust domain.
    pub async fn get_bundle(&self, domain: &str) -> Option<String> {
        self.foreign_bundles.read().await.get(domain).cloned()
    }

    /// Get all registered foreign trust domains.
    pub async fn list_domains(&self) -> Vec<String> {
        self.foreign_bundles.read().await.keys().cloned().collect()
    }

    /// Build a combined trust bundle containing the local CA and all
    /// federated foreign CAs. Used for mTLS verification.
    pub async fn combined_bundle(&self, local_ca_pem: &str) -> String {
        let mut bundle = local_ca_pem.to_string();
        let foreign = self.foreign_bundles.read().await;
        for pem in foreign.values() {
            bundle.push('\n');
            bundle.push_str(pem);
        }
        bundle
    }

    /// Check if a SPIFFE ID belongs to a trusted domain.
    pub async fn is_trusted(&self, spiffe_id: &str) -> bool {
        // spiffe://<domain>/...
        if let Some(rest) = spiffe_id.strip_prefix("spiffe://") {
            let domain = rest.split('/').next().unwrap_or("");
            if domain == self.local_domain {
                return true;
            }
            self.foreign_bundles.read().await.contains_key(domain)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn trust_local_domain() {
        let fed = TrustDomainFederation::new("fleet.internal");
        assert!(fed.is_trusted("spiffe://fleet.internal/service/api").await);
        assert!(!fed.is_trusted("spiffe://foreign.example/service/api").await);
    }

    #[tokio::test]
    async fn trust_federated_domain() {
        let fed = TrustDomainFederation::new("fleet.internal");
        fed.add_trust_domain(
            "partner.example",
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        )
        .await;

        assert!(fed.is_trusted("spiffe://partner.example/service/api").await);
    }

    #[tokio::test]
    async fn combined_bundle() {
        let fed = TrustDomainFederation::new("fleet.internal");
        fed.add_trust_domain("other", "FOREIGN_CA").await;

        let bundle = fed.combined_bundle("LOCAL_CA").await;
        assert!(bundle.contains("LOCAL_CA"));
        assert!(bundle.contains("FOREIGN_CA"));
    }
}
