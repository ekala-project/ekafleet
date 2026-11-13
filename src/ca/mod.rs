pub mod client;
pub mod csr;
pub mod issuer;
pub mod jwt;
pub mod persist;
pub mod pki;
pub mod root;
pub mod signer;

use root::CaError;

/// The identity an X.509 SVID is issued for.
///
/// The CA derives every identity-bearing field of the issued certificate (the
/// SPIFFE URI SAN, subject, key usages) from this value and *never* from the
/// CSR: a CSR only proves possession of the private key and contributes its
/// public key. Callers construct a subject only after authorizing the
/// requester for it (service assigned to the authenticated node, join token
/// bound to the node name, ...).
///
/// Server identities (`/server/*`) are deliberately not representable here;
/// they are only minted by [`CaSigner::issue_server_svid`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "lowercase")]
pub enum SvidSubject {
    /// A workload: `spiffe://<domain>/service/<name>`.
    Service(String),
    /// A fleet node's agent: `spiffe://<domain>/agent/<name>`.
    Agent(String),
}

impl SvidSubject {
    /// The name component (service or node name).
    pub fn name(&self) -> &str {
        match self {
            Self::Service(name) | Self::Agent(name) => name,
        }
    }

    /// The SPIFFE ID path, without the leading slash (`service/web`).
    pub fn spiffe_path(&self) -> String {
        match self {
            Self::Service(name) => format!("service/{name}"),
            Self::Agent(name) => format!("agent/{name}"),
        }
    }

    /// The full SPIFFE ID within `domain`.
    pub fn spiffe_id(&self, domain: &str) -> String {
        format!("spiffe://{domain}/{}", self.spiffe_path())
    }

    /// Subject common name for the issued certificate.
    pub fn common_name(&self) -> String {
        match self {
            Self::Service(name) => name.clone(),
            Self::Agent(name) => format!("agent-{name}"),
        }
    }

    /// Reject names that are not a single, well-formed SPIFFE path segment.
    pub fn validate(&self) -> Result<(), CaError> {
        validate_identity_name(self.name())
            .map_err(|e| CaError::InvalidCsr(format!("invalid SVID subject: {e}")))
    }
}

/// Validate a service or node name used as a SPIFFE ID path segment.
///
/// Names must be 1–253 characters of `[A-Za-z0-9._-]`, must start with an
/// alphanumeric character, and therefore can never contain `/` (which would
/// let a name escape its path prefix, e.g. `x/../server/y`).
pub fn validate_identity_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 253 {
        return Err(format!("'{name}' must be 1-253 characters"));
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(format!("'{name}' must start with a letter or digit"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "'{name}' may only contain letters, digits, '-', '_' and '.'"
        ));
    }
    Ok(())
}

/// Extract the node name from an agent SPIFFE ID in `domain`
/// (`spiffe://<domain>/agent/<name>`). Returns `None` for any other identity,
/// including agent IDs from a different trust domain.
pub fn agent_name_from_spiffe_id<'a>(domain: &str, spiffe_id: &'a str) -> Option<&'a str> {
    let rest = spiffe_id.strip_prefix("spiffe://")?;
    let rest = rest.strip_prefix(domain)?;
    let name = rest.strip_prefix("/agent/")?;
    validate_identity_name(name).ok()?;
    Some(name)
}

/// Abstraction over CA signing operations.
///
/// Two implementations exist:
/// - `DirectCaSigner`: in-process `RootCa` (used by `ekafleet server` / `ekafleet dev`)
/// - `RemoteCaSigner`: Unix-socket client to a `ekafleet ca-signer` daemon
#[tonic::async_trait]
pub trait CaSigner: Send + Sync + 'static {
    /// Sign a PKCS#10 CSR for `subject` and return (cert_pem, chain_pem,
    /// expires_at). The private key stays with the requester. The issued
    /// certificate's identity comes from `subject` alone; the caller must
    /// have authorized the requester for it.
    async fn sign_csr(
        &self,
        csr_der: &[u8],
        subject: &SvidSubject,
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError>;

    /// Issue a server SVID for gRPC TLS.
    /// Returns (cert_pem + key_pem combined, chain_pem, expires_at).
    async fn issue_server_svid(&self, server_id: &str) -> Result<(Vec<u8>, Vec<u8>, u64), CaError>;

    /// Get the root CA certificate PEM (trust bundle).
    async fn trust_bundle_pem(&self) -> Result<String, CaError>;

    /// Sign a JWT-SVID (ES256, [`jwt::JWT_SVID_TTL`]) for `subject` and
    /// `audience`. Returns (compact JWS, expires_at). As with
    /// [`Self::sign_csr`], the caller must have authorized the requester.
    async fn sign_jwt_svid(
        &self,
        subject: &SvidSubject,
        audience: &[String],
    ) -> Result<(String, u64), CaError>;

    /// The trust domain's JWT bundle (a JWKS document).
    async fn jwt_bundle(&self) -> Result<String, CaError>;
}

/// Validate a JWT-SVID audience list: 1–8 entries of 1–256 printable,
/// non-whitespace ASCII characters.
pub fn validate_jwt_audience(audience: &[String]) -> Result<(), CaError> {
    if audience.is_empty() || audience.len() > 8 {
        return Err(CaError::InvalidCsr("a JWT-SVID needs 1-8 audiences".into()));
    }
    for aud in audience {
        if aud.is_empty() || aud.len() > 256 || !aud.chars().all(|c| c.is_ascii_graphic()) {
            return Err(CaError::InvalidCsr(format!(
                "invalid JWT-SVID audience '{aud}'"
            )));
        }
    }
    Ok(())
}
