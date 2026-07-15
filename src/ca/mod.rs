pub mod client;
pub mod csr;
pub mod issuer;
pub mod pki;
pub mod root;
pub mod signer;

use root::CaError;

/// Abstraction over CA signing operations.
///
/// Two implementations exist:
/// - `DirectCaSigner`: in-process `RootCa` (used by `ekafleet server` / `ekafleet dev`)
/// - `RemoteCaSigner`: Unix-socket client to a `ekafleet ca-signer` daemon
#[tonic::async_trait]
pub trait CaSigner: Send + Sync + 'static {
    /// Sign a PKCS#10 CSR and return (cert_pem, chain_pem, expires_at).
    /// The private key stays with the requester.
    async fn sign_csr(
        &self,
        csr_der: &[u8],
        service_name: &str,
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError>;

    /// Issue a leaf certificate with a server-generated keypair (legacy path).
    /// Returns (cert_pem + key_pem combined, chain_pem, expires_at).
    async fn issue_certificate(
        &self,
        service_name: &str,
        csr_der: &[u8],
        store_path: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), CaError>;

    /// Issue a server SVID for gRPC TLS.
    /// Returns (cert_pem + key_pem combined, chain_pem, expires_at).
    async fn issue_server_svid(&self, server_id: &str) -> Result<(Vec<u8>, Vec<u8>, u64), CaError>;

    /// Get the root CA certificate PEM (trust bundle).
    async fn trust_bundle_pem(&self) -> Result<String, CaError>;
}
