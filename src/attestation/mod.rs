pub mod join_token;

/// Result of a successful node attestation.
pub struct AttestationResult {
    /// Verified node identity (typically a UUID).
    pub node_id: String,
    /// Key-value selectors describing the node (for SVID minting decisions).
    pub selectors: Vec<(String, String)>,
}

/// Errors during attestation.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("unknown attestation type: {0}")]
    UnknownType(String),
    #[error("attestation failed: {0}")]
    Failed(String),
    #[error("invalid attestation data: {0}")]
    InvalidData(String),
}
