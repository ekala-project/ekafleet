pub mod state;
pub mod storage;

use std::path::PathBuf;

/// Errors from the Raft state machine and its persistent storage.
#[derive(Debug, thiserror::Error)]
pub enum RaftError {
    #[error("raft storage I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("raft storage encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("raft storage crypto: {0}")]
    Crypto(&'static str),
    #[error("raft storage file {path} is unreadable: {reason}")]
    Corrupt { path: PathBuf, reason: String },
}
