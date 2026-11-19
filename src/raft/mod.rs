pub mod consensus;
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
    #[error("raft storage is inconsistent: {0}")]
    Inconsistent(String),
    /// This server is not the Raft leader; writes go to the leader.
    #[error("not the Raft leader{}", leader_hint(.leader_id, .leader_addr))]
    NotLeader {
        leader_id: Option<u64>,
        leader_addr: Option<String>,
    },
    #[error("raft consensus: {0}")]
    Consensus(String),
}

fn leader_hint(id: &Option<u64>, addr: &Option<String>) -> String {
    match (id, addr) {
        (Some(id), Some(addr)) => format!(" (leader is server {id} at {addr})"),
        (Some(id), None) => format!(" (leader is server {id})"),
        _ => " (no leader elected)".to_string(),
    }
}

impl RaftError {
    /// Map a failed `client_write`, keeping where the leader is.
    pub fn from_client_write(
        e: openraft::error::RaftError<
            u64,
            openraft::error::ClientWriteError<u64, openraft::BasicNode>,
        >,
    ) -> Self {
        match e.forward_to_leader() {
            Some(forward) => Self::NotLeader {
                leader_id: forward.leader_id,
                leader_addr: forward.leader_node.as_ref().map(|n| n.addr.clone()),
            },
            None => Self::Consensus(e.to_string()),
        }
    }
}
