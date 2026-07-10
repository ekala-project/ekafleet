use std::borrow::Borrow;

use derive_more::{AsRef, Deref, Display, From, Into};
use serde::{Deserialize, Serialize};

/// Unique identifier for a node in the fleet.
#[derive(
    Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Deref, Display, From, Into, AsRef,
    Serialize, Deserialize,
)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl Borrow<str> for NodeId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Name of a service in the fleet.
#[derive(
    Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Deref, Display, From, Into, AsRef,
    Serialize, Deserialize,
)]
pub struct ServiceName(String);

impl ServiceName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// Name of a node pool.
#[derive(
    Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Deref, Display, From, Into, AsRef,
    Serialize, Deserialize,
)]
pub struct PoolName(String);

impl PoolName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}
