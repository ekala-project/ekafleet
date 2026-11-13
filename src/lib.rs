//! ekafleet library — re-exports modules for integration tests.

pub mod types;

pub mod attestation;
pub mod ca;
pub mod config;
pub mod dns;
pub mod gossip;
pub mod mesh;
pub mod metrics;
pub mod policy;
pub mod proxy;
pub mod raft;
pub mod secrets;
pub mod server;
pub mod spiffe;

pub mod proto {
    #![allow(clippy::result_large_err)]
    tonic::include_proto!("fleet");
}

pub mod workload_proto {
    #![allow(clippy::result_large_err)]
    // workload.proto declares no package (matching the upstream SPIFFE
    // definition), so prost emits it as `_.rs`.
    tonic::include_proto!("_");
}

pub mod agent;
