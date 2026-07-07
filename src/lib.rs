//! ekafleet library — re-exports modules for integration tests.

#[allow(dead_code)]
pub mod attestation;
#[allow(dead_code)]
pub mod ca;
#[allow(dead_code)]
pub mod config;
#[allow(dead_code)]
pub mod dns;
#[allow(dead_code)]
pub mod gossip;
#[allow(dead_code)]
pub mod mesh;
#[allow(dead_code)]
pub mod metrics;
#[allow(dead_code)]
pub mod policy;
#[allow(dead_code)]
pub mod proxy;
#[allow(dead_code)]
pub mod raft;
#[allow(dead_code)]
pub mod secrets;
pub mod server;
#[allow(dead_code)]
pub mod spiffe;

pub mod proto {
    #![allow(clippy::result_large_err)]
    tonic::include_proto!("fleet");
}

pub mod workload_proto {
    #![allow(clippy::result_large_err)]
    tonic::include_proto!("spiffe.workload");
}

pub mod agent;
