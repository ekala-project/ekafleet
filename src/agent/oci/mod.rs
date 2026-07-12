//! OCI image management for ekafleet agents.
//!
//! Provides a native OCI registry client, content-addressable image store,
//! and layer unpacking for systemd-nspawn execution.

pub mod digest;
pub mod manifest;
pub mod reference;
