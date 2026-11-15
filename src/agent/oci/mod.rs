//! OCI image management for ekafleet agents.
//!
//! Provides a native OCI registry client, content-addressable image store,
//! and layer unpacking for systemd-nspawn execution.
//!
//! # Architecture
//!
//! ```text
//! ImageReference (pinned by the server: repo:tag@sha256:...)
//!   → signature (cosign verification of the pinned digest)
//!     → RegistryClient (fetch manifest + blobs with auth, digest-checked)
//!       → ImageStore (content-addressed local cache)
//!         → unpack (extract layers into a per-digest bundle rootfs)
//!           → bundle (generate config.json for nspawn)
//! ```
//!
//! `crate::agent::images` drives this per service.

pub mod auth;
pub mod bundle;
pub mod digest;
pub mod gc;
pub mod manifest;
pub mod pull;
pub mod reference;
pub mod registry;
pub mod signature;
pub mod store;
pub mod unpack;
