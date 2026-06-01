//! Tessera — zero-knowledge identity core (OPAQUE, RFC 9807).
//!
//! This crate wraps the audited `opaque-ke` library behind a fixed cipher
//! suite and a small set of stateless server-side helpers. The sidecar binary
//! exposes those helpers over a Unix domain socket for the Go server SDK.

pub mod error;
pub mod protocol;
pub mod server;
pub mod suite;

pub use error::TesseraError;
