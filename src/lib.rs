//! Workspace facade for the hardware-only RustCrypto fork effort.
//!
//! The implementation crates live under `crates/`. This top-level crate exists
//! so workspace-level integration tests and Criterion benchmarks can depend on
//! the candidate APIs and comparison implementations from one place.

pub use hardware_aes_gcm as aes_gcm;
pub use hardware_random as random;
