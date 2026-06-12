//! Hardware-only AES-256-GCM and key/nonce generation.
//!
//! Every AES round and every GF(2^128) multiply executes as a CPU instruction
//! (`AES-NI`/`PCLMULQDQ` on `x86_64`, `ARMv8` AES/`PMULL` on `aarch64`); no
//! software cipher is compiled in. If the required hardware is absent,
//! construction fails with a typed error rather than degrading to table-based
//! AES.
//!
//! The crate exposes two modules:
//!
//! - [`aes_gcm`]: AES-256-GCM. [`aes_gcm::HardwareAes256Gcm`] owns boxed key
//!   state; [`aes_gcm::HardwareAes256GcmKeyState`] owns allocation-free inline
//!   key state; [`aes_gcm::HardwareAes256GcmIn`] places the key state in
//!   caller-provided memory so the caller controls where keys and key-equivalent
//!   state live (use [`aes_gcm::HardwareAes256Gcm::key_state_layout`] to size
//!   and align the storage, [`aes_gcm::UninitKeyStateSlot`] to hand it over).
//!   All zeroize the key state on drop.
//! - [`random`]: a hardware AES-256-CTR key and nonce generator
//!   ([`random::AesCtrKeyGenerator`]) with fork detection and CPU hardware-RNG
//!   (`RDSEED`/`RNDRRS`) reseeding.
//!
//! Implementation details (the AES, GHASH, CTR, and fork-detection internals)
//! are private; only the high-level types above are part of the public API.

pub mod aes_gcm;
pub mod random;
