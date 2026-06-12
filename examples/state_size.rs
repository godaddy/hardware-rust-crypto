//! Prints the in-memory size of each reusable AES-256-GCM key-state type and
//! of the key/nonce generator states, for the cached-key footprint comparison
//! in docs/benchmarks.md.
//!
//! Note the `RustCrypto` `Aes256Gcm` size depends on build configuration: with
//! default flags on aarch64 it holds the fixsliced software state; with
//! `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"` it holds runtime-dispatch
//! state instead. Run it under both configurations.

use core::mem::size_of;

fn main() {
    let layout = hardware_rust_crypto::aes_gcm::HardwareAes256Gcm::key_state_layout();
    println!("AES-256-GCM reusable key state:");
    println!(
        "  candidate HardwareAes256Gcm: {} bytes (align {})",
        layout.size, layout.align
    );
    println!(
        "  RustCrypto aes_gcm::Aes256Gcm: {} bytes",
        size_of::<aes_gcm::Aes256Gcm>()
    );
    println!(
        "  ring LessSafeKey:              {} bytes",
        size_of::<ring::aead::LessSafeKey>()
    );

    let ctr_layout = hardware_rust_crypto::random::AesCtrKeyGenerator::state_layout();
    println!("Key/nonce generator state:");
    println!(
        "  candidate AesCtrKeyGenerator:  {} bytes (align {})",
        ctr_layout.size, ctr_layout.align
    );
    println!(
        "  rand_chacha ChaCha20Rng (baseline): {} bytes",
        size_of::<rand_chacha::ChaCha20Rng>()
    );
}
