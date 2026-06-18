#![no_main]
//! Parser-robustness fuzzing of the AES-256-GCM decrypt entry points - the only
//! surface that consumes attacker-controlled bytes. The invariant is "no panic,
//! no UB" on arbitrary input; libFuzzer (with ASan/UBSan) fails on any crash.

use hardware_rust_crypto::aes_gcm::HardwareAes256Gcm;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    key: [u8; 32],
    nonce: Vec<u8>,
    aad: Vec<u8>,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let Ok(cipher) = HardwareAes256Gcm::new(&input.key) else {
        return;
    };
    let _ = cipher.decrypt(&input.aad, &input.data); // envelope parse
    let _ = cipher.decrypt_with_nonce(&input.nonce, &input.aad, &input.data);
    let mut out = vec![0u8; input.data.len()];
    let _ = cipher.decrypt_to(&input.aad, &input.data, &mut out);
});
