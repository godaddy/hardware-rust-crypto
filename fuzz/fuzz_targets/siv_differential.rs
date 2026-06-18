#![no_main]
//! Differential fuzzing of AES-256-GCM-SIV against RustCrypto `aes-gcm-siv`.

use aes_gcm_siv::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use hardware_rust_crypto::aes_gcm::HardwareAes256GcmSiv;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    key: [u8; 32],
    nonce: [u8; 12],
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let ours = HardwareAes256GcmSiv::new(&input.key).unwrap();
    let theirs = Aes256GcmSiv::new_from_slice(&input.key).unwrap();

    let our_ct = ours
        .encrypt_with_nonce(&input.nonce, &input.aad, &input.plaintext)
        .unwrap();
    let their_ct = theirs
        .encrypt(
            Nonce::from_slice(&input.nonce),
            Payload { msg: &input.plaintext, aad: &input.aad },
        )
        .unwrap();
    assert_eq!(our_ct, their_ct, "ciphertext diverged from RustCrypto");
    assert_eq!(
        ours.decrypt_with_nonce(&input.nonce, &input.aad, &our_ct).unwrap(),
        input.plaintext
    );
});
