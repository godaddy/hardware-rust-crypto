//! Differential test against a third, lineage-independent AES-256-GCM oracle:
//! OpenSSL's C implementation. The existing interop suite cross-checks
//! `RustCrypto` `aes-gcm` (pure Rust) and `ring` (`BoringSSL` heritage); OpenSSL
//! is a separate C codebase, so agreement across all three makes a shared
//! specification-level bug far less likely than any single oracle could.
//!
//! Byte-exact in both directions: our `ciphertext || tag` must equal OpenSSL's,
//! each must decrypt the other's output, and the FAIL case (a flipped tag) must
//! be rejected by both. Requires the `hazmat-explicit-nonce` feature for the
//! fixed-nonce entry points used to line the two implementations up.

#![cfg(feature = "hazmat-explicit-nonce")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use hardware_rust_crypto::aes_gcm::HardwareAes256Gcm;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

fn case(seed: u64) -> ([u8; 32], [u8; 12], Vec<u8>, Vec<u8>) {
    // Deterministic, dependency-free pseudo-random inputs.
    let mut s = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let mut key = [0_u8; 32];
    for b in &mut key {
        *b = next() as u8;
    }
    let mut nonce = [0_u8; 12];
    for b in &mut nonce {
        *b = next() as u8;
    }
    let aad_len = (next() % 40) as usize;
    let pt_len = (next() % 300) as usize;
    let aad: Vec<u8> = (0..aad_len).map(|_| next() as u8).collect();
    let pt: Vec<u8> = (0..pt_len).map(|_| next() as u8).collect();
    (key, nonce, aad, pt)
}

#[test]
fn matches_openssl_aes_256_gcm_both_directions() {
    let cipher = Cipher::aes_256_gcm();
    for seed in 0..200_u64 {
        let (key, nonce, aad, pt) = case(seed);

        // Ours: ciphertext || tag (16-byte tag).
        let mut ours = HardwareAes256Gcm::new(&key).unwrap();
        let our_ct_tag = ours.encrypt_with_nonce(&nonce, &aad, &pt).unwrap();
        let (our_ct, our_tag) = our_ct_tag.split_at(pt.len());

        // OpenSSL.
        let mut ossl_tag = [0_u8; 16];
        let ossl_ct = encrypt_aead(cipher, &key, Some(&nonce), &aad, &pt, &mut ossl_tag).unwrap();

        // Byte-exact agreement.
        assert_eq!(
            our_ct,
            ossl_ct.as_slice(),
            "ciphertext differs at seed {seed}"
        );
        assert_eq!(our_tag, &ossl_tag, "tag differs at seed {seed}");

        // Each decrypts the other's output.
        let ossl_pt = decrypt_aead(cipher, &key, Some(&nonce), &aad, our_ct, our_tag).unwrap();
        assert_eq!(
            ossl_pt, pt,
            "OpenSSL failed to decrypt our output at seed {seed}"
        );

        let mut envelope = ossl_ct.clone();
        envelope.extend_from_slice(&ossl_tag);
        envelope.extend_from_slice(&nonce); // ours expects ct || tag || nonce
        assert_eq!(
            ours.decrypt(&aad, &envelope).unwrap(),
            pt,
            "we failed to decrypt OpenSSL's output at seed {seed}"
        );
    }
}

#[test]
fn both_reject_a_tampered_tag() {
    let cipher = Cipher::aes_256_gcm();
    let (key, nonce, aad, pt) = case(12_345);
    let mut ours = HardwareAes256Gcm::new(&key).unwrap();
    let mut ct_tag = ours.encrypt_with_nonce(&nonce, &aad, &pt).unwrap();
    let last = ct_tag.len() - 1;
    ct_tag[last] ^= 0x01; // flip a tag bit

    // Ours rejects.
    let mut env = ct_tag.clone();
    env.extend_from_slice(&nonce);
    assert!(ours.decrypt(&aad, &env).is_err());

    // OpenSSL rejects.
    let (ct, tag) = ct_tag.split_at(pt.len());
    assert!(decrypt_aead(cipher, &key, Some(&nonce), &aad, ct, tag).is_err());
}
