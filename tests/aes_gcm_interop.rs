//! Interoperability tests proving byte compatibility with `RustCrypto`
//! `aes-gcm` and `ring`, plus NIST known-answer and tampering coverage.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce as RustCryptoNonce};
use hardware_rust_crypto::aes_gcm::{Error, HardwareAes256Gcm, NONCE_SIZE, TAG_SIZE};
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use ring::aead::{Aad, LessSafeKey, Nonce as RingNonce, UnboundKey, AES_256_GCM};

const KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];
const NONCE: [u8; NONCE_SIZE] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];
const AAD: &[u8] = b"authenticated metadata";
const PLAINTEXT: &[u8] = b"hardware aes-gcm interop plaintext";

#[test]
fn default_encrypt_matches_rustcrypto_for_embedded_nonce() {
    let mut candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let envelope = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    let nonce = envelope_nonce(&envelope);
    let ciphertext_tag = envelope_ciphertext_tag(&envelope);

    assert_eq!(envelope.len(), PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE);
    assert_eq!(
        rustcrypto_encrypt_with(&KEY, &nonce, AAD, PLAINTEXT),
        ciphertext_tag
    );
    assert_eq!(candidate.decrypt(AAD, &envelope).unwrap(), PLAINTEXT);
}

#[test]
fn default_encrypt_matches_ring_for_embedded_nonce() {
    let mut candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let envelope = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    let nonce = envelope_nonce(&envelope);

    assert_eq!(
        ring_encrypt_with(&KEY, &nonce, AAD, PLAINTEXT),
        envelope_ciphertext_tag(&envelope)
    );
    assert_eq!(
        ring_decrypt_with(&KEY, &nonce, AAD, envelope_ciphertext_tag(&envelope)),
        PLAINTEXT
    );
}

#[test]
fn candidate_ring_and_rustcrypto_decrypt_each_other() {
    let mut candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let candidate_envelope = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    let candidate_nonce = envelope_nonce(&candidate_envelope);
    let candidate_ct = envelope_ciphertext_tag(&candidate_envelope);
    assert_eq!(
        rustcrypto_decrypt_with(&KEY, &candidate_nonce, AAD, candidate_ct),
        PLAINTEXT
    );
    assert_eq!(
        ring_decrypt_with(&KEY, &candidate_nonce, AAD, candidate_ct),
        PLAINTEXT
    );

    let rustcrypto_ct = rustcrypto_encrypt_with(&KEY, &NONCE, AAD, PLAINTEXT);
    assert_eq!(
        candidate
            .decrypt(AAD, &envelope_from_parts(&rustcrypto_ct, &NONCE))
            .unwrap(),
        PLAINTEXT
    );

    let ring_ct = ring_encrypt_with(&KEY, &NONCE, AAD, PLAINTEXT);
    assert_eq!(
        candidate
            .decrypt(AAD, &envelope_from_parts(&ring_ct, &NONCE))
            .unwrap(),
        PLAINTEXT
    );
}

#[test]
fn default_layout_is_ciphertext_tag_nonce() {
    let mut candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let envelope = candidate.encrypt(&[], PLAINTEXT).unwrap();

    assert_eq!(envelope.len(), PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE);
    assert_eq!(candidate.decrypt(&[], &envelope).unwrap(), PLAINTEXT);
    let nonce = envelope_nonce(&envelope);
    assert_eq!(
        rustcrypto_encrypt_with(&KEY, &nonce, &[], PLAINTEXT),
        envelope_ciphertext_tag(&envelope)
    );
}

#[test]
fn default_encrypt_generates_distinct_nonces() {
    let mut candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let first = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    let second = candidate.encrypt(AAD, PLAINTEXT).unwrap();

    assert_ne!(envelope_nonce(&first), envelope_nonce(&second));
    assert_eq!(candidate.decrypt(AAD, &first).unwrap(), PLAINTEXT);
    assert_eq!(candidate.decrypt(AAD, &second).unwrap(), PLAINTEXT);
}

#[test]
fn tampering_fails_authentication() {
    let mut candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let envelope = candidate.encrypt(AAD, PLAINTEXT).unwrap();

    for byte_index in 0..envelope.len() {
        let mut tampered = envelope.clone();
        tampered[byte_index] ^= 0x80;
        assert!(
            candidate.decrypt(AAD, &tampered).is_err(),
            "tampered byte {byte_index} authenticated"
        );
    }

    let mut tampered_aad = AAD.to_vec();
    tampered_aad[0] ^= 0x80;
    assert!(candidate.decrypt(&tampered_aad, &envelope).is_err());
}

#[test]
fn nist_known_answer_vectors_decrypt_from_envelope() {
    let key = [0_u8; 32];
    let nonce = [0_u8; NONCE_SIZE];
    let candidate = HardwareAes256Gcm::new(&key).unwrap();

    let empty_ciphertext_tag = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73,
        0x8b,
    ];
    assert_eq!(
        candidate
            .decrypt(&[], &envelope_from_parts(&empty_ciphertext_tag, &nonce))
            .unwrap(),
        []
    );

    let block_ciphertext_tag = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d,
        0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
        0xb9, 0x19,
    ];
    assert_eq!(
        candidate
            .decrypt(&[], &envelope_from_parts(&block_ciphertext_tag, &nonce))
            .unwrap(),
        [0_u8; 16]
    );
}

#[test]
fn randomized_differential_against_rustcrypto() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4841_5244_5741_5245);
    for plaintext_len in [
        0_usize, 1, 2, 3, 7, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024,
        4096,
    ] {
        for aad_len in [0_usize, 1, 2, 15, 16, 17, 31, 32, 33, 127] {
            let mut key = [0_u8; 32];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let mut candidate = HardwareAes256Gcm::new(&key).unwrap();
            let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
            let nonce = envelope_nonce(&envelope);
            let ciphertext_tag = envelope_ciphertext_tag(&envelope);
            let rustcrypto_ct = rustcrypto_encrypt_with(&key, &nonce, &aad, &plaintext);

            assert_eq!(ciphertext_tag, rustcrypto_ct);
            assert_eq!(candidate.decrypt(&aad, &envelope).unwrap(), plaintext);

            let mut inbound_nonce = [0_u8; NONCE_SIZE];
            rng.fill_bytes(&mut inbound_nonce);
            let inbound_ct = rustcrypto_encrypt_with(&key, &inbound_nonce, &aad, &plaintext);
            assert_eq!(
                candidate
                    .decrypt(&aad, &envelope_from_parts(&inbound_ct, &inbound_nonce))
                    .unwrap(),
                plaintext
            );

            if !envelope.is_empty() {
                let mut tampered = envelope.clone();
                let last = tampered.len() - 1;
                tampered[last] ^= 1;
                assert!(candidate.decrypt(&aad, &tampered).is_err());
            }
        }
    }
}

/// Dense sweep across the interleaved-batch (128 B) and GHASH-aggregation
/// (64 B) boundaries: every length from 0 through two full batches plus
/// boundary neighbors at larger sizes must match stock `RustCrypto` exactly.
#[test]
fn dense_length_sweep_matches_rustcrypto() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x424f_554e_4441_5259);
    let lengths = (0..=288_usize).chain([
        511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385,
    ]);
    for plaintext_len in lengths {
        for aad_len in [0_usize, 17] {
            let mut key = [0_u8; 32];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let mut candidate = HardwareAes256Gcm::new(&key).unwrap();
            let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
            let nonce = envelope_nonce(&envelope);
            let ciphertext_tag = envelope_ciphertext_tag(&envelope);
            let rustcrypto_ct = rustcrypto_encrypt_with(&key, &nonce, &aad, &plaintext);
            assert_eq!(
                ciphertext_tag, rustcrypto_ct,
                "ciphertext mismatch at plaintext_len={plaintext_len} aad_len={aad_len}"
            );

            let mut to_buffer = vec![0_u8; plaintext_len + TAG_SIZE + NONCE_SIZE];
            let written = candidate
                .encrypt_to(&aad, &plaintext, &mut to_buffer)
                .unwrap();
            assert_eq!(written, to_buffer.len());
            let to_nonce = envelope_nonce(&to_buffer);
            assert_eq!(
                envelope_ciphertext_tag(&to_buffer),
                rustcrypto_encrypt_with(&key, &to_nonce, &aad, &plaintext),
                "encrypt_to mismatch at plaintext_len={plaintext_len} aad_len={aad_len}"
            );

            let mut plaintext_out = vec![0_u8; plaintext_len];
            let written = candidate
                .decrypt_to(&aad, &to_buffer, &mut plaintext_out)
                .unwrap();
            assert_eq!(written, plaintext_len);
            assert_eq!(
                plaintext_out, plaintext,
                "decrypt_to mismatch at plaintext_len={plaintext_len} aad_len={aad_len}"
            );
        }
    }
}

#[test]
fn every_single_byte_tamper_fails_across_sizes() {
    let mut candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    for size in [0_usize, 1, 15, 16, 17, 31, 32, 64, 127, 128, 129] {
        let plaintext = vec![0xa5_u8; size];
        let envelope = candidate.encrypt(AAD, &plaintext).unwrap();

        for byte_index in 0..envelope.len() {
            for bit in [0x01_u8, 0x80] {
                let mut tampered = envelope.clone();
                tampered[byte_index] ^= bit;
                assert!(
                    candidate.decrypt(AAD, &tampered).is_err(),
                    "size {size}: tampered envelope byte {byte_index} bit {bit:#x} authenticated"
                );
            }
        }

        let mut tampered_aad = AAD.to_vec();
        tampered_aad[0] ^= 0x80;
        assert!(candidate.decrypt(&tampered_aad, &envelope).is_err());
    }
}

#[test]
fn wrong_key_nonce_or_aad_is_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4743_4d5f_5752_4f4e);
    for _ in 0..256 {
        let mut key = [0_u8; 32];
        let mut plaintext = vec![0_u8; 1 + (rng.next_u32() as usize % 200)];
        let mut aad = vec![0_u8; rng.next_u32() as usize % 64];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut plaintext);
        rng.fill_bytes(&mut aad);

        let mut cipher = HardwareAes256Gcm::new(&key).unwrap();
        let envelope = cipher.encrypt(&aad, &plaintext).unwrap();
        assert_eq!(cipher.decrypt(&aad, &envelope).unwrap(), plaintext);

        let mut wrong_key = key;
        wrong_key[rng.next_u32() as usize % 32] ^= 1;
        let wrong = HardwareAes256Gcm::new(&wrong_key).unwrap();
        assert_eq!(wrong.decrypt(&aad, &envelope), Err(Error::Decrypt));

        let mut wrong_nonce = envelope.clone();
        let nonce_index = wrong_nonce.len() - 1 - (rng.next_u32() as usize % NONCE_SIZE);
        wrong_nonce[nonce_index] ^= 1;
        assert_eq!(cipher.decrypt(&aad, &wrong_nonce), Err(Error::Decrypt));

        let mut wrong_aad = aad.clone();
        wrong_aad.push(0xff);
        assert_eq!(cipher.decrypt(&wrong_aad, &envelope), Err(Error::Decrypt));
    }
}

/// Dense AAD sweep across the GHASH 8/4/1-block aggregation boundaries, which
/// the plaintext-only `dense_length_sweep_matches_rustcrypto` did not exercise.
#[test]
fn dense_aad_sweep_matches_rustcrypto() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4743_4d5f_4141_4453);
    for aad_len in 0..=288_usize {
        for plaintext_len in [0_usize, 16, 37] {
            let mut key = [0_u8; 32];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let mut candidate = HardwareAes256Gcm::new(&key).unwrap();
            let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
            let nonce = envelope_nonce(&envelope);
            assert_eq!(
                envelope_ciphertext_tag(&envelope),
                rustcrypto_encrypt_with(&key, &nonce, &aad, &plaintext),
                "ciphertext mismatch at aad_len={aad_len} plaintext_len={plaintext_len}"
            );
            assert_eq!(candidate.decrypt(&aad, &envelope).unwrap(), plaintext);
        }
    }
}

#[test]
fn large_aad_and_plaintext() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4743_4d5f_4c52_4745);
    let mut key = [0_u8; 32];
    let mut plaintext = vec![0_u8; 9000];
    let mut aad = vec![0_u8; 5000];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut plaintext);
    rng.fill_bytes(&mut aad);

    let mut candidate = HardwareAes256Gcm::new(&key).unwrap();
    let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
    let nonce = envelope_nonce(&envelope);
    assert_eq!(
        envelope_ciphertext_tag(&envelope),
        rustcrypto_encrypt_with(&key, &nonce, &aad, &plaintext)
    );
    assert_eq!(candidate.decrypt(&aad, &envelope).unwrap(), plaintext);
}

fn envelope_ciphertext_tag(envelope: &[u8]) -> &[u8] {
    &envelope[..envelope.len() - NONCE_SIZE]
}

fn envelope_nonce(envelope: &[u8]) -> [u8; NONCE_SIZE] {
    envelope[envelope.len() - NONCE_SIZE..].try_into().unwrap()
}

fn envelope_from_parts(ciphertext_tag: &[u8], nonce: &[u8; NONCE_SIZE]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(ciphertext_tag.len() + NONCE_SIZE);
    envelope.extend_from_slice(ciphertext_tag);
    envelope.extend_from_slice(nonce);
    envelope
}

fn rustcrypto_encrypt_with(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let rustcrypto = Aes256Gcm::new_from_slice(key).unwrap();
    rustcrypto
        .encrypt(
            RustCryptoNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap()
}

fn rustcrypto_decrypt_with(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext_tag: &[u8],
) -> Vec<u8> {
    let rustcrypto = Aes256Gcm::new_from_slice(key).unwrap();
    rustcrypto
        .decrypt(
            RustCryptoNonce::from_slice(nonce),
            Payload {
                msg: ciphertext_tag,
                aad,
            },
        )
        .unwrap()
}

fn ring_encrypt_with(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        RingNonce::assume_unique_for_key(*nonce),
        Aad::from(aad),
        &mut in_out,
    )
    .unwrap();
    in_out
}

fn ring_decrypt_with(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext_tag: &[u8],
) -> Vec<u8> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let mut in_out = ciphertext_tag.to_vec();
    let plaintext = key
        .open_in_place(
            RingNonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .unwrap();
    let len = plaintext.len();
    in_out.truncate(len);
    in_out
}
