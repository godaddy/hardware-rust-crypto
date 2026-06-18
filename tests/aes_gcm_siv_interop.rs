//! Interoperability tests for the hardware AES-256-GCM-SIV path: byte
//! compatibility with `RustCrypto` `aes-gcm-siv`, RFC 8452 known-answer
//! vectors, and tampering coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use aes_gcm_siv::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as RustCryptoNonce};
use hardware_rust_crypto::aes_gcm::{
    HardwareAes256GcmSiv, HardwareAes256GcmSivIn, HardwareAes256GcmSivKeyState,
    SivUninitKeyStateSlot, NONCE_SIZE, TAG_SIZE,
};
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;

const KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];
const NONCE: [u8; NONCE_SIZE] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];
const AAD: &[u8] = b"authenticated metadata";
const PLAINTEXT: &[u8] = b"hardware aes-gcm-siv interop plaintext";

fn reference_encrypt(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(key).unwrap();
    cipher
        .encrypt(RustCryptoNonce::from_slice(nonce), Payload { msg, aad })
        .unwrap()
}

fn reference_decrypt(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(key).unwrap();
    cipher
        .decrypt(RustCryptoNonce::from_slice(nonce), Payload { msg: ct, aad })
        .unwrap()
}

#[test]
fn candidate_encrypts_same_bytes_as_rustcrypto() {
    let candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let candidate_ct = candidate.encrypt(&NONCE, AAD, PLAINTEXT).unwrap();
    let reference_ct = reference_encrypt(&KEY, &NONCE, AAD, PLAINTEXT);
    assert_eq!(candidate_ct, reference_ct);
}

#[test]
fn candidate_and_rustcrypto_decrypt_each_other() {
    let candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();

    let candidate_ct = candidate.encrypt(&NONCE, AAD, PLAINTEXT).unwrap();
    assert_eq!(reference_decrypt(&KEY, &NONCE, AAD, &candidate_ct), PLAINTEXT);

    let reference_ct = reference_encrypt(&KEY, &NONCE, AAD, PLAINTEXT);
    assert_eq!(
        candidate.decrypt(&NONCE, AAD, &reference_ct).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn nonce_appended_is_ciphertext_tag_nonce() {
    let candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let layout = candidate.encrypt_nonce_appended(&NONCE, PLAINTEXT).unwrap();

    assert_eq!(&layout[layout.len() - NONCE_SIZE..], NONCE);
    assert_eq!(layout.len(), PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE);
    assert_eq!(
        candidate.decrypt_nonce_appended(&layout).unwrap(),
        PLAINTEXT
    );

    // The ciphertext||tag prefix (empty AAD) must match the reference.
    let prefix = reference_encrypt(&KEY, &NONCE, &[], PLAINTEXT);
    assert_eq!(&layout[..layout.len() - NONCE_SIZE], prefix.as_slice());
}

#[test]
fn tampering_fails_authentication() {
    let candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let ciphertext = candidate.encrypt(&NONCE, AAD, PLAINTEXT).unwrap();

    for byte_index in 0..ciphertext.len() {
        let mut tampered = ciphertext.clone();
        tampered[byte_index] ^= 0x80;
        assert!(
            candidate.decrypt(&NONCE, AAD, &tampered).is_err(),
            "tampered byte {byte_index} authenticated"
        );
    }

    let mut tampered_aad = AAD.to_vec();
    tampered_aad[0] ^= 0x80;
    assert!(candidate
        .decrypt(&NONCE, &tampered_aad, &ciphertext)
        .is_err());

    let mut tampered_nonce = NONCE;
    tampered_nonce[0] ^= 0x80;
    assert!(candidate
        .decrypt(&tampered_nonce, AAD, &ciphertext)
        .is_err());
}

/// RFC 8452 Appendix C.2 AES-256-GCM-SIV known-answer vectors.
#[test]
fn rfc8452_known_answer_vectors() {
    // (aad, plaintext, expected ciphertext||tag). Key and nonce are shared.
    let key = hex32("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex12("030000000000000000000000");
    let candidate = HardwareAes256GcmSiv::new(&key).unwrap();

    let cases: &[(&str, &str, &str)] = &[
        ("", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
        ("", "0100000000000000", "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
        (
            "",
            "010000000000000000000000",
            "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        ),
        (
            "",
            "01000000000000000000000000000000",
            "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
        ),
        (
            "01",
            "0200000000000000",
            "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
        ),
    ];

    for (aad_hex, pt_hex, expected_hex) in cases {
        let aad = hex(aad_hex);
        let pt = hex(pt_hex);
        let expected = hex(expected_hex);
        let ct = candidate.encrypt(&nonce, &aad, &pt).unwrap();
        assert_eq!(ct, expected, "RFC 8452 vector pt={pt_hex} aad={aad_hex}");
        assert_eq!(candidate.decrypt(&nonce, &aad, &ct).unwrap(), pt);
    }
}

#[test]
fn randomized_differential_against_rustcrypto() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5349_565f_5241_4e44);
    for plaintext_len in [
        0_usize, 1, 2, 3, 7, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024,
        4096,
    ] {
        for aad_len in [0_usize, 1, 2, 15, 16, 17, 31, 32, 33, 127] {
            let mut key = [0_u8; 32];
            let mut nonce = [0_u8; NONCE_SIZE];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let candidate = HardwareAes256GcmSiv::new(&key).unwrap();
            let candidate_ct = candidate.encrypt(&nonce, &aad, &plaintext).unwrap();
            let reference_ct = reference_encrypt(&key, &nonce, &aad, &plaintext);

            assert_eq!(
                candidate_ct, reference_ct,
                "ciphertext mismatch at plaintext_len={plaintext_len} aad_len={aad_len}"
            );
            assert_eq!(
                candidate.decrypt(&nonce, &aad, &candidate_ct).unwrap(),
                plaintext
            );

            if !candidate_ct.is_empty() {
                let mut tampered = candidate_ct.clone();
                let last = tampered.len() - 1;
                tampered[last] ^= 1;
                assert!(candidate.decrypt(&nonce, &aad, &tampered).is_err());
            }
        }
    }
}

/// Dense sweep across the interleaved-batch (128 B) boundary: every length
/// from 0 through two full batches plus boundary neighbors at larger sizes
/// must match the reference and round-trip through `encrypt_to`/`decrypt_to`.
#[test]
fn dense_length_sweep_matches_rustcrypto() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5349_565f_5357_4550);
    let lengths = (0..=288_usize).chain([
        511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192, 8193,
    ]);
    for plaintext_len in lengths {
        for aad_len in [0_usize, 17] {
            let mut key = [0_u8; 32];
            let mut nonce = [0_u8; NONCE_SIZE];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let candidate = HardwareAes256GcmSiv::new(&key).unwrap();
            let candidate_ct = candidate.encrypt(&nonce, &aad, &plaintext).unwrap();
            let reference_ct = reference_encrypt(&key, &nonce, &aad, &plaintext);
            assert_eq!(
                candidate_ct, reference_ct,
                "ciphertext mismatch at plaintext_len={plaintext_len} aad_len={aad_len}"
            );

            let mut to_buffer = vec![0_u8; plaintext_len + TAG_SIZE];
            let written = candidate
                .encrypt_to(&nonce, &aad, &plaintext, &mut to_buffer)
                .unwrap();
            assert_eq!(written, to_buffer.len());
            assert_eq!(to_buffer, candidate_ct, "encrypt_to mismatch at {plaintext_len}");

            let mut pt_buffer = vec![0_u8; plaintext_len];
            let pt_written = candidate
                .decrypt_to(&nonce, &aad, &candidate_ct, &mut pt_buffer)
                .unwrap();
            assert_eq!(pt_written, plaintext_len);
            assert_eq!(pt_buffer, plaintext, "decrypt_to mismatch at {plaintext_len}");
        }
    }
}

#[test]
fn nonce_appended_in_place_round_trips() {
    let candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let mut buffer = PLAINTEXT.to_vec();
    candidate
        .encrypt_nonce_appended_in_place(&NONCE, &mut buffer)
        .unwrap();
    assert_eq!(buffer.len(), PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE);
    assert_eq!(
        candidate.decrypt_nonce_appended(&buffer).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn generated_nonce_round_trips() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let (nonce, ciphertext) = candidate
        .encrypt_with_generated_nonce(AAD, PLAINTEXT)
        .unwrap();
    assert_eq!(
        candidate.decrypt(&nonce, AAD, &ciphertext).unwrap(),
        PLAINTEXT
    );

    let framed = candidate.encrypt_nonce_appended_generated(PLAINTEXT).unwrap();
    assert_eq!(
        candidate.decrypt_nonce_appended(&framed).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn inline_and_caller_placed_match_owned() {
    let owned = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let owned_layout = owned.encrypt_nonce_appended(&NONCE, PLAINTEXT).unwrap();

    let inline = HardwareAes256GcmSivKeyState::new(&KEY).unwrap();
    let inline_layout = inline.encrypt_nonce_appended(&NONCE, PLAINTEXT).unwrap();
    assert_eq!(inline_layout, owned_layout);
    assert_eq!(
        inline.decrypt_nonce_appended(&inline_layout).unwrap(),
        PLAINTEXT
    );

    let layout = HardwareAes256GcmSiv::key_state_layout();
    let mut storage = vec![0_u8; layout.size + layout.align];
    let offset = storage.as_ptr().align_offset(layout.align);
    let slot = SivUninitKeyStateSlot::new(&mut storage[offset..offset + layout.size]).unwrap();
    let placed = HardwareAes256GcmSivIn::new_in(&KEY, slot).unwrap();
    let placed_ct = placed.encrypt(&NONCE, AAD, PLAINTEXT).unwrap();
    assert_eq!(placed_ct, reference_encrypt(&KEY, &NONCE, AAD, PLAINTEXT));
    assert_eq!(placed.decrypt(&NONCE, AAD, &placed_ct).unwrap(), PLAINTEXT);
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32-byte hex")
}

fn hex12(s: &str) -> [u8; NONCE_SIZE] {
    hex(s).try_into().expect("12-byte hex")
}
