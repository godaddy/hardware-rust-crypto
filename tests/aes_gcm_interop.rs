#![allow(clippy::unwrap_used, clippy::expect_used)]

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce as RustCryptoNonce};
use hardware_aes_gcm::{HardwareAes256Gcm, NONCE_SIZE, TAG_SIZE};
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
const PLAINTEXT: &[u8] = b"asherah hardware aes-gcm interop plaintext";

#[test]
fn candidate_encrypts_same_bytes_as_rustcrypto() {
    let candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let rustcrypto = Aes256Gcm::new_from_slice(&KEY).unwrap();

    let candidate_ct = candidate.encrypt(&NONCE, AAD, PLAINTEXT).unwrap();
    let rustcrypto_ct = rustcrypto
        .encrypt(
            RustCryptoNonce::from_slice(&NONCE),
            Payload {
                msg: PLAINTEXT,
                aad: AAD,
            },
        )
        .unwrap();

    assert_eq!(candidate_ct, rustcrypto_ct);
}

#[test]
fn candidate_ring_and_rustcrypto_decrypt_each_other() {
    let candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let candidate_ct = candidate.encrypt(&NONCE, AAD, PLAINTEXT).unwrap();
    assert_eq!(rustcrypto_decrypt(&candidate_ct), PLAINTEXT);
    assert_eq!(ring_decrypt(&candidate_ct), PLAINTEXT);

    let rustcrypto_ct = rustcrypto_encrypt();
    assert_eq!(
        candidate.decrypt(&NONCE, AAD, &rustcrypto_ct).unwrap(),
        PLAINTEXT
    );

    let ring_ct = ring_encrypt();
    assert_eq!(candidate.decrypt(&NONCE, AAD, &ring_ct).unwrap(), PLAINTEXT);
}

#[test]
fn asherah_layout_is_ciphertext_tag_nonce() {
    let candidate = HardwareAes256Gcm::new(&KEY).unwrap();
    let layout = candidate.encrypt_asherah_layout(&NONCE, PLAINTEXT).unwrap();

    assert_eq!(&layout[layout.len() - NONCE_SIZE..], NONCE);
    assert_eq!(layout.len(), PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE);
    assert_eq!(
        candidate.decrypt_asherah_layout(&layout).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn tampering_fails_authentication() {
    let candidate = HardwareAes256Gcm::new(&KEY).unwrap();
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

#[test]
fn nist_known_answer_vectors() {
    let key = [0_u8; 32];
    let nonce = [0_u8; NONCE_SIZE];
    let candidate = HardwareAes256Gcm::new(&key).unwrap();

    assert_eq!(
        candidate.encrypt(&nonce, &[], &[]).unwrap(),
        [
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
            0x73, 0x8b,
        ]
    );

    assert_eq!(
        candidate.encrypt(&nonce, &[], &[0_u8; 16]).unwrap(),
        [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
            0xd4, 0x8a, 0xb9, 0x19,
        ]
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
            let mut nonce = [0_u8; NONCE_SIZE];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let candidate = HardwareAes256Gcm::new(&key).unwrap();
            let rustcrypto = Aes256Gcm::new_from_slice(&key).unwrap();
            let candidate_ct = candidate.encrypt(&nonce, &aad, &plaintext).unwrap();
            let rustcrypto_ct = rustcrypto
                .encrypt(
                    RustCryptoNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext.as_slice(),
                        aad: aad.as_slice(),
                    },
                )
                .unwrap();

            assert_eq!(candidate_ct, rustcrypto_ct);
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

fn rustcrypto_encrypt() -> Vec<u8> {
    let rustcrypto = Aes256Gcm::new_from_slice(&KEY).unwrap();
    rustcrypto
        .encrypt(
            RustCryptoNonce::from_slice(&NONCE),
            Payload {
                msg: PLAINTEXT,
                aad: AAD,
            },
        )
        .unwrap()
}

fn rustcrypto_decrypt(ciphertext: &[u8]) -> Vec<u8> {
    let rustcrypto = Aes256Gcm::new_from_slice(&KEY).unwrap();
    rustcrypto
        .decrypt(
            RustCryptoNonce::from_slice(&NONCE),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .unwrap()
}

fn ring_encrypt() -> Vec<u8> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
    let mut in_out = PLAINTEXT.to_vec();
    key.seal_in_place_append_tag(
        RingNonce::assume_unique_for_key(NONCE),
        Aad::from(AAD),
        &mut in_out,
    )
    .unwrap();
    in_out
}

fn ring_decrypt(ciphertext: &[u8]) -> Vec<u8> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            RingNonce::assume_unique_for_key(NONCE),
            Aad::from(AAD),
            &mut in_out,
        )
        .unwrap();
    let len = plaintext.len();
    in_out.truncate(len);
    in_out
}
