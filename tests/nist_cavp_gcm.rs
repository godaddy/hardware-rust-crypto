//! NIST CAVP AES-256-GCM known-answer vectors.
//!
//! The official NIST Cryptographic Algorithm Validation Program GCM vectors -
//! an exhaustive known-answer set well beyond the handful of inline NIST KATs.
//! The vendored file `tests/data/nist_cavp_aes256_gcm.json` is the
//! `Keylen=256, IVlen=96, Taglen=128` subset (the parameters this crate
//! implements) of `gcmEncryptExtIV256.rsp` and `gcmDecrypt256.rsp`, a U.S.
//! Government work in the public domain (downloaded, not transcribed; see
//! NOTICE). Running these is functional KAT coverage, not CAVP accreditation.
//!
//! The crate's default API generates the nonce and returns a `ct||tag||nonce`
//! envelope, so each vector is validated by decrypting the known
//! `ct||tag||nonce` envelope and checking it recovers the known plaintext
//! (every byte of the AES-CTR keystream and GHASH must match the spec for the
//! known nonce), and the `FAIL` records must be rejected. With the
//! `hazmat-explicit-nonce` feature, encryption is additionally checked to
//! reproduce the known `ct||tag` byte-for-byte under the fixed nonce.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hardware_rust_crypto::aes_gcm::{HardwareAes256Gcm, NONCE_SIZE};
use serde_json::Value;

const VECTORS: &str = include_str!("data/nist_cavp_aes256_gcm.json");

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Decrypt the known `ct||tag||nonce` envelope and require it recovers `pt`.
fn check_decrypts_to(key: &[u8], iv: &[u8], aad: &[u8], ct: &[u8], tag: &[u8], pt: &[u8]) {
    assert_eq!(iv.len(), NONCE_SIZE, "unexpected nonce length");
    let mut envelope = ct.to_vec();
    envelope.extend_from_slice(tag);
    envelope.extend_from_slice(iv);
    let cipher = HardwareAes256Gcm::new(key).unwrap();
    assert_eq!(
        cipher.decrypt(aad, &envelope).unwrap(),
        pt,
        "CAVP decrypt mismatch"
    );
}

#[test]
fn nist_cavp_aes_256_gcm() {
    let root: Value = serde_json::from_str(VECTORS).expect("valid CAVP JSON");

    let mut enc_count = 0_usize;
    for v in root["encrypt"].as_array().unwrap() {
        let key = hex(v["Key"].as_str().unwrap());
        let iv = hex(v["IV"].as_str().unwrap());
        let pt = hex(v["PT"].as_str().unwrap());
        let aad = hex(v["AAD"].as_str().unwrap());
        let ct = hex(v["CT"].as_str().unwrap());
        let tag = hex(v["Tag"].as_str().unwrap());

        // Decrypting the official ct||tag||nonce must recover the plaintext.
        check_decrypts_to(&key, &iv, &aad, &ct, &tag, &pt);

        // Generated-envelope round trip (default API).
        let mut cipher = HardwareAes256Gcm::new(&key).unwrap();
        let envelope = cipher.encrypt(&aad, &pt).unwrap();
        assert_eq!(cipher.decrypt(&aad, &envelope).unwrap(), pt);

        // Byte-exact encryption under the fixed nonce (hazmat feature only).
        #[cfg(feature = "hazmat-explicit-nonce")]
        {
            let mut expected = ct.clone();
            expected.extend_from_slice(&tag);
            assert_eq!(
                cipher.encrypt_with_nonce(&iv, &aad, &pt).unwrap(),
                expected,
                "CAVP encrypt #{enc_count} byte mismatch"
            );
        }
        enc_count += 1;
    }

    let mut dec_count = 0_usize;
    let mut fail_count = 0_usize;
    for v in root["decrypt"].as_array().unwrap() {
        let key = hex(v["Key"].as_str().unwrap());
        let iv = hex(v["IV"].as_str().unwrap());
        let ct = hex(v["CT"].as_str().unwrap());
        let aad = hex(v["AAD"].as_str().unwrap());
        let tag = hex(v["Tag"].as_str().unwrap());

        if v.get("fail").is_some() {
            let mut envelope = ct.clone();
            envelope.extend_from_slice(&tag);
            envelope.extend_from_slice(&iv);
            let cipher = HardwareAes256Gcm::new(&key).unwrap();
            assert!(
                cipher.decrypt(&aad, &envelope).is_err(),
                "CAVP decrypt FAIL #{dec_count} was accepted"
            );
            fail_count += 1;
        } else {
            let pt = hex(v["PT"].as_str().unwrap());
            check_decrypts_to(&key, &iv, &aad, &ct, &tag, &pt);
        }
        dec_count += 1;
    }

    assert_eq!(enc_count, 375, "expected 375 CAVP encrypt vectors");
    assert_eq!(dec_count, 375, "expected 375 CAVP decrypt vectors");
    assert_eq!(fail_count, 191, "expected 191 CAVP decrypt FAIL vectors");
    println!(
        "NIST CAVP AES-256-GCM: {enc_count} encrypt + {dec_count} decrypt ({fail_count} FAIL) all passed"
    );
}
