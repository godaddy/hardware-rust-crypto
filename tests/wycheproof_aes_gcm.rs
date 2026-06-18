//! Project Wycheproof AES-256-GCM test vectors.
//!
//! Authoritative third-party known-answer coverage for the fused AES-256-GCM
//! path, independent of both this crate and `RustCrypto`. The vendored file
//! `tests/data/wycheproof_aes_gcm.json` is Project Wycheproof v0.9rc5
//! (Apache-2.0; see NOTICE), embedded verbatim and downloaded, not transcribed.
//!
//! This crate fixes AES-256, a 96-bit nonce, and a 128-bit tag, so the suite is
//! filtered to `keySize == 256 && ivSize == 96 && tagSize == 128`. The
//! `ModifiedTag` vectors exercise the authentication-rejection path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hardware_rust_crypto::aes_gcm::{HardwareAes256Gcm, NONCE_SIZE};
use serde_json::Value;

const VECTORS: &str = include_str!("data/wycheproof_aes_gcm.json");

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn wycheproof_aes_256_gcm() {
    let root: Value = serde_json::from_str(VECTORS).expect("valid Wycheproof JSON");
    assert_eq!(root["algorithm"], "AES-GCM", "unexpected vendored file");

    let mut total = 0_usize;
    let mut valid = 0_usize;
    let mut invalid = 0_usize;

    for group in root["testGroups"].as_array().unwrap() {
        // This crate implements only AES-256-GCM with a 96-bit nonce and a
        // 128-bit tag; skip the truncated-tag and exotic-IV groups.
        if group["keySize"].as_u64() != Some(256)
            || group["ivSize"].as_u64() != Some(96)
            || group["tagSize"].as_u64() != Some(128)
        {
            continue;
        }

        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let key = hex(test["key"].as_str().unwrap());
            let iv = hex(test["iv"].as_str().unwrap());
            let aad = hex(test["aad"].as_str().unwrap());
            let msg = hex(test["msg"].as_str().unwrap());
            let ct = hex(test["ct"].as_str().unwrap());
            let tag = hex(test["tag"].as_str().unwrap());
            let result = test["result"].as_str().unwrap();
            let flags: Vec<&str> = test["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();

            // The crate's wire format is ciphertext || tag.
            let mut ct_and_tag = ct.clone();
            ct_and_tag.extend_from_slice(&tag);

            assert_eq!(
                iv.len(),
                NONCE_SIZE,
                "tcId {tc_id}: unexpected nonce length"
            );
            let cipher = HardwareAes256Gcm::new(&key).unwrap();
            total += 1;

            match result {
                "valid" => {
                    valid += 1;
                    let produced = cipher.encrypt(&iv, &aad, &msg).unwrap();
                    assert_eq!(
                        produced, ct_and_tag,
                        "tcId {tc_id} ({flags:?}): encryption mismatch"
                    );
                    let recovered = cipher.decrypt(&iv, &aad, &ct_and_tag).unwrap();
                    assert_eq!(
                        recovered, msg,
                        "tcId {tc_id} ({flags:?}): decryption mismatch"
                    );
                }
                "invalid" => {
                    invalid += 1;
                    assert!(
                        cipher.decrypt(&iv, &aad, &ct_and_tag).is_err(),
                        "tcId {tc_id} ({flags:?}): invalid vector authenticated"
                    );
                }
                other => panic!("tcId {tc_id}: unknown result {other}"),
            }
        }
    }

    // Pin the counts so a silently-changed vendored file is noticed.
    assert_eq!(total, 66, "expected 66 AES-256-GCM (iv96/tag128) vectors");
    assert_eq!(valid, 39);
    assert_eq!(invalid, 27);
    println!(
        "Wycheproof AES-256-GCM: {total} vectors ({valid} valid, {invalid} invalid) all passed"
    );
}
