//! Project Wycheproof AES-256-GCM-SIV test vectors.
//!
//! Belt-and-suspenders known-answer coverage from an authoritative third-party
//! source independent of both this crate and `RustCrypto`. The vendored file
//! `tests/data/wycheproof_aes_gcm_siv.json` is Project Wycheproof v0.9rc5
//! (Apache-2.0; see NOTICE), embedded verbatim and downloaded, not transcribed.
//!
//! It is the strongest available counter-wrap check: the `WrappedIv` vectors
//! are "constructed to test for correct wrapping of the [mod 2^32] counter",
//! and the `ModifiedTag` vectors exercise the authentication-rejection path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hardware_rust_crypto::aes_gcm::{HardwareAes256GcmSiv, NONCE_SIZE};
use serde_json::Value;

const VECTORS: &str = include_str!("data/wycheproof_aes_gcm_siv.json");

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn wycheproof_aes_256_gcm_siv() {
    let root: Value = serde_json::from_str(VECTORS).expect("valid Wycheproof JSON");
    assert_eq!(root["algorithm"], "AES-GCM-SIV", "unexpected vendored file");

    let mut total = 0_usize;
    let mut valid = 0_usize;
    let mut invalid = 0_usize;
    let mut wrapped = 0_usize;

    for group in root["testGroups"].as_array().unwrap() {
        // Only AES-256 (the algorithm this crate implements) with the standard
        // 96-bit nonce and 128-bit tag.
        if group["keySize"].as_u64() != Some(256) {
            continue;
        }
        assert_eq!(group["ivSize"].as_u64(), Some(96));
        assert_eq!(group["tagSize"].as_u64(), Some(128));

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

            assert_eq!(iv.len(), NONCE_SIZE, "tcId {tc_id}: unexpected nonce length");
            let cipher = HardwareAes256GcmSiv::new(&key).unwrap();

            total += 1;
            let is_wrap = flags.contains(&"WrappedIv");
            if is_wrap {
                wrapped += 1;
            }

            match result {
                "valid" => {
                    valid += 1;
                    // Encryption must produce exactly ciphertext || tag.
                    let produced = cipher.encrypt(&iv, &aad, &msg).unwrap();
                    assert_eq!(
                        produced, ct_and_tag,
                        "tcId {tc_id} ({flags:?}): encryption mismatch"
                    );
                    // Decryption must recover the plaintext.
                    let recovered = cipher.decrypt(&iv, &aad, &ct_and_tag).unwrap();
                    assert_eq!(recovered, msg, "tcId {tc_id} ({flags:?}): decryption mismatch");
                }
                "invalid" => {
                    invalid += 1;
                    // Modified tag / ciphertext must be rejected.
                    assert!(
                        cipher.decrypt(&iv, &aad, &ct_and_tag).is_err(),
                        "tcId {tc_id} ({flags:?}): invalid vector authenticated"
                    );
                }
                other => panic!("tcId {tc_id}: unknown result {other}"),
            }
        }
    }

    // Pin the counts so a silently-changed vendored file is noticed, and prove
    // the counter-wrap and rejection paths were actually exercised.
    assert_eq!(total, 103, "expected 103 AES-256-GCM-SIV vectors");
    assert_eq!(valid, 69);
    assert_eq!(invalid, 34);
    assert_eq!(wrapped, 5, "the counter-wrap (WrappedIv) vectors must be present");
    println!("Wycheproof AES-256-GCM-SIV: {total} vectors ({valid} valid, {invalid} invalid, {wrapped} counter-wrap) all passed");
}
