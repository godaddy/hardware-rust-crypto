//! Property-based tests for both AEAD modes (envelope API).
//!
//! Two classes of property:
//!
//! - **Round-trip / consistency.** Decryption of the generated `ct||tag||nonce`
//!   envelope recovers the plaintext for arbitrary inputs.
//! - **Parser robustness.** The decrypt entry points are the only surface that
//!   consumes attacker-controlled bytes, so they must return a `Result` -
//!   never panic, never trip a debug assertion, never invoke undefined
//!   behavior - on *arbitrary* AAD/envelope input. proptest fails the test on
//!   any panic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hardware_rust_crypto::aes_gcm::{HardwareAes256Gcm, HardwareAes256GcmSiv};
use proptest::collection::vec;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // ---- round-trip ----

    #[test]
    fn gcm_round_trips(
        key in any::<[u8; 32]>(),
        aad in vec(any::<u8>(), 0..96),
        plaintext in vec(any::<u8>(), 0..600),
    ) {
        let mut cipher = HardwareAes256Gcm::new(&key).unwrap();
        let envelope = cipher.encrypt(&aad, &plaintext).unwrap();
        prop_assert_eq!(cipher.decrypt(&aad, &envelope).unwrap(), plaintext);
    }

    #[test]
    fn siv_round_trips(
        key in any::<[u8; 32]>(),
        aad in vec(any::<u8>(), 0..96),
        plaintext in vec(any::<u8>(), 0..600),
    ) {
        let mut cipher = HardwareAes256GcmSiv::new(&key).unwrap();
        let envelope = cipher.encrypt(&aad, &plaintext).unwrap();
        prop_assert_eq!(cipher.decrypt(&aad, &envelope).unwrap(), plaintext);
    }

    // ---- tampering is always rejected ----

    #[test]
    fn gcm_single_byte_tamper_is_rejected(
        key in any::<[u8; 32]>(),
        aad in vec(any::<u8>(), 0..32),
        plaintext in vec(any::<u8>(), 0..200),
        flip in any::<u8>(),
        idx in any::<prop::sample::Index>(),
    ) {
        let mut cipher = HardwareAes256Gcm::new(&key).unwrap();
        let mut env = cipher.encrypt(&aad, &plaintext).unwrap();
        let i = idx.index(env.len());
        env[i] ^= 1_u8 << (flip % 8);
        prop_assert!(cipher.decrypt(&aad, &env).is_err());
    }

    #[test]
    fn siv_single_byte_tamper_is_rejected(
        key in any::<[u8; 32]>(),
        aad in vec(any::<u8>(), 0..32),
        plaintext in vec(any::<u8>(), 0..200),
        flip in any::<u8>(),
        idx in any::<prop::sample::Index>(),
    ) {
        let mut cipher = HardwareAes256GcmSiv::new(&key).unwrap();
        let mut env = cipher.encrypt(&aad, &plaintext).unwrap();
        let i = idx.index(env.len());
        env[i] ^= 1_u8 << (flip % 8);
        prop_assert!(cipher.decrypt(&aad, &env).is_err());
    }

    // ---- parser robustness on arbitrary attacker-controlled bytes ----

    #[test]
    fn gcm_decrypt_never_panics(
        key in any::<[u8; 32]>(),
        aad in vec(any::<u8>(), 0..40),
        data in vec(any::<u8>(), 0..96),
    ) {
        let cipher = HardwareAes256Gcm::new(&key).unwrap();
        let _ = cipher.decrypt(&aad, &data);
        let mut out = vec![0_u8; data.len()];
        let _ = cipher.decrypt_to(&aad, &data, &mut out);
    }

    #[test]
    fn siv_decrypt_never_panics(
        key in any::<[u8; 32]>(),
        aad in vec(any::<u8>(), 0..40),
        data in vec(any::<u8>(), 0..96),
    ) {
        let cipher = HardwareAes256GcmSiv::new(&key).unwrap();
        let _ = cipher.decrypt(&aad, &data);
        let mut out = vec![0_u8; data.len()];
        let _ = cipher.decrypt_to(&aad, &data, &mut out);
    }

    // ---- construction never panics on arbitrary key bytes ----

    #[test]
    fn construction_never_panics(key in vec(any::<u8>(), 0..40)) {
        let _ = HardwareAes256Gcm::new(&key);
        let _ = HardwareAes256GcmSiv::new(&key);
    }
}
