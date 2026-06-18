//! dudect-style statistical timing check for the AES-256-GCM-SIV decrypt path.
//!
//! The companion of `timing_constant_time.rs` for the SIV mode. Same Welch
//! t-test methodology over interleaved samples; the same two properties must
//! hold for SIV decryption:
//!
//! - **Tag-comparison independence from mismatch position.** Two *invalid*
//!   inputs whose stored tag differs in the first byte versus the last must
//!   take the same time. In SIV the stored tag is also the initial CTR counter,
//!   so this additionally checks that the little-endian counter handling and
//!   the keystream pass are independent of which tag byte changed; what must
//!   never leak is *how much* of the recomputed tag matched, the property
//!   `subtle`'s constant-time comparison protects.
//! - **Independence from ciphertext content.** Two *valid* ciphertexts of equal
//!   length but different plaintext must decrypt in the same time. (This is also
//!   structural: SIV decryption is a data-independent CTR XOR followed by a
//!   POLYVAL pass over data-independent PMULL/CLMUL, then a constant-time tag
//!   comparison.)
//!
//! As in the GCM harness, valid-vs-invalid timing is deliberately NOT asserted
//! equal: failed authentication additionally zeroizes the output, and the
//! accept/reject outcome is the public `Result` the caller already learns.
//!
//! Coarse, machine-sensitive, `#[ignore]` by default; run deliberately:
//!
//! ```sh
//! cargo test --release --test timing_constant_time_siv -- --ignored --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::items_after_statements
)]

use std::hint::black_box;
use std::time::Instant;

use aes_gcm_siv::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as RustCryptoNonce};
use hardware_rust_crypto::aes_gcm::{HardwareAes256GcmSiv, NONCE_SIZE, TAG_SIZE};

const KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; NONCE_SIZE] = [0x24; NONCE_SIZE];
const MSG_LEN: usize = 1024;
const T_THRESHOLD: f64 = 25.0;
const MEASUREMENTS: usize = 300_000;
const WARMUP: usize = 30_000;
const OUTLIER_CEILING_NS: u64 = 2_000;

/// Online mean/variance accumulator (Welford) for one input class.
#[derive(Default, Clone, Copy)]
struct Stats {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Stats {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (x - self.mean);
    }

    fn variance(&self) -> f64 {
        if self.n < 2.0 {
            0.0
        } else {
            self.m2 / (self.n - 1.0)
        }
    }
}

fn welch_t(a: &Stats, b: &Stats) -> f64 {
    let va = a.variance() / a.n;
    let vb = b.variance() / b.n;
    let denom = (va + vb).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (a.mean - b.mean) / denom
    }
}

fn time_decrypt(key: &HardwareAes256GcmSiv, ciphertext: &[u8]) -> u64 {
    let start = Instant::now();
    let result = key.decrypt(black_box(&[]), black_box(ciphertext));
    black_box(&result);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn measure(label: &str, key: &HardwareAes256GcmSiv, mut prep: impl FnMut(bool) -> Vec<u8>) -> f64 {
    let mut rng_state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next_bit = || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state & 1 == 1
    };

    let mut class0 = Stats::default();
    let mut class1 = Stats::default();

    for i in 0..(MEASUREMENTS + WARMUP) {
        let class = next_bit();
        let ciphertext = prep(class);
        let dt = time_decrypt(key, &ciphertext);
        if i < WARMUP {
            continue;
        }
        if dt > OUTLIER_CEILING_NS {
            continue;
        }
        let dt = dt as f64;
        if class {
            class1.push(dt);
        } else {
            class0.push(dt);
        }
    }

    let t = welch_t(&class0, &class1);
    println!(
        "{label}: |t| = {:.3} (n0 = {}, n1 = {}, mean0 = {:.1}ns, mean1 = {:.1}ns)",
        t.abs(),
        class0.n as u64,
        class1.n as u64,
        class0.mean,
        class1.mean,
    );
    t.abs()
}

#[test]
#[ignore = "slow, machine-sensitive; run deliberately per docs/constant-time.md"]
fn siv_tag_comparison_independent_of_mismatch_position() {
    let key = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let plaintext = [0xa5_u8; MSG_LEN];
    let base = encrypt_envelope_with_nonce(&NONCE, &plaintext);
    let tag_start = base.len() - TAG_SIZE - NONCE_SIZE;

    // Both inputs fail authentication; they differ only in which stored-tag
    // byte was flipped (first versus last). A constant-time comparison plus a
    // data-independent CTR/POLYVAL pass cannot tell them apart.
    let mut early_mismatch = base.clone();
    early_mismatch[tag_start] ^= 0x01;
    let mut late_mismatch = base;
    late_mismatch[tag_start + TAG_SIZE - 1] ^= 0x01;

    let t = measure("siv-tag-mismatch-position", &key, |class| {
        if class {
            early_mismatch.clone()
        } else {
            late_mismatch.clone()
        }
    });

    assert!(
        t < T_THRESHOLD,
        "SIV tag comparison timing depends on mismatch position (|t| = {t:.3} >= {T_THRESHOLD})"
    );
}

#[test]
#[ignore = "slow, machine-sensitive; run deliberately per docs/constant-time.md"]
fn siv_decrypt_timing_independent_of_ciphertext_content() {
    let key = HardwareAes256GcmSiv::new(&KEY).unwrap();

    const POOL: usize = 256;
    let mut rng_state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next_byte = || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        (rng_state >> 24) as u8
    };
    let low_pool: Vec<Vec<u8>> = (0..POOL)
        .map(|p| {
            let nonce = nonce_for_pool_entry(p);
            encrypt_envelope_with_nonce(&nonce, &[p as u8; MSG_LEN])
        })
        .collect();
    let high_pool: Vec<Vec<u8>> = (0..POOL)
        .map(|p| {
            let mut plaintext = [0_u8; MSG_LEN];
            for byte in &mut plaintext {
                *byte = next_byte();
            }
            let nonce = nonce_for_pool_entry(POOL + p);
            encrypt_envelope_with_nonce(&nonce, &plaintext)
        })
        .collect();

    let mut pool_index = 0_usize;
    let t = measure("siv-low-vs-high-entropy-content", &key, |class| {
        pool_index = (pool_index + 1) % POOL;
        if class {
            high_pool[pool_index].clone()
        } else {
            low_pool[pool_index].clone()
        }
    });

    assert!(
        t < T_THRESHOLD,
        "SIV decrypt timing distinguishes ciphertext content (|t| = {t:.3} >= {T_THRESHOLD})"
    );
}

fn encrypt_envelope_with_nonce(nonce: &[u8; NONCE_SIZE], plaintext: &[u8]) -> Vec<u8> {
    let key = Aes256GcmSiv::new_from_slice(&KEY).unwrap();
    let mut envelope = key
        .encrypt(
            RustCryptoNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .unwrap();
    envelope.extend_from_slice(nonce);
    envelope
}

fn nonce_for_pool_entry(entry: usize) -> [u8; NONCE_SIZE] {
    let mut nonce = NONCE;
    nonce[4..].copy_from_slice(&(entry as u64).to_be_bytes());
    nonce
}
