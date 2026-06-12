//! dudect-style statistical timing check for the decryption path.
//!
//! Measures whether the public decrypt API's timing is distinguishable across
//! input classes that must be indistinguishable. Uses Welch's t-test over
//! interleaved samples (the dudect methodology). A |t| statistic that stays
//! bounded as samples accumulate is consistent with constant-time behavior; a
//! |t| that grows without bound indicates a data-dependent timing channel.
//!
//! The two properties tested:
//!
//! - **Tag-comparison independence from mismatch position.** Two *invalid*
//!   tags, one mismatching in the first byte and one in the last, must take
//!   the same time. A faster early-mismatch would mean the comparison
//!   early-exits, which is the leak that lets an attacker forge a tag byte by
//!   byte. (This is the property `subtle` protects.)
//! - **Independence from ciphertext content.** Two *valid* ciphertexts of
//!   equal length but different plaintext must decrypt in the same time.
//!
//! Note what is deliberately NOT asserted: valid and invalid tags take exactly
//! the same time. Failed authentication additionally zeroizes the output range
//! after the constant-time comparison, so valid-vs-invalid timing may differ.
//! That difference reveals only the authentication outcome, which is the public
//! `Result` the caller already receives. What must not leak is *how much* of
//! the tag matched, which the mismatch-position test covers.
//!
//! This is a coarse, machine-sensitive guard against gross regressions, not a
//! certification - see `docs/constant-time.md`. It is `#[ignore]` by default
//! because it is slow and noisy on shared CI; run it deliberately:
//!
//! ```sh
//! cargo test --release --test timing_constant_time -- --ignored --nocapture
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

use hardware_rust_crypto::aes_gcm::{HardwareAes256Gcm, NONCE_SIZE, TAG_SIZE};

const KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; NONCE_SIZE] = [0x24; NONCE_SIZE];
const MSG_LEN: usize = 1024;
/// Welch |t| above this is treated as evidence of a data-dependent channel.
///
/// dudect's canonical threshold is ~4.5 under its clean continuous-measurement
/// setup. This harness runs a single batch on a potentially noisy machine, so
/// it uses a wider margin calibrated to the demonstrated signal/noise gap: a
/// real early-exit leak in this code produces |t| in the hundreds (an
/// early-vs-late tag-mismatch leak measured ~267), while residual measurement
/// noise after outlier cropping sits in the low single digits. A threshold of
/// 25 cleanly separates the two without flaking on cache/scheduler jitter.
const T_THRESHOLD: f64 = 25.0;
const MEASUREMENTS: usize = 300_000;
const WARMUP: usize = 30_000;
/// Measurements slower than this are treated as preemption/scheduler outliers
/// and dropped (dudect-style cropping), rather than clamped - clamping biases
/// the mean, dropping does not. The decrypt paths here run in ~200-300 ns, so
/// anything past 2 us is OS noise, not the operation under test.
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

/// Welch's t-statistic between two classes.
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

/// Times one decrypt call (errors expected for the invalid-tag class; the
/// timing, not the result, is what we measure).
fn time_decrypt(key: &HardwareAes256Gcm, ciphertext: &[u8]) -> u64 {
    let start = Instant::now();
    let result = key.decrypt(black_box(&NONCE), black_box(&[]), black_box(ciphertext));
    black_box(&result);
    // Trim to a coarse tick count; wall-clock ns is fine for a t-test on
    // hundreds of thousands of samples.
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Runs an interleaved two-class measurement and returns the final |t|.
/// `prep` maps the class bit to the ciphertext fed to decrypt.
fn measure(label: &str, key: &HardwareAes256Gcm, mut prep: impl FnMut(bool) -> Vec<u8>) -> f64 {
    // Deterministic, dependency-free bit stream (xorshift) so the test needs
    // no rng crate and the class assignment is reproducible.
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
        // dudect discards the largest measurements as OS-scheduling noise.
        // Drop (do not clamp) outliers so the surviving mean is unbiased.
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
fn tag_comparison_independent_of_mismatch_position() {
    let key = HardwareAes256Gcm::new(&KEY).unwrap();
    let plaintext = [0xa5_u8; MSG_LEN];
    let base = key.encrypt(&NONCE, &[], &plaintext).unwrap();
    let tag_start = base.len() - TAG_SIZE;

    // Both ciphertexts fail authentication; they differ only in *where* the
    // tag mismatches. A constant-time comparison cannot tell them apart, and
    // both run the same decrypt-and-failure-wipe path.
    let mut early_mismatch = base.clone();
    early_mismatch[tag_start] ^= 0x01;
    let mut late_mismatch = base;
    *late_mismatch.last_mut().unwrap() ^= 0x01;

    let t = measure("tag-mismatch-position", &key, |class| {
        if class {
            early_mismatch.clone()
        } else {
            late_mismatch.clone()
        }
    });

    assert!(
        t < T_THRESHOLD,
        "tag comparison timing depends on mismatch position (|t| = {t:.3} >= {T_THRESHOLD})"
    );
}

#[test]
#[ignore = "slow, machine-sensitive; run deliberately per docs/constant-time.md"]
fn decrypt_timing_independent_of_ciphertext_content() {
    let key = HardwareAes256Gcm::new(&KEY).unwrap();

    // Two equal-size pools rotated in lockstep so both classes have an
    // identical memory-access pattern (same number of distinct buffers, same
    // rotation). The only difference is the plaintext content underlying each
    // ciphertext: the low-entropy pool encrypts byte 0x00, the high-entropy
    // pool encrypts pseudo-random bytes. A fixed-vs-fixed or hot-vs-cold-pool
    // design would instead measure cache residency of the harness, not the
    // crypto. (Content independence is also structural: the CTR pass is a byte
    // XOR and GHASH uses data-independent PMULL, so no instruction's timing
    // depends on the data bytes.)
    const POOL: usize = 256;
    let mut rng_state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next_byte = || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        (rng_state >> 24) as u8
    };
    // Distinct low-entropy plaintexts (a rotating single byte) so the two
    // pools occupy the same number of distinct buffers without being
    // identical ciphertexts.
    let low_pool: Vec<Vec<u8>> = (0..POOL)
        .map(|p| key.encrypt(&NONCE, &[], &[p as u8; MSG_LEN]).unwrap())
        .collect();
    let high_pool: Vec<Vec<u8>> = (0..POOL)
        .map(|_| {
            let mut plaintext = [0_u8; MSG_LEN];
            for byte in &mut plaintext {
                *byte = next_byte();
            }
            key.encrypt(&NONCE, &[], &plaintext).unwrap()
        })
        .collect();

    let mut pool_index = 0_usize;
    let t = measure("low-vs-high-entropy-content", &key, |class| {
        pool_index = (pool_index + 1) % POOL;
        if class {
            high_pool[pool_index].clone()
        } else {
            low_pool[pool_index].clone()
        }
    });

    assert!(
        t < T_THRESHOLD,
        "decrypt timing distinguishes ciphertext content (|t| = {t:.3} >= {T_THRESHOLD})"
    );
}
