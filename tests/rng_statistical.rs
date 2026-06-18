//! Lightweight always-on statistical sanity checks for the AES-CTR generator.
//!
//! These are *not* a substitute for a full battery (`PractRand` / dieharder via
//! `examples/rng_dump.rs`, see docs/randomness-testing.md) - they are cheap
//! deterministic guards that catch gross breakage (a stuck or biased
//! generator) in every CI run. The generator is seeded deterministically, so
//! the statistics are reproducible and the thresholds are generous enough never
//! to flake while a real defect would blow past them by orders of magnitude.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::similar_names,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use hardware_rust_crypto::random::{AesCtrKeyGenerator, KeyGenerator as _, AES_CTR_SEED_SIZE};

const SAMPLE_BYTES: usize = 4 * 1024 * 1024;

fn sample() -> Vec<u8> {
    let mut seed = [0_u8; AES_CTR_SEED_SIZE];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    let mut generator = AesCtrKeyGenerator::from_seed(&mut seed).expect("hardware AES-CTR");
    let mut out = vec![0_u8; SAMPLE_BYTES];
    for chunk in out.chunks_mut(1 << 16) {
        generator.fill_bytes(chunk).unwrap();
    }
    out
}

/// Monobit frequency: the fraction of one-bits must be ~0.5. With ~33.5M bits
/// the standard deviation of the count is ~2896; a |z| over 6 is astronomically
/// unlikely by chance but trivial for a biased generator.
#[test]
fn monobit_frequency() {
    let data = sample();
    let ones: u64 = data.iter().map(|b| u64::from(b.count_ones())).sum();
    let bits = (data.len() * 8) as f64;
    let mean = bits / 2.0;
    let sd = bits.sqrt() / 2.0;
    let z = (ones as f64 - mean).abs() / sd;
    assert!(z < 6.0, "monobit bias: ones={ones} bits={bits} |z|={z:.2}");
}

/// Byte-value chi-square over 256 buckets (255 dof, mean 255, sd ~22.6). A
/// uniform stream lands near 255; a stuck/structured stream explodes into the
/// thousands. Bounds are wide to never flake on a healthy generator.
#[test]
fn byte_distribution_chi_square() {
    let data = sample();
    let mut counts = [0_u64; 256];
    for &b in &data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    let chi2: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    assert!(
        (100.0..400.0).contains(&chi2),
        "byte chi-square out of range: {chi2:.1} (expected ~255)"
    );
}

/// Lag-1 serial correlation must be near zero. A generator that leaks structure
/// between successive bytes shows up as a non-trivial correlation coefficient.
#[test]
fn serial_correlation_near_zero() {
    let data = sample();
    let n = data.len() - 1;
    let mut sum_xy = 0.0_f64;
    let mut sum_x = 0.0_f64;
    let mut sum_x2 = 0.0_f64;
    for w in data.windows(2) {
        let (x, y) = (f64::from(w[0]), f64::from(w[1]));
        sum_xy += x * y;
        sum_x += x;
        sum_x2 += x * x;
    }
    let nf = n as f64;
    let num = nf * sum_xy - sum_x * sum_x;
    let den = nf * sum_x2 - sum_x * sum_x;
    let corr = num / den;
    assert!(
        corr.abs() < 0.01,
        "lag-1 serial correlation too high: {corr:.5}"
    );
}
