//! Criterion benchmarks comparing key/nonce generation backends.
//!
//! The production generator is `AesCtrKeyGenerator`; the raw `rand_chacha` and
//! `salsa20` rows are software-cipher comparison baselines (dev-dependencies
//! only), measured without lifecycle checks.

// Criterion's macros generate undocumented public items.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hardware_random::{AesCtrKeyGenerator, KeyGenerator as _};
use rand::{RngCore as _, SeedableRng as _, TryRngCore as _};
use rand_chacha::ChaCha20Rng;
use salsa20::cipher::{KeyIvInit as _, StreamCipher as _};
use salsa20::Salsa20;

fn bench_random(c: &mut Criterion) {
    if AesCtrKeyGenerator::hardware_available() {
        c.bench_function("random/aes-ctr-keygen-key-32", |b| {
            let mut rng = AesCtrKeyGenerator::from_os_entropy().unwrap();
            b.iter(|| rng.key_32().unwrap());
        });
    }

    c.bench_function("random/rand-chacha-key-32", |b| {
        let mut seed = <ChaCha20Rng as rand::SeedableRng>::Seed::default();
        rand::rngs::OsRng.try_fill_bytes(&mut seed).unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        b.iter(|| {
            let mut out = [0_u8; 32];
            rng.fill_bytes(black_box(&mut out));
            out
        });
    });

    c.bench_function("random/salsa20-keystream-key-32", |b| {
        // Raw Salsa20 keystream (no lifecycle checks), the Salsa-family
        // baseline alongside the raw rand_chacha row.
        let mut key = [0_u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut key).unwrap();
        let mut cipher = Salsa20::new(&key.into(), &[0_u8; 8].into());
        b.iter(|| {
            let mut out = [0_u8; 32];
            cipher.apply_keystream(black_box(&mut out));
            out
        });
    });

    c.bench_function("random/os-rng-key-32", |b| {
        b.iter(|| {
            let mut out = [0_u8; 32];
            rand::rngs::OsRng
                .try_fill_bytes(black_box(&mut out))
                .unwrap();
            out
        });
    });

    let mut group = c.benchmark_group("random/fill-4096");
    group.throughput(criterion::Throughput::Bytes(4096));
    if AesCtrKeyGenerator::hardware_available() {
        group.bench_function("aes-ctr-keygen", |b| {
            let mut rng = AesCtrKeyGenerator::from_os_entropy().unwrap();
            let mut out = vec![0_u8; 4096];
            b.iter(|| rng.fill_bytes(black_box(&mut out)).unwrap());
        });
    }
    group.bench_function("rand-chacha", |b| {
        let mut seed = <ChaCha20Rng as rand::SeedableRng>::Seed::default();
        rand::rngs::OsRng.try_fill_bytes(&mut seed).unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut out = vec![0_u8; 4096];
        b.iter(|| rng.fill_bytes(black_box(&mut out)));
    });
    group.bench_function("salsa20-keystream", |b| {
        let mut key = [0_u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut key).unwrap();
        let mut cipher = Salsa20::new(&key.into(), &[0_u8; 8].into());
        let mut out = vec![0_u8; 4096];
        b.iter(|| cipher.apply_keystream(black_box(&mut out)));
    });
    group.finish();

    if AesCtrKeyGenerator::hardware_available() {
        c.bench_function("random/aes-ctr-keygen-nonce-12", |b| {
            let mut rng = AesCtrKeyGenerator::from_os_entropy().unwrap();
            b.iter(|| rng.nonce_12().unwrap());
        });
    }
}

criterion_group!(benches, bench_random);
criterion_main!(benches);
