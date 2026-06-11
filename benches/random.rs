#![allow(clippy::unwrap_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hardware_random::{AesCtrKeyGenerator, ChaCha20KeyGenerator, FastRandom};
use rand::{RngCore as _, SeedableRng as _, TryRngCore as _};
use rand_chacha::ChaCha20Rng;

fn bench_random(c: &mut Criterion) {
    c.bench_function("random/fast-random-key-32", |b| {
        let mut rng = FastRandom::from_os_entropy().unwrap();
        b.iter(|| rng.key_32().unwrap());
    });

    c.bench_function("random/chacha20-keygen-key-32", |b| {
        let mut rng = ChaCha20KeyGenerator::from_os_entropy().unwrap();
        b.iter(|| rng.key_32().unwrap());
    });

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

    c.bench_function("random/os-rng-key-32", |b| {
        b.iter(|| {
            let mut out = [0_u8; 32];
            rand::rngs::OsRng
                .try_fill_bytes(black_box(&mut out))
                .unwrap();
            out
        });
    });

    c.bench_function("random/fast-random-nonce-12", |b| {
        let mut rng = FastRandom::from_os_entropy().unwrap();
        b.iter(|| rng.nonce_12().unwrap());
    });

    c.bench_function("random/chacha20-keygen-nonce-12", |b| {
        let mut rng = ChaCha20KeyGenerator::from_os_entropy().unwrap();
        b.iter(|| rng.nonce_12().unwrap());
    });

    if AesCtrKeyGenerator::hardware_available() {
        c.bench_function("random/aes-ctr-keygen-nonce-12", |b| {
            let mut rng = AesCtrKeyGenerator::from_os_entropy().unwrap();
            b.iter(|| rng.nonce_12().unwrap());
        });
    }
}

criterion_group!(benches, bench_random);
criterion_main!(benches);
