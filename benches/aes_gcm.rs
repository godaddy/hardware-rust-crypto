//! Criterion benchmarks comparing the candidate AES-256-GCM backend to stock
//! `RustCrypto` `aes-gcm` and `ring`.
//!
//! Run twice to capture both `RustCrypto` configurations (see
//! docs/benchmarks.md): once with default flags, once with
//! `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"` so the stock crates use
//! their aarch64 hardware backends.

// Criterion's macros generate undocumented public items, and the benchmark
// matrix is one long linear function by design.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce as RustCryptoNonce};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use hardware_rust_crypto::aes_gcm::{
    HardwareAes256Gcm, HardwareAes256GcmIn, HardwareAes256GcmKeyState, UninitKeyStateSlot,
    NONCE_SIZE, TAG_SIZE,
};
use ring::aead::{Aad, LessSafeKey, Nonce as RingNonce, UnboundKey, AES_256_GCM};

const KEY: [u8; 32] = [0x42; 32];
const AAD: &[u8] = b"";
const SIZES: [usize; 6] = [16, 64, 256, 1024, 4096, 16 * 1024];

#[repr(align(64))]
struct AlignedStorage([u8; 512]);

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-256-gcm encrypt");
    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xa5; size];

        group.bench_function(format!("candidate/{size}"), |b| {
            let key = HardwareAes256Gcm::new(&KEY).unwrap();
            let mut ctr = 0_u64;
            b.iter(|| {
                ctr = ctr.wrapping_add(1);
                key.encrypt(&nonce(ctr), AAD, black_box(&plaintext))
                    .unwrap()
            });
        });

        group.bench_function(format!("candidate-noalloc/{size}"), |b| {
            let key = HardwareAes256Gcm::new(&KEY).unwrap();
            let mut out = vec![0_u8; size + TAG_SIZE];
            let mut ctr = 0_u64;
            b.iter(|| {
                ctr = ctr.wrapping_add(1);
                key.encrypt_to(&nonce(ctr), AAD, black_box(&plaintext), &mut out)
                    .unwrap()
            });
        });

        group.bench_function(format!("rustcrypto/{size}"), |b| {
            let key = Aes256Gcm::new_from_slice(&KEY).unwrap();
            let mut ctr = 0_u64;
            b.iter(|| {
                ctr = ctr.wrapping_add(1);
                key.encrypt(
                    RustCryptoNonce::from_slice(&nonce(ctr)),
                    Payload {
                        msg: black_box(&plaintext),
                        aad: AAD,
                    },
                )
                .unwrap()
            });
        });

        group.bench_function(format!("ring/{size}"), |b| {
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
            let mut ctr = 0_u64;
            b.iter_batched(
                || {
                    ctr = ctr.wrapping_add(1);
                    (nonce(ctr), plaintext.clone())
                },
                |(nonce, mut in_out)| {
                    key.seal_in_place_append_tag(
                        RingNonce::assume_unique_for_key(nonce),
                        Aad::from(AAD),
                        black_box(&mut in_out),
                    )
                    .unwrap();
                    in_out
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-256-gcm decrypt");
    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xa5; size];
        let nonce = nonce(size as u64);

        let candidate_key = HardwareAes256Gcm::new(&KEY).unwrap();
        let candidate_ct = candidate_key.encrypt(&nonce, AAD, &plaintext).unwrap();
        group.bench_function(format!("candidate/{size}"), |b| {
            b.iter(|| {
                candidate_key
                    .decrypt(&nonce, AAD, black_box(&candidate_ct))
                    .unwrap()
            });
        });

        group.bench_function(format!("candidate-noalloc/{size}"), |b| {
            let mut out = vec![0_u8; size];
            b.iter(|| {
                candidate_key
                    .decrypt_to(&nonce, AAD, black_box(&candidate_ct), &mut out)
                    .unwrap()
            });
        });

        let rustcrypto_key = Aes256Gcm::new_from_slice(&KEY).unwrap();
        let rustcrypto_ct = rustcrypto_key
            .encrypt(
                RustCryptoNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .unwrap();
        group.bench_function(format!("rustcrypto/{size}"), |b| {
            b.iter(|| {
                rustcrypto_key
                    .decrypt(
                        RustCryptoNonce::from_slice(&nonce),
                        Payload {
                            msg: black_box(&rustcrypto_ct),
                            aad: AAD,
                        },
                    )
                    .unwrap()
            });
        });

        let ring_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
        let mut ring_ct = plaintext.clone();
        ring_key
            .seal_in_place_append_tag(
                RingNonce::assume_unique_for_key(nonce),
                Aad::from(AAD),
                &mut ring_ct,
            )
            .unwrap();
        group.bench_function(format!("ring/{size}"), |b| {
            b.iter_batched(
                || ring_ct.clone(),
                |mut in_out| {
                    let plaintext = ring_key
                        .open_in_place(
                            RingNonce::assume_unique_for_key(nonce),
                            Aad::from(AAD),
                            black_box(&mut in_out),
                        )
                        .unwrap();
                    plaintext.len()
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_encrypt_nonce_appended(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-256-gcm encrypt nonce-appended");
    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xa5; size];

        group.bench_function(format!("candidate/{size}"), |b| {
            let key = HardwareAes256Gcm::new(&KEY).unwrap();
            let mut ctr = 0_u64;
            b.iter(|| {
                ctr = ctr.wrapping_add(1);
                key.encrypt_nonce_appended(&nonce(ctr), black_box(&plaintext))
                    .unwrap()
            });
        });

        group.bench_function(format!("candidate-noalloc/{size}"), |b| {
            let key = HardwareAes256Gcm::new(&KEY).unwrap();
            let mut out = vec![0_u8; size + TAG_SIZE + NONCE_SIZE];
            let mut ctr = 0_u64;
            b.iter(|| {
                ctr = ctr.wrapping_add(1);
                key.encrypt_nonce_appended_to(&nonce(ctr), black_box(&plaintext), &mut out)
                    .unwrap()
            });
        });

        group.bench_function(format!("candidate-in-place/{size}"), |b| {
            let key = HardwareAes256Gcm::new(&KEY).unwrap();
            let mut ctr = 0_u64;
            b.iter_batched(
                || {
                    ctr = ctr.wrapping_add(1);
                    let nonce = nonce(ctr);
                    let mut in_out = Vec::with_capacity(size + TAG_SIZE + NONCE_SIZE);
                    in_out.extend_from_slice(&plaintext);
                    (nonce, in_out)
                },
                |(nonce, mut in_out)| {
                    key.encrypt_nonce_appended_in_place(&nonce, black_box(&mut in_out))
                        .unwrap();
                    in_out
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("ring/{size}"), |b| {
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
            let mut ctr = 0_u64;
            b.iter_batched(
                || {
                    ctr = ctr.wrapping_add(1);
                    let nonce = nonce(ctr);
                    let mut in_out = Vec::with_capacity(size + TAG_SIZE + NONCE_SIZE);
                    in_out.extend_from_slice(&plaintext);
                    (nonce, in_out)
                },
                |(nonce, mut in_out)| {
                    key.seal_in_place_append_tag(
                        RingNonce::assume_unique_for_key(nonce),
                        Aad::empty(),
                        black_box(&mut in_out),
                    )
                    .unwrap();
                    in_out.extend_from_slice(&nonce);
                    in_out
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_key_setup(c: &mut Criterion) {
    c.bench_function("aes-256-gcm key setup/candidate", |b| {
        b.iter(|| HardwareAes256Gcm::new(black_box(&KEY)).unwrap());
    });
    c.bench_function("aes-256-gcm key setup/candidate-inline", |b| {
        b.iter(|| HardwareAes256GcmKeyState::new(black_box(&KEY)).unwrap());
    });
    c.bench_function("aes-256-gcm key setup/candidate-placed", |b| {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut storage = AlignedStorage([0_u8; 512]);
        b.iter(|| {
            let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).unwrap();
            // Initialize and drop (wiping) inside the iteration; the handle
            // borrows the captured storage and must not escape the closure.
            let key = HardwareAes256GcmIn::new_in(black_box(&KEY), slot).unwrap();
            black_box(&key);
        });
    });
    c.bench_function("aes-256-gcm key setup/rustcrypto", |b| {
        b.iter(|| Aes256Gcm::new_from_slice(black_box(&KEY)).unwrap());
    });
    c.bench_function("aes-256-gcm key setup/ring", |b| {
        b.iter(|| LessSafeKey::new(UnboundKey::new(&AES_256_GCM, black_box(&KEY)).unwrap()));
    });

    c.bench_function("aes-256-gcm state-size/candidate", |b| {
        b.iter(|| black_box(HardwareAes256Gcm::state_size()));
    });
}

fn bench_aes_gcm(c: &mut Criterion) {
    bench_encrypt(c);
    bench_encrypt_nonce_appended(c);
    bench_decrypt(c);
    bench_key_setup(c);
}

criterion_group!(benches, bench_aes_gcm);
criterion_main!(benches);
