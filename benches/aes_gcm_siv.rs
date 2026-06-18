//! Criterion benchmarks for the hardware AES-256-GCM-SIV backend.
//!
//! Each operation is measured three ways: the candidate hardware SIV path, the
//! stock `RustCrypto` `aes-gcm-siv` reference, and (in the encrypt group) the
//! crate's own AES-256-GCM so the per-message key-derivation overhead inherent
//! to SIV is visible directly against the fused GCM path.
//!
//! As with the GCM benchmark, run twice to capture both `RustCrypto`
//! configurations: once with default flags, once with
//! `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"`.

// Criterion's macros generate undocumented public items, and the benchmark
// matrix is one long linear function by design.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use aes_gcm_siv::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as RustCryptoNonce};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hardware_rust_crypto::aes_gcm::{
    HardwareAes256Gcm, HardwareAes256GcmSiv, HardwareAes256GcmSivIn, HardwareAes256GcmSivKeyState,
    SivUninitKeyStateSlot, NONCE_SIZE, TAG_SIZE,
};

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
    let mut group = c.benchmark_group("aes-256-gcm-siv encrypt");
    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xa5; size];

        group.bench_function(format!("candidate/{size}"), |b| {
            let mut key = HardwareAes256GcmSiv::new(&KEY).unwrap();
            b.iter(|| key.encrypt(AAD, black_box(&plaintext)).unwrap());
        });

        group.bench_function(format!("candidate-noalloc/{size}"), |b| {
            let mut key = HardwareAes256GcmSiv::new(&KEY).unwrap();
            let mut out = vec![0_u8; size + TAG_SIZE + NONCE_SIZE];
            b.iter(|| {
                key.encrypt_to(AAD, black_box(&plaintext), &mut out)
                    .unwrap()
            });
        });

        // The crate's own AES-256-GCM, as the SIV-overhead baseline.
        group.bench_function(format!("gcm-candidate/{size}"), |b| {
            let mut key = HardwareAes256Gcm::new(&KEY).unwrap();
            b.iter(|| key.encrypt(AAD, black_box(&plaintext)).unwrap());
        });

        group.bench_function(format!("rustcrypto/{size}"), |b| {
            let key = Aes256GcmSiv::new_from_slice(&KEY).unwrap();
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
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-256-gcm-siv decrypt");
    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xa5; size];
        let nonce = nonce(size as u64);

        let mut candidate_key = HardwareAes256GcmSiv::new(&KEY).unwrap();
        let candidate_ct = candidate_key.encrypt(AAD, &plaintext).unwrap();
        group.bench_function(format!("candidate/{size}"), |b| {
            b.iter(|| {
                candidate_key
                    .decrypt(AAD, black_box(&candidate_ct))
                    .unwrap()
            });
        });

        group.bench_function(format!("candidate-noalloc/{size}"), |b| {
            let mut out = vec![0_u8; size];
            b.iter(|| {
                candidate_key
                    .decrypt_to(AAD, black_box(&candidate_ct), &mut out)
                    .unwrap()
            });
        });

        let rustcrypto_key = Aes256GcmSiv::new_from_slice(&KEY).unwrap();
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
    }
    group.finish();
}

fn bench_key_setup(c: &mut Criterion) {
    c.bench_function("aes-256-gcm-siv key setup/candidate", |b| {
        b.iter(|| HardwareAes256GcmSiv::new(black_box(&KEY)).unwrap());
    });
    c.bench_function("aes-256-gcm-siv key setup/candidate-inline", |b| {
        b.iter(|| HardwareAes256GcmSivKeyState::new(black_box(&KEY)).unwrap());
    });
    c.bench_function("aes-256-gcm-siv key setup/candidate-placed", |b| {
        let layout = HardwareAes256GcmSiv::key_state_layout();
        let mut storage = AlignedStorage([0_u8; 512]);
        b.iter(|| {
            let slot = SivUninitKeyStateSlot::new(&mut storage.0[..layout.size]).unwrap();
            // Initialize and drop (wiping) inside the iteration; the handle
            // borrows the captured storage and must not escape the closure.
            let key = HardwareAes256GcmSivIn::new_in(black_box(&KEY), slot).unwrap();
            black_box(&key);
        });
    });
    c.bench_function("aes-256-gcm-siv key setup/rustcrypto", |b| {
        b.iter(|| Aes256GcmSiv::new_from_slice(black_box(&KEY)).unwrap());
    });

    c.bench_function("aes-256-gcm-siv state-size/candidate", |b| {
        b.iter(|| black_box(HardwareAes256GcmSiv::state_size()));
    });
}

fn bench_aes_gcm_siv(c: &mut Criterion) {
    bench_encrypt(c);
    bench_decrypt(c);
    bench_key_setup(c);
}

criterion_group!(benches, bench_aes_gcm_siv);
criterion_main!(benches);
