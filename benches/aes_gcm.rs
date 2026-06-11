#![allow(clippy::unwrap_used)]

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce as RustCryptoNonce};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use hardware_aes_gcm::HardwareAes256Gcm;
use ring::aead::{Aad, LessSafeKey, Nonce as RingNonce, UnboundKey, AES_256_GCM};

const KEY: [u8; 32] = [0x42; 32];
const AAD: &[u8] = b"";

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn bench_aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-256-gcm encrypt");
    for size in [64_usize, 1024, 16 * 1024] {
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

    let mut group = c.benchmark_group("aes-256-gcm decrypt");
    for size in [64_usize, 1024, 16 * 1024] {
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

    c.bench_function("aes-256-gcm key setup/candidate", |b| {
        b.iter(|| HardwareAes256Gcm::new(black_box(&KEY)).unwrap());
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

criterion_group!(benches, bench_aes_gcm);
criterion_main!(benches);
