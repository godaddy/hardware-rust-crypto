//! Streams AES-CTR generator output to stdout for external statistical test
//! batteries. Deterministic from a fixed seed so runs are reproducible.
//!
//! ```sh
//! # PractRand (recommended; reads stdin):
//! cargo run --release --example rng_dump | RNG_test stdin64 -tlmin 1KB
//! # dieharder:
//! cargo run --release --example rng_dump | dieharder -g 200 -a
//! ```
//!
//! The generator output is the keystream the keygen API hands out; a battery
//! consumes as much as it needs and closes the pipe, at which point this exits.

#![allow(clippy::cast_possible_truncation)]

use hardware_rust_crypto::random::{AesCtrKeyGenerator, KeyGenerator as _, AES_CTR_SEED_SIZE};
use std::io::Write as _;

fn main() {
    // Deterministic seed; a different stream can be selected reproducibly with
    // RNG_DUMP_SEED=<u64> (used by the multi-seed randomness battery in CI).
    let offset: u64 = std::env::var("RNG_DUMP_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut seed = [0_u8; AES_CTR_SEED_SIZE];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_add(offset as u8);
    }
    let Ok(mut generator) = AesCtrKeyGenerator::from_seed(&mut seed) else {
        eprintln!("hardware AES-CTR backend unavailable");
        std::process::exit(1);
    };

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut buf = vec![0_u8; 1 << 16];
    loop {
        if generator.fill_bytes(&mut buf).is_err() {
            std::process::exit(1);
        }
        // A closed pipe (the battery has enough) ends the stream cleanly.
        if out.write_all(&buf).is_err() {
            break;
        }
    }
}
