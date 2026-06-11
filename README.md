# hardware-rust-crypto

Hardware-only AES-256-GCM and key/nonce generation for Rust. Every AES round
and every GF(2^128) multiply executes as a CPU instruction; no software
fallback is compiled in.

## Why: the performance and footprint delta

Leaning almost entirely on the CPU's dedicated cryptographic instructions -
AES-NI/PCLMULQDQ on x86_64, ARMv8 AES/PMULL on aarch64 - is what produces the
gap below. Encryption is faster than `ring` at every size from 16 bytes through
16 KiB, including bulk, because the encrypt path stitches the AES keystream and
GHASH multiply into one software-pipelined loop so both execution pipelines stay
busy. It runs an order of magnitude faster than a default RustCrypto build and
carries the smallest reusable key state of the three. (Decryption deliberately
trails `ring` on larger inputs: it verifies the tag before writing any
plaintext, a two-pass design `ring`'s decrypt-then-verify avoids; see
[docs/benchmarks.md](docs/benchmarks.md).)

| Operation (lower is better, ns) | this crate | ring | RustCrypto (default) | RustCrypto (armv8 cfgs) |
| --- | --- | --- | --- | --- |
| encrypt 1 KiB | 154 | 213 | 4950 | 565 |
| encrypt 16 KiB | 1950 | 2330 | 75500 | 8570 |

Reusable AES-256-GCM key-state size: **this crate 368 B / ring 544 B /
RustCrypto 992 B**. Measured on a MacBook Pro (Apple M4 Max, single machine);
at these ~200 ns scales run-to-run variance is roughly +/-10%. The allocation-free
`*_to` APIs run faster still (1 KiB encrypt 133 ns). The full matrix, both
RustCrypto build configurations, and methodology are in
[docs/benchmarks.md](docs/benchmarks.md).

**How it gets there:** a stitched encrypt loop that software-pipelines eight-way
interleaved hardware CTR against eight-block aggregated GHASH so the AES and
carryless-multiply pipelines run concurrently, a register-resident key schedule,
fused single-pass encryption that touches each ciphertext byte once, and
allocation-free `*_to` APIs.
**Why that is also safer:** the AES S-box never touches memory, so the classic
cache-timing attack surface does not exist here; and there is no silent
software fallback - if the required hardware is absent, construction fails with
a typed error instead of quietly degrading (a default RustCrypto build on
aarch64 silently runs ~8x-slower software AES, see
[docs/benchmarks.md](docs/benchmarks.md)).

## What it provides

- `hardware-aes-gcm`: hardware-only AES-256-GCM with compact reusable key state
  and caller-provided storage hooks.
- `hardware-random`: a hardware-only AES-CTR key/nonce generator with fork
  detection and zeroized state. Initial seeding uses OS entropy (`getrandom`);
  reseeding blends CPU hardware-RNG entropy (RDSEED on x86_64, RNDRRS on
  aarch64 Graviton) through the generator state when available, falling back
  to the OS otherwise (`cpu-rng-reseed` feature, default on).
- Interoperability tests against stock RustCrypto `aes-gcm` and `ring`,
  Criterion benchmark harnesses, and CI on Linux x64 and macOS aarch64.

Production dependency graphs contain **no software cipher and no third-party
crypto implementation**: `hardware-aes-gcm` depends on `subtle` + `zeroize`;
`hardware-random` on `getrandom` + `zeroize` (+ `libc` on Unix). ChaCha20
(via `rand_chacha`), Salsa20, `ring`, and stock RustCrypto appear only in
dev-dependencies as benchmark/interop/timing baselines - and CI fails the
build if any of them ever enters a production graph.

## Where this code comes from

The cryptographic cores are vendored, with minimal adaptation, from the
[RustCrypto](https://github.com/RustCrypto) project and from
[`rand_aes`](https://github.com/hasenbanck/rand_aes):

- The GHASH authenticator is the RustCrypto
  [`ghash` 0.5.1](https://github.com/RustCrypto/universal-hashes) GHASH-to-POLYVAL
  mapping over the [`polyval` 0.6.2](https://github.com/RustCrypto/universal-hashes)
  hardware backends (PCLMULQDQ on x86/x86_64, PMULL on aarch64).
- The AES-256 key expansion and block encryption paths, and the AES-256-CTR
  generator backend, are adapted from `rand_aes` 0.7.0's AES-NI and ARMv8
  hardware backends.
- The AES-GCM composition (J0 construction, CTR keystream, length-block
  authentication, tag handling) follows NIST SP 800-38D and the RustCrypto
  [`aes-gcm`](https://github.com/RustCrypto/AEADs) crate's design.

Exact upstream versions, commit SHAs, copyright holders, licenses, and the
modifications made are recorded in [NOTICE](NOTICE).

### Upstream audit history

The RustCrypto `aes-gcm` crate and its dependencies (including the AES
implementations and the POLYVAL authenticator this repository's GHASH backend
derives from) received a
[security audit by NCC Group](https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/)
in February 2020, funded by MobileCoin, with no significant findings. The
audit specifically noted that the implementations use the recommended
techniques for constant-time execution.

To be precise about what that means here: the audit covered the upstream
crates as they existed at the time, not this fork. What this repository
inherits is the audited design and backend structure; what it changes is
subtractive (removing the software fallback and runtime dispatch). Parity with
the audited lineage is enforced mechanically by the test suite described
below, and `ring` - an independently developed, BoringSSL-derived
implementation that is among the most widely deployed crypto code anywhere -
is used as a second cross-validation oracle.

## What was removed, and why

This is a strict subset of the upstream functionality: AES-256-GCM with
96-bit nonces, plus AES-256-CTR key generation. The deliberate deletions are:

- The fixsliced software AES fallback (and its state: 960 bytes of software
  round keys plus batch buffers, versus 240 bytes of hardware key schedule).
- The runtime autodetection enum and boxed dispatch state that let one type
  hold either a hardware or software backend.
- Every code path that could silently fall back to table-based or bitsliced
  software AES.

The motivation is the cached-key tier of applications that hold many keys resident: cached key-equivalent state
should be as small as a hardware key schedule actually needs
(`HardwareAes256Gcm` state is 368 bytes: 15 AES round keys plus eight
precomputed GHASH key powers), should fit guarded-memory placement policies,
and should never be able to *be* a software AES state. If the required CPU
features are absent, construction fails with a typed error instead of
degrading.

## Why this is safe to use in place of `ring` or RustCrypto directly

1. **Every secret-dependent operation executes in hardware.** AES rounds use
   AES-NI (`AESENC`/`AESENCLAST`) on x86_64 and the ARMv8 Cryptographic
   Extensions (`AESE`/`AESMC`) on aarch64. GHASH's GF(2^128) multiplication
   uses carryless multiply (`PCLMULQDQ` / `PMULL`). These instructions have no
   key- or data-dependent timing, no table lookups at secret-dependent
   addresses, and no secret-dependent branches - the classic AES cache-timing
   attack surface does not exist in this code because the S-box never touches
   memory. Tag comparison is constant-time via the `subtle` crate. The Rust
   glue performs no secret-dependent branching or indexing.
2. **Wire-format compatibility is proven, not assumed.** The test suite shows
   the candidate produces byte-identical AES-256-GCM ciphertext to RustCrypto
   `aes-gcm`, cross-decrypts in both directions with both `aes-gcm` and
   `ring`, matches NIST known-answer vectors, survives a randomized
   differential sweep across plaintext/AAD size combinations, and rejects
   every single-byte tampering of ciphertext, tag, nonce, and AAD. The
   AES-CTR generator is checked against FIPS-197 vectors independently
   verified with OpenSSL.
3. **Hardware support is verified, never guessed.** Construction checks CPU
   features at runtime and returns `UnsupportedCpu` before accepting key
   material, and CI asserts the hardware paths are actually exercised so a
   green build cannot mean "tests silently skipped".
4. **Key material lifecycle is explicit.** Key state zeroizes on drop (owned
   and caller-placed), encryption and decryption can target caller-controlled
   buffers (`encrypt_to`/`decrypt_to`) so decrypted keys never sit in
   unmanaged heap allocations, and the key generators detect process forks
   and reseed on interval.
5. **Nonce uniqueness can be the library's job.** GCM is catastrophic on nonce
   reuse, so beyond the caller-supplied-nonce API there are
   `encrypt_with_generated_nonce` / `encrypt_nonce_appended_generated` methods
   that generate a unique 96-bit nonce per call - a per-instance 64-bit counter
   over a 96-bit salt drawn **always from the OS** and re-salted on fork - and
   return it alongside the ciphertext.

## Why hardware-only is the right default in production

AES-NI and PCLMULQDQ have shipped in effectively every x86_64 server CPU
since Intel Westmere (2010) and AMD Bulldozer (2011). The ARMv8 Cryptographic
Extensions are present on every mainstream aarch64 server and client part -
AWS Graviton, Ampere, Apple Silicon. A production fleet in 2026 that lacks
these instructions essentially does not exist; the software fallback in
general-purpose crypto libraries serves hardware we do not run, while costing
cached key-state size and a larger audit surface. The silent-fallback risk is
not hypothetical: a default build of stock `aes-gcm` on aarch64 quietly runs
*software* AES and POLYVAL unless every consumer passes
`RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"` - measured at roughly 8x
slower, with nothing failing and nothing warning (see
[docs/benchmarks.md](docs/benchmarks.md)). Making hardware support a hard,
typed requirement converts that silent risk into a loud startup failure.

`ring` remains in the repository as an interop and benchmark baseline.

## Commands

```sh
# Tests (interop, KATs, differential sweeps, lifecycle) and lints:
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

# Hardware sanity check and key-state footprint report:
cargo run --example assert_hardware
cargo run --release --example state_size

# Benchmarks (see docs/benchmarks.md for both RustCrypto configurations):
cargo bench --bench aes_gcm
cargo bench --bench random

# Constant-time verification (manual; see docs/constant-time.md):
cargo test --release --test timing_constant_time -- --ignored --nocapture
```

See [docs/design.md](docs/design.md) for the implementation plan.
See [docs/benchmarks.md](docs/benchmarks.md) for locally measured numbers and
how to reproduce them.
See [docs/constant-time.md](docs/constant-time.md) for the emitted-assembly
inspection procedure and the dudect-style timing harness.
See [docs/security-audit.md](docs/security-audit.md) for the multi-model
agentic security assessment (threat model, findings, standards conformance,
and residual-risk register).

## Acknowledgments

This work exists because of the [RustCrypto](https://github.com/RustCrypto)
project and its maintainers, whose carefully engineered, audited, and openly
licensed implementations of AES-GCM, GHASH, and POLYVAL form the foundation of
this repository - our sincere thanks to them for years of rigorous work that
the wider Rust ecosystem builds on. Thanks also to Nils Hasenbanck for
[`rand_aes`](https://github.com/hasenbanck/rand_aes), whose clean hardware
AES-CTR backends this repository adapts, and to NCC Group and MobileCoin for
the public audit of the RustCrypto AEAD stack. See [NOTICE](NOTICE) for
formal attribution.
