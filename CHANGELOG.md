# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **AES-256-GCM-SIV (RFC 8452)**, nonce-misuse-resistant AEAD on the same
  hardware AES and carryless-multiply backends (POLYVAL authentication, no
  software fallback): `HardwareAes256GcmSiv`, `HardwareAes256GcmSivKeyState`,
  `HardwareAes256GcmSivIn`, and `SivUninitKeyStateSlot`, with full method parity
  with the GCM types. Reusable key state is 240 bytes.
- An 8-way interleaved AES `encrypt8` primitive driving the SIV CTR pass.
- Benchmarks for AES-256-GCM-SIV (`benches/aes_gcm_siv.rs`).

### Testing and assurance

- **Known-answer vectors:** RFC 8452 Appendix C.2 (SIV); NIST SP 800-38D KATs
  and the full NIST CAVP AES-256-GCM 96-bit-IV/128-bit-tag subset (750 vectors);
  Project Wycheproof AES-256-GCM (66) and AES-256-GCM-SIV (103, incl.
  counter-wrap and tag-rejection).
- **Direct aggregation-identity tests** proving the 8-/4-block aggregated
  GHASH/POLYVAL reduction equals the per-block evaluation.
- **Property-based tests** (proptest): round-trip, `*_to` consistency, SIV
  determinism, tamper rejection, and decrypt-parser robustness on arbitrary
  bytes.
- **Constant-time timing harnesses** (dudect) for both the GCM and SIV decrypt
  paths (latest run, |t| threshold 25: GCM 1.59/2.50, SIV 0.15/0.52).
- **Machine-checked proof suite** for the GHASH/POLYVAL core (`proofs/`, run by
  the `formal-proof` CI job): over all inputs and faithful to the exact intrinsic
  sequence (model pinned bit-for-bit to the running backend), the field multiply
  is proven equal to RFC 8452 POLYVAL (exhaustive over the 128×128 basis), the
  exact reductions are proven GF(2)-linear (reduce-once exact), and Horner ==
  the batch sum-of-powers (symbolic).
- **Miri** runs the entire key-state lifecycle and the real AES/GHASH paths on
  x86 under its UB checker (a `cfg(miri)`-only software key schedule, proven
  byte-identical to hardware, covers the one intrinsic Miri lacks); **Valgrind**
  memcheck over the real intrinsic binary, **AddressSanitizer/ThreadSanitizer**,
  and **fuzz** targets wired into CI, with deeper runs in a manual
  heavy-assurance workflow. CI also covers **Windows** (x86 AES-NI).
- **Heavy RNG statistical battery**: the AES-CTR generator passes PractRand
  cleanly to 32 GiB (`examples/rng_dump.rs`, `randomness-battery` CI job).
- Expanded GCM coverage to parity (dense AAD sweep, multi-size single-bit
  tamper, wrong key/nonce/AAD, large AAD+plaintext).

### Project

- `SECURITY.md` (vulnerability disclosure policy), `CHANGELOG.md`, and
  `deny.toml` (cargo-deny: advisories, licenses, sources, bans).

## [0.1.0]

- Initial hardware-only AES-256-GCM and AES-256-CTR key/nonce generation.
