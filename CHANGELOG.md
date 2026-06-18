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
  paths, now **CI-gated** by the `constant-time` job (best-of-3 batches, fails the
  build if Welch `|t| ≥ 25`; latest run ~0.4-2.4 vs ~267 for an early-exit leak).
- **Machine-checked proof suite** for the GHASH/POLYVAL core and the GHASH
  construction (`proofs/`, run by the `formal-proof` CI job): over all inputs and
  faithful to the exact intrinsic sequence (model pinned bit-for-bit to the
  running backend), the field multiply is proven equal to RFC 8452 POLYVAL
  (exhaustive over the 128×128 basis, both architectures), the exact reductions
  are proven GF(2)-linear (reduce-once exact), Horner == the batch sum-of-powers
  (symbolic), and the crate's ByteReverse + mulX + POLYVAL construction is proven
  equal to NIST SP 800-38D **GHASH** for every subkey and block count
  (`prove_ghash_polyval_mapping.py`).
- **Composition proof** (`prove_composition.py`, Z3 with AES and the
  authenticator as uninterpreted oracles): over all inputs, the intrinsic-free
  AEAD glue matches SP 800-38D / RFC 8452 — the GCM `increment_counter` ==
  `inc_32` and the SIV counter == the RFC little-endian 32-bit increment, the
  J0 / SIV key-derivation / SIV tag layouts, and **decryption inverts encryption
  and accepts genuine ciphertext** for both modes (`seal`/`open` modeled
  independently; includes a non-vacuity check that a broken `open` is rejected).
- **GHASH input-framing proof** (`prove_input_format.py`, Z3): the partial-block
  zero padding, the 64+64-bit length block (`8·len`, big-endian, AAD then
  ciphertext), no length-field overflow on accepted inputs, and the enforced
  length limits == the standards' caps (`2^39−256`-bit GCM, `2^36`-byte SIV).
- **Kani model checking** (`cargo kani`, new `kani` CI job): Kani/CBMC verifies
  the *actual compiled Rust* of the intrinsic-free logic over all inputs (bounded
  where noted) — the GCM/SIV counter increments == the spec increments, J0
  layout, length validation, the nonce parser, and the two attacker-facing
  envelope splitters never panic, never index out of bounds, and split at the
  correct boundary; and `constant_time_eq` == bytewise equality on equal-length
  tags (the authentication decision never accepts a wrong tag or rejects a right
  one). Unlike the Z3 proofs (which reason about a faithful model), Kani checks
  the shipped machine code.
- **hax → F\* extraction of the composition** (`proofs/hax/extract.sh`): the
  AES-256-GCM/SIV composition glue now extracts from the *actual Rust source* to
  F\* via hax (toolchain built against hax's pinned nightly + the OCaml engine;
  two `cfg(hax)` no-ops keep the RNG/fork-handler out of the importer). The F\*
  proof itself (axiomatize the opaque backends, check the lemmas against the
  SP 800-38D/RFC 8452 spec) is the remaining, well-scoped step. `cfg(hax)` is a
  build-config no-op for normal builds and all other tooling.
- **Proof-coverage map** (`docs/proof-coverage.md`): one table of every verified
  property with its method and an explicit trust level — compiled-code proof
  (Kani/Miri), all-inputs model proof (Z3/sympy/exhaustive), exhaustive vectors,
  or tooling — plus the named open items.
- **Generated-nonce uniqueness proof** (`nonce_value_is_injective_in_counter`,
  cfg(kani)): Kani/CBMC proves the compiled `nonce = (base + counter) mod 2^96`
  arithmetic is injective in the counter over the full 2^64 sequence for every
  base, so the generated-nonce path cannot reuse a nonce within an instance
  (machine-checking the core of the GCM nonce-reuse mitigation; HRC-2026-01).
  The arithmetic was factored into a `nonce_value` helper to make it checkable.
- **AES S-box proof** (`aes_sbox_is_fips197_affine_inverse` test): the shipped
  `AES_SBOX` constant is proven to be the genuine FIPS-197 S-box —
  `affine(inverse_GF(2^8)(x))` — for all 256 inputs, and a bijection, ruling out
  a transcription error in the table that feeds the (cfg(miri)) software key
  schedule.
- **Cross-architecture proof anchor** (`mul_reference_anchor`): the real backend
  `imp::mul` is checked to reproduce the proof's reference vectors on each CI
  architecture, so the x86 proof model is anchored to actual AES-NI/PCLMULQDQ
  silicon, not only aarch64-captured output.
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
