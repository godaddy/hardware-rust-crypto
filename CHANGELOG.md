# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-19

First stable release. AES-256-GCM and AES-256-GCM-SIV on hardware-only backends,
with the full machine-checked proof and multi-platform verification battery
(Z3/sympy, Kani, SAW, crux-mir, F\*, binary constant-time, Miri/Valgrind/
sanitizers across x86_64 and aarch64) gating every release.

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
- **Inductive composition proof** (`proofs/prove_composition_inductive.py`): lifts the GHASH Horner == sum-of-powers identity and the CTR decrypt-inverts-encrypt round-trip from representative block counts to **arbitrary n**, by symbolic induction (the Horner step is a ring identity; the CTR counter-sequence invariant + per-block bijection are checked with Z3).
- **Third differential oracle (OpenSSL)** (`tests/openssl_interop.rs`): cross-validates AES-256-GCM byte-for-byte (200 cases, both directions, plus
  tag-rejection) against OpenSSL's C implementation - a codebase independent of
  both RustCrypto (pure Rust) and `ring` (BoringSSL heritage), so agreement
  across all three rules out a shared specification-level bug. OpenSSL is a
  vendored-build dev-dependency, never in the production dependency graph.
- **crux-mir proofs over Rust MIR** (`proofs/crux-mir/`): brings up the
  mir-json + crux-mir (Galois) toolchain (schema-8 mir-json to match SAW 1.5.1)
  and proves `increment_counter` == SP 800-38D `inc_32` over the MIR - a fourth
  independent toolchain (Z3, Kani/CBMC, SAW-LLVM, crux-mir) corroborating the
  same property, at the MIR level (no LLVM poison). A probe (`clmul_probe.rs`)
  establishes that crux-mir, like SAW-LLVM, does NOT model the PMULL/PCLMULQDQ
  carryless-multiply intrinsic - so the hardware SIMD crypto must be axiomatized
  for any source-level proof, which is exactly why the field arithmetic is proven
  via a model anchored to the captured real backend output (`field_model.py`).
- **SAW field-multiply bilinearity (target, tool-blocked)** (`proofs/saw/field_bilinearity.saw`): residual harnesses (`saw_field_mul_*`, `saw-verify`
  feature) encode a SAW proof that the compiled PCLMULQDQ field multiply is
  GF(2)-bilinear and commutative - reaching *through* the intrinsic. Currently
  blocked by SAW 1.5 panicking on the LLVM `poison` values rustc emits for the
  128-bit SIMD lowering (every opt level); documented in `proofs/saw/README.md`.
  Bilinearity is already proven for all inputs by `prove_multiply.py`.
- **SAW proofs over the compiled LLVM bitcode** (`proofs/saw/`): SAW (Galois)
  verifies rustc's LLVM bitcode for `increment_counter` and `j0` against a Cryptol
  spec (SP 800-38D `inc_32` and `J0 = IV‖0³¹‖1`) — a third independent
  verification toolchain (its own Z3/Yices/CVC/ABC solvers) corroborating the Z3
  model proofs and the Kani/CBMC compiled-code proofs. Build-time-only
  `saw-verify` feature emits the `extern "C"` wrappers; SAW is the route to later
  proving the AES-calling composition by axiomatizing the intrinsics.
- **Mutation testing** (`cargo-mutants`, `docs/mutation-testing.md`, in the
  `heavy-assurance` workflow): validates that the test suite actually catches
  injected bugs in the GCM composition and the nonce generator (319 mutants,
  239 caught on the first run). It surfaced four real test gaps — the
  `HardwareAes256GcmIn` explicit-buffer methods and `HardwareAes256GcmKeyState::
  encrypt_to` were called but not output-verified, a constant `os_salt` (broken
  cross-instance nonce uniqueness) survived, and `validate_gcm_lengths`'s `||`
  chain was unpinned — each now closed by a new test. Residual survivors
  (formatting, hardware detection, 2^36-byte limits, fork/wrap paths,
  security-equivalent nonce masks) are individually documented.
- **Binary-level constant-time verification** (`proofs/constant-time/verify.sh`,
  in the `constant-time` CI job): disassembles the two scalar secret-handling
  functions — the tag comparison (`constant_time_eq`) and the GHASH `mulX` carry
  fold (`mulx`) — and fails the build unless they compile **branch-free over
  their secret inputs** (`mulx` has no conditional branch; `constant_time_eq` has
  none after the first secret-byte load — its only branch is the public length
  check). Includes a non-vacuity control (a deliberately leaky comparison that
  must be rejected). Upgrades the constant-time claim for the scalar secret
  surface from statistical (dudect) to a checkable property of the shipped
  machine code. New build-time-only `ct-verify` feature emits the named wrappers.
- **First checked F\* proof over hax-extracted source** (`proofs/fstar/HrcComposition.fst`,
  `check.sh`): F\* proves `j0` places the GCM pre-counter byte and
  `increment_counter` preserves the leading 96 bits (the SP 800-38D `inc_32`
  invariant) over the function bodies hax extracts verbatim from `src/aes_gcm/`,
  with a drift guard that the proved bodies match a fresh extraction. A new
  "extracted-source proof" (T1.5) trust tier in `docs/proof-coverage.md`.
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

### CI and gating

- **Each proof/test framework is its own runnable workflow** (`.github/workflows/`,
  with a catalog in `.github/workflows/README.md`): Z3/sympy proofs, Kani, SAW,
  crux-mir, F\*, constant-time, Miri, Valgrind, sanitizers, fuzz, randomness, and
  mutation can each be launched on demand from the Actions tab.
- **The full verification battery gates merges.** Branch protection requires all
  ~23 checks (5 platforms + 5 proof engines + constant-time/Miri/Valgrind/
  sanitizers across both architectures + fuzz + RNG + audit/deny), `strict`. A
  pull request cannot merge unless the entire battery passes.
- **F\* gates every PR *and* every release**, via a **prebuilt toolchain container
  image** (`.github/docker/fstar-proof.Dockerfile`, built/pushed to GHCR by
  `proof-image.yml`). The proof runs inside the pinned image (~2 min, no
  from-source build or network at run time), so the heaviest proof is affordable
  on every change; it is also a `publish.yml` release gate.
- **aarch64 verification on free Linux arm64 runners** (`ubuntu-24.04-arm`):
  Valgrind memcheck, ASan/TSan, the binary branch-freedom check, dudect, and the
  full build/test/differential suite now run on real aarch64, so the shipped
  ARMv8 AES/PMULL machine code is verified on hardware (not by proxy). Only Miri
  stays x86 (it does not model NEON crypto intrinsics).
- **Five platforms** in CI: Linux x64, **Linux arm64**, **macOS arm64**,
  Windows x64, **Windows arm64** — the aarch64 intrinsics are exercised on all of
  ELF/GNU, Mach-O/Apple, and PE/MSVC.
- **Nightly deep batteries** (`heavy-assurance.yml`, scheduled 07:00 UTC): the
  long runs that would risk the per-job timeout — full-suite Valgrind, 30-min/
  target fuzz, 256 GB multi-seed PractRand + dieharder, extended proofs, and
  mutation — run continuously out of band instead of blocking each PR.

### Project

- `SECURITY.md` (vulnerability disclosure policy), `CHANGELOG.md`, and
  `deny.toml` (cargo-deny: advisories, licenses, sources, bans).

## [0.1.0]

- Initial hardware-only AES-256-GCM and AES-256-CTR key/nonce generation.
