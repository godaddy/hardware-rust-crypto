# Assurance: what is tested, proven, and still open

This document is the map of the crate's correctness and safety assurance: the
layers in place today, the formal-verification roadmap, and what an independent
audit or CAVP/CMVP validation would still add. It complements the threat model
and findings in [security-audit.md](security-audit.md).

## 1. Assurance layers in place

| Layer | What it covers | Where |
| --- | --- | --- |
| **Known-answer vectors** | RFC 8452 C.2 (SIV); NIST SP 800-38D (GCM); full NIST CAVP AES-256-GCM 96/128 subset (750 vectors); FIPS-197 (AES-CTR) | `tests/nist_cavp_gcm.rs`, `aes_gcm_siv_interop.rs`, `aes_gcm_interop.rs`, `src/random/` |
| **Third-party vectors** | Project Wycheproof AES-256-GCM (66) and AES-256-GCM-SIV (103, incl. counter-wrap + tag-rejection) | `tests/wycheproof_aes_gcm*.rs` |
| **Differential** | Byte-for-byte vs RustCrypto `aes-gcm` / `aes-gcm-siv` (GCM also vs `ring`), both directions, dense plaintext + AAD sweeps | interop tests |
| **Aggregation identity** | 8-/4-block aggregated reduction == per-block Horner evaluation | `src/aes_gcm/ghash.rs` (`aggregation_tests`) |
| **Property-based** | Round-trip, `*_to` consistency, SIV determinism, tamper rejection, decrypt-parser robustness on arbitrary bytes | `tests/proptest_aead.rs` |
| **Fuzzing** | Differential + parser-robustness on the decrypt surface (no panic / no UB) | `fuzz/` |
| **Memory-safety (interpreted)** | Miri over the entire **AES-256-GCM/SIV** key-state lifecycle and the real AES/GHASH paths on x86 (aliasing, provenance, OOB, uninit) | `cargo miri test --lib aes_gcm` (x86) |
| **Memory-safety (native binary)** | Valgrind memcheck + ASan over the real AES-NI/PCLMULQDQ binary; TSan over the `Send/Sync` and cross-thread paths | CI jobs |
| **Constant-time** | dudect Welch t-test on both decrypt paths (mismatch-position and content independence) | `tests/timing_constant_time*.rs` |
| **RNG quality** | Monobit / chi-square / serial-correlation sanity (CI) + PractRand/dieharder procedure | `tests/rng_statistical.rs`, `docs/randomness-testing.md` |
| **Supply chain** | No third-party cipher in the production graph (CI-enforced); `cargo audit` + `cargo deny` | CI, `deny.toml` |

Memory safety is the dominant risk in a hand-written `unsafe` hardware crate, so
it is covered twice over. On x86, Miri implements the AES-NI and PCLMULQDQ
intrinsics, so `cargo miri test --lib aes_gcm` runs the **whole** AES-256-GCM and
AES-256-GCM-SIV key-state lifecycle (caller-placement, `NonNull`/`MaybeUninit`,
the opaque handle, `Send`/`Sync`, drop-and-wipe) and the real AES/GHASH code
under its undefined-behavior checker (aliasing, provenance, out-of-bounds,
uninitialized reads) - and it passes. The one missing intrinsic, AES key
expansion (`aeskeygenassist`), is routed under `cfg(miri)` through a software key
schedule that `software_schedule_matches_hardware` proves byte-identical to the
hardware path (and which is never compiled into a normal build). The AES-CTR
generator backend (`random::`) has its own key expansion still using
`aeskeygenassist`, so it is excluded from the Miri job and covered by Valgrind
and ASan on the real binary (extending the software schedule to it is a tracked
follow-up). aarch64 NEON crypto intrinsics are not yet implemented by Miri, so
the Miri job runs on x86; the aarch64 binary's memory safety is covered by
Valgrind and ASan. The approaches are complementary - Miri adds
aliasing/provenance checking the others cannot.

Miri did its job: on the first full-lifecycle run it flagged a genuine Stacked
Borrows violation - in a *test* (`inline_owned_key_state_wipes_storage_on_drop`)
that read through a raw pointer whose provenance a later `ManuallyDrop::drop`
had invalidated. The production `unsafe` was clean; the test was fixed to
re-derive the pointer after the drop.

## 2. Formal verification

### 2.1 GHASH/POLYVAL core: machine-checked against the spec for all inputs

The novel, hand-built arithmetic is the GHASH/POLYVAL carryless-multiply core
(the `karatsuba1`/`karatsuba2`/`mont_reduce` field multiply and the eight-block
aggregated reduction). It is proven correct **for every input**, faithfully to
the actual intrinsic sequence, by the suite in [`proofs/`](../proofs) (see
[`proofs/README.md`](../proofs/README.md)). The proofs reason about a Python
model of the exact NEON sequence; `field_model.py` first pins that model to
reality - it reproduces, byte-for-byte, reference outputs captured from the
running backend `imp::mul`, and equals the independent RFC 8452 POLYVAL `dot`.
So "the model" = "the shipped code" = "the spec" before any proof is trusted.

| Proof | Statement (all inputs) | Method |
| --- | --- | --- |
| `prove_multiply.py` | The field multiply `mont_reduce(karatsuba2(karatsuba1(a,b)))` equals RFC 8452 POLYVAL `dot(a,b)`. | Both maps are GF(2)-bilinear, so they are determined by their values on a basis; equality is checked **exhaustively on all 128×128 standard-basis pairs** ⇒ equality everywhere. |
| `prove_aggregation.py` | The exact `mont_reduce ∘ karatsuba2` (aarch64) and `reduce` (x86) are GF(2)-linear. | Z3 SMT, closed universally-quantified query. |
| `prove_ghash_identity.py` | The per-block Horner recurrence equals the sum-of-powers form the batch path computes. | Symbolic expansion over a commutative ring (sympy). |

Chained: the multiply computes the correct POLYVAL product; linearity of the
reduction means folding the per-slot Karatsuba partials and reducing **once**
equals reducing each (so `update_blocks8`/`update_blocks4` compute
`Σ_i x_i · H^{n-i+1}`); and that sum is exactly the GHASH/POLYVAL Horner
accumulator of the specification. Therefore the batch path computes the
specified accumulator for every input. This fully closes the formal portion of
HRC-2026-08 for the field core.

Reproduce: `pip install z3-solver sympy && ./proofs/run_all.sh` (exit 0). The
`formal-proof` CI job runs it on every build. Scope: these proofs cover the
GHASH/POLYVAL field arithmetic; AES correctness is covered by FIPS-197 / CAVP /
RFC known-answer tests, and the `unsafe` memory handling by Miri and Valgrind
(below). The aarch64 multiply is proven in full; the x86 path shares the
bilinear basis argument and has its reduction proven linear directly, with the
cross-architecture differential/KAT suites confirming byte-identical output.

### 2.2 Functional-correctness FV (roadmap, not yet done)

A full proof that the Rust matches a reference specification is not in place. The
realistic paths, in increasing cost:

- **hax / Cryspen** - extract the safe Rust glue to F\*/Coq and prove the AEAD
  composition (J0/CTR/length-block/tag, SIV derivation/POLYVAL/SIV-CTR) matches
  an RFC-derived spec. The arithmetic backends are intrinsic `unsafe`, outside
  hax's safe-subset, so they would remain trusted/axiomatized.
- **SAW / Cryptol** - prove the compiled routine matches a Cryptol spec at the
  LLVM level, which can reach the intrinsic code the above cannot.

These are tracked as future work; the crate does not currently claim
machine-checked functional correctness.

### 2.3 Constant-time verification method

Constant-time is verified **statistically** (dudect / Welch t-test), not by a
deterministic tool. The Valgrind-secret-poisoning technique (ctgrind: mark the
key as uninitialized, let memcheck flag any branch/index that depends on it) is
deliberately **not** used here: memcheck's shadow-value propagation through the
AES-NI/PCLMULQDQ SIMD instructions is incomplete, which produces false
positives and lost tracking on exactly this code. The hardware vendors guarantee
data-independent timing for those instructions; the dudect harness empirically
checks the surrounding Rust glue. See HRC-2026-05.

## 3. Independent audit and CAVP/CMVP readiness

This code has **not** had an independent third-party audit, and is **not**
CAVP/CMVP validated (HRC-2026-09). What exists to support that work when it
happens:

- **Spec mapping.** `docs/design.md` and `NOTICE` map each routine to its
  governing standard (SP 800-38D, RFC 8452, FIPS-197) and upstream lineage.
- **Test-vector coverage.** The NIST CAVP GCM vectors already run in the suite;
  an ACVP (automated CAVP) integration would reuse the same parser shape. The
  crate implements a fixed, narrow parameter set (AES-256, 96-bit nonce, 128-bit
  tag) which simplifies a validation scope statement.
- **Threat model and residual-risk register.** `docs/security-audit.md` provides
  the findings, conformance matrix, and residual risks an auditor starts from.
- **Reproducibility.** Pinned toolchain actions, vendored vectors (downloaded
  not transcribed, provenance in `NOTICE`), and deterministic tests.

Engaging an accredited lab for CAVP (algorithm) and, if a FIPS boundary is
desired, CMVP (module) validation - plus an independent code audit of the
post-fork `unsafe` and the SIV addition (which post-dates the internal review) -
are the remaining steps to the highest assurance tier.
