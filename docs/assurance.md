# Assurance: what is tested, proven, and still open

This document is the map of the crate's correctness and safety assurance: the
layers in place today, the formal-verification roadmap, and what an independent
audit or CAVP/CMVP validation would still add. It complements the threat model
and findings in [security-audit.md](security-audit.md). For a single table of
every verified property with its method and explicit trust level, see
[proof-coverage.md](proof-coverage.md).

## 1. Assurance layers in place

| Layer | What it covers | Where |
| --- | --- | --- |
| **Known-answer vectors** | RFC 8452 C.2 (SIV); NIST SP 800-38D (GCM); full NIST CAVP AES-256-GCM 96/128 subset (750 vectors); FIPS-197 (AES-CTR) | `tests/nist_cavp_gcm.rs`, `aes_gcm_siv_interop.rs`, `aes_gcm_interop.rs`, `src/random/` |
| **Third-party vectors** | Project Wycheproof AES-256-GCM (66) and AES-256-GCM-SIV (103, incl. counter-wrap + tag-rejection) | `tests/wycheproof_aes_gcm*.rs` |
| **Differential** | Byte-for-byte vs RustCrypto `aes-gcm` / `aes-gcm-siv` (GCM also vs `ring`), both directions, dense plaintext + AAD sweeps | interop tests |
| **Aggregation identity** | 8-/4-block aggregated reduction == per-block Horner evaluation | `src/aes_gcm/ghash.rs` (`aggregation_tests`) |
| **Property-based** | Round-trip, `*_to` consistency, SIV determinism, tamper rejection, decrypt-parser robustness on arbitrary bytes | `tests/proptest_aead.rs` |
| **Fuzzing** | Differential + parser-robustness on the decrypt surface (no panic / no UB) | `fuzz/` |
| **Model checking (compiled Rust)** | Kani/CBMC verifies the **actual compiled** intrinsic-free logic over all inputs: GCM/SIV counter increments == the spec increments, J0 layout, length validation, the nonce parser, the two envelope splitters (no panic, correct boundaries), `constant_time_eq` == bytewise equality on equal-length tags (the auth decision never accepts a wrong tag or rejects a right one), and the generated-nonce arithmetic is injective in the counter (no nonce reuse within an instance; HRC-2026-01) | `cargo kani` (`cfg(kani)` harnesses) |
| **AES S-box** | The shipped `AES_SBOX` constant == the genuine FIPS-197 `affine(inverse_GF(2^8)(x))` for all 256 inputs (and is a bijection) - rules out a transcription error feeding the key schedule | `aes_sbox_is_fips197_affine_inverse` test |
| **Memory-safety (interpreted)** | Miri over the entire **AES-256-GCM/SIV** key-state lifecycle and the real AES/GHASH paths on x86 (aliasing, provenance, OOB, uninit) | `cargo miri test --lib aes_gcm` (x86) |
| **Memory-safety (native binary)** | Valgrind memcheck + ASan over the real AES-NI/PCLMULQDQ binary; TSan over the `Send/Sync` and cross-thread paths | CI jobs |
| **Constant-time** | dudect Welch t-test on both decrypt paths (mismatch-position and content independence), best-of-3 and **CI-gated** (`|t| < 25`) | `tests/timing_constant_time*.rs`, `constant-time` CI job |
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
| `prove_ghash_polyval_mapping.py` | The crate's `ByteReverse` + `mulX` + POLYVAL construction equals NIST SP 800-38D **GHASH**, for all hash subkeys and all block counts. | The single-block identity `gmul(X,H) = R(dot(R(X), mulX(R(H))))` is bilinear ⇒ exhaustive on all 128×128 basis pairs; the multi-block lift needs only that plus `ByteReverse` being a GF(2)-linear involution (Horner induction). |

Chained: the multiply computes the correct POLYVAL product; linearity of the
reduction means folding the per-slot Karatsuba partials and reducing **once**
equals reducing each (so `update_blocks8`/`update_blocks4` compute
`Σ_i x_i · H^{n-i+1}`); and that sum is exactly the GHASH/POLYVAL Horner
accumulator of the specification. Therefore the batch path computes the
specified POLYVAL accumulator for every input. This fully closes the formal
portion of HRC-2026-08 for the field core. `prove_ghash_polyval_mapping.py` then
closes the POLYVAL→GHASH step: AES-GCM needs GHASH, but the backend computes
POLYVAL, and the crate bridges the two with a byte-reversal + `mulX` trick
(`GHashKey::init_in_place`, the per-block reversals, the reversed output). That
bridge is the only novel hand-built algebra in the AEAD composition, and it is
now proven to compute SP 800-38D GHASH for every subkey and block count.

Reproduce: `pip install z3-solver sympy && ./proofs/run_all.sh` (exit 0). The
`formal-proof` CI job runs it on every build. Scope: these proofs cover the
GHASH/POLYVAL field arithmetic and the GHASH construction; AES correctness is
covered by FIPS-197 / CAVP / RFC known-answer tests, and the `unsafe` memory
handling by Miri and Valgrind (below). **Both architectures' field multiplies
are basis-proven in full** (`prove_multiply.py` runs the exhaustive 128×128 sweep
for both the aarch64 `karatsuba`+`mont_reduce` and the x86 `clmul_wide`+`reduce`
sequences), and both reductions are proven GF(2)-linear. The model is anchored to
real silicon on **both** architectures: the reference vectors are reproduced
byte-for-byte by the running backend `imp::mul` in the
`imp_mul_matches_proof_reference_vectors` test, which the CI matrix runs on x86
AES-NI/PCLMULQDQ as well as aarch64 - so the x86 model is no longer anchored only
to aarch64-captured output.

### 2.2 Composition functional correctness

The AEAD composition - the byte plumbing that wires AES and the authenticator
into AES-GCM and AES-GCM-SIV - is intrinsic-free, so it is reasoned about
directly by an SMT solver in `prove_composition.py` (Z3), with AES and the
authenticator as **uninterpreted functions** (their correctness comes from the
field proofs above and the FIPS-197 / CAVP / RFC known-answer tests). Proven for
all inputs:

- the GCM counter increment `increment_counter` equals SP 800-38D `inc_32`
  (big-endian, trailing 32 bits, leading 96 bits untouched), and the SIV counter
  equals the RFC 8452 little-endian 32-bit increment (trailing 96 bits untouched);
- the `J0 = IV ‖ 0^31 ‖ 1` construction, the SIV key-derivation input blocks
  (`LE32(i) ‖ nonce`, low 8 bytes of each AES output, counters 0,1 then 2..5),
  the SIV tag construction (nonce XOR, clear the `0x80` flag, AES), and the
  SIV-CTR counter initialization (set the `0x80` flag);
- **decryption inverts encryption and accepts genuine ciphertext** for both
  modes, with `seal` and `open` modeled *independently* from their `mod.rs`/
  `siv.rs` sources so a wiring divergence would fail the proof - confirmed by a
  built-in non-vacuity check that a deliberately broken `open` (missing the
  counter increment) is rejected.

Each model mirrors the named function line for line and is anchored to the
shipped bytes by the NIST CAVP / RFC 8452 C.2 end-to-end KATs and the
`increment_counter` / `counter_wraps_*` unit tests.

`prove_input_format.py` adds the GHASH/POLYVAL input framing - the zero-padding
of partial AAD/ciphertext blocks and the 64+64-bit length block (`bit_len = 8 ·
len`, big-endian, AAD then ciphertext) - matches SP 800-38D / RFC 8452, the
bit-length conversion never overflows on accepted inputs, and the enforced length
limits equal the standards' caps (the GCM `2^39 − 256`-bit plaintext cap and the
RFC 8452 `2^36`-byte cap).

For the intrinsic-free logic, the **extraction-based** step is already partly
done: the `cfg(kani)` harnesses (§1, "Model checking") run Kani/CBMC over the
*actual compiled* counter increments, length validators, J0 layout, nonce
parser, and envelope splitters - verifying the shipped machine code, not a model.
What remains open is extraction of the *AES-composition* glue (the parts that
call the AES/authenticator oracles), proving the compiled Rust there matches the
spec:

- **hax / Cryspen** - extract the safe Rust glue to F\*/Coq and prove the AEAD
  composition matches an RFC-derived spec. The arithmetic backends are intrinsic
  `unsafe`, outside hax's safe-subset, so they would remain trusted/axiomatized.
  *Attempted, materially advanced:* the full hax toolchain now builds and runs on
  this machine - the `driver-hax-frontend-exporter` and the Rust engine compile
  against hax's pinned `nightly-2025-11-08`, and the F\* path needs no opam, so the
  original toolchain blocker is solved. The live blocker is now that the crate's
  fn-pointers (`pthread_atfork`) and pervasive intrinsics are outside hax's
  importable subset, so the composition must be reformulated before it extracts.
  The working bring-up commands, the exact incompatibilities, and the remaining
  steps are recorded in [`proofs/hax/README.md`](../proofs/hax/README.md).
- **SAW / Cryptol** - prove the compiled routine matches a Cryptol spec at the
  LLVM level, which can reach the intrinsic code the above cannot.

These extraction routes are tracked as future work; the crate does not yet claim
extraction-based machine-checked functional correctness, only the SMT-checked
composition correctness (modulo the hand-translated model) described above.

### 2.3 Constant-time verification method

Constant-time is verified **statistically** (dudect / Welch t-test), not by a
deterministic tool. The Valgrind-secret-poisoning technique (ctgrind: mark the
key as uninitialized, let memcheck flag any branch/index that depends on it) is
deliberately **not** used here: memcheck's shadow-value propagation through the
AES-NI/PCLMULQDQ SIMD instructions is incomplete, which produces false
positives and lost tracking on exactly this code. The hardware vendors guarantee
data-independent timing for those instructions; the dudect harness empirically
checks the surrounding Rust glue. It is now **CI-gated**: the `constant-time` job
runs both decrypt paths (GCM and SIV; tag-mismatch-position and content
independence) and fails the build if Welch `|t|` stays at or above 25. To absorb
shared-runner jitter without flaking, each test takes the best of three batches
and exits on the first passing batch - a real early-exit leak holds `|t|` in the
hundreds across every batch (measured ~267 for an early-vs-late tag comparison),
three orders of magnitude above the ~0.4-2.4 constant-time code produces, so the
gate separates the two cleanly. The remaining residual (no machine-checked CT
proof; ARMv8.4 `PSTATE.DIT` not set) is unchanged. See HRC-2026-05.

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
