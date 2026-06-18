# Proof coverage map

One place to see exactly what is proven about this crate, by which method, and at
what level of trust - so a reviewer does not have to reconstruct it from six proof
scripts, the Kani harnesses, and the test suite. It complements
[`assurance.md`](assurance.md) (the narrative) and
[`security-audit.md`](security-audit.md) (the threat model and findings).

## How to read the trust levels

Not all "verified" is equal. From strongest to weakest, a property here is at one
of these levels:

| Level | Meaning | What is trusted |
| --- | --- | --- |
| **T1 Compiled-code proof** | A tool symbolically verifies the *shipped machine code* over all inputs (bounded where noted). | The tool (CBMC/Miri) and the property statement. |
| **T2 All-inputs model proof** | A property is proven for *all inputs*, but about a model (a faithful hand-translation or an exhaustive basis argument) rather than the compiled binary. | The model's fidelity to the code (anchored to real output / KATs) + the tool (Z3/sympy/exhaustive). |
| **T3 Exhaustive vectors / differential** | Byte-for-byte agreement with the standards' vectors and independent implementations over a dense, boundary-targeted corpus - strong, but a finite sample. | The vector set and the reference implementations. |
| **T4 Statistical / dynamic tooling** | Empirical checks: sanitizers, fuzzing, statistical timing/RNG tests. | The tool and the sample/run length. |
| **OPEN** | Named, not yet done. | - |

The design goal: the most error-prone, hand-built, or security-critical a piece
is, the higher the level it is held to. Novel field arithmetic and the
authentication decision are at T1/T2; the standard AES rounds (a hardware
instruction) are at T3.

## Coverage by component

### Authentication core - GHASH / POLYVAL (the novel, hand-built arithmetic)

| Property | Level | Method | Where |
| --- | --- | --- | --- |
| Field multiply `karatsuba1∘karatsuba2∘mont_reduce` == RFC 8452 POLYVAL `dot`, all inputs, both arches | T2 | Exhaustive over the 128×128 GF(2) basis (bilinear ⇒ everywhere); model pinned to the running `imp::mul` | `proofs/prove_multiply.py`, `field_model.py` |
| Model == real backend on each arch (incl. x86 silicon) | T1/T2 | Captured `imp::mul` vectors reproduced by the running backend on the CI matrix | `mul_reference_anchor` test, `field_model.py` |
| 8-/4-block aggregated reduction == per-block (reduce-once is exact) | T2 | Z3: both reductions GF(2)-linear; runtime cross-check | `proofs/prove_aggregation.py`, `ghash::aggregation_tests` |
| Per-block Horner == batch sum-of-powers | T2 | Symbolic (sympy) | `proofs/prove_ghash_identity.py` |
| `ByteReverse`+`mulX`+POLYVAL == NIST SP 800-38D **GHASH**, all subkeys/blocks | T2 | Single-block identity exhaustive on the 128×128 basis, lifted by Horner induction + `ByteReverse` involution | `proofs/prove_ghash_polyval_mapping.py` |
| GHASH input framing (partial-block zero pad, 64+64 length block, no length overflow, limits == caps) | T2 | Z3 over symbolic lengths/blocks + concrete limit equalities | `proofs/prove_input_format.py` |

### AEAD composition (J0 / CTR / tag wiring, SIV derivation)

| Property | Level | Method | Where |
| --- | --- | --- | --- |
| GCM `increment_counter` == SP 800-38D `inc_32` | **T1** | Kani/CBMC over all 2¹²⁸ blocks | `kani_proofs` (mod.rs) |
| SIV counter == RFC 8452 LE32 increment | **T1** | Kani/CBMC over all blocks | `kani_proofs` (siv.rs) |
| J0 layout, length validators, nonce parser, both envelope splitters (no panic / no OOB / correct boundary) | **T1** | Kani/CBMC, all inputs (bounded where noted) | `kani_proofs` |
| `constant_time_eq` == bytewise equality on equal-length tags (the auth decision) | **T1** | Kani/CBMC over all tag-pairs | `kani_proofs` (mod.rs) |
| Generated nonce `(base+counter) mod 2⁹⁶` injective in the counter (no reuse within an instance) | **T1** | Kani/CBMC, all bases + counter pairs | `kani_proofs` (nonce.rs) |
| Counters/J0/derivation/tag layouts + decrypt-inverts-encrypt + accepts genuine ciphertext == SP 800-38D / RFC 8452 | T2 | Z3 with AES & authenticator as uninterpreted oracles; `seal`/`open` modeled independently; non-vacuity check included | `proofs/prove_composition.py` |
| Composition output == RustCrypto `aes-gcm`/`aes-gcm-siv` and `ring`, both directions, dense length+AAD sweeps | T3 | Differential KATs | `tests/aes_gcm_interop.rs`, `aes_gcm_siv_interop.rs` |
| Composition == NIST CAVP (750) / RFC 8452 C.2 / Project Wycheproof (66 GCM + 103 SIV) | T3 | Vendored known-answer vectors | `tests/nist_cavp_gcm.rs`, `wycheproof_*` |

### AES-256 block cipher and key schedule

| Property | Level | Method | Where |
| --- | --- | --- | --- |
| `AES_SBOX` == genuine FIPS-197 `affine(inverse_GF(2⁸)(x))`, all 256 inputs (and a bijection) | T2 | Independent GF(2⁸) inverse + affine reconstruction, exhaustive | `aes_sbox_is_fips197_affine_inverse` test |
| Software key schedule == hardware key expansion (anchors the cfg(miri) path and, transitively, the shipped expansion) | T3 | Byte-for-byte over FIPS-197 + pseudo-random keys | `software_schedule_matches_hardware` test |
| AES round function (AES-NI / NEON) | T3 | FIPS-197 / NIST CAVP known-answer + differential | interop + CAVP suites |

### Memory safety, side channels, supply chain

| Property | Level | Method | Where |
| --- | --- | --- | --- |
| Full AES-256-GCM/SIV key-state lifecycle + real AES/GHASH paths are UB-free (aliasing, provenance, OOB, uninit) | T1 | Miri on x86 (incl. the unsafe envelope-trailer write `append_tag_nonce`) | `cargo miri test --lib aes_gcm` |
| Native intrinsic binary is memory-clean | T4 | Valgrind memcheck + ASan; TSan on cross-thread paths | CI |
| Decrypt parser never panics / no UB on arbitrary bytes | T1+T4 | Kani (splitters) + fuzz + proptest | `kani_proofs`, `fuzz/`, `tests/proptest_aead.rs` |
| Decrypt paths constant-time (data-independent) | T4 | dudect Welch t-test, **CI-gated** (`\|t\| < 25`, best-of-3) | `constant-time` CI job |
| No third-party cipher in the production graph; advisories/licenses clean | T4 | CI-enforced graph check + `cargo audit` + `cargo deny` | CI, `deny.toml` |
| RNG output quality | T4 | monobit/chi-square/serial-correlation + PractRand/dieharder procedure | `tests/rng_statistical.rs`, `docs/randomness-testing.md` |

## What is still open

| Item | Why it's open | Plan |
| --- | --- | --- |
| **Extraction-based proof of the AES-*calling* composition glue** (`seal`/`open`, SIV derivation) | These call the intrinsic backends, so CBMC/Kani can't reach them; `prove_composition.py` proves a faithful *model* (T2), not the compiled source. | hax/F\*. **Extraction now works** — `proofs/hax/extract.sh` emits the composition as F\* from the real source. Remaining: write + check the F\* lemmas (axiomatize the opaque backends, relate to the SP 800-38D/RFC 8452 spec). Full status in [`proofs/hax/README.md`](../proofs/hax/README.md). |
| **`append_tag_nonce` functional proof** | `Vec` allocator modeling is impractical under CBMC. | Soundness is already Miri-covered (T1 for UB); a functional T1 proof awaits a lighter harness or a different tool. |
| **Independent third-party audit / CAVP-CMVP accreditation** | Not performed; not claimed. | See `security-audit.md` HRC-2026-09 and `assurance.md` §3. |
| **aarch64 under Miri** | Miri does not model NEON crypto intrinsics, so the Miri job runs on x86; aarch64 memory safety is Valgrind/ASan only (T4). | Track Miri intrinsic support. |

## Reproduce everything

```sh
# T2 all-inputs model proofs (Z3/sympy):
pip install z3-solver sympy && ./proofs/run_all.sh

# T1 compiled-code proofs (Kani/CBMC):
cargo install --locked kani-verifier && cargo kani setup && cargo kani

# T1 memory safety (Miri, x86):
cargo +nightly miri test --lib aes_gcm

# T3 vectors + differential, T4 tooling:
cargo test --workspace --all-targets
# constant-time (T4), gated:
cargo test --release --test timing_constant_time --test timing_constant_time_siv -- --ignored
```

Every row above runs in CI (`.github/workflows/ci.yml`); the heavy variants
(deep fuzz, multi-seed PractRand, extended proofs) are in
`.github/workflows/heavy-assurance.yml`.
