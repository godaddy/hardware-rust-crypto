# Machine-checked proofs

Formal, reproducible proofs that the crate's GHASH/POLYVAL carryless-multiply
core is correct **for all inputs** - intended as part of the evidence base that
substitutes for paid algorithm certification. Every proof reasons about the
*actual* intrinsic sequence in `src/aes_gcm/ghash.rs`, and the model used is
pinned bit-for-bit to the running code before any proof is trusted.

## What is proven

| Script | Statement | Method | Completeness |
| --- | --- | --- | --- |
| `field_model.py` | The Python model == the real backend `imp::mul` (3 captured vectors) **and** == RFC 8452 POLYVAL `dot`. | Concrete bit-for-bit replay | Anchor (data) |
| `prove_multiply.py` | `field_mul(a,b)` (the exact `karatsuba1`+`karatsuba2`+`mont_reduce`) == RFC 8452 POLYVAL `dot(a,b)` for **all** `a,b`. | Both maps are GF(2)-bilinear; bilinear maps are determined by a basis, so equality on all 128x128 standard-basis pairs ⇒ equality everywhere (exhaustive). | Complete |
| `prove_aggregation.py` | The exact `mont_reduce ∘ karatsuba2` (aarch64) and `reduce` (x86) are GF(2)-linear ⇒ the batch path "fold the partials, reduce once" equals the per-block reduction. | Z3 SMT, closed universally-quantified query | Complete |
| `prove_ghash_identity.py` | The per-block Horner recurrence == the sum-of-powers form the batch path computes. | Symbolic expansion over a commutative ring (sympy) | Complete |
| `prove_ghash_polyval_mapping.py` | The crate's `ByteReverse` + `mulX` + POLYVAL construction == NIST SP 800-38D **GHASH**, for all subkeys and block counts. | Single-block mapping `gmul(X,H) == R(dot(R(X),mulX(R(H))))` is bilinear ⇒ exhaustive on all 128x128 basis pairs; the multi-block lift needs only that plus `ByteReverse` being a linear involution (Horner induction). | Complete |
| `prove_composition.py` | The intrinsic-free AEAD glue == SP 800-38D / RFC 8452, for all inputs: GCM `increment_counter` == `inc_32`; SIV counter == RFC LE32 increment; J0 and SIV key-derivation/tag layouts; and decryption inverts encryption and accepts genuine ciphertext (both modes). | Z3 SMT with AES and the authenticator as **uninterpreted functions** (their correctness comes from the other proofs + KATs); each model mirrors the named `mod.rs`/`siv.rs` function line for line; includes a non-vacuity check that a broken wiring is rejected. | Complete (modulo correct AES/authenticator) |
| `prove_input_format.py` | The GHASH/POLYVAL input framing == SP 800-38D / RFC 8452: partial-block zero padding, the 64+64-bit length block (`8·len`, big-endian, AAD then ciphertext), no length-field overflow on accepted inputs, and the enforced length limits == the standards' caps. | Z3 SMT over symbolic lengths/blocks + concrete limit equalities. | Complete |

Beyond the Python/Z3 suite, the `cfg(kani)` harnesses in `src/aes_gcm/{mod,siv}.rs`
run the **Kani** model checker (CBMC) over the *actual compiled Rust* of the
intrinsic-free logic - the counter increments, J0 layout, length validators, the
nonce parser, and the two envelope splitters - verifying over all inputs (bounded
where noted) that they match the spec increments and never panic / never index
out of bounds. Unlike the Z3 proofs, which reason about a faithful model, Kani
verifies the shipped machine code. Run with `cargo kani` (see `docs/assurance.md`).

Chained together: the field multiply computes the correct POLYVAL product
(`prove_multiply`); folding the per-slot Karatsuba partials and reducing once
gives the sum of those products (`prove_aggregation`); and that sum is exactly
the GHASH/POLYVAL Horner accumulator of the specification
(`prove_ghash_identity`). Therefore `update_blocks8` / `update_blocks4` compute
the specified POLYVAL accumulator for every input. Finally,
`prove_ghash_polyval_mapping` closes the gap between POLYVAL (the backend's
native operation) and GHASH (what AES-GCM authentication actually needs): the
byte-reversal + `mulX` bridge the crate uses to drive GHASH on the POLYVAL engine
provably computes SP 800-38D GHASH for every input - the one piece of novel
hand-built algebra in the AEAD composition. The model's fidelity to the shipped
code is established by `field_model.py` (model == `imp::mul` == RFC 8452) and the
`imp_mul_matches_proof_reference_vectors` test (the real backend reproduces the
anchor vectors on each CI architecture, including x86 AES-NI/PCLMULQDQ silicon).

## Faithfulness (why this is about the real code, not a toy)

`field_model.py` emulates the exact NEON sequence - `pmull`/`pmull2`
(`vmull_p64`), `vextq_u8(.,.,8)`, `karatsuba1`, `karatsuba2`, and `mont_reduce`
with its literal `poly` constant - and is checked to reproduce, byte-for-byte,
reference outputs captured from the running `imp::mul` (and to equal the
independent RFC 8452 `dot`). The Z3 model in `prove_aggregation.py` uses the same
sequence. So a disagreement between "the model" and "the code" would show up as
a failed vector before any proof runs.

## Scope

These proofs cover the **GHASH/POLYVAL field arithmetic**, the **GHASH
construction**, and the **intrinsic-free composition glue** (J0/counter
construction, the GCM and SIV counter increments, SIV key derivation and tag
layout, and the decrypt-inverts-encrypt round-trip). They do **not** prove the
AES block cipher itself; AES correctness is covered by FIPS-197 / NIST CAVP / RFC
known-answer tests, and the `unsafe` memory handling by Miri and Valgrind (see
`docs/assurance.md`). `prove_composition.py` treats AES and the authenticator as
uninterpreted oracles, so it proves the *wiring* is the specification given
correct primitives; it is a hand-translated model of the `mod.rs`/`siv.rs`
functions (anchored to the real code by the NIST CAVP / RFC 8452 C.2 end-to-end
KATs and the `increment_counter` / `counter_wraps_*` unit tests), not a tool that
extracts the compiled Rust. A full extraction-based functional-correctness proof
(hax/F\* or SAW) that removes the hand-translation trust step remains future work
(see `docs/assurance.md` 2.2). **Both architectures are proven in full**: each
exact intrinsic sequence (aarch64 `karatsuba`+`mont_reduce`, x86
`clmul_wide`+`reduce`) is modeled, anchored to the same captured backend output
and to RFC 8452, and basis-proven equal to POLYVAL `dot`, with both reductions
proven GF(2)-linear.

## Reproduce

```sh
pip install z3-solver sympy
./proofs/run_all.sh           # runs all seven; exits non-zero on any failure
# or individually:
python3 proofs/field_model.py
python3 proofs/prove_multiply.py
python3 proofs/prove_aggregation.py
python3 proofs/prove_ghash_identity.py
python3 proofs/prove_ghash_polyval_mapping.py
python3 proofs/prove_composition.py
python3 proofs/prove_input_format.py

# Kani model checking of the compiled intrinsic-free logic (separate toolchain):
cargo install --locked kani-verifier && cargo kani setup
cargo kani
```

The Python/Z3 suite runs on every build by the `formal-proof` CI job and Kani by
the `kani` CI job (`.github/workflows/ci.yml`). `prove_multiply.py` takes ~1-2
minutes (the exhaustive basis sweep); `prove_ghash_polyval_mapping.py` a few
seconds (its two 128x128 sweeps); `prove_composition.py`, `prove_input_format.py`
and the others are seconds.
