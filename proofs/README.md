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

These proofs cover the **GHASH/POLYVAL field arithmetic and the GHASH
construction** (the novel, hand-built parts). They do **not** prove the AES block
cipher itself; AES correctness is covered by FIPS-197 / NIST CAVP / RFC
known-answer tests, and the `unsafe` memory handling by Miri and Valgrind (see
`docs/assurance.md`). The rest of the AEAD composition (J0, the CTR keystream,
the length block, the tag XOR; SIV key derivation and the SIV-CTR counter) is
straight-line byte plumbing validated byte-for-byte by the NIST CAVP / RFC 8452 /
Wycheproof known-answer suites and the RustCrypto/ring differential tests, not by
these proofs - a full functional-correctness proof of that glue (hax/F\* or SAW)
remains future work (see `docs/assurance.md` 2.2). **Both architectures are
proven in full**: each exact intrinsic sequence (aarch64 `karatsuba`+`mont_reduce`,
x86 `clmul_wide`+`reduce`) is modeled, anchored to the same captured backend
output and to RFC 8452, and basis-proven equal to POLYVAL `dot`, with both
reductions proven GF(2)-linear.

## Reproduce

```sh
pip install z3-solver sympy
./proofs/run_all.sh           # runs all five; exits non-zero on any failure
# or individually:
python3 proofs/field_model.py
python3 proofs/prove_multiply.py
python3 proofs/prove_aggregation.py
python3 proofs/prove_ghash_identity.py
python3 proofs/prove_ghash_polyval_mapping.py
```

Run on every build by the `formal-proof` CI job (`.github/workflows/ci.yml`).
`prove_multiply.py` takes ~1-2 minutes (the exhaustive basis sweep);
`prove_ghash_polyval_mapping.py` a few seconds (its two 128x128 sweeps); the
others are seconds.
