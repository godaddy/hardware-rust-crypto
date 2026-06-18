#!/usr/bin/env python3
"""Proof: the crate's batch aggregation computes the same accumulator as the
per-block path, for ALL inputs - faithful to the exact intrinsic sequences.

`update_blocks8`/`update_blocks4` compute `karatsuba1` per slot, XOR-fold the
(h, m, l) partials across the batch, then apply `karatsuba2` and the reduction
ONCE. The per-block path would apply `karatsuba2`+reduction to each block and
XOR the results. The two are identical iff

    G(h, m, l) := reduce(karatsuba2(h, m, l))

is GF(2)-linear in (h, m, l): then
    XOR_i G(h_i, m_i, l_i) == G(XOR_i h_i, XOR_i m_i, XOR_i l_i).

This script models the EXACT aarch64 `karatsuba2` + `mont_reduce` and the EXACT
x86 `reduce`, as written in `src/aes_gcm/ghash.rs`, and proves with Z3 that each
G is GF(2)-linear over all inputs (a closed universally-quantified query, so an
`unsat` is a proof, not a sample). The intrinsics here are XOR / byte-permute /
shift / and carryless-multiply-by-the-constant-poly, all GF(2)-linear, so the
queries are tractable. Faithfulness of the model is established separately by
`field_model.py` (model == real `imp::mul` == RFC 8452 POLYVAL).

Run: python3 proofs/prove_aggregation.py    (requires z3-solver)
"""

import sys
from z3 import BitVec, BitVecVal, Concat, Extract, Solver, ZeroExt, unsat

# mont_reduce constant poly, exactly as in ghash.rs.
POLY = (1 << 127) | (1 << 126) | (1 << 121) | (1 << 63) | (1 << 62) | (1 << 57)
POLY_LO = POLY & ((1 << 64) - 1)          # bits 63,62,57
POLY_HI = (POLY >> 64) & ((1 << 64) - 1)  # bits 63,62,57


def lo64(a):
    return Extract(63, 0, a)


def hi64(a):
    return Extract(127, 64, a)


def ext8(a, b):
    # vextq_u8(a, b, 8): low 64 = high64(a), high 64 = low64(b).
    return Concat(lo64(b), hi64(a))


def clmul64_const(x64, const):
    # Carryless product of a 64-bit value by a constant -> 128-bit. Only the set
    # bits of the constant contribute (XOR of shifted copies); cheap.
    acc = BitVecVal(0, 128)
    x = ZeroExt(64, x64)
    for i in range(64):
        if (const >> i) & 1:
            acc = acc ^ (x << i)
    return acc


def pmull_const(a, const_lo):
    return clmul64_const(lo64(a), const_lo)


def pmull2_const(a, const_hi):
    return clmul64_const(hi64(a), const_hi)


def karatsuba2(h, m, l):
    t0 = m ^ ext8(l, h)
    t1 = h ^ l
    t = t0 ^ t1
    x01 = ext8(ext8(l, l), t)
    x23 = ext8(t, ext8(h, h))
    return x23, x01


def mont_reduce(x23, x01):
    a = pmull_const(x01, POLY_LO)
    b = x01 ^ ext8(a, a)
    c = pmull2_const(b, POLY_HI)
    return x23 ^ c ^ b


def g_aarch64(h, m, l):
    x23, x01 = karatsuba2(h, m, l)
    return mont_reduce(x23, x01)


# --- exact x86 `reduce` ---

def shuffle_epi32_0e(x):
    # imm 0x0E: dst dwords = [src2, src3, src0, src0].
    d0 = Extract(95, 64, x)
    d1 = Extract(127, 96, x)
    d2 = Extract(31, 0, x)
    d3 = Extract(31, 0, x)
    return Concat(d3, d2, d1, d0)


def srli_epi64(x, n):
    from z3 import LShR
    return Concat(LShR(hi64(x), n), LShR(lo64(x), n))


def slli_epi64(x, n):
    return Concat(hi64(x) << n, lo64(x) << n)


def unpacklo_epi64(a, b):
    return Concat(lo64(b), lo64(a))


def reduce_x86(t0, t1, t2):
    t2 = t2 ^ (t0 ^ t1)
    v0 = t0
    v1 = shuffle_epi32_0e(t0) ^ t2
    v2 = t1 ^ shuffle_epi32_0e(t2)
    v3 = shuffle_epi32_0e(t1)
    v2 = v2 ^ v0 ^ srli_epi64(v0, 1) ^ srli_epi64(v0, 2) ^ srli_epi64(v0, 7)
    v1 = v1 ^ slli_epi64(v0, 63) ^ slli_epi64(v0, 62) ^ slli_epi64(v0, 57)
    v3 = v3 ^ v1 ^ srli_epi64(v1, 1) ^ srli_epi64(v1, 2) ^ srli_epi64(v1, 7)
    v2 = v2 ^ slli_epi64(v1, 63) ^ slli_epi64(v1, 62) ^ slli_epi64(v1, 57)
    return unpacklo_epi64(v2, v3)


def prove(name, claim_negation):
    s = Solver()
    s.add(claim_negation)
    if s.check() == unsat:
        print(f"  PROVED   {name}", flush=True)
        return True
    print(f"  FAILED   {name}", flush=True)
    return False


def main():
    ok = True
    print("aarch64: G(h,m,l) = mont_reduce(karatsuba2(h,m,l)) is GF(2)-linear")
    print("(=> folding the karatsuba1 partials and reducing once == per-block)")
    h1, m1, l1 = BitVec("h1", 128), BitVec("m1", 128), BitVec("l1", 128)
    h2, m2, l2 = BitVec("h2", 128), BitVec("m2", 128), BitVec("l2", 128)
    lhs = g_aarch64(h1 ^ h2, m1 ^ m2, l1 ^ l2)
    rhs = g_aarch64(h1, m1, l1) ^ g_aarch64(h2, m2, l2)
    ok &= prove("aarch64 mont_reduce o karatsuba2 linear", lhs != rhs)

    print("\nx86: reduce(t0,t1,t2) is GF(2)-linear")
    a0, a1, a2 = BitVec("a0", 128), BitVec("a1", 128), BitVec("a2", 128)
    b0, b1, b2 = BitVec("b0", 128), BitVec("b1", 128), BitVec("b2", 128)
    lhs = reduce_x86(a0 ^ b0, a1 ^ b1, a2 ^ b2)
    rhs = reduce_x86(a0, a1, a2) ^ reduce_x86(b0, b1, b2)
    ok &= prove("x86 reduce linear", lhs != rhs)

    print()
    if ok:
        print("PROVED for all inputs: both reductions are GF(2)-linear, so the")
        print("8-/4-block aggregation (fold partials, reduce once) equals the")
        print("per-block reduction. Faithful to the exact intrinsic sequences;")
        print("model fidelity to the real code is pinned by field_model.py.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
