#!/usr/bin/env python3
"""Proof: the crate's single-block field multiply computes the correct
GF(2^128) POLYVAL product (RFC 8452 `dot`), for ALL 2^256 inputs.

`field_mul(a,b) = mont_reduce(karatsuba2(karatsuba1(a,b)))` (the exact intrinsic
sequence; see field_model.py, validated bit-for-bit against the running
backend) is GF(2)-BILINEAR in (a,b): `karatsuba1` enters a and b only through
`clmul64` (the carryless product, which is bilinear by definition), and every
later step - `karatsuba2`, `mont_reduce` - is a GF(2)-linear combination
(byte-permute `ext8`, XOR, and carryless-multiply-by-the-constant-poly). A
GF(2)-linear combination of bilinear maps is bilinear. The RFC 8452 reference
`dot(a,b) = a . b . x^-128 mod p` is likewise bilinear.

A bilinear map B: V x W -> U is determined uniquely by its values on a basis of
V and a basis of W. Hence two bilinear maps are equal everywhere IFF they agree
on every basis pair (e_i, e_j). The standard basis of GF(2)^128 is
{2^0, ..., 2^127}, so we check all 128 x 128 = 16384 pairs exhaustively. If they
all match, `field_mul == dot` on all of GF(2^128) x GF(2^128) - a complete
proof, not a sample.

The script also (belt and suspenders) confirms `field_mul` reconstructs from its
basis values on random inputs - an empirical witness of the bilinearity the
proof relies on - and that the two agree on random inputs.

Run: python3 proofs/prove_multiply.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from field_model import field_mul_int, field_mul_x86_int, polyval_dot  # noqa: E402


def basis_equality(mul):
    """Exhaustive check over the 128 x 128 standard basis pairs."""
    mismatches = 0
    for i in range(128):
        ei = 1 << i
        for j in range(128):
            ej = 1 << j
            if mul(ei, ej) != polyval_dot(ei, ej):
                mismatches += 1
    return mismatches


def reconstructs_from_basis(a, b):
    """field_mul(a,b) == XOR over set bits i of a, set bits j of b, of
    field_mul(e_i, e_j) - holds iff field_mul is bilinear."""
    acc = 0
    ai = a
    i = 0
    while ai:
        if ai & 1:
            bj = b
            j = 0
            while bj:
                if bj & 1:
                    acc ^= field_mul_int(1 << i, 1 << j)
                bj >>= 1
                j += 1
        ai >>= 1
        i += 1
    return acc == field_mul_int(a, b)


def xorshift(state):
    state ^= (state << 13) & ((1 << 128) - 1)
    state ^= state >> 7
    state ^= (state << 17) & ((1 << 128) - 1)
    return state & ((1 << 128) - 1)


def main():
    print("Exhaustive basis check: field_mul(e_i,e_j) == POLYVAL dot(e_i,e_j)")
    print("for all 128 x 128 = 16384 standard-basis pairs, per architecture ...")
    for arch, mul in (("aarch64", field_mul_int), ("x86", field_mul_x86_int)):
        mism = basis_equality(mul)
        if mism == 0:
            print(f"  PROVED   {arch}: field_mul == RFC 8452 POLYVAL dot on all basis pairs")
            print(f"           => equal on all of GF(2^128) x GF(2^128) (both bilinear)")
        else:
            print(f"  FAILED   {arch}: {mism} basis pairs disagree")
            return 1

    print("\nWitnessing bilinearity (basis reconstruction) on random inputs ...")
    st = 0x0123456789abcdef0fedcba987654321
    recon_ok = True
    eq_ok = True
    for _ in range(2000):
        st = xorshift(st)
        a = st
        st = xorshift(st)
        b = st
        recon_ok &= reconstructs_from_basis(a, b)
        eq_ok &= field_mul_int(a, b) == polyval_dot(a, b)
    print(f"  field_mul reconstructs from basis (=> bilinear): {recon_ok}")
    print(f"  field_mul == dot on random inputs               : {eq_ok}")
    if not (recon_ok and eq_ok):
        return 1

    print("\nPROVED for all inputs: the crate's carryless multiply + Montgomery")
    print("reduction computes the RFC 8452 POLYVAL field product. Faithful to the")
    print("exact intrinsics (field_model.py), complete via basis determination.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
