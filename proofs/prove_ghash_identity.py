#!/usr/bin/env python3
"""Proof: the per-block GHASH/POLYVAL Horner recurrence equals the
sum-of-powers form the batch path computes, for an 8- and 4-block batch.

The batch path (`update_blocks8`/`update_blocks4`) computes, after the multiply
and reduce-once proofs in this directory:

    sum_i  x_i (x) H^(n-i+1)        (x_1 = Y XOR b_1, x_k = b_k)

while the GHASH/POLYVAL specification accumulates the blocks by the Horner
recurrence

    acc <- (acc XOR b_k) (x) H,   acc_0 = Y.

This script proves, symbolically over a commutative ring (so it holds in any
field, in particular GF(2^128)), that the Horner recurrence expands to exactly
the sum-of-powers form - the one remaining algebraic step linking the verified
batch computation to the specification. `(x)` is the field multiply (proven
correct by prove_multiply.py); here it is the ring product, and `XOR` is ring
addition, which is the relevant structure for this identity.

Run: python3 proofs/prove_ghash_identity.py    (requires sympy)
"""

import sys

import sympy


def horner(y, blocks, h):
    acc = y
    for b in blocks:
        acc = sympy.expand((acc + b) * h)
    return sympy.expand(acc)


def sum_of_powers(y, blocks, h):
    n = len(blocks)
    xs = [y + blocks[0]] + list(blocks[1:])
    total = 0
    for i in range(n):
        total += xs[i] * h ** (n - i)
    return sympy.expand(total)


def prove(n):
    y = sympy.symbols("Y")
    h = sympy.symbols("H")
    blocks = list(sympy.symbols(f"b0:{n}"))
    diff = sympy.expand(horner(y, blocks, h) - sum_of_powers(y, blocks, h))
    # Over GF(2) coefficients are mod 2; the identity holds over Z already
    # (it is the same polynomial), so the difference is the zero polynomial.
    if diff == 0:
        print(f"  PROVED   {n}-block Horner == sum_i x_i * H^(n-i+1)", flush=True)
        return True
    print(f"  FAILED   {n}-block: residual {diff}", flush=True)
    return False


def main():
    print("Symbolic identity (commutative ring): Horner recurrence ==")
    print("sum-of-powers form computed by the batch path.")
    ok = prove(4) and prove(8)
    print()
    if ok:
        print("PROVED: the per-block GHASH/POLYVAL Horner recurrence equals the")
        print("sum-of-powers the batch path computes. Combined with prove_multiply")
        print("(the field product is correct) and prove_aggregation (reduce-once is")
        print("exact), update_blocks8/4 compute the GHASH/POLYVAL accumulator of the")
        print("specification, for every input.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
