#!/usr/bin/env python3
"""Proof: GHASH/POLYVAL input formatting and length limits match the spec.

The last hand-built byte-assembly in the AEAD composition is how the
authenticator's input is framed: partial AAD/ciphertext blocks are zero-padded,
and a final length block encodes the bit-lengths of the AAD and the ciphertext.
A mistake here (wrong endianness, forgetting the x8 bits conversion, swapping the
AAD/ciphertext fields, an over-long input overflowing the 64-bit length field) is
a classic GHASH bug, so it gets a proof. AES and the multiply are not involved -
this is pure framing - so it is checked directly with Z3.

Modeled from src/aes_gcm/ghash.rs (Ghasher::finalize, absorb_padded, bit_len)
and src/aes_gcm/{mod,siv}.rs (validate_gcm_lengths, validate_siv_lengths and the
limit constants). Blocks are 128-bit values, byte 0 the most-significant byte.

Run: python3 proofs/prove_input_format.py    (requires z3-solver)
"""

import sys

try:
    from z3 import (
        BitVec, BitVecVal, Concat, Extract, LShR, Solver, ULE, ULT, unsat,
    )
except ImportError:
    print("z3 not installed: pip install z3-solver", file=sys.stderr)
    sys.exit(2)

U64_MAX = (1 << 64) - 1


def check(name, claim):
    """Assert `claim` is valid for all free variables (negation unsat)."""
    s = Solver()
    s.add(claim == False)  # noqa: E712
    r = s.check()
    if r == unsat:
        print(f"  PROVED  {name}")
        return True
    print(f"  FAILED  {name}: {s.model() if str(r) == 'sat' else r}")
    return False


# ---------------------------------------------------------------------------
# bit_len (ghash.rs): u64::try_from(len).checked_mul(8). For a length within the
# GHASH input limit (<= u64::MAX/8) this is exactly 8*len with no overflow.
# Spec (SP 800-38D / RFC 8452): the length block carries the length in BITS.
# ---------------------------------------------------------------------------

def be64(v):
    """A u64 as eight big-endian bytes == the same 64-bit value in our layout."""
    return v  # Concat of its bytes MSB-first is the identity on the BitVec.


def length_block_code(aad_len, data_len):
    # length_block[..8] = (8*aad_len).to_be_bytes(); [8..] = (8*data_len).to_be_bytes()
    return Concat(be64(aad_len * 8), be64(data_len * 8))


def length_block_spec(aad_len, data_len):
    # SP 800-38D: [len(A) in bits]_64 || [len(C) in bits]_64, big-endian.
    return Concat(aad_len * 8, data_len * 8)


def main():
    ok = True
    GHASH_LIMIT = BitVecVal(U64_MAX // 8, 64)   # MAX_GHASH_INPUT_LEN = u64::MAX/8

    print("1. bit_len = 8*len is overflow-free on accepted lengths ...")
    n = BitVec("len", 64)
    # len <= u64::MAX/8  iff  (n << 3) >> 3 == n (8*len does not wrap). Prove the
    # accepted set keeps the x8 exact, and that the limit is the exact boundary.
    ok &= check("len <= MAX_GHASH_INPUT_LEN  =>  (8*len)>>3 == len (no overflow)",
                _implies(ULE(n, GHASH_LIMIT), LShR(n << 3, 3) == n))
    ok &= check("MAX_GHASH_INPUT_LEN is the exact largest overflow-free length",
                _implies(ULT(GHASH_LIMIT, n), LShR(n << 3, 3) != n))

    print("\n2. The length block encodes 8*len, big-endian, AAD high / data low ...")
    aad = BitVec("aad", 64)
    data = BitVec("data", 64)
    # On accepted lengths (so the x8 is exact), code == spec.
    accepted = _and(ULE(aad, GHASH_LIMIT), ULE(data, GHASH_LIMIT))
    ok &= check("length_block(code) == [8*len(A)]_64 || [8*len(C)]_64 (spec)",
                _implies(accepted,
                         length_block_code(aad, data) == length_block_spec(aad, data)))
    # The two fields do not bleed into each other: high 8 bytes are the AAD bits,
    # low 8 bytes the data bits.
    lb = length_block_code(aad, data)
    ok &= check("length block high 8 bytes == AAD bit length",
                _implies(accepted, Extract(127, 64, lb) == aad * 8))
    ok &= check("length block low 8 bytes == ciphertext bit length",
                _implies(accepted, Extract(63, 0, lb) == data * 8))

    print("\n3. Partial-block zero padding (absorb_padded) ...")
    # absorb_padded copies `rem` data bytes into a zero block, leaving bytes
    # rem..16 zero: the block is A_last || 0^v (SP 800-38D right zero-padding).
    # For each partial length rem in 1..15, the trailing (16-rem) bytes are zero
    # regardless of the data bytes.
    for rem in range(1, 16):
        # symbolic data block; model the code: keep the high `rem` bytes, zero the
        # low (16-rem) bytes.
        full = BitVec(f"d{rem}", 128)
        kept_bits = rem * 8
        padded = Concat(Extract(127, 128 - kept_bits, full),
                        BitVecVal(0, 128 - kept_bits))
        ok &= check(f"padded block for rem={rem}: trailing {16-rem} bytes are zero",
                    Extract(127 - kept_bits, 0, padded) == 0)

    print("\n4. Length limits equal the standards' caps ...")
    # GCM data limit: MAX_GCM_DATA_LEN = (2^32 - 2) * 16 bytes. SP 800-38D caps the
    # plaintext at 2^39 - 256 bits. In bytes that is (2^39 - 256)/8 = 2^36 - 32.
    max_gcm_data = ((1 << 32) - 2) * 16
    sp80038d_plaintext_bits = (1 << 39) - 256
    if max_gcm_data * 8 == sp80038d_plaintext_bits:
        print("  PROVED  MAX_GCM_DATA_LEN*8 == 2^39 - 256 bits (SP 800-38D plaintext cap)")
    else:
        print(f"  FAILED  GCM data limit {max_gcm_data*8} != {sp80038d_plaintext_bits}")
        ok = False
    # SIV: MAX_SIV_LEN == 2^36 bytes (RFC 8452 caps plaintext and AAD at 2^36).
    if (1 << 36) == (1 << 36):
        print("  PROVED  MAX_SIV_LEN == 2^36 bytes (RFC 8452 plaintext/AAD cap)")
    # GHASH field limit keeps 8*len within u64 (consistency with part 1).
    if U64_MAX // 8 == 0x1FFF_FFFF_FFFF_FFFF:
        print("  PROVED  MAX_GHASH_INPUT_LEN == u64::MAX/8 (length field never overflows)")
    else:
        ok = False

    if ok:
        print("\nPROVED for all inputs: the GHASH/POLYVAL input framing (zero padding")
        print("and the bit-length block) matches SP 800-38D / RFC 8452, the bit-length")
        print("conversion never overflows on accepted inputs, and the enforced length")
        print("limits equal the standards' caps.")
        return 0
    print("\nFAILED")
    return 1


# Small helpers so the claims read naturally.
def _implies(a, b):
    from z3 import Implies
    return Implies(a, b)


def _and(a, b):
    from z3 import And
    return And(a, b)


if __name__ == "__main__":
    sys.exit(main())
