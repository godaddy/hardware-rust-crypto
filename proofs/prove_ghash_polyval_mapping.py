#!/usr/bin/env python3
"""Proof: the crate computes NIST SP 800-38D GHASH, for ALL inputs.

The crate has no native GHASH multiplier. It authenticates AES-GCM with the
POLYVAL backend (the same carryless-multiply core proven correct in
prove_multiply.py) and bridges POLYVAL to GHASH with a byte-reversal + mulX
trick (src/aes_gcm/ghash.rs::GHashKey::init_in_place and Ghasher::absorb_*/
finalize). Concretely, to GHASH message blocks X_1..X_n under hash subkey H the
crate computes

    h1   = mulX(ByteReverse(H))                         # the POLYVAL key
    out  = ByteReverse( POLYVAL(h1, ByteReverse(X_1), ..., ByteReverse(X_n)) )

This file proves out == GHASH(H, X_1..X_n) for every H and every block sequence.

This byte-reversal bridge is the ONE piece of novel hand-built algebra in the
AEAD composition (everything else - J0, the CTR keystream, the length block, the
tag XOR - is straight-line byte plumbing exercised byte-for-byte by the NIST
CAVP and Wycheproof KATs and the RustCrypto/ring differential suite). It is also
the easiest place to be subtly wrong, so it gets a real proof.

Structure of the proof
-----------------------
Let R = ByteReverse (a GF(2)-linear involution: R(a^b)=R(a)^R(b), R(R(a))=a),
`dot` = the POLYVAL field product (a.b.x^-128 mod the POLYVAL poly; this is the
backend's native op, proven == the real intrinsic multiply in prove_multiply.py),
`mulX` = the crate's exact mulx() (multiply-by-x in the POLYVAL field), and
`gmul` = the independent GHASH/GCM field multiply (NIST SP 800-38D Algorithm 1).

1. SINGLE-BLOCK IDENTITY (all inputs):  for all 128-bit X, H,

       gmul(X, H)  ==  R( dot( R(X), mulX(R(H)) ) ).                    (*)

   Both sides are GF(2)-BILINEAR in (X, H) - gmul by definition; the RHS because
   R and mulX are GF(2)-linear and dot is bilinear. Two bilinear maps are equal
   everywhere iff they agree on every basis pair, so (*) is settled by checking
   all 128 x 128 = 16384 standard-basis pairs (e_i, e_j). Complete, not a sample.

2. HORNER LIFT (any number of blocks):  GHASH's Horner accumulator and the
   crate's POLYVAL Horner accumulator (conjugated by R) step identically.
   Writing the crate's POLYVAL accumulator Z_i and its GHASH-domain image
   W_i := R(Z_i):

       W_i = R( (Z_{i-1} ^ R(X_i)) . h1 )                 [crate step, h1=mulX(R(H))]
           = R( ( R(W_{i-1}) ^ R(X_i) ) . h1 )            [Z_{i-1}=R(W_{i-1}), R invol.]
           = R( R(W_{i-1} ^ X_i) . mulX(R(H)) )           [R linear]
           = gmul( W_{i-1} ^ X_i, H )                     [by (*)]

   which is exactly the GHASH Horner step Y_i = gmul(Y_{i-1} ^ X_i, H). With
   W_0 = R(0) = 0 = Y_0, induction gives W_n = Y_n, i.e. the crate's final
   ByteReverse(POLYVAL ...) equals GHASH(H, X_1..X_n) for every n and every
   block sequence. The lift needs ONLY (*) plus R being a linear involution -
   both established here - so proving (*) proves the whole construction.

`gmul` is pinned to the spec by definition-derived anchors (the field identity
element, and the defining reduction x*x^127 == R = x^7+x^2+x+1) and, decisively,
by the 16384-pair agreement in step 1 against the independently-correct backend
`dot`: a wrong `gmul` could not match. (POLYVAL `dot` is itself anchored to the
running backend in field_model.py and proven == RFC 8452 in prove_multiply.py.)

Run: python3 proofs/prove_ghash_polyval_mapping.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from field_model import polyval_dot  # noqa: E402  (the proven backend product)

MASK = (1 << 128) - 1


# ---------------------------------------------------------------------------
# Byte/representation helpers (16-byte blocks)
# ---------------------------------------------------------------------------

def byte_reverse(b):
    """R: reverse the 16 bytes. The GHASH<->POLYVAL byte mapping."""
    return bytes(reversed(b))


def le_int(b):
    return int.from_bytes(b, "little")


def le_bytes(n):
    return (n & MASK).to_bytes(16, "little")


# ---------------------------------------------------------------------------
# mulX: a faithful model of src/aes_gcm/ghash.rs::mulx (multiply-by-x in the
# POLYVAL field). Mirrors the exact u128 little-endian shift/reduce.
# ---------------------------------------------------------------------------

def mulx_code(b):
    v = le_int(b)
    v_hi = v >> 127
    v = (v << 1) & MASK
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121)
    return le_bytes(v)


# ---------------------------------------------------------------------------
# gmul: the GHASH/GCM field multiply, NIST SP 800-38D Section 6.3, Algorithm 1.
# Independent of the crate. Bit 0 is the leftmost bit of byte 0 and is the x^0
# coefficient (the GCM bit-reflected convention); we carry blocks as big-endian
# integers so that GCM's ">>1" is an integer >>1 and GCM's R lands as shown.
# ---------------------------------------------------------------------------

# R = 11100001 || 0^120  (x^7 + x^2 + x + 1, the GCM reduction tail), as a
# big-endian-integer: leftmost bits {0,1,2,7} -> integer bits {127,126,125,120}.
GCM_R = (1 << 127) | (1 << 126) | (1 << 125) | (1 << 120)


def be_int(b):
    return int.from_bytes(b, "big")


def be_bytes(n):
    return (n & MASK).to_bytes(16, "big")


def gmul(x_bytes, y_bytes):
    """GHASH product X . Y over GF(2^128) with the GCM reduction polynomial."""
    x = be_int(x_bytes)
    z = 0
    v = be_int(y_bytes)
    for i in range(128):
        # x_i, leftmost bit first == integer bit (127 - i).
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ GCM_R
        else:
            v >>= 1
    return be_bytes(z)


# ---------------------------------------------------------------------------
# The crate's single-block GHASH-via-POLYVAL computation: the RHS of (*).
# ---------------------------------------------------------------------------

def crate_single_block(x_bytes, h_bytes):
    h1 = mulx_code(byte_reverse(h_bytes))
    prod = polyval_dot(le_int(byte_reverse(x_bytes)), le_int(h1))
    return byte_reverse(le_bytes(prod))


# ---------------------------------------------------------------------------
# Basis vectors over the 128-bit block space (any 128 distinct single-bit
# vectors span GF(2)^128; bilinearity is coordinate-free).
# ---------------------------------------------------------------------------

def e(i):
    out = bytearray(16)
    out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def xorshift(state):
    state ^= (state << 13) & MASK
    state ^= state >> 7
    state ^= (state << 17) & MASK
    return state & MASK


def anchor_gmul():
    """Pin gmul to the spec by definition-derived facts (no transcribed vector)."""
    ok = True

    # Multiplicative identity: "1" = x^0 = leftmost bit set = byte 0x80.
    one = bytes([0x80]) + bytes(15)
    st = 0x0123456789abcdef0fedcba987654321
    for _ in range(64):
        st = xorshift(st)
        h = be_bytes(st)  # arbitrary 16-byte value
        if gmul(one, h) != h or gmul(h, one) != h:
            ok = False
    print(f"  gmul identity element (1 . H == H)            : {ok}")

    # Defining reduction: x . x^127 == x^128 == x^7+x^2+x+1 == R (0xE1||0^120).
    x = bytes([0x40]) + bytes(15)            # b_1 set == x^1
    x127 = bytes(15) + bytes([0x01])         # b_127 set == x^127
    red_ok = gmul(x, x127) == be_bytes(GCM_R)
    print(f"  gmul reduction (x . x^127 == x^7+x^2+x+1)     : {red_ok}")

    # Commutativity sanity (field multiply is symmetric).
    comm_ok = True
    st = 0xdeadbeef0badc0de1234567890abcdef
    for _ in range(64):
        st = xorshift(st)
        a = be_bytes(st)
        st = xorshift(st)
        b = be_bytes(st)
        if gmul(a, b) != gmul(b, a):
            comm_ok = False
    print(f"  gmul commutativity                            : {comm_ok}")
    return ok and red_ok and comm_ok


def prove_R_linear_involution():
    """R(a^b) == R(a)^R(b) and R(R(a)) == a, exhaustively on the basis."""
    lin = True
    invol = True
    basis = [e(i) for i in range(128)]
    for i in range(128):
        a = basis[i]
        if byte_reverse(byte_reverse(a)) != a:
            invol = False
        for j in range(128):
            b = basis[j]
            lhs = byte_reverse(bytes(p ^ q for p, q in zip(a, b)))
            rhs = bytes(p ^ q for p, q in zip(byte_reverse(a), byte_reverse(b)))
            if lhs != rhs:
                lin = False
    print(f"  ByteReverse linear (R(a^b)==R(a)^R(b))        : {lin}")
    print(f"  ByteReverse involution (R(R(a))==a)           : {invol}")
    return lin and invol


def prove_single_block_identity():
    """(*) gmul(X,H) == R(dot(R(X), mulX(R(H)))) on all 128x128 basis pairs."""
    basis = [e(i) for i in range(128)]
    mism = 0
    for i in range(128):
        ex = basis[i]
        for j in range(128):
            ej = basis[j]
            if gmul(ex, ej) != crate_single_block(ex, ej):
                mism += 1
    if mism == 0:
        print("  single-block (*): gmul == crate on all 16384 basis pairs")
        print("                    => equal for all (X,H) (both bilinear)")
    else:
        print(f"  single-block (*): FAILED, {mism} basis pairs disagree")
    return mism == 0


def witness_random_blocks():
    """Belt and suspenders: full multi-block GHASH == crate on random messages,
    confirming the Horner lift end to end (not just the single-block identity)."""
    def ghash(h, blocks):
        y = bytes(16)
        for x in blocks:
            y = gmul(bytes(p ^ q for p, q in zip(y, x)), h)
        return y

    def crate_ghash(h, blocks):
        h1 = mulx_code(byte_reverse(h))
        z = 0
        for x in blocks:
            z = polyval_dot(z ^ le_int(byte_reverse(x)), le_int(h1))
        return byte_reverse(le_bytes(z))

    st = 0xa5a5a5a5_5a5a5a5a_0f0f0f0f_f0f0f0f0
    ok = True
    for n in range(0, 9):
        st = xorshift(st)
        h = be_bytes(st)
        blocks = []
        for _ in range(n):
            st = xorshift(st)
            blocks.append(be_bytes(st))
        if ghash(h, blocks) != crate_ghash(h, blocks):
            ok = False
    print(f"  multi-block GHASH == crate on random messages : {ok}")
    return ok


def main():
    print("Anchoring the GHASH multiply to NIST SP 800-38D ...")
    a = anchor_gmul()
    print("\nByteReverse is a GF(2)-linear involution ...")
    r = prove_R_linear_involution()
    print("\nSingle-block mapping identity (exhaustive basis) ...")
    s = prove_single_block_identity()
    print("\nWitnessing the Horner lift on random multi-block messages ...")
    w = witness_random_blocks()
    if a and r and s and w:
        print("\nPROVED for all inputs: the crate's ByteReverse + mulX + POLYVAL")
        print("construction computes NIST SP 800-38D GHASH(H, X_1..X_n) for every")
        print("hash subkey and every block sequence. Faithful to ghash.rs (mulx,")
        print("byte reversal) and to the proven POLYVAL core (field_model.py).")
        return 0
    print("\nFAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
