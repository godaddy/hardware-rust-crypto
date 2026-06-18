#!/usr/bin/env python3
"""Faithful Python model of the crate's GF(2^128) carryless-multiply backend.

This emulates the EXACT aarch64 intrinsic sequence in `src/aes_gcm/ghash.rs`
(`karatsuba1`, `karatsuba2`, `mont_reduce`, `pmull`/`pmull2` = `vmull_p64`,
`vextq_u8(.,.,8)`) bit for bit. It is the anchor for the proofs in this
directory: the proofs reason about *this* model, and `validate()` shows the
model reproduces the real backend's `imp::mul` output bit-for-bit on reference
vectors captured from the running code, plus matches the independent RFC 8452
POLYVAL `dot` definition. So "the model" = "the code" = "the spec", pinned by
data, before any proof is trusted.

Run directly to self-check: `python3 proofs/field_model.py`.
"""

M64 = (1 << 64) - 1
M128 = (1 << 128) - 1

# mont_reduce's constant `poly`, exactly as written in ghash.rs:
#   1<<127 | 1<<126 | 1<<121 | 1<<63 | 1<<62 | 1<<57
POLY = (1 << 127) | (1 << 126) | (1 << 121) | (1 << 63) | (1 << 62) | (1 << 57)

# POLYVAL field modulus (RFC 8452): x^128 + x^127 + x^126 + x^121 + 1.
POLYVAL_MOD = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1


def low64(a):
    return a & M64


def high64(a):
    return (a >> 64) & M64


def clmul64(x, y):
    """Carryless product of two 64-bit polynomials -> <=127-bit (vmull_p64)."""
    r = 0
    for i in range(64):
        if (y >> i) & 1:
            r ^= x << i
    return r & M128


def pmull(a, b):
    """vmull_p64(low lane of a, low lane of b)."""
    return clmul64(low64(a), low64(b))


def pmull2(a, b):
    """vmull_p64(high lane of a, high lane of b)."""
    return clmul64(high64(a), high64(b))


def ext8(a, b):
    """vextq_u8(a, b, 8): low 64 bits = high64(a), high 64 bits = low64(b)."""
    return (high64(a) | (low64(b) << 64)) & M128


def karatsuba1(x, y):
    m = pmull(x ^ ext8(x, x), y ^ ext8(y, y))
    h = pmull2(x, y)
    l = pmull(x, y)
    return h, m, l


def karatsuba2(h, m, l):
    t0 = m ^ ext8(l, h)
    t1 = h ^ l
    t = t0 ^ t1
    x01 = ext8(ext8(l, l), t)
    x23 = ext8(t, ext8(h, h))
    return x23, x01


def mont_reduce(x23, x01):
    a = pmull(x01, POLY)
    b = x01 ^ ext8(a, a)
    c = pmull2(b, POLY)
    return (x23 ^ c ^ b) & M128


def field_mul_int(a, b):
    """The crate's single-block field multiply on 128-bit integers."""
    h, m, l = karatsuba1(a, b)
    x23, x01 = karatsuba2(h, m, l)
    return mont_reduce(x23, x01)


def field_mul_bytes(a_bytes, b_bytes):
    a = int.from_bytes(a_bytes, "little")
    b = int.from_bytes(b_bytes, "little")
    return field_mul_int(a, b).to_bytes(16, "little")


# --- independent reference: RFC 8452 POLYVAL dot(a, b) = a * b * x^-128 mod p ---

def _clmul_full(a, b):
    r = 0
    for i in range(128):
        if (b >> i) & 1:
            r ^= a << i
    return r


def _mod_reduce(p, mod, deg):
    for i in range(2 * deg - 1, deg - 1, -1):
        if (p >> i) & 1:
            p ^= mod << (i - deg)
    return p & ((1 << deg) - 1)


def _inv_x_pow(mod, deg, n):
    # x^-1 mod p, raised to n, by repeated multiply-by-x^-1.
    # x^-1 = (x^128 reduced) shifted... compute x^-1 as inverse of x.
    # x * x^-1 = 1 mod p. Since p = x^128 + ... + 1, x*(x^127 + ...) ...
    # Simpler: x^-1 = x^(2^128 - 2) but that is huge; instead compute by
    # solving x * t = 1: t = (1 + (p - x^128 ... )) — use that x^128 = lowterms,
    # so x^-1 = x^127 * (x^128)^-1 ... Just brute force via extended structure:
    # multiply 1 by x^-1 n times, where mul-by-x^-1 = (if bit0: (v>>1)^topterms
    # else v>>1) using that x^-1 = high part of mod.
    inv = 1
    # x^-1 satisfies: if v is odd, (v ^ mod) is even and = x*(...); so
    # v * x^-1 = (v even ? v>>1 : (v ^ mod) >> 1).
    for _ in range(n):
        v = inv
        if v & 1:
            v ^= mod
        inv = v >> 1
    return inv


def polyval_dot(a, b):
    """RFC 8452 dot(a,b) = a . b . x^-128 mod (x^128+x^127+x^126+x^121+1)."""
    prod = _clmul_full(a, b)
    prod = _mod_reduce(prod, POLYVAL_MOD, 128)
    xinv128 = _inv_x_pow(POLYVAL_MOD, 128, 128)
    # multiply prod * x^-128 mod p
    full = _clmul_full(prod, xinv128)
    return _mod_reduce(full, POLYVAL_MOD, 128)


# Reference vectors captured from the running aarch64 backend `imp::mul`
# (src/aes_gcm/ghash.rs dump_mul_vectors), little-endian byte order.
REFERENCE_VECTORS = [
    ("41208240000000004114010c06410010", "2926866e2f841e9b25805d5503f554f5",
     "a466d404a7df230146bd094d6c19fca2"),
    ("ad4df30bae771bdc76606e02b9eef064", "366190e591ce077b74cc8d360c055f30",
     "055fe5bec6717fd3a7331331366d31de"),
    ("ed8e046d8246dc27b09c408075613b88", "8931e30b3d2b6310aab55d84465d4573",
     "23578745031c5659ede3ce9940043ee5"),
]


def validate():
    ok = True
    for a_hex, b_hex, p_hex in REFERENCE_VECTORS:
        a = bytes.fromhex(a_hex)
        b = bytes.fromhex(b_hex)
        got = field_mul_bytes(a, b).hex()
        match = got == p_hex
        ok &= match
        print(f"  model==code : {match}   mul({a_hex[:8]}..,{b_hex[:8]}..) = {got[:12]}..")
    # Cross-check the model against the independent RFC 8452 POLYVAL dot.
    spec_ok = True
    for a_hex, b_hex, _ in REFERENCE_VECTORS:
        a = int.from_bytes(bytes.fromhex(a_hex), "little")
        b = int.from_bytes(bytes.fromhex(b_hex), "little")
        spec_ok &= field_mul_int(a, b) == polyval_dot(a, b)
    print(f"  model==RFC 8452 POLYVAL dot : {spec_ok}")
    ok &= spec_ok
    return ok


# ---------------------------------------------------------------------------
# x86 model: the exact `clmul_wide` (3 Karatsuba partials) + `reduce` sequence
# from ghash.rs. Output equals the aarch64 path (byte-identical, by interop),
# so it is anchored against the same captured `imp::mul` reference vectors and
# the RFC 8452 `dot`.
# ---------------------------------------------------------------------------

def _shuffle_epi32_0e(v):
    d = [(v >> (32 * i)) & 0xFFFFFFFF for i in range(4)]
    # imm 0x0E -> dwords [d2, d3, d0, d0]
    return d[2] | (d[3] << 32) | (d[0] << 64) | (d[0] << 96)


def clmul_wide(x, h):
    h0 = h
    h1 = _shuffle_epi32_0e(h)
    h2 = h0 ^ h1
    y0 = x
    y1 = _shuffle_epi32_0e(x)
    y2 = y0 ^ y1
    t0 = clmul64(low64(y0), low64(h0))   # _mm_clmulepi64(.,.,0x00)
    t1 = clmul64(high64(x), high64(h))   # _mm_clmulepi64(.,.,0x11)
    t2 = clmul64(low64(y2), low64(h2))   # _mm_clmulepi64(.,.,0x00)
    return t0, t1, t2


def _srli_epi64(v, n):
    return ((low64(v) >> n) | ((high64(v) >> n) << 64)) & M128


def _slli_epi64(v, n):
    return (((low64(v) << n) & M64) | (((high64(v) << n) & M64) << 64)) & M128


def _unpacklo_epi64(a, b):
    return (low64(a) | (low64(b) << 64)) & M128


def reduce_x86(t0, t1, t2):
    t2 = t2 ^ (t0 ^ t1)
    v0 = t0
    v1 = _shuffle_epi32_0e(t0) ^ t2
    v2 = t1 ^ _shuffle_epi32_0e(t2)
    v3 = _shuffle_epi32_0e(t1)
    v2 = v2 ^ v0 ^ _srli_epi64(v0, 1) ^ _srli_epi64(v0, 2) ^ _srli_epi64(v0, 7)
    v1 = v1 ^ _slli_epi64(v0, 63) ^ _slli_epi64(v0, 62) ^ _slli_epi64(v0, 57)
    v3 = v3 ^ v1 ^ _srli_epi64(v1, 1) ^ _srli_epi64(v1, 2) ^ _srli_epi64(v1, 7)
    v2 = v2 ^ _slli_epi64(v1, 63) ^ _slli_epi64(v1, 62) ^ _slli_epi64(v1, 57)
    return _unpacklo_epi64(v2, v3)


def field_mul_x86_int(a, b):
    return reduce_x86(*clmul_wide(a, b))


def validate_x86():
    ok = True
    for a_hex, b_hex, p_hex in REFERENCE_VECTORS:
        a = int.from_bytes(bytes.fromhex(a_hex), "little")
        b = int.from_bytes(bytes.fromhex(b_hex), "little")
        got = field_mul_x86_int(a, b)
        match = got == int.from_bytes(bytes.fromhex(p_hex), "little")
        ok &= match
        print(f"  x86 model==code : {match}")
    spec_ok = all(
        field_mul_x86_int(
            int.from_bytes(bytes.fromhex(a), "little"),
            int.from_bytes(bytes.fromhex(b), "little"),
        ) == polyval_dot(
            int.from_bytes(bytes.fromhex(a), "little"),
            int.from_bytes(bytes.fromhex(b), "little"),
        )
        for a, b, _ in REFERENCE_VECTORS
    )
    print(f"  x86 model==RFC 8452 dot : {spec_ok}")
    return ok and spec_ok


if __name__ == "__main__":
    import sys
    print("Validating the field model against the real backend and RFC 8452:")
    print("aarch64:")
    a_ok = validate()
    print("x86:")
    x_ok = validate_x86()
    sys.exit(0 if (a_ok and x_ok) else 1)
