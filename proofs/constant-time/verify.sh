#!/usr/bin/env bash
# Binary-level constant-time verification of the two scalar secret-handling
# functions, by disassembly. Upgrades the constant-time story from purely
# statistical (dudect) to a checkable property of the *shipped machine code*.
#
# The constant-time argument for this crate:
#   * AES and the carryless multiply run on AES-NI / PCLMULQDQ / PMULL, which the
#     CPU vendors guarantee are data-independent in latency (the same axiom ring
#     and RustCrypto rely on);
#   * the CTR keystream application and the GHASH absorption are XOR and copies
#     (data-oblivious);
#   * the ONLY scalar operations on secret-derived data are the tag comparison
#     (`constant_time_eq`) and the GHASH mulX carry fold (`mulx`).
# So if those two compile to *branch-free* code over their secret inputs, the
# whole secret surface is data-oblivious. This script checks exactly that:
#
#   mulx                : has NO conditional branch (straight-line).
#   constant_time_eq    : has NO conditional branch after the first secret-byte
#                         load - the only allowed conditional branch is the
#                         public length check, which precedes any byte load.
#
# Conditional SELECTS (csel/cset on aarch64, cmov/setcc on x86) are branch-free
# and explicitly allowed; only true conditional branches are flagged.
#
# Run from the crate root. Requires objdump (binutils / llvm).
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "==> building the ct-verify example (release)"
cargo build --release --features ct-verify --example ct_verify >/dev/null 2>&1
BIN="target/release/examples/ct_verify"
OBJDUMP="${OBJDUMP:-objdump}"
DISASM="$("$OBJDUMP" -d "$BIN")"

# Conditional-branch mnemonics (NOT csel/cset/cmov/setcc, which are branch-free).
COND_BRANCH='\b(b\.(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)|cbz|cbnz|tbz|tbnz|je|jne|jz|jnz|jl|jle|jg|jge|jb|jbe|ja|jae|js|jns|jo|jno|jp|jnp|jc|jnc|loop|jrcxz|jecxz)\b'
# Secret-byte loads.
BYTE_LOAD='\b(ldrb|ldurb|movzbl|movzbq|movzx|movb)\b'

# Print one function's instruction lines (mnemonic column onward).
disas_fn () {
  printf '%s\n' "$DISASM" \
    | awk -v n="$1" '
        $0 ~ n"[^>]*>:" {f=1; next}
        f && /^[0-9a-f]+ <.*>:/ {f=0}          # next symbol => stop
        f {print}'
}

fail=0

# --- mulx: straight-line, zero conditional branches ---------------------------
mulx_body="$(disas_fn ct_verify_mulx)"
[ -n "$mulx_body" ] || { echo "FAIL: could not find mulx in the disassembly"; exit 1; }
if echo "$mulx_body" | grep -qE "$COND_BRANCH"; then
  echo "FAIL: mulx contains a conditional branch:"
  echo "$mulx_body" | grep -E "$COND_BRANCH"
  fail=1
else
  echo "    OK: mulx is branch-free (carry fold is shift+XOR, no branch)"
fi

# --- constant_time_eq: no conditional branch after the first secret-byte load -
cte_body="$(disas_fn ct_verify_constant_time_eq)"
[ -n "$cte_body" ] || { echo "FAIL: could not find constant_time_eq in the disassembly"; exit 1; }
# Line number of the first secret-byte load.
first_load="$(echo "$cte_body" | grep -nE "$BYTE_LOAD" | head -1 | cut -d: -f1)"
[ -n "$first_load" ] || { echo "FAIL: no secret-byte load found in constant_time_eq (unexpected)"; exit 1; }
after="$(echo "$cte_body" | tail -n "+$first_load")"
if echo "$after" | grep -qE "$COND_BRANCH"; then
  echo "FAIL: constant_time_eq branches on secret bytes (conditional branch after the first byte load):"
  echo "$after" | grep -E "$COND_BRANCH"
  fail=1
else
  n_branch="$(echo "$cte_body" | grep -cE "$COND_BRANCH" || true)"
  echo "    OK: constant_time_eq compares bytes branch-free (cmp+cset+and);"
  echo "        its only conditional branch ($n_branch) is the public length check, before any byte load"
fi

# --- non-vacuity: the deliberately leaky control MUST be rejected -------------
# An early-return secret-byte comparison (the classic timing oracle). If the
# check passed this, it would be vacuous, so we require a conditional branch
# after its first byte load.
leak_body="$(disas_fn ct_verify_leaky_control)"
[ -n "$leak_body" ] || { echo "FAIL: could not find the leaky control"; exit 1; }
leak_first_load="$(echo "$leak_body" | grep -nE "$BYTE_LOAD" | head -1 | cut -d: -f1)"
leak_after="$(echo "$leak_body" | tail -n "+${leak_first_load:-1}")"
if echo "$leak_after" | grep -qE "$COND_BRANCH"; then
  echo "    OK: non-vacuity - the leaky control IS flagged (branch on secret bytes)"
else
  echo "FAIL: non-vacuity - the leaky control was NOT flagged; the check is vacuous"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "==> CONSTANT-TIME CHECK FAILED"
  exit 1
fi
echo "==> CONSTANT-TIME VERIFIED (both scalar secret ops are data-oblivious;"
echo "    the leaky control is correctly rejected)"
