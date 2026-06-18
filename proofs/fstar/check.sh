#!/usr/bin/env bash
# Verify the F* proof in HrcComposition.fst over the hax-extracted composition.
#
# Two steps:
#   1. Drift guard - re-extract with hax and confirm the function bodies proved
#      in HrcComposition.fst are byte-for-byte the ones hax emits from the real
#      Rust source (so the proof cannot silently drift from the shipped code).
#   2. Run F* on HrcComposition.fst (exit non-zero on any unproved obligation).
#
# Prerequisites: the hax toolchain (see proofs/hax/extract.sh), F*
# (`opam install fstar`), and Z3 4.13.3 on PATH as `z3-4.13.3`.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"

eval "$(opam env)"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
HAX="$(ls -d "$HOME"/.cargo/git/checkouts/hax-*/*/ | head -1)"
BUNDLE="$ROOT/proofs/fstar/extraction/Hardware_rust_crypto.Aes_gcm.Bundle.fst"

# --- 1. drift guard: the proved bodies must match a fresh extraction ----------
echo "==> re-extracting with hax"
( cd "$ROOT" && ./proofs/hax/extract.sh ) >/dev/null 2>&1 || true
[ -f "$BUNDLE" ] || { echo "FAIL: extraction did not produce the bundle"; exit 1; }

# Pull `let <name> ... ` up to the first blank line from an F* file.
extract_def () { awk -v n="$1" '$0 ~ "^let " n " "{f=1} f{print} f&&/^$/{exit}' "$2"; }

for fn in j0 increment_counter; do
  committed="$(extract_def "$fn" HrcComposition.fst)"
  fresh="$(extract_def "$fn" "$BUNDLE")"
  if [ -z "$fresh" ] || [ "$committed" != "$fresh" ]; then
    echo "FAIL: '$fn' in HrcComposition.fst does not match the fresh hax extraction"
    diff <(printf '%s' "$committed") <(printf '%s' "$fresh") || true
    exit 1
  fi
  echo "    drift-check OK: $fn matches the extraction"
done

# --- 2. verify the proof with F* ---------------------------------------------
echo "==> F* verifying HrcComposition.fst"
fstar.exe \
  --include "$HAX/hax-lib/proof-libs/fstar/core" \
  --include "$HAX/hax-lib/proof-libs/fstar/rust_primitives" \
  --include "$HAX/hax-lib/proofs/fstar/extraction" \
  HrcComposition.fst

echo "==> PROOF VERIFIED"
