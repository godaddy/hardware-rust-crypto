#!/usr/bin/env bash
# Build the crate to LLVM bitcode and run the SAW proofs (proofs/saw/composition.saw).
#
# Prerequisite: SAW on PATH with its bundled solvers, e.g.
#   curl -L -o saw.tgz \
#     https://github.com/GaloisInc/saw-script/releases/download/v1.5.1/saw-1.5.1-<platform>-with-solvers.tar.gz
#   tar xzf saw.tgz && export PATH="$PWD/saw-1.5.1-<platform>-with-solvers/bin:$PATH"
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "==> building the crate to LLVM bitcode (saw-verify wrappers)"
RUSTFLAGS="--emit=llvm-bc -C codegen-units=1 -C lto=off" \
  cargo build --release --features saw-verify --lib >/dev/null 2>&1

BC="$PWD/$(command ls -1 target/release/deps/ | grep -E '^hardware_rust_crypto-[0-9a-f]+\.bc$' | head -1 \
  | sed 's|^|target/release/deps/|')"
[ -f "$BC" ] || { echo "FAIL: crate bitcode not found"; exit 1; }
echo "    bitcode: $BC"

tmp="$(mktemp -t hrc_saw.XXXXXX.saw)"
sed "s|BITCODE_PATH|$BC|" proofs/saw/composition.saw > "$tmp"
echo "==> running SAW"
saw "$tmp"
rm -f "$tmp"
