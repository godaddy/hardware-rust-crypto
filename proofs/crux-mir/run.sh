#!/usr/bin/env bash
# Run the crux-mir proofs (proofs/crux-mir/*.rs).
#
# crux-mir = mir-json (rustc -> MIR JSON) + crux-mir-comp (the verifier, shipped
# in the SAW bundle). The two must agree on the MIR JSON *schema version*: SAW
# 1.5.1's crux-mir-comp wants schema 8, so mir-json must be the schema-8 commit.
#
# One-time setup (see proofs/crux-mir/README.md for why each step):
#   rustup toolchain install nightly-2025-09-14 --force -c rustc-dev -c rust-src
#   git clone https://github.com/GaloisInc/mir-json && cd mir-json
#   git checkout 48d0b4b2          # last schema-8 commit (matches SAW 1.5.1)
#   cargo +nightly-2025-09-14 install --path . --locked
#   mir-json-translate-libs        # run from the mir-json checkout; produces rlibs/
#   ln -s "$SAW_BIN/crux-mir-comp" ~/.local/bin/crux-mir
#   export CRUX_RUST_LIBRARY_PATH=$PWD/rlibs
#
# Then, for each .rs here, build a tiny crate around it and `cargo crux-test`.
set -euo pipefail
cd "$(dirname "$0")"
: "${CRUX_RUST_LIBRARY_PATH:?set CRUX_RUST_LIBRARY_PATH to the mir-json rlibs dir}"
command -v crux-mir >/dev/null || { echo "crux-mir not on PATH (symlink crux-mir-comp)"; exit 1; }

run_one() {
  local src="$1" tmp
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/src"
  cp "$src" "$tmp/src/lib.rs"
  cat > "$tmp/Cargo.toml" <<TOML
[package]
name = "cruxproof"
version = "0.1.0"
edition = "2021"
[dependencies]
TOML
  echo "==> crux-test $src"
  ( cd "$tmp" && cargo crux-test 2>&1 | grep -E '\[Crux\]|Overall status|Proved|Disproved' )
  rm -rf "$tmp"
}

run_one increment_counter.rs   # expect: Overall status: Valid (Proved: 1)
run_one clmul_probe.rs || true  # expect: Invalid - unmodeled vmull_p64 intrinsic
