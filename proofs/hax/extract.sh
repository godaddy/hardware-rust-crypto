#!/usr/bin/env bash
# Extract the AES-256-GCM/SIV composition to F* with hax (Cryspen).
#
# This produces proofs/fstar/extraction/*.fst: the safe composition glue
# (j0, increment_counter, nonce_value, the seal/open/SIV machinery) translated
# from the *actual Rust source* into F*, ready for an F* functional-correctness
# proof against the SP 800-38D / RFC 8452 spec (the theorem prove_composition.py
# checks against a hand-written model). The intrinsic AES/GHASH backends are
# extracted as opaque calls, to be axiomatized in the F* proof.
#
# Prerequisites (one-time; see proofs/hax/README.md for why each is needed):
#   1. hax frontend + drivers, built against hax's pinned nightly:
#        rustup toolchain install nightly-2025-11-08 \
#          -c rustc-dev -c llvm-tools-preview -c rust-src -c rustfmt
#        HAX=$(ls -d ~/.cargo/git/checkouts/hax-*/*/ | head -1)   # hax checkout
#        cargo install --git https://github.com/hacspec/hax cargo-hax
#        cargo +nightly-2025-11-08 install --path "$HAX/cli/driver"          # driver
#        cargo +nightly-2025-11-08 install --path "$HAX/rust-engine"         # rust engine
#        cargo +nightly-2025-11-08 install --path "$HAX/engine/names/extract" # codegen
#   2. The OCaml engine (the Rust engine delegates some phases to it):
#        brew install opam node && opam init -y --disable-sandboxing
#        eval $(opam env)
#        (cd "$HAX/engine" && opam install . -y --confirm-level=unsafe-yes --assume-depexts)
#
# Then run this script from the crate root.
set -euo pipefail
cd "$(dirname "$0")/../.."

eval "$(opam env)"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

# `--cfg hax` (set automatically by hax) excludes the RNG module and the
# pthread_atfork fork-handler from extraction; HAX_EXPERIMENTAL_FULL_DEF routes
# the F* backend through the Rust engine. `-i` keeps the backend output scoped to
# the aes_gcm composition (the importer still reads the whole crate).
HAX_EXPERIMENTAL_FULL_DEF=true \
  cargo +nightly-2025-11-08 hax into \
    -i '-** +hardware_rust_crypto::aes_gcm::**' \
    fstar

echo
echo "Extracted F* modules:"
ls -1 proofs/fstar/extraction/*.fst
