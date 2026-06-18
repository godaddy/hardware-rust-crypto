# hax / F\* extraction — attempted, blocked, documented

This directory records an **honest attempt** to add an *extraction-based* proof of
the AES-composition glue with [hax](https://github.com/hacspec/hax) (Cryspen) and
F\*, and the exact steps to complete it. It did **not** land in the session that
created it; nothing here claims a checked F\* proof exists. It is a runnable plan,
not a result.

## Why this, and what it would add over what we already have

Today's proofs split into two trust levels:

- **Verifying the compiled Rust** (strongest): the `cfg(kani)` harnesses run
  Kani/CBMC over the *actual machine code* of the intrinsic-free logic — counter
  increments, length validation, the nonce parser, the envelope splitters. No
  hand-translation step.
- **Verifying a faithful model** (`proofs/*.py`, Z3/sympy): the field arithmetic,
  the GHASH construction, and the AES-composition glue are proven against the
  spec, but the connection from "the model" to "the shipped Rust" is by
  line-for-line translation anchored to KATs, not by extraction.

hax would close the one remaining model→code gap that Kani cannot reach: the
**AES-composition glue** (`seal`/`open`, `siv_seal`/`siv_open` and helpers) calls
the AES and POLYVAL backends, which are intrinsic `unsafe` and therefore opaque to
CBMC. hax extracts the *safe* Rust to F\* and lets those backends be axiomatized
as pure functions `E`, `polyval`, leaving an F\* proof obligation that the
compiled composition equals an RFC-derived spec — the same shape as
`prove_composition.py`, but over the extracted source rather than a translated
model.

## What was attempted (two sessions)

### Session 1 — blocked on the toolchain

| Step | Result |
| --- | --- |
| `cargo install --git https://github.com/hacspec/hax cargo-hax` | OK — frontend `cargo-hax` 0.3.7. |
| `driver-hax-frontend-exporter` (the rustc driver) | BLOCKED — building `cli/driver` failed (~226 `rustc_private` errors) on the ambient nightly. |
| Check extracted F\* | BLOCKED — assumed an OCaml/opam F\* engine was required. |

### Session 2 — toolchain SOLVED; new blocker is the crate, not the tools

The toolchain wall is gone. The exact, reproducible bring-up that works on this
machine (aarch64 macOS, no opam):

```sh
HAX=~/.cargo/git/checkouts/hax-*/$(…)          # the cargo-installed checkout
# hax pins this nightly with rustc-dev (cli/.../rust-toolchain.toml):
rustup toolchain install nightly-2025-11-08 -c rustc-dev -c llvm-tools-preview -c rust-src -c rustfmt
# build the rustc driver AGAINST the pinned nightly (this is what session 1 missed):
cargo +nightly-2025-11-08 install --path "$HAX/cli/driver"        # -> driver-hax-frontend-exporter
# F* does NOT need opam: hax 0.3.7 has a Rust engine. Build it:
cargo +nightly-2025-11-08 install --path "$HAX/rust-engine"       # -> hax-rust-engine
# the new input format routes F* to the Rust engine (not the OCaml one):
HAX_EXPERIMENTAL_FULL_DEF=true cargo +nightly-2025-11-08 hax \
    into -i '-** +hardware_rust_crypto::aes_gcm::increment_counter' fstar
```

With all three binaries present, `cargo hax` now **compiles the crate, runs the
frontend, and invokes the Rust engine** — the pipeline is live. The remaining
blocker is no longer the tools but the **crate not being in hax's supported
subset**: the importer (which processes the *whole crate*, before the `-i` filter
is applied to the backend) aborts with `[HAX0002] Pointer … UnsafeFnPointer` on
the first unsupported construct - the `pthread_atfork(.., Some(fn))` function
pointer in both `random/fork.rs` and `aes_gcm/fork.rs`. Excluding `random` under
`#[cfg(not(hax))]` clears the first; the second is reached by the AEAD's
fork-safe `NonceGen`. Past the fork guards, the pervasive `core::arch` intrinsics
in `aes.rs`/`ghash.rs` are the same class of problem.

So the true remaining work is **making the composition hax-ingestible**, not
installing anything.

## Steps to complete it (reproducible plan)

1. **Toolchain: done** — use the four commands above (driver + rust-engine built
   against `nightly-2025-11-08`, `HAX_EXPERIMENTAL_FULL_DEF=true`).
2. **Make the crate hax-ingestible.** The importer must not meet an unsupported
   construct. Either (a) annotate every intrinsic/fn-pointer item the importer
   reaches with hax's opacity attributes (`#[hax_lib::opaque]` / `#[hax_lib::exclude]`,
   adding the `hax-lib` dev-dependency), or (b) lift the safe composition
   (`seal`/`open`, `j0`, counters, `derive_keys`, `polyval_digest`, `siv_tag`,
   `ctr_apply`) into a module written against **trait/abstract** AES and
   authenticator interfaces, so the intrinsic backends are never in hax's import
   path. (b) is cleaner but proves the lifted module, so it must *be* the shipped
   code path, not a copy.
3. **Extract** the composition with the backends as opaque `val E : block -> block`
   etc., producing `proofs/fstar/extraction/*.fst`.
4. **State the spec and prove with F\*.** Port the SP 800-38D / RFC 8452
   definitions (already encoded in `prove_composition.py`) as an F\* reference and
   prove the extracted functions equal it, given the axiomatized primitives —
   the same theorem `prove_composition.py` checks with Z3, now over the extracted
   source, removing the hand-translation trust step. (F\* itself still needs
   installing to *check* the `.fst`; the Rust engine only *emits* it.)

## Honest status

Not done, but materially advanced. The **toolchain is solved** (the binaries
build against the pinned nightly and the F\* pipeline runs without opam — the
original blocker is gone). The remaining work is **reformulating the composition
so hax's importer can ingest it** (the crate's fn-pointers and intrinsics are
outside hax's subset), then writing and checking the F\* proof. That is a real
engineering effort, not a toolchain install.

In the meantime the intrinsic-free logic is already verified as *compiled code*
by Kani, and the AES-calling composition glue is covered as a KAT-anchored model
by `prove_composition.py`. Completing the hax route would upgrade that one piece
from "proven model" to "proven extracted source."
