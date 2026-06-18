# hax / F\* extraction — extraction working; F\* proof remaining

This directory records progress toward an *extraction-based* proof of the
AES-composition glue with [hax](https://github.com/hacspec/hax) (Cryspen) and F\*.

**Status: the composition now extracts to F\*.** `./extract.sh` produces
`proofs/fstar/extraction/*.fst` — the safe composition (`j0`,
`increment_counter`, `nonce_value`, and the `seal`/`open`/SIV machinery)
translated from the *actual Rust source* into F\* by hax, with the intrinsic
AES/GHASH backends left as opaque calls. What is **not** yet done is the F\* side:
axiomatizing those opaque backends and writing + checking the
functional-correctness lemmas (the theorem `prove_composition.py` checks against
a hand-written model). So this is no longer "blocked" — it is a working
extraction pipeline plus a remaining, well-scoped F\* proof effort. No checked
F\* proof is claimed yet.

A sample of what hax emits — the real `increment_counter`, faithfully translated:

```fstar
let increment_counter (counter: t_Array u8 (mk_usize 16)) : t_Array u8 (mk_usize 16) =
  let low_bytes:t_Array u8 (mk_usize 4) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 4) in
  let low_bytes = Core_models.Slice.impl__copy_from_slice #u8 low_bytes
      (counter.[ { f_start = mk_usize 12 } ] <: t_Slice u8) in
  let low:u32 = Core_models.Num.impl_u32__wrapping_add
      (Core_models.Num.impl_u32__from_be_bytes low_bytes <: u32) (mk_u32 1) in
  ...   (* writes low.to_be_bytes() back into counter[12..] *)
```

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

### Session 3 — extraction working

Both remaining issues were resolved:

- **Crate ingestibility.** Under `cfg(hax)` (set automatically by hax), the RNG
  module is excluded (`#[cfg(not(hax))] pub mod random;` in `lib.rs`) and the
  fork-handler falls back to the process-id path (`src/aes_gcm/fork.rs`), so the
  `pthread_atfork` fn pointer and the `RDSEED`/`RNDRRS` inline asm never reach the
  importer. Both are no-ops for normal builds and all other tooling. The importer
  then reads the whole crate without error.
- **The OCaml engine.** hax 0.3.7's Rust engine delegates some F\* phases to the
  OCaml `hax-engine`, which does need opam (`brew install opam node`, `opam init`,
  `opam install ./engine`) plus the `hax-engine-names-extract` codegen tool. Built.

With the full toolchain and the two `cfg(hax)` no-ops, `./extract.sh` produces
nine F\* modules under `proofs/fstar/extraction/` (a `[HAX0008] reject_ArbitraryLhs`
is reported for the in-place-mutating helpers, which hax's functional model does
not translate; the by-value composition functions extract cleanly).

## Steps to complete it (reproducible plan)

1. **Toolchain: done.** Build the four hax binaries against `nightly-2025-11-08`
   and the OCaml engine via opam (see the prerequisites in `extract.sh`).
2. **Ingestibility: done.** The two `cfg(hax)` no-ops in `lib.rs` and
   `aes_gcm/fork.rs` keep the RNG / fork-handler out of the importer's path.
3. **Extraction: done.** `./extract.sh` emits `proofs/fstar/extraction/*.fst`
   with the intrinsic AES/GHASH backends as opaque calls.
4. **State the spec and prove with F\* (remaining).** Install F\*
   (`opam install fstar`), axiomatize the opaque AES/GHASH backends as
   `assume val`s, port the SP 800-38D / RFC 8452 definitions (already encoded in
   `prove_composition.py`) as an F\* reference, and prove the extracted functions
   equal it. This is the same theorem `prove_composition.py` checks against a
   hand-written model, now over the hax-extracted source — removing the
   hand-translation trust step. A practical first milestone is to typecheck the
   extracted modules (no proof, just well-formedness) against hax's F\* support
   libraries, then add lemmas function by function (`increment_counter`,
   `nonce_value`, `j0`, … first; the in-place `seal`/`open` helpers, which hax
   currently rejects, need either a by-value reformulation or hax-side support).

## Toward a typecheck — concrete next blockers (found, not yet fixed)

F\* itself installs and runs (`opam install fstar`; it accepts the system Z3).
Pointing it at the extraction with the hax F\* support libraries on the include
path (`hax-lib/proof-libs/fstar/{core,rust_primitives}`) surfaces two standard,
bounded setup issues that the F\* effort must resolve first:

1. **`Module not found: Zeroize`** — the composition calls the `zeroize` crate
   (key wiping); hax emits references to a `Zeroize` module but not its body.
   Provide an F\* interface stub (`Zeroize.fsti` with `val zeroize`), or mark the
   `Zeroize` impls opaque on the Rust side.
2. **`Recursive dependency on … Bundle.fst`** — hax's bundling makes the
   per-module re-export files and `Bundle.fst` mutually depend. Typecheck the
   self-contained `Bundle.fst` directly (don't feed the thin re-export modules),
   or adjust hax's module-bundling options.

Neither is conceptual; both are the usual "wire up the F\* project" chores.

## Honest status

**Extraction works** (`./extract.sh` emits the F\* modules); **F\* installs and
runs**. What remains is the F\* proof project: resolve the two setup blockers
above, axiomatize the opaque AES/GHASH backends as `assume val`s, and write +
check the functional-correctness lemmas relating the extracted composition to the
SP 800-38D / RFC 8452 spec — the same theorem `prove_composition.py` checks
against a hand-written model, now over the hax-extracted source. That is a
bounded but non-trivial F\* effort and is not done; no checked F\* proof is
claimed.

The extraction output is **not committed** (it is large and regenerable; see
`proofs/.gitignore`). Until the F\* proof lands, the AES-calling composition glue
remains covered as a KAT-anchored model by `prove_composition.py` (T2) and, for
its intrinsic-free parts, as compiled code by the Kani harnesses (T1). Completing
the F\* proof would upgrade the composition from "proven model" to "proven
extracted source."
