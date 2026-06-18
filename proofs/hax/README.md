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

## What was attempted (and where it blocked)

| Step | Result |
| --- | --- |
| `cargo install --git https://github.com/hacspec/hax cargo-hax` | **OK** — frontend `cargo-hax` 0.3.7 installed. |
| `cargo hax into fstar` backend present | **OK** — F\*, Coq, Lean, ProVerif, … backends are available. |
| `driver-hax-frontend-exporter` (the rustc driver hax shells out to) | **BLOCKED** — not installed by the frontend; building `cli/driver` (`hax-driver`) from the checkout fails to compile (`hax-frontend-exporter`, ~226 errors) because it links `rustc_private` internals and must be built against hax's **exact pinned nightly**, not the ambient toolchain. |
| Check the extracted F\* | **BLOCKED** — no F\* / Z3-for-F\* engine present to typecheck `.fst` output even if extraction succeeded. |

So the wall is the standard hax bring-up: a rustc-driver pinned to a precise
nightly, plus an F\* toolchain. Both are multi-hour, fragile installs in a
sandbox; neither was completed here.

## Steps to complete it (reproducible plan)

1. **Use hax's pinned toolchain.** Clone `hacspec/hax` and build with its own
   `rust-toolchain.toml`, or install via the project's Nix flake / `setup.sh`,
   which pins the nightly the `driver-hax-frontend-exporter` must be built
   against. Verify `cargo hax into fstar -i '-** +hardware_rust_crypto::aes_gcm::increment_counter' fstar`
   produces `proofs/fstar/extraction/*.fst` on a trivial function first.
2. **Install F\*** (and its Z3) so the extracted modules can be checked
   (`fstar.exe --include … Module.fst`).
3. **Scope the extraction.** Include only the safe composition items and exclude
   the intrinsic backends, axiomatizing them as F\* `assume val`s:
   `seal`, `open`, `seal_in_place`, `apply_ctr_serial`, `j0`, `increment_counter`
   (GCM); `siv_seal`, `siv_open`, `derive_keys`, `polyval_digest`, `siv_tag`,
   `ctr_apply`, `increment_siv_counter` (SIV). The AES `encrypt_block`/`encrypt8`
   and the GHASH/POLYVAL backends become opaque `val E : block -> block`, etc.
4. **State the spec and prove.** Port the SP 800-38D / RFC 8452 definitions
   (already encoded in `prove_composition.py`) as an F\* reference and prove the
   extracted functions equal it, given the axiomatized primitives. This is the
   same theorem `prove_composition.py` checks with Z3, but now over the extracted
   source — removing the hand-translation trust step.

## Honest status

Not done. The intrinsic-free logic is already verified as *compiled code* by Kani,
so the remaining extraction gap is specifically the AES-calling composition glue,
which `prove_composition.py` covers as a KAT-anchored model. Completing the hax
route would upgrade that one piece from "proven model" to "proven extracted
source"; it requires the toolchain bring-up above.
