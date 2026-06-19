# CI & verification workflows

Every proof and test framework is its **own** workflow so it can be run on
demand: open the repo's **Actions** tab, pick the workflow in the left sidebar,
and click **Run workflow**. The lighter ones also run automatically on every push
and pull request.

| Workflow | File | Auto-runs | What it does |
|---|---|---|---|
| **CI** | `ci.yml` | push + PR | Build, format, clippy, full test suite (incl. NIST CAVP / Wycheproof / OpenSSL / RustCrypto differential vectors), `cargo audit`, `cargo deny`, Windows AES-NI path. The cross-platform gate. |
| **Z3/sympy proofs** | `proofs-z3.yml` | push + PR | `proofs/run_all.sh` — field multiply == POLYVAL, reductions linear, Horner == sum-of-powers, GHASH mapping, and the intrinsic-free AEAD composition == SP 800-38D / RFC 8452, over all inputs. |
| **Kani model checking** | `kani.yml` | push + PR | CBMC over the actual compiled Rust: counter increments, J0 layout, length validation, nonce parser, envelope splitters. |
| **SAW (LLVM bitcode proof)** | `saw.yml` | push + PR | SAW verifies rustc's LLVM bitcode against a Cryptol spec (`saw_increment_counter` == inc_32, `saw_j0` == J0). Third independent prover. Bundle cached → ~1 min. |
| **crux-mir (Rust MIR proof)** | `crux-mir.yml` | push + PR | crux-mir proves `increment_counter` == inc_32 over Rust MIR (fourth toolchain); `clmul_probe` documents the unmodeled-intrinsic boundary. mir-json binaries cached → ~2 min warm (~7 min cold; the stdlib MIR is regenerated each run). |
| **F\* / hax extraction proof** | `fstar.yml` | manual + **release gate** | Extracts the composition from real Rust to F\* with hax, drift-checks it, and verifies `HrcComposition.fst`. Heaviest (~10 min warm); runs as a `publish.yml` gate, not on every PR. |
| **Constant-time** | `constant-time.yml` | push + PR | Binary-level branch-freedom (disassembly) of the secret-handling functions + dudect Welch t-tests on both decrypt paths. |
| **Miri (UB checker)** | `miri.yml` | push + PR | Runs the aes_gcm key-state lifecycle + real AES/GHASH (x86 intrinsics) under Miri's UB checker. |
| **Valgrind memcheck** | `valgrind.yml` | push + PR | memchecks the real x86_64 AES-NI/PCLMULQDQ test binaries. |
| **Sanitizers (ASan/TSan)** | `sanitizers.yml` | push + PR | AddressSanitizer + ThreadSanitizer over the intrinsic binary. |
| **Fuzz smoke** | `fuzz.yml` | push + PR | Short libFuzzer run per target (decrypt parser, differential vs RustCrypto). |
| **Randomness battery** | `randomness.yml` | push + PR | Streams the AES-CTR generator into PractRand (to 4 GiB). |
| **Mutation testing** | `mutation.yml` | manual | cargo-mutants over the GCM composition + nonce generator (test-suite effectiveness). |
| **Heavy assurance** | `heavy-assurance.yml` | manual | Deep/long bundle: full-suite Valgrind, ASan/TSan/MSan, 30-min/target fuzz, multi-seed PractRand + dieharder, extended proofs, mutation. |
| **Publish** | `publish.yml` | tag | crates.io release, gated on the F\* proof (`fstar-gate`). |

## Tiering & speed

- **On every push/PR:** the cross-platform gate plus all the proofs/checks that
  finish in ~minutes — including **SAW** (~20 s warm) and **crux-mir** (~2 min
  warm), whose toolchains are cached (`actions/cache`, keyed on the pinned
  versions). Caches are scoped by ref: a PR reads caches from the base branch, so
  the warm path engages once these have run on `main`. crux-mir caches only the
  mir-json binaries — the translated stdlib MIR is regenerated each run (~1 min)
  because those artifacts don't survive cache transport to a fresh runner.
- **F\*** is the one wildly-long proof. It runs on **manual dispatch** and as a
  **release gate** in `publish.yml` (a tagged release can't publish unless it
  verifies). F\* is pulled as a prebuilt binary (bundles its own z3) and the hax
  Rust binaries are cached, so a warm run is ~10 min; only the OCaml engine still
  builds per run.
- **Mutation / Heavy assurance** are slow by design and report rather than gate;
  see `docs/mutation-testing.md` for the reviewed survivor set.

Caches are keyed on the pinned tool versions (SAW version, `mir-json` commit, hax
rev), so they only rebuild when a pin changes. The GitHub cache budget is 10 GB
per repo and entries evict after 7 days idle, so a long-quiet repo pays the cold
cost (~7 min crux-mir, ~16 min F\*) on the first run after a gap.

## Pinned tool versions (advance on purpose)

Every external proof tool is pinned to an exact version/commit — nothing tracks a
moving upstream, so a green result stays green. Advance a pin **deliberately**:
bump the value below, push, and re-run the workflow; the cache key changes with
the pin, so the toolchain rebuilds exactly once.

| Tool | Pin | Where |
|---|---|---|
| SAW | `1.5.1` | `saw.yml`, `crux-mir.yml` (`SAW_VERSION`) |
| mir-json | commit `48d0b4b2` (last schema-8) | `crux-mir.yml` (`MIR_JSON_COMMIT`) |
| hax | rev `a914ac7` | `fstar.yml` (`HAX_REV`); mirrored in `proofs/hax/extract.sh` |
| F\* | `v2026.03.24` (prebuilt) | `fstar.yml` (`FSTAR_VERSION`) |
| Rust nightly (hax) | `nightly-2025-11-08` | `fstar.yml` |
| Rust nightly (mir-json) | `nightly-2025-09-14` | `crux-mir.yml` |
| OCaml | `5.2` | `fstar.yml` |

The F\* drift guard reuses the already-installed pinned hax (it does not reinstall
from `main`), so the proof is checked against the **same** hax that produced the
extraction. To advance hax: bump `HAX_REV` in `fstar.yml` *and* `extract.sh`,
re-extract locally (`proofs/hax/extract.sh`), commit any extraction changes, then
let the F\* workflow rebuild against the new pin.

Each workflow mirrors a script under `proofs/` (or a documented `cargo` command),
so anything here reproduces locally — see `proofs/README.md` and `docs/assurance.md`.
