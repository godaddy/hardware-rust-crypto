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
| **SAW (LLVM bitcode proof)** | `saw.yml` | manual | SAW verifies rustc's LLVM bitcode against a Cryptol spec (`saw_increment_counter` == inc_32, `saw_j0` == J0). Third independent prover. |
| **crux-mir (Rust MIR proof)** | `crux-mir.yml` | manual | crux-mir proves `increment_counter` == inc_32 over Rust MIR (fourth toolchain); `clmul_probe` documents the unmodeled-intrinsic boundary. |
| **F\* / hax extraction proof** | `fstar.yml` | manual | Extracts the composition from real Rust to F\* with hax, drift-checks it, and verifies `HrcComposition.fst`. Heaviest bring-up (builds hax + F\* + Z3). |
| **Constant-time** | `constant-time.yml` | push + PR | Binary-level branch-freedom (disassembly) of the secret-handling functions + dudect Welch t-tests on both decrypt paths. |
| **Miri (UB checker)** | `miri.yml` | push + PR | Runs the aes_gcm key-state lifecycle + real AES/GHASH (x86 intrinsics) under Miri's UB checker. |
| **Valgrind memcheck** | `valgrind.yml` | push + PR | memchecks the real x86_64 AES-NI/PCLMULQDQ test binaries. |
| **Sanitizers (ASan/TSan)** | `sanitizers.yml` | push + PR | AddressSanitizer + ThreadSanitizer over the intrinsic binary. |
| **Fuzz smoke** | `fuzz.yml` | push + PR | Short libFuzzer run per target (decrypt parser, differential vs RustCrypto). |
| **Randomness battery** | `randomness.yml` | push + PR | Streams the AES-CTR generator into PractRand (to 4 GiB). |
| **Mutation testing** | `mutation.yml` | manual | cargo-mutants over the GCM composition + nonce generator (test-suite effectiveness). |
| **Heavy assurance** | `heavy-assurance.yml` | manual | Deep/long bundle: full-suite Valgrind, ASan/TSan/MSan, 30-min/target fuzz, multi-seed PractRand + dieharder, extended proofs, mutation. |
| **Publish** | `publish.yml` | tag | crates.io release. |

## Manual workflows worth knowing

- **SAW / crux-mir** install a prebuilt SAW release bundle (Linux x86_64, with
  solvers); crux-mir additionally builds the schema-8 `mir-json` to match the
  bundle's `crux-mir-comp`. A few minutes of setup each.
- **F\* / hax** is the heaviest: it builds the hax Rust + OCaml engines, F\*, and
  Z3 from source (`timeout-minutes: 120`). Run it when you want the source-level
  F\* proof re-checked against a fresh extraction.
- **Mutation / Heavy assurance** are slow by design and report rather than gate;
  see `docs/mutation-testing.md` for the reviewed survivor set.

Each workflow mirrors a script under `proofs/` (or a documented `cargo` command),
so anything here reproduces locally — see `proofs/README.md` and `docs/assurance.md`.
