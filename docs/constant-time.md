# Constant-Time Verification

This document records how the constant-time claims in `docs/design.md` are
checked, so the checks can be reproduced when the code, compiler, or target
changes. The basis is summarized in design.md: hardware-vendor instruction
timing is accepted as fundamental; the two properties we control (no
secret-dependent control flow/indexing, and compiler non-interference) are
verified here.

## The constant-time argument, in full

Three classes of operation touch secret-derived data, and each is data-oblivious:

1. **AES rounds and the carryless multiply** run on AES-NI / PCLMULQDQ (x86) and
   AESE/PMULL (aarch64), which the CPU vendors specify as data-independent in
   latency. This is the same trust boundary `ring` and RustCrypto rely on, and it
   is the only *axiom* in the argument.
2. **The CTR keystream application and the GHASH absorption** are byte XOR and
   copies at fixed strides - oblivious by construction.
3. **The only scalar operations on secret data** are the tag comparison
   (`constant_time_eq`) and the GHASH `mulX` carry fold (`mulx`).

So the secret surface reduces to: *are (3)'s two functions branch-free over their
secret inputs?* Section 0 verifies exactly that, automatically, on the shipped
machine code; sections 1-2 are the underlying manual inspection and the
statistical cross-check.

## 0. Binary-level branch-freedom verification (automated, CI-gated)

`proofs/constant-time/verify.sh` builds the crate (`--features ct-verify`, which
emits `#[inline(never)]` wrappers so the functions appear as named symbols),
disassembles `mulx` and `constant_time_eq` with `objdump`, and **fails unless**:

- `mulx` contains **no conditional branch** (its carry fold is `shift`+`XOR`);
- `constant_time_eq` contains **no conditional branch after the first
  secret-byte load** - its only conditional branch is the *public* length check,
  which precedes any byte access; the 16 byte comparisons compile to
  `cmp`+`cset`/`setcc`+`and` (branchless conditional *select*, not a branch).

Conditional *selects* (`csel`/`cset`, `cmov`/`setcc`) are branch-free and
explicitly allowed; only true branches (`b.cond`/`cbz`/`tbz`, `jcc`) are flagged.
A built-in **non-vacuity control** - a deliberately leaky early-return comparison
- must be *rejected*, proving the check would catch a real regression. Runs in
the `constant-time` CI job on x86; reproduce locally with
`./proofs/constant-time/verify.sh`.

This upgrades the constant-time claim for the scalar secret surface from
*statistical* (dudect) to a *checkable property of the compiled binary*. It does
not replace a whole-program constant-time prover (`ct-verif`/`binsec`), which
would taint all secrets and check every path; it verifies the two functions that
the structural argument above isolates as the entire scalar secret surface.

## 1. Emitted-assembly inspection

Confirms that the compiler (a) actually emits the hardware AES/carryless-
multiply instructions rather than any scalar substitute, and (b) does not emit
a secret-dependent conditional branch in the scalar secret-handling code
(`mulx`, the tag path).

Tooling: [`cargo-show-asm`](https://crates.io/crates/cargo-show-asm)
(`cargo install cargo-show-asm`).

```sh
# Dump the key-state init path, which inlines mulx and the AES/GHASH setup:
cargo asm -p hardware-rust-crypto --lib 'hardware_rust_crypto::aes_gcm::KeyState::init_in_place' > init.s

# (a) hardware crypto instructions are present:
grep -cE 'aes[em]|pmull' init.s            # expect a large count (200+ on aarch64)

# (b) the mulx carry fold is branchless: locate the `eor ..., lsl #N` cascade
#     and confirm no conditional branch sits within it:
grep -nE 'eor .*lsl #(57|62|63)' init.s
```

### Observed result (aarch64, rustc 1.96.0, release)

- 213 AES/PMULL instructions in `init_in_place` - the hardware path is used.
- The conditional branches in the function are all on public values: the
  `cmp x1, #32; b.ne` key-length check and the `ands ...#0x...c0; b.eq`
  64-byte chunk-length mask. None branch on key, subkey, or message bytes.
- `mulx`'s carry fold emits as straight-line
  `eor x8, x8, x11, lsl #62 / #63 / #57` with **no branch**. The
  `core::hint::black_box` on the carry appears as an `; InlineAsm Start/End`
  barrier (the carry is forced through the stack as an opaque value), which is
  exactly what prevents LLVM from proving the carry is 0/1 and specializing it
  into a conditional.

Re-run this inspection after any compiler upgrade or change to `mulx` /
`ghash.rs` / the tag path.

## 2. Statistical timing harness (dudect-style)

Inspection proves the *shape* of the code; this measures the *behavior*. The
harness in `tests/timing_constant_time.rs` times the public decryption path
across input classes that must not be distinguishable by timing, and applies
a Welch's t-test (the dudect methodology). It is `#[ignore]`d by default
because it is slow and machine-sensitive; run it deliberately on a quiet box:

```sh
cargo test --release --test timing_constant_time -- --ignored --nocapture
```

Two properties are tested:

- **Tag comparison vs. mismatch position.** Two *invalid* tags, one
  mismatching in the first byte and one in the last, must take the same time.
  A faster early-mismatch would mean the comparison early-exits - the leak
  that enables byte-by-byte tag forgery. This is the security-critical check
  and the property `subtle` exists to protect.
- **Decrypt vs. ciphertext content.** Two pools of equal-length ciphertexts
  (low-entropy and high-entropy plaintext) rotated in lockstep, so both
  classes share an identical memory-access pattern and differ only in the
  data bytes processed.

What is deliberately **not** asserted: that valid and invalid tags take exactly
the same time. Failed authentication additionally zeroizes the output range
after the constant-time comparison, so valid-vs-invalid timing may differ. That
difference reveals only the authentication outcome, which is the public
`Result`; it is not a channel about how much of the tag matched.

### AES-256-GCM-SIV

`tests/timing_constant_time_siv.rs` is the parallel harness for the SIV decrypt
path, asserting the same two properties:

```sh
cargo test --release --test timing_constant_time_siv -- --ignored --nocapture
```

The mismatch-position check is slightly stronger for SIV: the stored tag is also
the initial CTR counter, so the test additionally exercises the little-endian
counter handling and the keystream pass being independent of which tag byte
changed. Both modes settle far below the 25.0 threshold on a quiet box (Apple
M4 Max, release); a representative run:

| Property | GCM \|t\| | SIV \|t\| |
| --- | --- | --- |
| tag comparison vs. mismatch position | 1.59 | 0.15 |
| decrypt vs. ciphertext content | 2.50 | 0.52 |

### Methodology notes (learned while building this)

- **Crop, do not clamp, outliers.** Measurements above ~2 us are preemption
  noise and are dropped; clamping them to a ceiling instead biases the mean.
- **Symmetric access patterns.** A fixed buffer vs. a rotating pool measures
  the harness's cache residency (hot fixed buffer vs. cold pool), not the
  crypto - it produces a large, *sign-flipping* |t| that is noise, not a leak.
  Rotating both classes in lockstep removes this artifact. Both checks then
  settle to |t| < 1.5 across runs.
- **Calibration.** A real early-exit leak in this code registers |t| in the
  hundreds (an early-vs-late mismatch leak measured ~267); post-crop noise
  sits near 1. The 25.0 threshold sits in the wide gap between them.

This is a coarse, machine-dependent guard against gross regressions, not a
certification. A bounded |t| is consistent with - not proof of - constant
time; a large, sample-growing, consistent-sign |t| is a signal to
investigate.

The harness is now **CI-gated** in the `constant-time` job (on both x86_64 and
aarch64), and **fails the build if Welch `|t| ≥ 25`**. To survive shared-runner
jitter without flaking, each test takes the best of three batches and exits on the
first passing batch - a real early-exit leak holds `|t|` in the hundreds across
*every* batch (~267 measured), three orders of magnitude above the ~0.4-2.4 that
constant-time code produces, so the gate separates the two cleanly. It
corroborates, but is secondary to, the deterministic binary branch-freedom check
(section 1), which is the primary CI guarantee.
