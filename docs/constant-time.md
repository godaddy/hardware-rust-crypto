# Constant-Time Verification

This document records how the constant-time claims in `docs/design.md` are
checked, so the checks can be reproduced when the code, compiler, or target
changes. The basis is summarized in design.md: hardware-vendor instruction
timing is accepted as fundamental; the two properties we control (no
secret-dependent control flow/indexing, and compiler non-interference) are
verified here.

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

The harness is intentionally **not** wired into CI: shared CI runners are too
noisy for a ~200 ns-scale timing measurement, and a flaky timing gate would be
worse than none. The deterministic CI-friendly check is the assembly
inspection in section 1; the dudect harness is a manual tool to run on a quiet
machine when the secret-handling code or the compiler changes.
