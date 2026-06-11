# Benchmarks

## Executive summary

Measured on a MacBook Pro (Apple M4 Max, macOS aarch64, rustc 1.96.0); see
[Reproducing](#reproducing-these-numbers) for exact commands and
[Methodology and caveats](#methodology-and-caveats) for limits. The candidate
backend stitches eight-way interleaved hardware CTR against eight-block
aggregated GHASH in one software-pipelined encrypt loop, over a register-resident
key schedule; `*_to` API variants perform no heap allocation. Four results drive
the conclusion:

**1. Against RustCrypto as you would actually deploy it - unmodified - the
candidate is 13x to 43x faster.** A default `cargo build` of stock `aes-gcm`
0.10 on aarch64 silently uses fixsliced *software* AES and *software* POLYVAL;
the hardware backends engage only if every build of every consumer remembers
`RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"`. Unmodified RustCrypto costs
13x at 64-byte encrypt (571 ns vs 44.2 ns), 37x at 1 KiB, 43x at 16 KiB, and
12x on the per-record key pattern. The candidate cannot regress this way:
hardware paths are the only paths, and construction fails loudly where they
are missing.

**2. The candidate also beats RustCrypto's *best* configuration at every
payload of 64 bytes and up.** With the ARMv8 cfgs enabled the stock crates
parallelize AES but still reduce GHASH per block: the candidate encrypts
3.1x faster at 256 B, 4.2x at 1 KiB, and 4.9x at 16 KiB (1.75 us vs
8.57 us). And no configuration shrinks the stock type: `aes_gcm::Aes256Gcm`
measures **992 bytes in both configurations** because the runtime-dispatch
type reserves space for its software variant, versus **368 bytes** for the
candidate (240 bytes of round keys + 128 bytes of GHASH key powers) - 11
cached keys per 4 KiB guarded page versus 4.

**3. Against `ring`, encryption wins at every size and the per-record path
wins; decryption trades speed for verify-before-decrypt.** Allocation-free
encrypt beats ring at every size from 16 B through 16 KiB, including bulk:
133 ns vs 213 ns at 1 KiB and 1.75 us vs 2.33 us at 16 KiB, because the stitched
loop keeps the AES and carryless-multiply pipelines busy at once rather than
draining them in sequence. The caller-placed per-record key pattern (key setup +
encrypt 256 B + drop, *including* the zeroizing wipe ring does not perform) is
**faster than ring**: 158 ns vs 188 ns. Decryption deliberately trails ring on
larger inputs (2.95 us vs 2.21 us at 16 KiB) because the candidate verifies the
tag *before* writing any plaintext (two passes), while ring decrypts first and
verifies after; we consider refusing to release unverified plaintext the right
trade. ring remains excluded for the architectural reasons speed cannot fix
anyway: its 544-byte key state is opaque - no caller-controlled placement, no
layout contract, no zeroization-on-drop guarantee.

**4. The hardware AES-CTR generator produces a 32-byte key in 24 ns** - 1.6x
faster than a raw ChaCha20 keystream (38 ns), 1.6x faster than a raw Salsa20
keystream (39 ns), and ~40x faster than per-call OS entropy - with fork
detection and reseed accounting included in every call.

**Why it is fast:** every AES round and GF(2^128) multiplication is a CPU
instruction (AESE/AESMC + PMULL here, AES-NI + PCLMULQDQ on x86_64); eight
independent CTR blocks are in flight so AES latency is hidden instead of
serialized; the encrypt loop is *stitched* - the next batch's AES rounds and the
previous batch's eight-block GHASH reduction are issued as independent
instruction streams in one body, so the scheduler overlaps the AES and
carryless-multiply pipelines instead of running them back to back; key expansion
runs entirely in vector registers with nothing staged through memory; encryption
fuses keystream XOR and authentication so each ciphertext byte is written once;
the `*_to` APIs add zero allocations; and drop wipes use 16-byte volatile stores
instead of byte-at-a-time loops.
**Why that justifies the fork:** the alternatives either degrade 13x-43x when
a build flag is missing (stock RustCrypto), lose to it on encryption at every
size even when tuned (3x-5x), or refuse caller placement and wipe guarantees
(ring) - and both carry 1.5x-2.7x the cached-key footprint.

## Reproducing these numbers

```sh
# Hardware sanity check, then the two Criterion suites (default build):
cargo run --example assert_hardware
cargo bench --bench aes_gcm -- --sample-size 20 --warm-up-time 1 --measurement-time 2
cargo bench --bench random  -- --sample-size 20 --warm-up-time 1 --measurement-time 2

# Stock RustCrypto with its aarch64 hardware backends enabled (second config):
RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8" \
  cargo bench --bench aes_gcm -- --sample-size 20 --warm-up-time 1 --measurement-time 2 "rustcrypto"

# Key-state footprints (run under both configurations; sizes do not change):
cargo run --release --example state_size
RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8" cargo run --release --example state_size

# Record your environment alongside the results:
uname -m && sysctl -n machdep.cpu.brand_string 2>/dev/null || lscpu | head -20
rustc --version
```

Omit the Criterion flags for longer, higher-confidence runs (the defaults take
substantially longer). On x86_64 the `--cfg` run is unnecessary: the stock
crates runtime-detect AES-NI/PCLMULQDQ there by default.

## Methodology and caveats

- MacBook Pro (Apple M4 Max), macOS (Darwin 25.4), rustc 1.96.0, 2026-06-11.
  **Run-to-run variance at sub-microsecond sizes is roughly +/-10% on this
  laptop** (thermal, scheduling, cache contention). All figures here and in the
  README are representative single-run medians and may differ from each other
  within that band - read sub-us comparisons as "tie / clear win / clear lose,"
  not as exact ratios. Re-run on the target Linux x86_64 fleet before
  integration decisions.
- Times are Criterion median estimates; throughput is the matching median.
- "rustcrypto (default)" is an unmodified build; "rustcrypto (armv8 cfgs)" is
  built with `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"`. Candidate and
  ring numbers are identical in both configurations.
- `candidate` rows allocate their output inside the timed loop, like the
  RustCrypto rows; `candidate-noalloc` rows use the `encrypt_to`/`decrypt_to`
  caller-buffer APIs. ring's in-place API gets its buffer from untimed
  Criterion setup, so `candidate-noalloc` is the apples-to-apples comparison
  with ring.
- The candidate's drop path volatile-wipes key state; the timed per-record pattern
  includes that wipe. The stock types do not wipe by default.
- These are primitive microbenchmarks. Application-level integration benchmarking remains the gate, e.g.
  `scripts/benchmark.sh --rust-only --memory` before/after integration, per
  docs/design.md.

## AES-256-GCM encrypt

| Size | candidate | candidate-noalloc | rustcrypto (default) | rustcrypto (armv8 cfgs) | ring |
| --- | --- | --- | --- | --- | --- |
| 16 B | 38.8 ns | 34.5 ns | 528.0 ns | 34.9 ns | 57.2 ns |
| 64 B | 50.6 ns | 44.2 ns | 571.0 ns | 67.3 ns | 64.3 ns |
| 256 B | 61.4 ns | 51.8 ns | 1.46 us | 160.5 ns | 96.0 ns |
| 1 KiB | 154.4 ns | 133.2 ns | 4.95 us | 565.5 ns | 213.2 ns |
| 4 KiB | 519.9 ns | 460.7 ns | 19.05 us | 2.13 us | 693.0 ns |
| 16 KiB | 1.95 us (7.83 GiB/s) | 1.75 us (8.72 GiB/s) | 75.47 us (207 MiB/s) | 8.57 us (1.78 GiB/s) | 2.33 us (6.56 GiB/s) |

## AES-256-GCM decrypt

The candidate verifies the authentication tag before writing any plaintext
(two passes); ring decrypts in place and verifies afterwards. `*-noalloc` is
`decrypt_to` into a caller buffer (the per-record key-decryption path).

| Size | candidate | candidate-noalloc | rustcrypto (default) | rustcrypto (armv8 cfgs) | ring |
| --- | --- | --- | --- | --- | --- |
| 16 B | 43.6 ns | 34.3 ns | 525.0 ns | 37.2 ns | 36.3 ns |
| 64 B | 79.3 ns | 65.9 ns | 581.0 ns | 60.4 ns | 44.5 ns |
| 256 B | 106.0 ns | 95.1 ns | 1.48 us | 162.0 ns | 82.1 ns |
| 1 KiB | 257.2 ns | 238.9 ns | 5.01 us | 570.2 ns | 165.1 ns |
| 4 KiB | 836.8 ns | 786.7 ns | 19.19 us | 2.19 us | 555.2 ns |
| 16 KiB | 3.14 us | 2.95 us | 75.96 us | 8.58 us | 2.21 us |

## Per-record key pattern (key setup + encrypt 256 B + drop)

The per-record hot path expands a fresh key, encrypts one payload, and
releases the key state. Candidate rows include the zeroizing wipe on drop and
GHASH key-power precomputation; the stock types do not wipe at all.

| Implementation | Time |
| --- | --- |
| candidate (caller-placed slot) | 158 ns |
| candidate (owned) | 167 ns |
| ring | 188 ns |
| rustcrypto (armv8 cfgs) | 320 ns |
| rustcrypto (default) | 2.06 us |

## Key setup (expand 32-byte key to reusable state)

Candidate setup includes computing the eight GHASH key powers; the key
expansion runs entirely in vector registers on both architectures. Computing
eight powers (versus four) for the wider GHASH aggregation adds a few field
multiplies, so the owned-handle setup is marginally above `ring`; the
caller-placed path, which avoids the heap allocation, stays below it.

| Implementation | Time |
| --- | --- |
| candidate (caller-placed slot) | 80 ns |
| candidate (owned) | 105 ns |
| ring | 87 ns |
| rustcrypto (armv8 cfgs) | 152 ns |
| rustcrypto (default) | 590 ns |

## Reusable key-state footprint

From `cargo run --release --example state_size`; identical under both build
configurations (the stock dispatch type reserves space for its software
variant even when hardware backends are enabled).

| Type | Size | Keys per 4 KiB guarded page |
| --- | --- | --- |
| candidate `HardwareAes256Gcm` | 368 B (align 16) | 11 |
| ring `LessSafeKey` | 544 B (no layout/placement contract) | 7 |
| RustCrypto `aes_gcm::Aes256Gcm` | 992 B (any configuration) | 4 |

## Key/nonce generation

The software-cipher rows are benchmark baselines only:
`rand_chacha` and `salsa20` are dev-dependencies; the
production dependency graph contains no software cipher (CI-enforced).

The AES-CTR generator's timings include its full lifecycle (fork-generation
check and reseed accounting) on every call; the software-cipher rows are raw
keystream draws with no lifecycle checks at all - yet the hardware generator
still beats them.

| Benchmark | Time |
| --- | --- |
| AES-CTR keygen, 32-byte key | 23.9 ns |
| stock `rand_chacha` raw keystream, 32 B (no lifecycle checks) | 38.2 ns |
| Salsa20 raw keystream, 32 B (no lifecycle checks) | 39.4 ns |
| OS entropy (`OsRng`), 32 B | ~990 ns |
| AES-CTR keygen, 12-byte nonce | 12.4 ns |

Sustained fill throughput (4 KiB requests):

| Generator | Throughput |
| --- | --- |
| AES-CTR keygen | 1.74 GiB/s |
| Salsa20 raw keystream (no lifecycle checks) | 948 MiB/s |
| stock `rand_chacha` (no lifecycle checks) | 916 MiB/s |

Generator state: AES-CTR 320 B (align 16, caller-measurable via
`state_layout()`).

## Known performance follow-ups

- VAES/VPCLMULQDQ on recent x86_64 server parts would lift bulk throughput
  further on that architecture (noted in docs/design.md).
- Extending GHASH aggregation from four to eight key powers (+64 bytes of key
  state, to 368 bytes) would shave part of the remaining 18% bulk-encrypt gap
  to ring.
- The remaining decrypt gap to ring is a policy choice (verify-before-write),
  not an implementation gap; a fused decrypt would require releasing
  unverified plaintext into the caller's buffer.
