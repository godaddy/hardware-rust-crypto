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
candidate is 14x to 43x faster.** A default `cargo build` of stock `aes-gcm`
0.10 on aarch64 silently uses fixsliced *software* AES and *software* POLYVAL;
the hardware backends engage only if every build of every consumer remembers
`RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"`. Unmodified RustCrypto costs
14x at 64-byte encrypt (597 ns vs 41.6 ns), 39x at 1 KiB, and 43x at 16 KiB.
The candidate cannot regress this way: hardware paths are the only paths, and
construction fails loudly where they are missing.

**2. The candidate also beats RustCrypto's *best* configuration at every
payload of 64 bytes and up.** With the ARMv8 cfgs enabled the stock crates
parallelize AES but still reduce GHASH per block: the candidate encrypts
3.4x faster at 256 B, 4.4x at 1 KiB, and 5.0x at 16 KiB (1.77 us vs
8.86 us). And no configuration shrinks the stock type: `aes_gcm::Aes256Gcm`
measures **992 bytes in both configurations** because the runtime-dispatch
type reserves space for its software variant, versus **368 bytes** for the
candidate (240 bytes of round keys + 128 bytes of GHASH key powers) - 11
cached keys per 4 KiB guarded page versus 4.

**3. Against `ring`, encryption wins at every size; bulk decryption now wins
too.** Allocation-free encrypt beats ring at every size from 16 B through
16 KiB, including bulk: 131 ns vs 217 ns at 1 KiB and 1.77 us vs 2.38 us at
16 KiB. Allocation-free decrypt also beats ring in this run from 16 B through
16 KiB: 143 ns vs 168 ns at 1 KiB and 1.79 us vs 2.19 us at 16 KiB. Both bulk
paths keep the AES and carryless-multiply pipelines busy at once rather than
draining them in sequence.
Key setup is the one row where ring is faster in this run (86 ns versus 94 ns
for the caller-placed candidate handle). The new inline owned candidate key
state removes the boxed allocation path and lands at 108 ns versus 114 ns for
the boxed owner, while still computing the GHASH key powers and zeroizing key
state on drop. ring remains excluded for the
architectural reasons speed cannot fix anyway: its 544-byte key state is opaque
- no caller-controlled placement, no layout contract, no zeroization-on-drop
guarantee.

**4. The hardware AES-CTR generator produces a 32-byte key in 24.5 ns** - 1.6x
faster than a raw ChaCha20 keystream (38.2 ns), 1.6x faster than a raw Salsa20
keystream (39.8 ns), and ~37x faster than per-call OS entropy - with fork
detection and reseed accounting included in every call.

**Why it is fast:** every AES round and GF(2^128) multiplication is a CPU
instruction (AESE/AESMC + PMULL here, AES-NI + PCLMULQDQ on x86_64); eight
independent CTR blocks are in flight so AES latency is hidden instead of
serialized; the encrypt and decrypt bulk loops are *stitched* - the next
batch's AES rounds and the previous batch's eight-block GHASH reduction are
issued as independent instruction streams in one body, so the scheduler overlaps
the AES and carryless-multiply pipelines instead of running them back to back;
key expansion runs entirely in vector registers with nothing staged through
memory; the fused bulk paths touch each message byte once; the `*_to` APIs add
zero allocations; and drop wipes use 16-byte volatile stores instead of
byte-at-a-time loops.
**Why that justifies the fork:** the alternatives either degrade 14x-43x when
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
  README are representative single-run estimates and may differ from each other
  within that band - read sub-us comparisons as "tie / clear win / clear lose,"
  not as exact ratios. Re-run on the target Linux x86_64 fleet before
  integration decisions.
- Times are Criterion displayed `time` estimates (`slope.point_estimate` in
  `estimates.json`); throughput is the matching displayed throughput.
- "rustcrypto (default)" is an unmodified build; "rustcrypto (armv8 cfgs)" is
  built with `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"`. Candidate and
  ring numbers are identical in both configurations.
- `candidate` rows allocate their output inside the timed loop, like the
  RustCrypto rows; `candidate-noalloc` rows use the `encrypt_to`/`decrypt_to`
  caller-buffer APIs. ring's in-place API gets its buffer from untimed
  Criterion setup, so `candidate-noalloc` is the apples-to-apples comparison
  with ring.
- The candidate's drop path volatile-wipes key state; the key-setup timings
  include that wipe. The stock types do not wipe by default.
- These are primitive microbenchmarks; real workloads should be measured in the
  consuming application before integration decisions.

## AES-256-GCM encrypt

| Size | candidate | candidate-noalloc | rustcrypto (default) | rustcrypto (armv8 cfgs) | ring |
| --- | --- | --- | --- | --- | --- |
| 16 B | 33.6 ns | 26.8 ns | 538.3 ns | 34.9 ns | 57.8 ns |
| 64 B | 48.9 ns | 41.6 ns | 597.5 ns | 69.3 ns | 67.1 ns |
| 256 B | 60.9 ns | 48.8 ns | 1.47 us | 165.7 ns | 97.4 ns |
| 1 KiB | 156.7 ns | 130.5 ns | 5.04 us | 579.2 ns | 216.6 ns |
| 4 KiB | 529.5 ns | 459.3 ns | 19.27 us | 2.26 us | 702.6 ns |
| 16 KiB | 1.97 us (7.74 GiB/s) | 1.77 us (8.64 GiB/s) | 76.10 us (205 MiB/s) | 8.86 us (1.72 GiB/s) | 2.38 us (6.41 GiB/s) |

## AES-256-GCM encrypt, nonce-appended layout

These rows measure the self-framed `ciphertext || tag || nonce` layout used by
callers that store the nonce with the ciphertext. The ring row seals in place
and appends the nonce after the AEAD operation; `candidate-in-place` starts
from a plaintext `Vec` with capacity for the tag and nonce.

| Size | candidate | candidate-noalloc | candidate-in-place | ring |
| --- | --- | --- | --- | --- |
| 16 B | 34.8 ns | 28.1 ns | 28.4 ns | 41.6 ns |
| 64 B | 39.1 ns | 44.1 ns | 34.9 ns | 46.3 ns |
| 256 B | 62.6 ns | 49.8 ns | 52.4 ns | 71.2 ns |
| 1 KiB | 154.1 ns | 131.6 ns | 137.0 ns | 171.9 ns |
| 4 KiB | 511.0 ns | 459.9 ns | 476.9 ns | 575.2 ns |
| 16 KiB | 1.91 us | 1.77 us | 1.81 us | 2.08 us |

## AES-256-GCM decrypt

The candidate decrypts into the output buffer before the final tag comparison
and zeroizes the plaintext-length prefix on authentication failure. `*-noalloc`
is `decrypt_to` into a caller buffer and is the closest comparison to ring's
in-place API.

| Size | candidate | candidate-noalloc | rustcrypto (default) | rustcrypto (armv8 cfgs) | ring |
| --- | --- | --- | --- | --- | --- |
| 16 B | 38.1 ns | 33.6 ns | 535.2 ns | 37.5 ns | 36.6 ns |
| 64 B | 47.5 ns | 39.8 ns | 585.0 ns | 60.3 ns | 45.0 ns |
| 256 B | 72.4 ns | 60.4 ns | 1.48 us | 166.4 ns | 83.5 ns |
| 1 KiB | 169.3 ns | 143.2 ns | 5.04 us | 590.6 ns | 168.3 ns |
| 4 KiB | 512.1 ns | 471.9 ns | 19.32 us | 2.28 us | 560.1 ns |
| 16 KiB | 1.91 us | 1.79 us | 75.90 us | 8.93 us | 2.19 us |

## Key setup (expand 32-byte key to reusable state)

Candidate setup includes computing the eight GHASH key powers; the key
expansion runs entirely in vector registers on both architectures. Computing
eight powers (versus four) for the wider GHASH aggregation adds a few field
multiplies. The caller-placed path is closest to `ring`; the inline owned
prepared key state avoids the boxed allocation/free path while preserving
zeroize-on-drop semantics.

| Implementation | Time |
| --- | --- |
| ring | 86 ns |
| candidate (caller-placed slot) | 94 ns |
| candidate (inline owned key state) | 108 ns |
| candidate (boxed owned handle) | 114 ns |
| rustcrypto (armv8 cfgs) | 162 ns |
| rustcrypto (default) | 593 ns |

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
| AES-CTR keygen, 32-byte key | 24.5 ns |
| stock `rand_chacha` raw keystream, 32 B (no lifecycle checks) | 38.2 ns |
| Salsa20 raw keystream, 32 B (no lifecycle checks) | 39.8 ns |
| OS entropy (`OsRng`), 32 B | 914 ns |
| AES-CTR keygen, 12-byte nonce | 12.6 ns |

Sustained fill throughput (4 KiB requests):

| Generator | Throughput |
| --- | --- |
| AES-CTR keygen | 1.80 GiB/s |
| Salsa20 raw keystream (no lifecycle checks) | 1008 MiB/s |
| stock `rand_chacha` (no lifecycle checks) | 950 MiB/s |

Generator state: AES-CTR 320 B (align 16, caller-measurable via
`state_layout()`).

## Known performance follow-ups

- VAES/VPCLMULQDQ on recent x86_64 server parts would lift bulk throughput
  further on that architecture (noted in docs/design.md).
- Tiny 16 B / 64 B allocating decrypt still has fixed overhead above ring's
  in-place path; `decrypt_to` is the path to use for tiny messages when the
  caller can provide a buffer.
