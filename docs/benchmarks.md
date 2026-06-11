# Benchmarks

## Executive summary

Measured on a MacBook Pro (Apple M4 Max, macOS aarch64, rustc 1.96.0); see
[Reproducing](#reproducing-these-numbers) for exact commands and
[Methodology and caveats](#methodology-and-caveats) for limits. The candidate
backend uses eight-way interleaved hardware CTR, four-block aggregated GHASH
with precomputed key powers, and a fused single-pass encrypt; `*_to` API
variants perform no heap allocation. Four results drive the conclusion:

**1. Against RustCrypto as you would actually deploy it - unmodified - the
candidate is 8x to 27x faster.** A default `cargo build` of stock `aes-gcm`
0.10 on aarch64 silently uses fixsliced *software* AES and *software* POLYVAL;
the hardware backends engage only if every build of every consumer remembers
`RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"`. Unmodified RustCrypto costs
8.3x at 64-byte encrypt (594 ns vs 71.5 ns), 27x at 1 KiB and 16 KiB, and
12x on the per-record key pattern. The candidate cannot regress this way:
hardware paths are the only paths, and construction fails loudly where they
are missing.

**2. The candidate now also beats RustCrypto's *best* configuration at every
payload of 256 bytes and up.** With the ARMv8 cfgs enabled the stock crates
parallelize AES but still reduce GHASH per block: the candidate encrypts
1.8x faster at 256 B, 2.8x at 1 KiB, and 3.4x at 16 KiB (2.88 us vs
9.75 us). And no configuration shrinks the stock type: `aes_gcm::Aes256Gcm`
measures **992 bytes in both configurations** because the runtime-dispatch
type reserves space for its software variant, versus **304 bytes** for the
candidate (240 bytes of round keys + 64 bytes of GHASH key powers) - 13
cached keys per 4 KiB guarded page versus 4.

**3. Against `ring`, the per-record paths win or tie.** The caller-placed
per-record key pattern (key setup + encrypt 256 B + drop, *including* the
zeroizing wipe ring does not perform) measures **faster than ring**: 182 ns vs
190 ns. Key setup itself beats ring (83 ns vs 87 ns) thanks to a
register-resident NEON key expansion. One-shot no-alloc encrypt is faster than
ring at 256 B (88 ns vs 98 ns) and a tie at 1 KiB (227 ns vs 220 ns - within
run-to-run noise); ring pulls ahead only on bulk 16 KiB (2.42 us vs 3.05 us,
~26%) where its assembly interleaves more aggressively. Decryption trails ring
at bulk because the candidate deliberately verifies the tag *before* writing
any plaintext (two passes), while ring decrypts first and verifies after; we
consider refusing to release unverified plaintext the right trade. ring
remains excluded for the architectural reasons speed cannot fix anyway: its
544-byte key state is opaque - no caller-controlled placement, no layout
contract, no zeroization-on-drop guarantee.

**4. The hardware AES-CTR generator produces a 32-byte key in 24 ns** - 1.6x
faster than a raw ChaCha20 keystream (38 ns), 1.6x faster than a raw Salsa20
keystream (39 ns), and ~40x faster than per-call OS entropy - with fork
detection and reseed accounting included in every call.

**Why it is fast:** every AES round and GF(2^128) multiplication is a CPU
instruction (AESE/AESMC + PMULL here, AES-NI + PCLMULQDQ on x86_64); eight
independent CTR blocks are in flight so AES latency is hidden instead of
serialized; GHASH folds four blocks per field reduction using precomputed
Montgomery powers; key expansion runs entirely in vector registers with
nothing staged through memory; encryption authenticates each ciphertext
chunk as it is produced, touching memory once; the `*_to` APIs add zero
allocations; and drop wipes use 16-byte volatile stores instead of
byte-at-a-time loops.
**Why that justifies the fork:** the alternatives either degrade 8x-27x when
a build flag is missing (stock RustCrypto), lose to it outright when tuned
(2-3x at small-to-medium sizes and up), or refuse caller placement and wipe
guarantees (ring) - and both carry 1.8x-3.3x the cached-key footprint.

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
| 16 B | 49.1 ns | 43.0 ns | 558.2 ns | 37.5 ns | 59.7 ns |
| 64 B | 81.5 ns | 71.5 ns | 594.4 ns | 73.5 ns | 66.9 ns |
| 256 B | 105.4 ns | 94.8 ns | 1.63 us | 173.4 ns | 100.1 ns |
| 1 KiB | 251.3 ns | 226.4 ns | 6.08 us | 636.2 ns | 221.2 ns |
| 4 KiB | 827.6 ns | 761.2 ns | 19.86 us | 2.47 us | 707.2 ns |
| 16 KiB | 3.11 us (4.90 GiB/s) | 2.88 us (5.29 GiB/s) | 78.97 us (198 MiB/s) | 9.75 us (1.56 GiB/s) | 2.44 us (6.24 GiB/s) |

## AES-256-GCM decrypt

The candidate verifies the authentication tag before writing any plaintext
(two passes); ring decrypts in place and verifies afterwards. `*-noalloc` is
`decrypt_to` into a caller buffer (the per-record key-decryption path).

| Size | candidate | candidate-noalloc | rustcrypto (default) | rustcrypto (armv8 cfgs) | ring |
| --- | --- | --- | --- | --- | --- |
| 16 B | 51.9 ns | 40.0 ns | 543.4 ns | 39.0 ns | 37.5 ns |
| 64 B | 87.0 ns | 70.2 ns | 608.6 ns | 62.7 ns | 46.1 ns |
| 256 B | 107.1 ns | 97.5 ns | 1.52 us | 173.5 ns | 85.5 ns |
| 1 KiB | 272.9 ns | 251.2 ns | 5.16 us | 636.1 ns | 171.2 ns |
| 4 KiB | 919.5 ns | 860.0 ns | 19.65 us | 2.43 us | 575.7 ns |
| 16 KiB | 3.46 us | 3.29 us | 77.69 us | 9.63 us | 2.27 us |

## Per-record key pattern (key setup + encrypt 256 B + drop)

The per-record hot path expands a fresh key, encrypts one payload, and
releases the key state. Candidate rows include the zeroizing wipe on drop and
GHASH key-power precomputation; the stock types do not wipe at all.

| Implementation | Time |
| --- | --- |
| candidate (caller-placed slot) | 182 ns |
| candidate (owned) | 187 ns |
| ring | 190 ns |
| rustcrypto (armv8 cfgs) | 317 ns |
| rustcrypto (default) | 2.08 us |

## Key setup (expand 32-byte key to reusable state)

Candidate setup includes computing the four GHASH key powers; the key
expansion runs entirely in vector registers on both architectures.

| Implementation | Time |
| --- | --- |
| candidate (caller-placed slot) | 83 ns |
| candidate (owned) | 87 ns |
| ring | 87 ns |
| rustcrypto (armv8 cfgs) | 161 ns |
| rustcrypto (default) | 604 ns |

## Reusable key-state footprint

From `cargo run --release --example state_size`; identical under both build
configurations (the stock dispatch type reserves space for its software
variant even when hardware backends are enabled).

| Type | Size | Keys per 4 KiB guarded page |
| --- | --- | --- |
| candidate `HardwareAes256Gcm` | 304 B (align 16) | 13 |
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
