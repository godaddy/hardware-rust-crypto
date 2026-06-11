# Hardware Rust Crypto Design

## Goal

Build a small, auditable RustCrypto-derived primitive set for Asherah that keeps
AES-256-GCM wire compatibility while eliminating software AES fallback state from
cached keys. The target platforms are:

- `x86_64` with AES hardware support.
- `aarch64` with ARMv8 AES and PMULL support.

If required CPU features are absent, initialization must fail with a typed error
or the process must fail at startup in binaries that explicitly opt into
mandatory hardware crypto. The library crate should not silently fall back to
software AES.

## Asherah Requirements

Asherah currently needs only a narrow primitive surface:

- AES-256-GCM encryption and decryption.
- 32-byte keys.
- 12-byte nonces.
- 16-byte authentication tags.
- Current wire layout: `ciphertext || tag || nonce`.
- Empty AAD for compatibility with existing cross-language Asherah payloads.
- Reusable per-key state for cached system/intermediate/DRK keys.
- Fast random bytes for DRKs, data nonces, and key generation.
- Caller-controlled storage for raw keys and expanded key-equivalent state.
- Guaranteed zeroization of owned or caller-provided key-state storage.

This is not a general replacement for all RustCrypto crates.

## Why Fork/Vendor

The public RustCrypto `aes` type carries software fallback state so the same type
can run on machines without AES hardware. That fallback is valuable generally,
but it is counterproductive for Asherah's guarded one-page unencrypted cache
tier: the key-equivalent state becomes much larger than a hardware-only key
schedule needs to be.

For Asherah, the desired policy is explicit:

- Hardware AES is required.
- Software AES fallback is not compiled into the cached key-state type.
- Constant-time GHASH behavior is preserved by using PMULL/PCLMULQDQ paths.
- Interoperability with AES-256-GCM ciphertexts is non-negotiable.

## Crate Layout

Planned workspace crates:

- `hardware-aes-gcm`
  - Public AES-256-GCM API consumed by Asherah.
  - Owns reusable key-state layout.
  - Exposes state-size validation hooks for tests/benchmarks.
- `hardware-random`
  - Fast random bytes for DRKs/nonces/key generation.
  - Starts with the current ChaCha20 CSPRNG model.
  - Adds hardware entropy seeding/direct paths only when measured and available.

Current implementation:

- `hardware-aes-gcm` uses vendored hardware-only AES-256 and GHASH paths for
  `x86_64`/AES-NI/PCLMULQDQ and `aarch64`/AES/PMULL.
- `hardware-aes-gcm` exposes owned and caller-placed key-state APIs.
- `hardware-random` wraps `rand_chacha::ChaCha20Rng` seeded from OS entropy.
- `hardware-random` includes a hardware-only AES-256-CTR-128 key generator.
- Tests and benchmarks already compare candidate behavior to RustCrypto and
  `ring`.

## RustCrypto Sources to Vendor

Pull only the parts required for AES-256-GCM:

- `aes`
  - AES-256 key expansion.
  - x86/x86_64 AES-NI backend.
  - aarch64 ARMv8 AES backend.
  - Do not expose or retain fixsliced/software fallback state in the public
    cached key type.
- `ghash` / universal-hash pieces
  - GHASH over GF(2^128).
  - x86 PCLMULQDQ backend.
  - aarch64 PMULL backend.
  - Compact precomputed state only.
- `aes-gcm` composition logic
  - Nonce/J0 construction for 96-bit nonces.
  - CTR mode encryption.
  - GHASH authentication.
  - Tag generation/verification.
  - In-place APIs where practical.
- `aead` traits only if needed for compatibility.

Do not vendor unrelated algorithms or modes.

## Hardware Feature Policy

`x86_64` requirements:

- AES-NI.
- PCLMULQDQ.

Optional later:

- VAES/VPCLMULQDQ acceleration for larger buffers.

`aarch64` requirements:

- AES.
- PMULL.

Detection strategy:

- Prefer compile-time `target_feature` when Asherah builds dedicated artifacts.
- Support runtime detection when one binary must run across a CPU family.
- Cache detection once.
- Return `UnsupportedCpu` before any key material is accepted.

The public API should make unsupported hardware explicit:

```rust
let key = HardwareAes256Gcm::new(raw_key)?;
```

`new` should fail before storing or expanding key material if features are
missing.

## Key-State Target

Expected compact state for AES-256-GCM:

- AES-256 encryption round keys: 15 round keys x 16 bytes = 240 bytes.
- GHASH hash subkey and compact precompute: target 16 to 64 bytes initially.
- Alignment/padding: keep the whole state 64-byte aligned if it is placed in the
  guarded slab.

Target size:

- Preferred: <= 320 bytes per cached key state.
- Acceptable initial ceiling: <= 384 bytes.
- Non-goal: matching RustCrypto's public fallback-capable `Aes256Gcm` state
  size.

The benchmark/test harness asserts the state size now that the ring-backed
temporary implementation has been replaced.

## Opaque Storage Control Contract

Asherah must be able to decide where raw keys and expanded key-equivalent state
live. That means the completed hardware backend cannot allocate key state
internally and hand back an opaque heap-owning object.

The key state should be opaque. Consumers may know its layout, reserve storage
for it, and decide what memory tier backs it, but they should not inspect or
mutate the state bytes.

Required API properties:

- Report key-state size and alignment without taking key material.
- Accept caller-provided storage for key expansion.
- Validate storage size and alignment before touching the key.
- Initialize key-equivalent state directly into that storage.
- Avoid hidden heap allocations or hidden static caches containing key material.
- Zeroize key-equivalent state on explicit release and on drop.
- Make borrowed/caller-owned state lifetime explicit in the type system.
- Expose only an opaque initialized key-state handle, not raw initialized bytes.

Public API shape under consideration:

```rust
pub struct KeyStateLayout {
    pub size: usize,
    pub align: usize,
}

pub struct UninitKeyStateSlot<'a> {
    // private: caller owns placement, crate owns interpretation
    _private: core::marker::PhantomData<&'a mut [u8]>,
}

pub struct OpaqueKeyState<'a> {
    // private initialized key-equivalent state
    _private: core::marker::PhantomData<&'a mut [u8]>,
}

pub struct HardwareAes256Gcm<'a> {
    state: OpaqueKeyState<'a>,
}

impl HardwareAes256Gcm<'_> {
    pub const fn key_state_layout() -> KeyStateLayout;
    pub fn new_in(key: &[u8; 32], slot: UninitKeyStateSlot<'_>) -> Result<Self, Error>;
}
```

Asherah can then route high-value key states into guarded slab slots, larger
locked allocations, or ordinary owned state depending on benchmarked capacity
and policy. The crate should also offer an owned convenience type for tests and
non-Asherah consumers, but that owned type must zeroize on drop and must be
implemented in terms of the same layout.

The one-page guarded slab is not the only reason to shrink state. Even when all
RNG/key states cannot fit in that page, smaller hardware-only state can still
improve performance and security posture by reducing:

- L1/L2 cache footprint.
- Cache-line churn on frequently accessed key state.
- Memory bandwidth for key-state movement.
- Working-set pressure when concurrent sessions hold multiple states.
- The amount of key-equivalent material resident in ordinary locked or owned
  memory.

Placement policy should therefore be tiered:

- Highest-frequency / highest-value states get guarded slab placement first.
- Spillover states use locked/zeroizing owned storage.
- All states remain compact, opaque, and zeroized regardless of placement.
- Benchmarks must measure both slab-resident and spillover behavior.

Zeroization is mandatory:

- `OpaqueKeyState` zeroizes on drop.
- Explicit release zeroizes before returning the slot to the caller/pool.
- Zeroization uses `zeroize` or an equivalent volatile wipe path.
- Tests must prove storage is wiped after drop/release for owned test storage.
- The API must not provide `AsRef<[u8]>`, `AsMut<[u8]>`, `Debug` byte dumps, or
  clone/copy semantics for initialized key state.

The current hardware backend exposes caller-provided storage and wipe-on-drop
tests for owned and placed key state.

## Randomness and Key Generation

Asherah currently uses ChaCha20 CSPRNG output for hot-path DRKs and nonces, with
OS entropy only for seeding. That exists for performance: direct OS entropy or
direct CPU hardware random per nonce/key can be slower and can serialize the
pipeline.

Policy decision:

- Design for both a `ChaCha20` key generator and a hardware-only AES-CTR key
  generator.
- Keep `ChaCha20` as the baseline/default until Asherah benchmarks prove the
  AES-CTR generator is better.
- Use OS entropy, and optionally CPU hardware entropy, to seed or reseed that
  CSPRNG.
- Do not generate every DRK, key, or nonce directly from CPU RNG instructions by
  default.

Rationale:

- A CSPRNG amortizes entropy-source cost and avoids a syscall or serializing CPU
  RNG instruction in every encryption operation.
- It avoids depending on one vendor instruction as the sole source of key
  material.
- It behaves consistently across Apple Silicon, Graviton, Intel, and AMD.
- It gives us one place to add health checks, reseeding policy, and zeroization.

This project should include random generation because it is part of the hot
crypto path:

- `hardware-random::ChaCha20KeyGenerator` keeps the current
  per-thread/per-worker `ChaCha20` CSPRNG model.
- `hardware-random::AesCtrKeyGenerator` is the hardware-only AES-CTR candidate
  derived from clipped `rand_aes` code.
- Both generators implement the same fallible `KeyGenerator` contract.
- Seed material must be wiped after initialization.
- `key_32` generates DRKs and AES-256 keys.
- `nonce_12` generates AES-GCM nonces.
- Backend state must be opaque, caller-placeable where needed, and zeroized on
  release/drop.
- Both current generators track generated bytes, reseed from OS entropy after a
  fixed interval, and return an error if the process ID changes after seeding.

Hardware entropy policy:

- Use OS entropy as the baseline portable seed source.
- CPU hardware RNG is an optional seed/reseed input, not the primary direct
  hot-path generator.
- Add x86 `RDSEED`/`RDRAND` only behind runtime feature detection, health
  checks, and measured platform support.
- Add aarch64 `RNDR`/`RNDRRS` only behind runtime feature detection, health
  checks, and measured platform support.
- Mix CPU RNG output with OS entropy before seeding the CSPRNG when both are
  available; do not trust CPU RNG as the only entropy source by default.
- A direct CPU-RNG mode may exist only as an explicit experimental/benchmark
  feature and must not be the Asherah default without target-hardware evidence.

ChaCha20/Salsa20 scope:

- ChaCha20 is not an AES fallback and does not create the same AES key-state
  bloat problem.
- If we vendor it, vendor only the CSPRNG block function/state needed for random
  byte generation.
- Salsa20 is not currently used by Asherah's hot path; include it only if a
  compatibility surface requires it.

## `rand_aes` Assessment

`rand_aes` is useful source material and a useful benchmark baseline, but it is
not a drop-in Asherah dependency without changes.

Observed in `rand_aes 0.7.0`:

- It provides AES-CTR PRNG variants, including `Aes256Ctr64` and
  `Aes256Ctr128`.
- It has hardware backends for:
  - `x86`/`x86_64` using AES-NI.
  - `aarch64` using the AES/NEON cryptographic extension.
- With `std`, it can runtime-detect hardware AES support.
- If hardware AES is unavailable, or if `force_software` is enabled, it exposes
  a fixsliced software backend.
- The crate docs state that the PRNG is not intended for cryptographic key
  generation because safe automatic reseeding is not provided.
- Runtime dispatch stores either hardware or software state behind boxed enum
  variants, which prevents caller-controlled placement of key state.

Vendoring implication:

- Do not use the public `rand_aes` runtime wrapper as Asherah's generator.
- Clip out the software backend from any Asherah-facing build.
- Clip out `force_software` and any fallback path that can instantiate software
  AES state.
- Clip out runtime `Box` allocation for key state.
- Keep only the AES-256 CTR hardware backend shape relevant to `x86_64` and
  `aarch64`.
- Keep the crate-owned reseed and fork-detection policy in front of DRK, AES key,
  and nonce generation.
- Wrap it in our opaque storage contract so Asherah controls placement and the
  state always zeroizes on release/drop.

Expected hardware-only AES-256 CTR state:

- Counter: 16 bytes.
- AES-256 round keys: 15 x 16 bytes = 240 bytes.
- Total before alignment/padding: about 256 bytes.

State we do not want in the Asherah-facing type:

- Fixsliced AES-256 software round keys: 120 x 8 bytes = 960 bytes.
- Software batch buffers.
- Runtime enum/`Box` indirection.
- Any branch that silently falls back to software AES.

## Keygen Constant-Time Considerations

Key generation has different constant-time concerns than encryption/decryption.
There is no attacker-chosen plaintext/ciphertext being transformed under a
secret key. The core requirements are:

- CSPRNG output must not depend on secret state through table lookups,
  secret-dependent branches, or secret-dependent memory access.
- Generator state updates must be deterministic and independent of generated
  byte values.
- Rejection loops must not branch on generated secret bytes for fixed-size keys
  and nonces. Asherah's 32-byte keys and 12-byte nonces are direct byte draws,
  so no modulo/rejection sampling is needed.
- State, seed material, and buffered output must be zeroized on release/drop.
- Thread/fork behavior must not clone state into duplicate streams.

`ChaCha20` and hardware AES-CTR are both appropriate under those constraints:

- `ChaCha20` uses arithmetic/rotations/xors and has no lookup-table AES timing
  issue.
- Hardware AES-CTR uses AES instructions for block generation and avoids
  table-based software AES cache timing.

The main risks are not ordinary constant-time tag-style comparisons; they are
state compromise, duplicate stream creation, insufficient reseeding, and
accidental software AES fallback. Those are handled by API policy and tests.

## Constant-Time and Side-Channel Constraints

Required:

- No table-based AES fallback.
- Hardware AES instructions only.
- Hardware carryless multiply for GHASH.
- Constant-time tag comparison.
- No secret-dependent branches in Rust glue.
- No secret-dependent indexing outside vetted vendored primitive code.

Important limitation:

- Hardware-only AES reduces cache-timing risk from software AES tables and
  shrinks key-equivalent state. It does not make the unencrypted cache tier
  immune to Spectre/Meltdown-class attacks.

## Interoperability Testing

Tests must prove:

- Candidate AES-256-GCM ciphertext equals stock RustCrypto for fixed key, nonce,
  AAD, and plaintext.
- Candidate decrypts stock RustCrypto output.
- Stock RustCrypto decrypts candidate output.
- Candidate decrypts `ring` output.
- `ring` decrypts candidate output.
- Asherah layout remains `ciphertext || tag || nonce`.
- Tampered ciphertext/tag/nonce fails authentication.

Future test expansion:

- NIST AES-GCM known-answer vectors.
- Wycheproof AES-GCM vectors if license and vendoring policy allow.
- Randomized differential tests across many plaintext sizes, AAD sizes, keys,
  nonces, and tamper positions.
- Cross-architecture CI on x86_64 and aarch64.

## Benchmarking

Benchmarks compare:

- Candidate implementation.
- Stock RustCrypto `aes-gcm`.
- `ring`.

AES-GCM benchmark dimensions:

- Key setup cost.
- Encrypt 64 bytes, 1 KiB, 16 KiB.
- Decrypt 64 bytes, 1 KiB, 16 KiB.
- In-place variants once implemented.
- State size and alignment.

Random benchmark dimensions:

- FastRandom 32-byte key generation.
- FastRandom 12-byte nonce generation.
- Stock `rand_chacha::ChaCha20Rng`.
- `rand_aes::Aes256Ctr128` as an upstream baseline.
- Hardware-only AES-CTR candidate.
- Direct OS entropy.
- Future hardware RNG seed/reseed paths where available.
- Explicit direct hardware RNG benchmark mode where available, to prove whether
  it is actually viable before considering any policy change.

Asherah integration benchmark:

- After the primitive is usable, wire it into an Asherah branch and run
  `scripts/benchmark.sh --rust-only --memory` before/after.

## Implementation Phases

1. Scaffold
   - Candidate crates.
   - Design doc.
   - Interop tests.
   - Benchmark harness.
2. Vendor audit
   - Import the minimal RustCrypto AES/GHASH/AES-GCM source set.
   - Preserve license headers and upstream attribution.
   - Record upstream crate versions and commit SHAs.
3. Hardware-only backend
   - Remove fallback-capable public state from the candidate cached-key type.
   - Fail on missing CPU features.
   - Keep implementation safe Rust at the public boundary.
4. Validation
   - Add known-answer and randomized differential tests.
   - Run tests on x86_64 and aarch64.
   - Measure state size.
   - Measure throughput and latency.
5. Asherah integration
   - Replace `ring::LessSafeKey` cache with candidate key state.
   - Place DRK/IK/SK key-equivalent state according to slab capacity policy.
   - Re-run Asherah unit, lint, interop, and memory benchmarks.

See `docs/asherah-integration.md` for the concrete feature-flag plan.

## Open Decisions

- Whether unsupported hardware should return an error everywhere or panic only
  in binaries that explicitly request mandatory startup enforcement.
- Whether the candidate key state must be exactly 64-byte aligned in its Rust
  type or only when allocated inside the guarded slab.
- Whether to keep RustCrypto traits in the public API or expose a smaller
  Asherah-specific API.
