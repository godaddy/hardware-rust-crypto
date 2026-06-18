# Hardware Rust Crypto Design

## Goal

Build a small, auditable RustCrypto-derived primitive set for consuming applications that keeps
AES-256-GCM wire compatibility while eliminating software AES fallback state from
cached keys. The target platforms are:

- `x86_64` with AES hardware support.
- `aarch64` with ARMv8 AES and PMULL support.

If required CPU features are absent, initialization must fail with a typed error
or the process must fail at startup in binaries that explicitly opt into
mandatory hardware crypto. The library crate should not silently fall back to
software AES.

## Consumer Requirements

A consuming application typically needs only a narrow primitive surface:

- AES-256-GCM encryption and decryption.
- 32-byte keys.
- 12-byte nonces.
- 16-byte authentication tags.
- Current wire layout: `ciphertext || tag || nonce`.
- Empty AAD by default; callers may supply AAD explicitly.
- Reusable per-key state for cached keys.
- Fast random bytes for keys, nonces, and key generation.
- Caller-controlled storage for raw keys and expanded key-equivalent state.
- Guaranteed zeroization of owned or caller-provided key-state storage.

This is not a general replacement for all RustCrypto crates.

## Why Fork/Vendor

The public RustCrypto `aes` type carries software fallback state so the same type
can run on machines without AES hardware. That fallback is valuable generally,
but it is counterproductive for a guarded one-page unencrypted cache
tier: the key-equivalent state becomes much larger than a hardware-only key
schedule needs to be.

For this library, the desired policy is explicit:

- Hardware AES is required.
- Software AES fallback is not compiled into the cached key-state type.
- Constant-time GHASH behavior is preserved by using PMULL/PCLMULQDQ paths.
- Interoperability with AES-256-GCM ciphertexts is non-negotiable.

## Module Layout

The crate `hardware-rust-crypto` has two public modules:

- `aes_gcm`
  - Public AES-256-GCM API consumed by the application.
  - Owns reusable key-state layout.
  - Exposes state-size validation hooks for tests/benchmarks.
- `random`
  - Fast random bytes for keys/nonces/key generation.
  - Ships only the hardware AES-CTR generator. Software stream ciphers are
    used only as dev-dependency benchmark baselines.
  - Adds hardware entropy seeding/direct paths only when measured and available.

The AES, GHASH, CTR, and fork-detection internals are private modules; only the
high-level types are public.

Current implementation:

- `aes_gcm` uses vendored hardware-only AES-256 and GHASH paths for
  `x86_64`/AES-NI/PCLMULQDQ and `aarch64`/AES/PMULL.
- CTR runs eight interleaved block chains; GHASH folds eight blocks per field
  reduction using precomputed Montgomery key powers (`H^1..H^8`, 128 bytes of
  key state). The encrypt path fuses the keystream and the previous batch's
  GHASH into one software-pipelined loop so the AES and carryless-multiply
  pipelines overlap; encryption authenticates each ciphertext chunk as it is
  produced (single pass). Decryption uses a matching fused bulk loop: it writes
  plaintext while authenticating ciphertext, then zeroizes the written range if
  the final tag comparison fails.
- `hardware-aes-gcm` exposes owned and caller-placed key-state APIs, plus
  allocation-free `encrypt_to`/`decrypt_to` caller-buffer variants.
- `hardware-random` ships a hardware-only AES-256-CTR-128 key generator
  seeded and reseeded from OS entropy via `getrandom`; its production
  dependency graph contains no software cipher (CI enforces this with a
  dependency-tree check). Software stream ciphers (`rand_chacha`, `salsa20`)
  appear only as dev-dependency benchmark baselines, never in the library.
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

- Prefer compile-time `target_feature` when the consumer builds dedicated artifacts.
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
  guarded memory.

Target size:

- Preferred: <= 320 bytes per cached key state.
- Acceptable initial ceiling: <= 384 bytes.
- Non-goal: matching RustCrypto's public fallback-capable `Aes256Gcm` state
  size.

The benchmark/test harness asserts the state size now that the ring-backed
temporary implementation has been replaced.

## Opaque Storage Control Contract

Consumers must be able to decide where raw keys and expanded key-equivalent state
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

Consumers can then route high-value key states into guarded-memory slots, larger
locked allocations, or ordinary owned state depending on benchmarked capacity
and policy. The crate should also offer an owned convenience type for tests and
other consumers, but that owned type must zeroize on drop and must be
implemented in terms of the same layout.

The one-page guarded memory.is not the only reason to shrink state. Even when all
RNG/key states cannot fit in that page, smaller hardware-only state can still
improve performance and security posture by reducing:

- L1/L2 cache footprint.
- Cache-line churn on frequently accessed key state.
- Memory bandwidth for key-state movement.
- Working-set pressure when concurrent sessions hold multiple states.
- The amount of key-equivalent material resident in ordinary locked or owned
  memory.

Placement policy should therefore be tiered:

- Highest-frequency / highest-value states get guarded memory.placement first.
- Spillover states use locked/zeroizing owned storage.
- All states remain compact, opaque, and zeroized regardless of placement.
- Benchmarks must measure both guarded-resident and spillover behavior.

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

A common strategy uses a CSPRNG for hot-path keys and nonces, with
OS entropy only for seeding. That exists for performance: direct OS entropy or
direct CPU hardware random per nonce/key can be slower and can serialize the
pipeline.

Policy decision (updated after primitive benchmarks):

- Production code ships only the hardware AES-CTR key generator. A
  software-cipher generator does not belong in a package named
  hardware-rust-crypto, and the measured numbers back the identity: AES-CTR
  generates a 32-byte key in 26 ns with lifecycle checks included, vs 41.2 ns
  for a raw ChaCha20 keystream and 43.7 ns for a raw Salsa20 keystream, both
  with no checks at all (see docs/benchmarks.md).
- Software stream ciphers (`rand_chacha`, `salsa20`) exist only as
  dev-dependency benchmark baselines; no software cipher ships in the library.
  CI fails if any software cipher (or `ring`/stock RustCrypto) enters a
  production dependency graph.
- Use OS entropy (via `getrandom`), and optionally CPU hardware entropy, to
  seed or reseed the CSPRNG.
- Do not generate every key or nonce directly from CPU RNG instructions by
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

- `hardware-random::AesCtrKeyGenerator` is the hardware-only AES-CTR generator
  derived from clipped `rand_aes` code; it is the only generator shipped.
- It implements the fallible `KeyGenerator` contract.
- Seed material must be wiped after initialization.
- `key_32` generates AES-256 keys.
- `nonce_12` generates AES-GCM nonces.
- Backend state must be opaque, caller-placeable where needed, and zeroized on
  release/drop.
- Both current generators track generated bytes, reseed from OS entropy after a
  fixed interval, and fail with a typed error when generator state crosses a
  process fork. On Unix targets fork detection uses a `pthread_atfork` child
  handler that bumps a process-global generation counter, so the per-call check
  is an atomic load (no `getpid` syscall on the hot path) and survives
  process-id reuse. If the handler cannot be installed, or on targets without
  `fork`, detection falls back to process-id comparison. `MADV_WIPEONFORK` on
  guarded-memory-backed state is a future hardening option once caller-placed storage lands.

Hardware entropy policy:

- Use OS entropy (`getrandom`) as the baseline portable seed source. Initial
  seeding always comes from the OS, so every generator chain is rooted in a
  full-entropy OS seed.
- CPU hardware RNG is a reseed input, not the primary direct hot-path
  generator and not the initial seed source.
- `RDSEED` (`x86_64`) and `RNDRRS`/`FEAT_RNG` (`aarch64`) are used only behind
  runtime feature detection with OS fallback. Detection reflects what the
  *guest* sees: Graviton3/4 expose `FEAT_RNG`, x86 servers expose `RDSEED`,
  Apple Silicon exposes neither, and a virtualized guest may hide the
  instruction even where the silicon implements it. A detection miss or a
  retry-budget exhaustion falls back to the OS, never panics.

Implemented reseed construction (`cpu-rng-reseed` feature, default on):

- On reseed, if the CPU RNG is available, draw fresh CPU entropy and blend it
  through the current secret state with a CTR_DRBG-style update:
  `new_seed = AES-CTR keystream(current state) XOR cpu_entropy`, then rekey
  the AES-CTR backend from `new_seed`. The keystream block is secret (it
  depends on the current key, rooted in the original OS seed), so the CPU RNG
  output is never used raw.
- Security property: the new seed is unpredictable unless **both** the prior
  state is compromised **and** the CPU RNG is malicious - strictly stronger
  than trusting either source alone. A malicious CPU that controls
  `cpu_entropy` still cannot force the new seed without already knowing the
  secret keystream; an honest CPU makes the new seed fresh even if the prior
  state had leaked.
- This keeps CPU RNG out of the trusted-sole-source position while using it
  on an ongoing basis, fitting the hardware mission. The `cpu-rng-reseed`
  feature can be disabled to force OS reseed everywhere; platforms without a
  hardware RNG instruction reseed from the OS automatically.
- Residual: post-compromise recovery on a CPU-RNG-only reseed schedule relies
  on the CPU RNG being honest. Because reseeding is cheap, the reseed interval
  can be shortened to bound the window; an occasional forced OS reseed is a
  possible future addition if a platform's CPU RNG is not trusted.

ChaCha20/Salsa20 scope:

- ChaCha20 is not an AES fallback and does not create the same AES key-state
  bloat problem.
- If we vendor it, vendor only the CSPRNG block function/state needed for random
  byte generation.
- Salsa20 is not used by this library's hot path; include it only if a
  compatibility surface requires it.

## `rand_aes` Assessment

`rand_aes` is useful source material and a useful benchmark baseline, but it is
not a drop-in dependency without changes.

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

- Do not use the public `rand_aes` runtime wrapper as this library's generator.
- Clip out the software backend from any production build.
- Clip out `force_software` and any fallback path that can instantiate software
  AES state.
- Clip out runtime `Box` allocation for key state.
- Keep only the AES-256 CTR hardware backend shape relevant to `x86_64` and
  `aarch64`.
- Keep the crate-owned reseed and fork-detection policy in front of AES key
  and nonce generation.
- Wrap it in our opaque storage contract so the consumer controls placement and the
  state always zeroizes on release/drop.

Expected hardware-only AES-256 CTR state:

- Counter: 16 bytes.
- AES-256 round keys: 15 x 16 bytes = 240 bytes.
- Total before alignment/padding: about 256 bytes.

State we do not want in the public key-state type:

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
  and nonces. The 32-byte keys and 12-byte nonces are direct byte draws,
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

### Constant-time basis

The constant-time claim rests on one accepted foundation and two engineering
properties we control:

**Foundation (accepted): hardware-vendor instruction timing.** This package
takes as fundamental that the AES and carryless-multiply instructions it
relies on execute in data-independent time: AES-NI/PCLMULQDQ on x86 and
AESE/AESMC/PMULL on aarch64. This is a documented guarantee from Intel, AMD,
and ARM, and it is the same trust boundary `ring` and `RustCrypto` rely on.
We do not attempt to verify or enforce it; we trust the silicon vendors for
it. (Footnote for completeness: on ARMv8.4+ the formal guarantee is gated by
`PSTATE.DIT`, which this library - like `ring` and `RustCrypto` - does not
set, because shipping cores are constant-time for these instructions
regardless. Setting DIT around crypto sections is a possible future hardening
once stable intrinsics exist.)

**Property we control: no secret-dependent control flow or indexing.**
Verified by review across every path: branches and memory indices depend only
on public values (lengths, buffer positions, CPU feature checks, and the
public accept/reject of the tag check). The only secret-derived comparison is
tag verification, done through `subtle`'s constant-time `ct_eq`.

**Property we control: compiler non-interference.** Two defenses, no
hand-written assembly (which would forfeit the auditability and portability
this fork exists for - a trade `RustCrypto`'s audited code also declines):

1. Secret-dependent comparison goes through `subtle`, whose `Choice`/`ct_eq`
   types carry `optimization_barrier` (`core::hint::black_box`) so LLVM
   cannot reconstruct an early-exit byte compare.
2. The one scalar function that branches could plausibly be specialized into
   - `mulx`'s carry-bit fold - passes its carry through `black_box` so the
   compiler cannot prove it is 0 or 1 and emit a conditional. Everywhere else
   there is simply no comparison or select on a secret for the optimizer to
   transform; the XOR/copy loops are unconditional.

This is checked, not just asserted: see `docs/constant-time.md` for the
procedure that inspects the emitted assembly of the secret-handling paths
(confirming AES/PMULL instructions are present and no secret-dependent
branch is emitted), and for the dudect-style statistical timing harness that
measures decrypt timing across valid/invalid tags.

Accepted zeroization residual risk:

- Ephemeral copies of secret material on the stack and in registers cannot be
  reliably wiped from safe Rust. Known instances: the `u128` intermediate in
  the GHASH `mulx` key derivation, and the by-value round-key array returns
  when constructing or reseeding the AES-CTR generator backend. Long-lived
  state is wiped on drop; these transient copies are accepted and documented
  rather than chased.
- `core::mem::forget` and leaked handles bypass drop-based zeroization, as in
  any drop-based wipe scheme.

## Nonce Generation

AES-GCM fails catastrophically on `(key, nonce)` reuse (it leaks plaintext XOR
and allows recovery of the GHASH subkey, enabling universal forgery), and SP
800-38D section 8.3 bounds a key to ~2^32 invocations under randomly generated 96-bit
nonces. The primary API takes a caller-supplied nonce and does not enforce
uniqueness - standard for a low-level primitive, but a footgun.

For callers that prefer the library to manage uniqueness, the
`encrypt_with_generated_nonce` / `encrypt_nonce_appended_generated` APIs
generate the nonce internally and return it. The construction:

- `nonce = (salt + counter) mod 2^96`.
- `salt` is a 96-bit value **always drawn from the OS entropy source**
  (`getrandom`), never the CPU RNG or a userspace generator - drawn at first
  use and re-drawn on fork (and on the unreachable 2^64 counter wrap).
- `counter` is a per-instance 64-bit value incremented once per nonce.

Properties: within an instance the sequential counter guarantees no collision
for up to 2^64 nonces; across instances (process restart, fork, other hosts)
the random base differentiates, with the only residual being a 96-bit
base-range overlap of order `M^2 * n / 2^96` for M instances of n nonces each -
below the point-collision rate of independent random nonces. The base is
re-drawn on fork via the same `pthread_atfork` generation counter used by
`hardware-random`, so a forked child never repeats its parent's nonces. The
generator state lives on the handle, not in the placed key state, so the
368-byte key-state footprint is unchanged. This is plain AES-GCM (no
AES-GCM-SIV): it *prevents* reuse rather than *surviving* it; SIV remains the
option for call sites that cannot guarantee unique nonces at all.

## Interoperability Testing

Tests prove, for both AES-256-GCM and AES-256-GCM-SIV:

- Candidate ciphertext equals the stock reference for fixed key, nonce, AAD,
  and plaintext (RustCrypto `aes-gcm` for GCM; RustCrypto `aes-gcm-siv` for SIV).
- Candidate decrypts the reference output and the reference decrypts candidate
  output (both directions; GCM additionally cross-decrypts with `ring`).
- The nonce-appended layout remains `ciphertext || tag || nonce`.
- Tampered ciphertext/tag/nonce/AAD fails authentication.

Implemented test coverage (originally listed here as future expansion, now
landed):

- **NIST SP 800-38D** AES-GCM known-answer vectors (GCM) and **RFC 8452
  Appendix C.2** known-answer vectors (SIV).
- **Project Wycheproof** vectors, vendored verbatim under Apache-2.0 (dev-only,
  not in the production graph; see `NOTICE`): AES-256-GCM (66 cases) and
  AES-256-GCM-SIV (103 cases, including the `WrappedIv` counter-wrap and
  `ModifiedTag` rejection vectors) - this addresses security-audit finding
  HRC-2026-08.
- Randomized differential tests and dense length sweeps across many plaintext
  sizes, AAD sizes (0..=288, across the GHASH/POLYVAL aggregation seams), keys,
  nonces, and tamper positions; wrong key/nonce/AAD rejection over random trials.
- White-box SIV tests for the per-message key derivation and the little-endian
  CTR counter wrapping mod 2^32 (the wrap path is otherwise unreachable from the
  public API).
- dudect-style constant-time timing harnesses for both the GCM and SIV decrypt
  paths (see docs/constant-time.md).
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

- Hardware-only AES-CTR generator (32-byte key and 12-byte nonce).
- Stock `rand_chacha::ChaCha20Rng` (software baseline).
- `salsa20` raw keystream (software baseline).
- Direct OS entropy.
- Future hardware RNG seed/reseed paths where available.
- Explicit direct hardware RNG benchmark mode where available, to prove whether
  it is actually viable before considering any policy change.

Integration benchmark:

- After the primitive is usable, wire it into a consumer branch and measure
  end-to-end throughput and memory before/after.

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
   - Done: the repository `NOTICE` file records each vendored project
     (`rand_aes` v0.7.0, `ghash` v0.5.1, `polyval` v0.6.2), its upstream
     commit SHA, copyright holder, license, and the modifications made.
3. Hardware-only backend
   - Remove fallback-capable public state from the candidate cached-key type.
   - Fail on missing CPU features.
   - Keep implementation safe Rust at the public boundary.
4. Validation
   - Add known-answer and randomized differential tests.
   - Run tests on x86_64 and aarch64.
   - Measure state size.
   - Measure throughput and latency.
5. Consumer integration
   - Replace `ring::LessSafeKey` cache with candidate key state.
   - Place per-key state according to placement-capacity policy.
   - Re-run consumer unit, lint, interop, and memory benchmarks.



## Open Decisions

- Whether unsupported hardware should return an error everywhere or panic only
  in binaries that explicitly request mandatory startup enforcement.
- Whether the candidate key state must be exactly 64-byte aligned in its Rust
  type or only when allocated inside the guarded memory.
- Whether to keep RustCrypto traits in the public API or expose a smaller
  consumer-specific API.
