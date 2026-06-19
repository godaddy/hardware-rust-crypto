# hardware-rust-crypto

Hardware-only AES-256-GCM, AES-256-GCM-SIV, and key/nonce generation for Rust.
Every AES round and every GF(2^128) multiply executes as a CPU instruction; no
software fallback is compiled in.

<!-- The whole verification battery runs in the open. Each badge links to its live
     runs and full logs - click through to see exactly what executed and its output. -->
[![CI](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/ci.yml)
[![Z3/sympy proofs](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/proofs-z3.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/proofs-z3.yml)
[![Kani](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/kani.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/kani.yml)
[![SAW](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/saw.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/saw.yml)
[![crux-mir](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/crux-mir.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/crux-mir.yml)
[![F*](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/fstar.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/fstar.yml)
[![Constant-time](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/constant-time.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/constant-time.yml)
[![Miri](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/miri.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/miri.yml)
[![Sanitizers](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/godaddy/hardware-rust-crypto/actions/workflows/sanitizers.yml)

## Proven secure, not just asserted secure

Most crypto libraries ask you to trust that their code is correct. This one is
built so you do not have to: the security-critical logic is **machine-checked
from several independent angles**, the cryptographic primitives are computed by
**validated CPU silicon** rather than by this code, and every check runs in CI
where you can re-run it yourself.

**The cryptography is the CPU's job; the orchestration is ours, and we prove the
orchestration.** Every AES round and every GF(2^128) multiplication is a single
dedicated hardware instruction - AES-NI / PCLMULQDQ on x86_64, the ARMv8
Cryptographic Extensions (AES / PMULL) on aarch64 - the same cryptographic
silicon that terminates TLS across the internet. There is no software S-box, no
table lookup, no bitsliced fallback, so the classic AES cache-timing attack
surface does not exist here: the S-box never touches memory. What this library
*adds* is the thin, non-secret plumbing around those instructions - counter
increments, the `J0` construction, nonce generation, length framing, the
tag-comparison decision, key lifecycle - and that plumbing is what we have proven
exhaustively.

### The composition logic is checked by independent verification engines

The intrinsic-free glue is verified **for all inputs** by tools that share no
code and no solver heritage - they would each have to fail the same way to let a
bug through. The single most safety-critical line - the counter increment, since
a wrong increment silently breaks nonce uniqueness and is catastrophic for GCM -
is independently confirmed by **five** of them:

| Engine | Verifies over… | Proves (among others) |
| --- | --- | --- |
| **Kani / CBMC** | the **actual compiled machine code** | counter == SP 800-38D `inc_32` / RFC 8452 increment over all 2¹²⁸ blocks; `J0` layout; length validators; the nonce parser and envelope splitters never panic or read out of bounds; `constant_time_eq` accepts exactly the correct tags; generated nonces are injective in the counter (no reuse within an instance) |
| **SAW** (Galois) | the **LLVM bitcode** | `increment_counter` == `inc_32`, `j0` == `IV‖0³¹‖1`, against a Cryptol spec |
| **crux-mir** (Galois) | the **Rust MIR** | `increment_counter` == `inc_32` |
| **F\*** (via hax) | **F\* extracted from the real Rust source** | `j0` sets the pre-counter byte; `increment_counter` preserves the leading 96 bits - with a drift guard that the proved code matches a fresh extraction |
| **Z3 / SMT** | an independently-written model | decryption inverts encryption, the SIV key derivation, and the length framing == SP 800-38D / RFC 8452, with a built-in non-vacuity check |
| **sympy** | symbolic algebra | the Horner recurrence == the batch sum-of-powers, for every block count |

### The one piece of novel math is proven for every possible input

The GHASH/POLYVAL field multiply is the only hand-built cryptographic arithmetic
in the crate. It is proven **equal to the RFC 8452 specification for all inputs**
- not sampled, all of them - by an exhaustive argument over the 128×128 GF(2)
basis (the operation is GF(2)-bilinear, so its values on a basis determine it
everywhere), on both architectures. The model is first pinned byte-for-byte to
the output of the real CPU instructions, so "the model" = "the shipped code" =
"the spec" before any proof is trusted. Notably, two of the engines above (SAW
and crux-mir) independently established that no source- or bitcode-level tool can
see *through* the hardware carryless-multiply instruction itself - which is
exactly why the field proof is anchored to that instruction's real output: the
primitive is the CPU vendor's validated silicon, and we prove our use of it.

### …and tested the way you test something you cannot afford to get wrong

- **Constant-time, in the shipped binary.** The secret-handling routines are
  disassembled and verified **branch-free over their secret inputs** - a
  checkable property of the machine code, with a deliberately-leaky control that
  must be rejected - backed by a CI-gated dudect (Welch t-test) timing test on
  both decrypt paths.
- **Memory safety, five ways.** The entire key-state lifecycle and the real
  AES/GHASH paths run clean under Miri's undefined-behavior checker (aliasing,
  provenance, out-of-bounds, uninitialized reads), Valgrind memcheck,
  AddressSanitizer, ThreadSanitizer, and continuous fuzzing of the decrypt parser.
- **Wire-format correctness against three independent lineages.** Byte-for-byte
  agreement with RustCrypto, **`ring`** (BoringSSL-derived), and **OpenSSL** -
  implementations with no shared ancestry - plus NIST CAVP (750 vectors),
  RFC 8452 Appendix C.2, and Project Wycheproof (every tag-rejection and
  counter-wrap case included).
- **Randomness quality.** The hardware AES-CTR key/nonce generator passes the
  PractRand and dieharder statistical batteries.
- **We test the tests.** Mutation testing (`cargo-mutants`) confirms the suite
  actually catches injected bugs; the few intentional survivors are individually
  accounted for.
- **Supply chain.** The production dependency graph contains no third-party
  cipher and no third-party crypto implementation - and CI **fails the build** if
  one ever appears.

None of this is a one-time claim, and none of it is hidden. Every item above runs
in **public continuous integration** as its own re-runnable workflow: the badges
at the top of this file link straight to the live runs, where anyone can read the
exact commands that executed and their full output - the SAW and crux-mir proofs
printing `Proof succeeded`, Kani discharging its harnesses, F\* printing
`PROOF VERIFIED`, the constant-time disassembly check, the differential vectors.
The verification is open to inspection, reproducible from the scripts under
[`proofs/`](proofs/), and re-runnable on demand from the Actions tab. For the
exact statement of each property, its method, and an explicit trust level -
compiled-code proof → all-inputs model proof → exhaustive vectors → tooling - see
[docs/proof-coverage.md](docs/proof-coverage.md); for the full narrative, see
[docs/assurance.md](docs/assurance.md).

### Will quantum computers break this? No - and AES-256 is the reason

A fair question, and the short answer for symmetric encryption is **no**. The
algorithms quantum computers actually break are the *asymmetric* ones - RSA and
elliptic-curve key exchange and signatures, via Shor's algorithm - and this
library uses none of them. Symmetric ciphers like AES are only modestly affected:
the best known quantum attack, Grover's algorithm, at most *halves* the effective
key length. That takes **AES-256 from a 256-bit to an estimated 128-bit security
level - still far beyond the reach of any computer, classical or quantum** - and
Grover's speedup parallelizes so poorly that the practical margin is larger
still. This is precisely why NIST and the NSA's CNSA 2.0 suite both list
**AES-256 as quantum-resistant** and approved for protecting information into the
post-quantum era, and why doubling the symmetric key size (to 256 bits) is the
standard post-quantum guidance.

Because this library is **AES-256 throughout** - both AEAD modes and the
key/nonce generator - the symmetric cryptography here is considered safe against
quantum attack. (Post-quantum *key exchange* and *signatures* are a separate,
asymmetric problem that a symmetric AEAD library neither solves nor needs to.)

## Why: the performance and footprint delta

Leaning almost entirely on the CPU's dedicated cryptographic instructions -
AES-NI/PCLMULQDQ on x86_64, ARMv8 AES/PMULL on aarch64 - is what produces the
gap below. Encryption is faster than `ring` at every size from 16 bytes through
16 KiB, including bulk, because the encrypt path stitches the AES keystream and
GHASH multiply into one software-pipelined loop so both execution pipelines stay
busy. Bulk decryption uses the same policy as high-performance in-place AEAD
APIs: write plaintext while authenticating, then wipe the caller buffer on tag
failure. It runs an order of magnitude faster than a default RustCrypto build
and carries the smallest reusable key state of the three; see
[docs/benchmarks.md](docs/benchmarks.md).

| Operation (lower is better, ns) | this crate | ring | RustCrypto (default) | RustCrypto (armv8 cfgs) |
| --- | --- | --- | --- | --- |
| encrypt 1 KiB | 157 | 217 | 5040 | 579 |
| encrypt 16 KiB | 1970 | 2380 | 76100 | 8860 |
| decrypt 1 KiB | 169 | 168 | 5040 | 591 |
| decrypt 16 KiB | 1910 | 2190 | 75900 | 8930 |

Reusable AES-256-GCM key-state size: **this crate 368 B / ring 544 B /
RustCrypto 992 B**. Measured on a MacBook Pro (Apple M4 Max, single machine);
at these ~200 ns scales run-to-run variance is roughly +/-10%. The allocation-free
`*_to` APIs run faster still (1 KiB encrypt 131 ns, decrypt 143 ns). The full matrix, both
RustCrypto build configurations, and methodology are in
[docs/benchmarks.md](docs/benchmarks.md).

**How it gets there:** stitched encrypt and decrypt loops that software-pipeline eight-way
interleaved hardware CTR against eight-block aggregated GHASH so the AES and
carryless-multiply pipelines run concurrently, a register-resident key schedule,
fused bulk paths that touch each message byte once, and allocation-free `*_to`
APIs. Failed `decrypt_to` authentication zeroizes the plaintext-length prefix of
the caller buffer before returning an error.
**Why that is also safer:** the AES S-box never touches memory, so the classic
cache-timing attack surface does not exist here; and there is no silent
software fallback - if the required hardware is absent, construction fails with
a typed error instead of quietly degrading (a default RustCrypto build on
aarch64 silently runs ~8x-slower software AES, see
[docs/benchmarks.md](docs/benchmarks.md)).

## AES-256-GCM-SIV: nonce-misuse-resistant, same hardware

The crate also implements AES-256-GCM-SIV (RFC 8452) on the same hardware AES
and carryless-multiply backends - POLYVAL is the field operation that backend
computes natively, so it reuses the eight-block aggregated reduction, and the
CTR pass drives eight interleaved AES chains. SIV is a two-pass design (it
authenticates the plaintext before deriving the counter, so it cannot use the
fused GCM loop) and derives a fresh per-message key, so it is slower than this
crate's own AES-256-GCM - but it beats RustCrypto's AES-256-GCM-SIV at every
size, **including RustCrypto's hardware-enabled configuration**, and is 12x-27x
faster than the default build a consumer gets unmodified. There is no `ring`
column here because `ring` implements no GCM-SIV mode (its only AEADs are
AES-128/256-GCM and ChaCha20-Poly1305), so RustCrypto `aes-gcm-siv` is the only
external reference; it is also our interop oracle, including the RFC 8452
known-answer vectors.

| Operation (lower is better, ns) | this crate (SIV) | this crate (GCM) | RustCrypto SIV (default) | RustCrypto SIV (armv8 cfgs) |
| --- | --- | --- | --- | --- |
| encrypt 1 KiB | 392 | 157 | 7350 | 891 |
| encrypt 16 KiB | 3110 | 1970 | 84600 | 9960 |
| decrypt 1 KiB | 395 | 169 | 7390 | 874 |
| decrypt 16 KiB | 3040 | 1910 | 85100 | 10040 |

Reusable AES-256-GCM-SIV key-state size: **this crate 240 B / RustCrypto 960 B**
(unchanged across build configurations). At 240 bytes it is the leanest state in
the crate - smaller than the 368-byte AES-256-GCM state - because the POLYVAL
key powers are derived per message rather than precomputed into reusable state,
so it holds only the key-generating AES schedule. Key setup is correspondingly
cheap (23-41 ns versus 347 ns for RustCrypto). Same Apple M4 Max machine and
+/-10% sub-microsecond caveat as above; the full SIV matrix, both RustCrypto
configurations, and the per-message-overhead breakdown are in
[docs/benchmarks.md](docs/benchmarks.md).

## What it provides

A single crate, `hardware-rust-crypto`, with two modules:

- `aes_gcm`: hardware-only AES-256-GCM with compact reusable key state. The
  default encrypt API generates a unique nonce and returns the self-framed
  `ciphertext || tag || nonce` envelope; decrypt parses the nonce from that
  envelope. Allocation-free inline owned prepared keys
  (`HardwareAes256GcmKeyState`) and caller-controlled storage placement
  (`HardwareAes256GcmIn` / `UninitKeyStateSlot` / `key_state_layout`) let the
  caller decide where keys and key-equivalent state live. Key state zeroizes on
  drop. The same module also provides nonce-misuse-resistant **AES-256-GCM-SIV**
  (RFC 8452) through a parallel set of types (`HardwareAes256GcmSiv` /
  `HardwareAes256GcmSivKeyState` / `HardwareAes256GcmSivIn` /
  `SivUninitKeyStateSlot`) with the same default envelope API, built on the
  same hardware AES and carryless-multiply backends with POLYVAL
  authentication. Its 240-byte reusable state is the leanest of the set (just
  the key-generating AES schedule) and 4x smaller than RustCrypto's
  `Aes256GcmSiv`; see [docs/benchmarks.md](docs/benchmarks.md).
- `random`: a hardware-only AES-CTR key/nonce generator with fork detection
  and zeroized state. Initial seeding uses OS entropy (`getrandom`); reseeding
  blends CPU hardware-RNG entropy (RDSEED on x86_64, RNDRRS on aarch64
  Graviton) through the generator state when available, falling back to the OS
  otherwise (`cpu-rng-reseed` feature, default on).

Interoperability tests against stock RustCrypto `aes-gcm`, `aes-gcm-siv`, and
`ring` (including RFC 8452 known-answer vectors and the Project Wycheproof
AES-256-GCM-SIV suite - counter-wrap and tag-rejection vectors included - for
the SIV path), dudect-style constant-time timing harnesses for both the GCM and
SIV decrypt paths, Criterion benchmark harnesses, and CI on Linux x64 and macOS
aarch64 round out the repo.

The production dependency graph contains **no software cipher and no
third-party crypto implementation**: only `getrandom`, `subtle`, and `zeroize`
(plus `libc` on Unix). ChaCha20 (via `rand_chacha`), Salsa20, `ring`, and stock
RustCrypto appear only in dev-dependencies as benchmark/interop/timing
baselines - and CI fails the
build if any of them ever enters a production graph.

## Where this code comes from

The cryptographic cores are vendored, with minimal adaptation, from the
[RustCrypto](https://github.com/RustCrypto) project and from
[`rand_aes`](https://github.com/hasenbanck/rand_aes):

- The GHASH authenticator is the RustCrypto
  [`ghash` 0.5.1](https://github.com/RustCrypto/universal-hashes) GHASH-to-POLYVAL
  mapping over the [`polyval` 0.6.2](https://github.com/RustCrypto/universal-hashes)
  hardware backends (PCLMULQDQ on x86/x86_64, PMULL on aarch64).
- The AES-256 key expansion and block encryption paths, and the AES-256-CTR
  generator backend, are adapted from `rand_aes` 0.7.0's AES-NI and ARMv8
  hardware backends.
- The AES-GCM composition (J0 construction, CTR keystream, length-block
  authentication, tag handling) follows NIST SP 800-38D and the RustCrypto
  [`aes-gcm`](https://github.com/RustCrypto/AEADs) crate's design.
- The AES-256-GCM-SIV composition (per-nonce key derivation, POLYVAL over the
  same carryless-multiply backend, SIV tag and little-endian CTR) follows
  RFC 8452 and the RustCrypto
  [`aes-gcm-siv`](https://github.com/RustCrypto/AEADs) crate's design. POLYVAL is
  the field operation the vendored backend computes natively; the GHASH path is
  the byte-reversed adaptation of it.

Exact upstream versions, commit SHAs, copyright holders, licenses, and the
modifications made are recorded in [NOTICE](NOTICE).

### Upstream audit history

The RustCrypto `aes-gcm` crate and its dependencies (including the AES
implementations and the POLYVAL authenticator this repository's GHASH backend
derives from) received a
[security audit by NCC Group](https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/)
in February 2020, funded by MobileCoin, with no significant findings. The
audit specifically noted that the implementations use the recommended
techniques for constant-time execution.

To be precise about what that means here: the audit covered the upstream
crates as they existed at the time, not this fork. What this repository
inherits is the audited design and backend structure; what it changes is
subtractive (removing the software fallback and runtime dispatch). Parity with
the audited lineage is enforced mechanically by the test suite described
below, and `ring` - an independently developed, BoringSSL-derived
implementation that is among the most widely deployed crypto code anywhere -
is used as a second cross-validation oracle.

## What was removed, and why

This is a strict subset of the upstream functionality: AES-256-GCM and
AES-256-GCM-SIV with 96-bit nonces, plus AES-256-CTR key generation. The
deliberate deletions are:

- The fixsliced software AES fallback (and its state: 960 bytes of software
  round keys plus batch buffers, versus 240 bytes of hardware key schedule).
- The runtime autodetection enum and boxed dispatch state that let one type
  hold either a hardware or software backend.
- Every code path that could silently fall back to table-based or bitsliced
  software AES.

The motivation is the cached-key tier of applications that hold many keys resident: cached key-equivalent state
should be as small as a hardware key schedule actually needs
(`HardwareAes256Gcm` state is 368 bytes: 15 AES round keys plus eight
precomputed GHASH key powers), should fit guarded-memory placement policies,
and should never be able to *be* a software AES state. If the required CPU
features are absent, construction fails with a typed error instead of
degrading.

## Why this is safe to use in place of `ring` or RustCrypto directly

1. **Every secret-dependent operation executes in hardware.** AES rounds use
   AES-NI (`AESENC`/`AESENCLAST`) on x86_64 and the ARMv8 Cryptographic
   Extensions (`AESE`/`AESMC`) on aarch64. GHASH's GF(2^128) multiplication
   uses carryless multiply (`PCLMULQDQ` / `PMULL`). These instructions have no
   key- or data-dependent timing, no table lookups at secret-dependent
   addresses, and no secret-dependent branches - the classic AES cache-timing
   attack surface does not exist in this code because the S-box never touches
   memory. Tag comparison is constant-time via the `subtle` crate. The Rust
   glue performs no secret-dependent branching or indexing.
2. **Wire-format compatibility is proven, not assumed.** Both AEAD modes are
   held to the same bar:
   - **AES-256-GCM** produces byte-identical ciphertext to RustCrypto `aes-gcm`,
     cross-decrypts in both directions with both `aes-gcm` and `ring`, matches
     NIST SP 800-38D known-answer vectors, and passes the **Project Wycheproof**
     AES-256-GCM suite (66 vectors: 39 valid, 27 tag-rejection).
   - **AES-256-GCM-SIV** matches the **RFC 8452 Appendix C.2** known-answer
     vectors, byte-matches RustCrypto `aes-gcm-siv`, and passes the **Project
     Wycheproof** AES-256-GCM-SIV suite (103 vectors, including 5 counter-wrap
     and 34 tag-rejection cases).
   - Both survive randomized differential sweeps and dense length sweeps across
     plaintext *and* AAD sizes (every length 0..=288 across the GHASH/POLYVAL
     aggregation seams), reject every single-bit tampering of ciphertext, tag,
     nonce, and AAD across many sizes, and reject wrong key / nonce / AAD over
     hundreds of random trials.
   - Both decrypt paths carry **dudect-style constant-time timing harnesses**
     (Welch t-test): tag-comparison timing is independent of mismatch position
     and decrypt timing is independent of ciphertext content (`|t|` far below
     threshold for both modes; see [docs/constant-time.md](docs/constant-time.md)).
   - The AES-CTR generator is checked against FIPS-197 vectors independently
     verified with OpenSSL.
   - Wycheproof vectors are vendored verbatim (downloaded, not transcribed;
     Apache-2.0, see `NOTICE`) and are dev-only - absent from the production
     dependency graph.
3. **Hardware support is verified, never guessed.** Construction checks CPU
   features at runtime and returns `UnsupportedCpu` before accepting key
   material, and CI asserts the hardware paths are actually exercised so a
   green build cannot mean "tests silently skipped".
4. **Key material lifecycle is explicit.** Key state zeroizes on drop (owned
   and caller-placed), encryption and decryption can target caller-controlled
   buffers (`encrypt_to`/`decrypt_to`) so decrypted keys never sit in
   unmanaged heap allocations, and the key generators detect process forks
   and reseed on interval.
5. **Nonce uniqueness is the library's job by default.** GCM is catastrophic
   on nonce reuse, so `encrypt`/`encrypt_to` generate a unique 96-bit nonce per
   call - a per-instance 64-bit counter over a 96-bit salt drawn **always from
   the OS** and re-salted on fork - and append it to the ciphertext as
   `ciphertext || tag || nonce`. `decrypt`/`decrypt_to` parse the nonce only
   from that envelope. The same default envelope shape applies to AES-GCM-SIV;
   SIV additionally degrades gracefully under accidental reuse (identical
   `(nonce, key, message)` tuples produce identical ciphertext, but reuse does
   not leak the authentication key or earlier plaintexts the way GCM does).
   Low-level caller-supplied-nonce entry points for both modes are kept behind
   the non-default `hazmat-explicit-nonce` feature for test vectors,
   interoperability work, and benchmark investigations.

## Why hardware-only is the right default in production

AES-NI and PCLMULQDQ have shipped in effectively every x86_64 server CPU
since Intel Westmere (2010) and AMD Bulldozer (2011). The ARMv8 Cryptographic
Extensions are present on every mainstream aarch64 server and client part -
AWS Graviton, Ampere, Apple Silicon. A production fleet in 2026 that lacks
these instructions essentially does not exist; the software fallback in
general-purpose crypto libraries serves hardware we do not run, while costing
cached key-state size and a larger audit surface. The silent-fallback risk is
not hypothetical: a default build of stock `aes-gcm` on aarch64 quietly runs
*software* AES and POLYVAL unless every consumer passes
`RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"` - measured at roughly 8x
slower, with nothing failing and nothing warning (see
[docs/benchmarks.md](docs/benchmarks.md)). Making hardware support a hard,
typed requirement converts that silent risk into a loud startup failure.

`ring` remains in the repository as an interop and benchmark baseline.

## Commands

```sh
# Tests (interop, KATs, differential sweeps, lifecycle) and lints:
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

# Hardware sanity check and key-state footprint report:
cargo run --example assert_hardware
cargo run --release --example state_size

# Benchmarks (see docs/benchmarks.md for both RustCrypto configurations):
cargo bench --bench aes_gcm
cargo bench --bench aes_gcm_siv
cargo bench --bench random

# Constant-time verification (manual; see docs/constant-time.md):
cargo test --release --test timing_constant_time -- --ignored --nocapture
cargo test --release --test timing_constant_time_siv -- --ignored --nocapture

# Machine-checked field-arithmetic proofs (GHASH/POLYVAL core; see proofs/):
pip install z3-solver sympy
./proofs/run_all.sh

# Full-lifecycle Miri over the AES-256-GCM/SIV key-state paths (x86):
cargo +nightly miri test --lib aes_gcm
```

See [docs/design.md](docs/design.md) for the implementation plan.
See [docs/benchmarks.md](docs/benchmarks.md) for locally measured numbers and
how to reproduce them.
See [docs/constant-time.md](docs/constant-time.md) for the emitted-assembly
inspection procedure and the dudect-style timing harness.
See [docs/proof-coverage.md](docs/proof-coverage.md) for the proof-coverage map:
every verified property, by method, at an explicit trust level (compiled-code
proof / all-inputs model proof / exhaustive vectors / tooling), in one table.
See [docs/assurance.md](docs/assurance.md) for the full assurance narrative: the
test/proof layers in place, the machine-checked GHASH/POLYVAL proofs
([proofs/](proofs/)), Miri/Valgrind/sanitizer coverage, and what an independent
audit or CAVP/CMVP validation would still add.
See [docs/randomness-testing.md](docs/randomness-testing.md) for the RNG
statistical-test battery (PractRand/dieharder) and how to reproduce it.
See [docs/security-audit.md](docs/security-audit.md) for the multi-model
agentic security assessment (threat model, findings, standards conformance,
and residual-risk register).

## Acknowledgments

This work exists because of the [RustCrypto](https://github.com/RustCrypto)
project and its maintainers, whose carefully engineered, audited, and openly
licensed implementations of AES-GCM, GHASH, and POLYVAL form the foundation of
this repository - our sincere thanks to them for years of rigorous work that
the wider Rust ecosystem builds on. Thanks also to Nils Hasenbanck for
[`rand_aes`](https://github.com/hasenbanck/rand_aes), whose clean hardware
AES-CTR backends this repository adapts, and to NCC Group and MobileCoin for
the public audit of the RustCrypto AEAD stack. See [NOTICE](NOTICE) for
formal attribution.
