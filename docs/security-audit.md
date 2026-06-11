# Security Assessment - hardware-rust-crypto

**Multi-Model Agentic Cryptographic Review**

---

## Document control

| Field | Value |
| --- | --- |
| **Title** | Security Assessment of the `hardware-rust-crypto` AES-256-GCM and key-generation primitives |
| **Target** | `hardware-rust-crypto` workspace - `hardware-aes-gcm`, `hardware-random` |
| **Version reviewed** | git `71396df` (branch `pr-1-review`, PR #1) |
| **Assessment type** | Multi-model agentic cryptographic source review with differential, statistical, and assembly-level verification |
| **Assessment date** | 2026-06-11 |
| **Toolchain** | rustc 1.96.0; crate MSRV 1.88; edition 2021 |
| **Platforms** | `x86_64` (AES-NI, PCLMULQDQ, RDSEED); `aarch64` (ARMv8 AES, PMULL, FEAT_RNG) |
| **Classification** | Internal / pre-integration |
| **Status** | Initial |

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Scope and limitations](#2-scope-and-limitations)
3. [Methodology](#3-methodology)
4. [Threat model](#4-threat-model)
5. [System overview](#5-system-overview)
6. [Findings](#6-findings)
7. [Cryptographic construction analysis](#7-cryptographic-construction-analysis)
8. [Constant-time and side-channel analysis](#8-constant-time-and-side-channel-analysis)
9. [Memory safety and `unsafe` review](#9-memory-safety-and-unsafe-review)
10. [Dependency and supply-chain assessment](#10-dependency-and-supply-chain-assessment)
11. [Test coverage assessment](#11-test-coverage-assessment)
12. [Standards conformance matrix](#12-standards-conformance-matrix)
13. [Residual risk register](#13-residual-risk-register)
14. [Recommendations](#14-recommendations)
15. [Conclusion](#15-conclusion)
- [Appendix A - Rating methodology](#appendix-a---rating-methodology)
- [Appendix B - Verification performed and captured evidence](#appendix-b---verification-performed-and-captured-evidence)
- [Appendix C - References](#appendix-c---references)
- [Appendix D - Glossary](#appendix-d---glossary)

---

## 1. Executive summary

`hardware-rust-crypto` is a small, hardware-only cryptographic primitive set
intended to replace `ring`/RustCrypto in a cached-key tier that holds many keys resident. It
provides AES-256-GCM authenticated encryption (`hardware-aes-gcm`) and
AES-256-CTR key/nonce generation (`hardware-random`). Its defining design
decision is the deliberate removal of all software cipher fallback: AES rounds
and GF(2^128) multiplication execute exclusively as CPU instructions (AES-NI /
PCLMULQDQ on `x86_64`; ARMv8 AES / PMULL on `aarch64`), and the implementation
fails closed with a typed error where the hardware is absent.

The codebase comprises approximately **3,961 lines of Rust** across two
production crates, a large fraction of it necessarily `unsafe` (SIMD intrinsics
and in-place initialization). The cryptographic cores are adapted from audited
upstreams (`ghash`/`polyval` from RustCrypto; AES backends from `rand_aes`)
with provenance recorded in `NOTICE`.

### 1.1 Overall assessment

Within the threat model of section 4 and the scope of section 2, the implementation is
**well-constructed and the cryptographic constructions are sound as reviewed.**
AES-256-GCM output was verified byte-identical to two independent
implementations - RustCrypto `aes-gcm` 0.10 and `ring` 0.17 - across a dense
differential corpus, and against NIST Special Publication 800-38D known-answer
vectors. The `unsafe` surface is uniformly documented with `SAFETY:`
justifications and the memory-safety arguments hold under review. **No critical
or high-severity vulnerability was identified.** Constant-time behavior of the
authentication path was confirmed both by emitted-assembly inspection and by a
statistical (dudect) timing test.

The remaining findings are characteristic of any AES-GCM deployment and of an
un-certified library, and are dominated by integrator responsibilities and
assurance residuals rather than implementation defects.

### 1.2 Findings summary

| ID | Title | Risk | Status |
| --- | --- | --- | --- |
| [HRC-2026-01](#hrc-2026-01---aes-gcm-nonce-uniqueness-and-invocation-limits-are-not-enforced) | AES-GCM nonce uniqueness and invocation limits are not enforced | **Medium** | Mitigation available |
| [HRC-2026-02](#hrc-2026-02---cpu-rng-only-reseed-narrows-post-compromise-recovery-to-the-cpu-vendor) | CPU-RNG-only reseed narrows post-compromise recovery to the CPU vendor | **Low** | Open (residual) |
| [HRC-2026-03](#hrc-2026-03---rng-health-test-is-not-sp-800-90b-conformant) | RNG health test is not SP 800-90B-conformant | **Low** | Open |
| [HRC-2026-04](#hrc-2026-04---unsafeffi-soundness-is-not-tool-verified) | Unsafe/FFI soundness is not tool-verified | **Low** | Open (residual) |
| [HRC-2026-05](#hrc-2026-05---constant-time-assurance-is-empirical-not-formal) | Constant-time assurance is empirical, not formal | **Low** | Open (residual) |
| [HRC-2026-06](#hrc-2026-06---ephemeral-stack-and-register-copies-of-key-material-are-not-wiped) | Ephemeral stack/register copies of key material are not wiped | Info | Open (inherent) |
| [HRC-2026-07](#hrc-2026-07---drop-based-zeroization-is-defeated-by-memforget-and-leaks) | Drop-based zeroization is defeated by `mem::forget`/leaks | Info | Open (inherent) |
| [HRC-2026-08](#hrc-2026-08---no-wycheproof-or-formal-coverage-of-ghash-aggregation-edge-cases) | No Wycheproof or formal coverage of GHASH aggregation edge cases | **Low** | Open |
| [HRC-2026-09](#hrc-2026-09---independent-review-and-cavp-validation-not-yet-performed) | Independent review and CAVP validation not yet performed | Info | Open |

**Risk distribution:** 0 Critical / 0 High / 1 Medium / 4 Low / 4 Informational.

All workspace status checks (format, Clippy `-D warnings`, tests, docs,
dependency audit) are green at the reviewed commit on both CI architectures
(`x86_64` Linux, `aarch64` macOS).

---

## 2. Scope and limitations

This is a multi-model agentic cryptographic review: source analysis combined
with execution of the project's verification tooling and independent
differential, statistical, and assembly-level cross-checks (section 3). Findings are
cross-checked across models; reviewers should re-run the verification commands
in [Appendix B](#appendix-b---verification-performed-and-captured-evidence) and
apply their own judgment.

- **It is a source-level cryptographic review**, not an accredited
  certification. Nothing here constitutes FIPS 140-3 validation, CAVP algorithm
  validation, or Common Criteria evaluation. Where conformance to a NIST or
  IETF specification is asserted, it means "the construction follows the cited
  specification as verified by source review and differential/known-answer
  testing," not "validated by an accredited laboratory."
- **Scope is the two production crates and their direct support code.** Out of
  scope: the consuming application, the eventual FFI integration, build/release
  infrastructure beyond the committed CI workflow, and the development host.
- **It is a point-in-time review** of git `71396df`.

Ratings follow the methodology in [Appendix A](#appendix-a---rating-methodology).

---

## 3. Methodology

The review combined manual source analysis with execution of the project's
tooling and independent cross-checks.

**Manual review passes** (iterative; each from a distinct angle): cryptographic
construction conformance; memory safety and `unsafe`/FFI soundness;
constant-time / side-channel behavior; key-material lifecycle (placement,
zeroization, fork safety); API contract / type-state / misuse resistance;
dependency and supply-chain posture; adversarial input handling and resource
bounds.

**Dynamic and differential verification** (commands and captured output in
[Appendix B](#appendix-b---verification-performed-and-captured-evidence)):

- Byte-for-byte differential testing against RustCrypto `aes-gcm` 0.10 and
  `ring` 0.17 (encryption equality and cross-decryption both directions).
- NIST SP 800-38D known-answer vectors (zero-key/zero-nonce, empty and 16-byte
  plaintext).
- AES-256-CTR keystream cross-checked against OpenSSL AES-256-ECB.
- Emitted-assembly inspection of secret-handling paths (`cargo-show-asm`).
- A dudect-style statistical timing test (Welch's t-test) over decryption.
- Dependency vulnerability scan (`cargo audit`).

**Standards consulted:** FIPS 197; NIST SP 800-38A, 800-38D, 800-90A Rev. 1,
800-90B, 800-133 Rev. 2; FIPS 140-3 (terminology / non-conformance scoping);
RFC 5116, 5288, 8452. Report structure follows publicly available
cryptographic review deliverables, including the NCC Group review of the
RustCrypto AEAD crates (2020, MobileCoin-funded) - the direct lineage of this
code's GHASH/POLYVAL paths - and the general format of NCC Group, Trail of
Bits, and Cure53 reports and OSTIF-coordinated open-source crypto audits.

---

## 4. Threat model

### 4.1 Assets

- **Long-lived key material**: AES-256 system/intermediate/data-row keys
  cached in the consuming application's memory tiers.
- **Key-equivalent state**: expanded AES round keys and GHASH key powers.
- **CSPRNG state**: AES-CTR generator seeds and counters.
- **Plaintext**: data-encryption-key material and protected records.

### 4.2 Security goals

1. Confidentiality and integrity of AES-256-GCM-protected data
   (IND-CPA + INT-CTXT).
2. Wire interoperability with existing AES-256-GCM ciphertexts (the nonce-appended layout
   `ciphertext || tag || nonce`).
3. Reduced side-channel surface versus table-based software AES.
4. Minimal, caller-placeable, zeroizable key-state footprint.
5. Generator hygiene: reseeding, fork detection, no duplicate keystreams.

### 4.3 Adversaries

| ID | Adversary | In scope |
| --- | --- | --- |
| A1 | Network / chosen-ciphertext: submits crafted ciphertext/tag/AAD/nonce to decryption seeking forgery or recovery | Yes |
| A2 | Co-resident timing: measures operation timing to recover key material | Yes (software/cache timing); transient-execution attacks **out** |
| A3 | Malicious/defective hardware RNG | Yes (reseed path) |
| A4 | Process-image: reads memory post-compromise or inherits state across `fork`/snapshot | Partial (zeroization, fork detection); live full-memory compromise **out** |

### 4.4 Explicitly out of scope

Spectre/Meltdown and other transient-execution / micro-architectural data
sampling; physical attacks (power/EM, fault injection, cold-boot); the
correctness of the AES/CLMUL/PMULL silicon (trusted vendor primitive - see
[HRC-2026-05](#hrc-2026-05---constant-time-assurance-is-empirical-not-formal));
and nonce-generation *policy* at the integration layer (the library emits uniform
random bytes; uniqueness discipline is the integrator's - see
[HRC-2026-01](#hrc-2026-01---aes-gcm-nonce-uniqueness-and-invocation-limits-are-not-enforced)).

---

## 5. System overview

```
hardware-rust-crypto (workspace facade, src/lib.rs)
|-- hardware-aes-gcm            AES-256-GCM, hardware-only
|   |-- lib.rs    public API; GCM composition (J0, CTR, GHASH glue, tag)
|   |-- aes.rs    AES-256 key expansion + 1-/8-block encryption (NI / ARMv8)
|   |-- ghash.rs  GHASH->POLYVAL, CLMUL/PMULL, 4-block aggregated reduction
|   |-- nonce.rs  generated-nonce sequence (96-bit OS salt + 64-bit counter)
|   `-- fork.rs   pthread_atfork generation counter (nonce re-salt)
`-- hardware-random            key/nonce generation
    |-- lib.rs    AES-CTR generator; reseed, fork detection
    |-- aes_ctr.rs  AES-256-CTR-128 backend (NI / ARMv8)
    |-- entropy.rs  CPU-RNG (RDSEED / RNDRRS) + stuck-output screen
    `-- fork.rs     pthread_atfork generation counter
```

### 5.1 Encryption data flow

```
key (32B) --> KeyState::init_in_place
                 |- aes::Aes256::init_in_place          (expand round keys)
                 `- H = E(K, 0^128) --> GHashKey         (derive POLYVAL H^1..H^4)
nonce(12B),aad,plaintext --> seal()
                 J0 = nonce || 0^31 || 1
                 mask = E(K, J0)
                 for each 128B batch:  C = P XOR AES-CTR(inc32(J0)...)   (8-way)
                                       GHASH <- C                      (4-block agg.)
                 S = GHASH(aad, C, lengths)
                 tag = S XOR mask
                 out = C || tag                          (|| nonce in the nonce-appended layout)
```

### 5.2 Production dependency graph (verified minimal)

- `hardware-aes-gcm` -> `subtle` 2.6.1, `zeroize` 1.8.2, `getrandom` 0.3.4
  (nonce salt), `libc` 0.2 (Unix; fork detection)
- `hardware-random` -> `getrandom` 0.3.4, `zeroize` 1.8.2, `libc` 0.2 (Unix)

No software cipher and no third-party cryptographic *implementation* appears in
either production graph. `ring`, RustCrypto `aes-gcm`, `rand_chacha`, and
`salsa20` are dev-dependencies only, used as benchmark/interop/timing
baselines. A CI step fails the build if a forbidden crate enters a production
graph.

---

## 6. Findings

Each finding states an overall **Risk** plus the **Impact** and
**Exploitability** components ([Appendix A](#appendix-a---rating-methodology)),
a CVSS 3.1 reference where one is meaningful, the affected **Location**,
**Evidence**, an **Impact** analysis, and a **Recommendation**.

---

### HRC-2026-01 - AES-GCM nonce uniqueness and invocation limits are not enforced

| | |
| --- | --- |
| **Risk** | Medium |
| **Impact** | High (on misuse) |
| **Exploitability** | Low (requires integrator misuse) |
| **CVSS 3.1** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` -> 7.4 (conditional impact; see note) |
| **Category** | Cryptography - key/IV management |
| **Status** | Open on the caller-supplied-nonce API; a generated-nonce API provides a safe alternative |
| **Location** | `crates/hardware-aes-gcm/src/lib.rs` - `nonce_from_slice`, `validate_gcm_lengths`, public caller-supplied `encrypt*` APIs; mitigation in `nonce.rs` |

**Description.** AES-GCM is catastrophically fragile to nonce reuse under a
fixed key. Two messages encrypted with the same `(key, nonce)` pair leak the
XOR of their plaintexts and, more seriously, allow recovery of the GHASH
authentication subkey `H`, enabling universal forgery for that key. AES-GCM is
also bounded in the number of invocations per key: for randomly generated
96-bit IVs, NIST SP 800-38D section 8.3 limits a key to roughly 2^32 invocations to
keep the IV-collision probability acceptably low.

The library validates nonce *length* but performs no uniqueness tracking and
enforces no per-key invocation counter. This matches the contract of `ring`
and RustCrypto (a low-level primitive defers nonce management to the caller),
but it means an integrator who generates random 96-bit nonces at high volume,
or who reuses a nonce through a bug, receives no signal before the security
property is lost.

**Evidence.** The caller-supplied-nonce path validates length only
(`nonce_from_slice` in `crates/hardware-aes-gcm/src/lib.rs`):

```rust
fn nonce_from_slice(nonce: &[u8]) -> Result<[u8; NONCE_SIZE], Error> {
    nonce.try_into().map_err(|_| Error::InvalidNonceLength)
}
```

`encrypt(nonce, aad, plaintext)` accepts any 12-byte value with no uniqueness
or invocation-count check.

**Impact.** If the integration layer reuses a `(key, nonce)` pair, an A1
adversary observing two ciphertexts can recover `H` and forge arbitrary
authenticated ciphertexts under that key, and can recover plaintext XOR. The
CVSS base of 7.4 reflects this *conditional* impact; the assessed Risk is
**Medium**, not High, because exploitation requires an integration defect and
correct usage avoids it. This divergence is a known limitation of CVSS for
secure-by-default API gaps.

**Mitigation.** The library provides generated-nonce APIs -
`encrypt_with_generated_nonce` and `encrypt_nonce_appended_generated`
(`crates/hardware-aes-gcm/src/nonce.rs`) - that own nonce uniqueness so the
caller cannot reuse one. The construction is `nonce = (salt + counter) mod
2^96`, with `salt` a 96-bit value drawn from the OS (re-drawn on fork) and
`counter` a per-instance 64-bit value (see section 7.6). Within an instance
uniqueness is guaranteed; across instances the residual is a sub-random 96-bit
base-range overlap. This *prevents* reuse but, being plain AES-GCM, does not
*survive* it - a call site that cannot guarantee unique nonces still needs a
misuse-resistant mode. The caller-supplied-nonce path is unenforced, so the
finding is open for that path.

**Recommendation.**
1. For call sites that do not need to control the nonce, default to the
   generated-nonce APIs.
2. Document the nonce-uniqueness contract and the SP 800-38D section 8.3 per-key
   invocation limit prominently on the caller-supplied-nonce API, with the
   failure mode stated explicitly.
3. Where a deterministic nonce is required, use the SP 800-38D section 8.2.1
   construction or rotate keys before 2^32 invocations.
4. Consider offering an AES-GCM-SIV (RFC 8452) misuse-resistant mode for call
   sites that cannot guarantee uniqueness at all.

---

### HRC-2026-02 - CPU-RNG-only reseed narrows post-compromise recovery to the CPU vendor

| | |
| --- | --- |
| **Risk** | Low |
| **Impact** | Medium |
| **Exploitability** | Low (requires prior state compromise + malicious CPU RNG) |
| **CVSS 3.1** | `AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N` -> ~4.4 (conditional) |
| **Category** | Cryptography - RNG / reseeding |
| **Status** | Open (residual) |
| **Location** | `crates/hardware-random/src/lib.rs` - `reseed` (L386), `reseed_blend` (L422); `crates/hardware-random/src/entropy.rs` |

**Description.** When `cpu-rng-reseed` is enabled (default) and a CPU hardware
RNG is present, reseeds draw exclusively from the CPU RNG, blended through the
current secret state; the OS entropy source is not consulted on reseed. Because
the blend incorporates prior state, a *weak-but-live* CPU RNG cannot reduce
security below "no reseed" (see section 7.4). However, *recovery from a state
compromise* then depends on the CPU RNG contributing genuine fresh entropy. A
fully malicious CPU RNG combined with a prior state leak (A3 + A4) defeats
recovery - an unavoidable "both sources bad" case - but a CPU-RNG-only reseed
schedule narrows the recovery guarantee to a single vendor's TRNG.

**Evidence.** The reseed path consults the CPU RNG and only falls back to the
OS when it is unavailable or the draw is screened out:

```rust
// crates/hardware-random/src/lib.rs:386
fn reseed(&mut self) -> Result<(), Error> {
    let mut entropy_input = Zeroizing::new([0_u8; AES_CTR_SEED_SIZE]);
    if entropy::cpu_rng_fill(entropy_input.as_mut()) {
        self.reseed_blend(&entropy_input);          // CPU RNG path
    } else {
        fill_from_os(entropy_input.as_mut())?;      // OS fallback only
        self.reset_from_seed(&entropy_input)?;
    }
    ...
}
```

**Impact.** Limited. Initial seeding is always from the OS (so every chain is
rooted in a full-entropy seed), and the blend (section 7.4) means a degraded CPU RNG
cannot weaken a non-compromised state. The residual is confined to
post-compromise recovery speed/assurance under a hostile CPU RNG.

**Recommendation.** Add a periodic forced OS reseed (e.g., every Nth reseed or
on a wall-clock interval) so recovery never depends solely on the CPU RNG. At
the default 1 GiB reseed interval the cost is negligible.

---

### HRC-2026-03 - RNG health test is not SP 800-90B-conformant

| | |
| --- | --- |
| **Risk** | Low |
| **Impact** | Low |
| **Exploitability** | Low |
| **CVSS 3.1** | N/A (assurance/compliance gap) |
| **Category** | Cryptography - entropy source health |
| **Status** | Open |
| **Location** | `crates/hardware-random/src/entropy.rs` - `stuck_output` (L62), `cpu_rng_fill` (L32) |

**Description.** Each CPU-RNG draw is screened for stuck output by rejecting any
draw containing two identical 64-bit words - the granularity at which
RDSEED/RNDRRS return data. This catches all-zero, all-ones, constant-word, and
short-period sources, and is conceptually a continuous repetition test. NIST SP
800-90B section 4.4 requires both a Repetition Count Test (section 4.4.1) and an Adaptive
Proportion Test (section 4.4.2), with cutoffs derived from the source's assessed
min-entropy, plus start-up testing. The implemented screen has no APT (so it
will not detect a source biased but not stuck), no min-entropy-derived cutoff,
and no startup self-test; it is therefore not an SP 800-90B-conformant
health-test suite.

**Evidence.**

```rust
// crates/hardware-random/src/entropy.rs:62
fn stuck_output(buf: &[u8]) -> bool {
    let mut outer = 0_usize;
    while outer + 8 <= buf.len() {
        let word = &buf[outer..outer + 8];
        let mut inner = outer + 8;
        while inner + 8 <= buf.len() {
            if &buf[inner..inner + 8] == word { return true; }
            inner += 8;
        }
        outer += 8;
    }
    false
}
```

**Impact.** Low. The CPU RNG is never the sole entropy source (initial seed is
the OS), and the reseed blend (section 7.4) neutralizes a weak-but-live source, so the
screen only needs to catch gross failure (a dead/stuck source contributing zero
entropy) - which it does. Subtle bias is mitigated architecturally rather than
detected.

**Recommendation.** Document the screen precisely as "continuous stuck-output
detection, not SP 800-90B validation." If SP 800-90B conformance becomes a
requirement, add an APT and startup self-tests with cutoffs matched to the
assessed source min-entropy.

---

### HRC-2026-04 - Unsafe/FFI soundness is not tool-verified

| | |
| --- | --- |
| **Risk** | Low |
| **Impact** | High (if latent UB existed) |
| **Exploitability** | Low (no evidence of UB; differential corpus would surface most corruption) |
| **CVSS 3.1** | N/A (assurance gap) |
| **Category** | Memory safety - assurance |
| **Status** | Open (residual) |
| **Location** | `crates/hardware-aes-gcm/src/{aes,ghash,lib}.rs`; `crates/hardware-random/src/{aes_ctr,entropy,lib}.rs` |

**Description.** The crates contain a substantial `unsafe` surface
([section 9](#9-memory-safety-and-unsafe-review)). Miri cannot execute AES/PMULL
intrinsics, inline assembly, or `is_*_feature_detected!`, so the `unsafe` paths
are not Miri-checked, and CI runs no sanitizer or Valgrind pass. Soundness is
therefore argued by review and validated only indirectly by the differential
corpus (which would surface most memory-corruption regressions as output
mismatches or crashes).

**Evidence.** Every `unsafe` block carries a `SAFETY:` comment and the
soundness-critical patterns were reviewed (write-before-read in-place init;
raw-pointer-plus-`PhantomData` aliasing model; runtime-feature-gated
intrinsics). No defect was found, but no tool independently proves the absence
of UB.

**Impact.** A latent unsafe-Rust defect (out-of-bounds, aliasing violation,
uninitialized read) could in principle cause memory corruption or information
disclosure. None was identified; this finding records the *assurance gap*, not
a known vulnerability.

**Recommendation.** Add a Miri job covering the architecture-independent logic
(length checks, buffer handling, the stuck-output screen, the fork guard),
optionally behind a cfg that stubs the intrinsics with a scalar reference path
used only under Miri.

---

### HRC-2026-05 - Constant-time assurance is empirical, not formal

| | |
| --- | --- |
| **Risk** | Low |
| **Impact** | High (if a leak existed) |
| **Exploitability** | Low (no leak found; requires co-residency) |
| **CVSS 3.1** | N/A (assurance/residual) |
| **Category** | Cryptography - side channel |
| **Status** | Open (residual) |
| **Location** | `crates/hardware-aes-gcm/src/lib.rs` - `constant_time_eq` (L887); `crates/hardware-aes-gcm/src/ghash.rs` - `mulx` (L201) |

**Description.** The constant-time guarantee rests on three pillars
(documented in `docs/constant-time.md`): (1) the *accepted* vendor guarantee
that AES and carryless-multiply instructions are data-independent in timing -
the same trust boundary `ring`/RustCrypto rely on; on ARMv8.4+ the formal
guarantee is gated by `PSTATE.DIT`, which this library does not set; (2)
absence of secret-dependent control flow, verified by review and assembly
inspection; (3) compiler non-interference, defended by `subtle` and
`core::hint::black_box` barriers. None of these is a machine-checked proof, and
the statistical test is machine-sensitive and not CI-gated.

**Evidence.** Tag comparison is constant-time via `subtle`; the one scalar
secret-dependent operation (`mulx`'s carry fold) is barriered:

```rust
// crates/hardware-aes-gcm/src/lib.rs:887
fn constant_time_eq(expected: &[u8; TAG_SIZE], actual: &[u8]) -> bool {
    expected.as_slice().ct_eq(actual).into()
}
// crates/hardware-aes-gcm/src/ghash.rs:201
fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = core::hint::black_box(v >> 127);   // barrier: no 0/1 specialization
    ...
}
```

Emitted-assembly inspection and a dudect test confirm the property
empirically (section 8, Appendix B): the tag-mismatch-position test is stable at
|t| ~ 0.7, two orders of magnitude below the |t| ~ 267 an early-exit
comparison produces.

**Impact.** If a future compiler or code change introduced a secret-dependent
branch undetected, a co-resident A2 adversary could in principle recover key
or tag bits. No such leak exists at the reviewed commit.

**Recommendation.** Retain the assembly inspection and dudect procedures and
re-run them on compiler upgrades. Consider setting `PSTATE.DIT` around crypto
sections on `aarch64` once stable intrinsics exist. Transient-execution
attacks remain out of scope by design.

---

### HRC-2026-06 - Ephemeral stack and register copies of key material are not wiped

| | |
| --- | --- |
| **Risk** | Informational |
| **Category** | Cryptography - key hygiene |
| **Status** | Open (inherent) |
| **Location** | `crates/hardware-aes-gcm/src/ghash.rs` (`mulx` `u128`); SIMD by-value locals across both crates |

**Description.** Long-lived key state is zeroized on drop, but register and
stack spills of key material created by the compiler (e.g., the `u128` in
`mulx`, by-value SIMD locals) cannot be reliably wiped from safe Rust and are
not. This is an inherent limitation, documented as accepted residual in
`docs/design.md`.

**Recommendation.** No action required; documented residual. A full mitigation
would require assembly-level control the project deliberately avoids
([section 9](#9-memory-safety-and-unsafe-review)).

---

### HRC-2026-07 - Drop-based zeroization is defeated by `mem::forget` and leaks

| | |
| --- | --- |
| **Risk** | Informational |
| **Category** | Cryptography - key hygiene |
| **Status** | Open (inherent) |
| **Location** | `Drop` implementations across both crates |

**Description.** Zeroization is implemented in `Drop`. A handle that is
`mem::forget`-ten, leaked (`Box::leak`), or whose owning allocation is never
dropped is never wiped. This is the standard caveat for all drop-based
zeroization in Rust and is not specific to this library.

**Recommendation.** No action required; ensure integration code does not
`forget`/leak key-state handles.

---

### HRC-2026-08 - No Wycheproof or formal coverage of GHASH aggregation edge cases

| | |
| --- | --- |
| **Risk** | Low |
| **Impact** | Medium (a latent aggregation bug would break authentication) |
| **Exploitability** | Low (dense differential corpus already exercises boundaries) |
| **CVSS 3.1** | N/A (test-coverage gap) |
| **Category** | Testing / assurance |
| **Status** | Open |
| **Location** | `tests/aes_gcm_interop.rs`; `crates/hardware-aes-gcm/src/ghash.rs` |

**Description.** The 4-block aggregated GHASH reduction (section 7.2) is novel relative
to the per-block upstream POLYVAL and is the most intricate arithmetic in the
codebase. Its correctness currently rests on differential testing against
RustCrypto/`ring` and NIST KATs - strong evidence, but not a machine-checked
proof, and the well-known Google Project Wycheproof AES-GCM vectors (which
target truncated tags, oversized inputs, and special-value nonces) are not
integrated.

**Evidence.** The dense differential sweep exercises the aggregation/batch
boundaries:

```rust
// tests/aes_gcm_interop.rs (dense_length_sweep_matches_rustcrypto)
let lengths = (0..=288_usize).chain([511,512,513,1023,1024,1025,4095,4096,4097]);
```

**Impact.** A latent aggregation defect would manifest as authentication
failure or, worst case, a tag that validates incorrectly. The boundary-dense
differential corpus makes an undetected defect unlikely but does not formally
exclude one.

**Recommendation.** Integrate Project Wycheproof AES-GCM vectors and add
property-based (`proptest`) round-trip and decrypt-parser tests. Consider a
formal or computer-algebra check of the aggregation identity (section 7.2).

---

### HRC-2026-09 - Independent review and CAVP validation not yet performed

| | |
| --- | --- |
| **Risk** | Informational |
| **Category** | Process / assurance |
| **Status** | Open |

**Description.** The library has not received an independent third-party
cryptographic review or CAVP/CMVP algorithm validation. This is expected for a
pre-integration primitive but is a precondition many deployments require before
a library protects production data.

**Recommendation.** Obtain independent third-party cryptographic review and,
where the regulatory posture requires it, CAVP/CMVP validation before
production deployment.

---

## 7. Cryptographic construction analysis

### 7.1 AES-256-GCM composition (NIST SP 800-38D)

The GCM composition is implemented in `hardware-aes-gcm/src/lib.rs`
(`KeyState::seal`, `tag`, `apply_ctr`) over the AES and GHASH backends.

**Hash subkey.** `H = E(K, 0^128)` is computed at key setup by encrypting a
zero block, then converted into the POLYVAL domain (section 7.2). Conforms to
SP 800-38D section 6.3.

**Pre-counter block J0 (96-bit IV).** Per section 7.1, `J0 = IV || 0^31 || 1`. The code
writes the 12 nonce bytes followed by `0x00000001`:

```rust
// crates/hardware-aes-gcm/src/lib.rs:858
fn j0(nonce: &[u8; NONCE_SIZE]) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..NONCE_SIZE].copy_from_slice(nonce);
    out[15] = 1;
    out
}
```

**Counter.** GCTR increments the rightmost 32 bits modulo 2^32 (`inc32`,
section 6.5), big-endian; verified branch-free (section 8, HRC-2026-05).

**Tag.** `T = MSB_t(GHASH_H(A,C,lens)) XOR E(K, J0)`. The code XORs the encrypted
J0 mask into the GHASH output. Tag comparison on decrypt uses a constant-time
compare and occurs **before** any plaintext is released (verify-before-decrypt;
see section 11 for the timing implication, which is a public outcome, not a leak).

**Length limits.** `MAX_GCM_DATA_LEN = (2^32-2) * 16 = 2^36-32` bytes = exactly the
SP 800-38D section 5.2.1.1 plaintext bound of `2^39-256` bits. AAD and ciphertext are
each bounded to fit the 64-bit GCM length field:

```rust
// crates/hardware-aes-gcm/src/lib.rs:43
const MAX_GCM_DATA_LEN: u64 = ((u32::MAX as u64) - 1) * AES_BLOCK_SIZE as u64;
const MAX_GHASH_INPUT_LEN: u64 = u64::MAX / 8;
```

**Conformance:** the construction conforms to SP 800-38D as reviewed, confirmed
by NIST KATs and byte-for-byte differential equality with two independent
implementations (Appendix B).

### 7.2 GHASH via POLYVAL and the 4-block aggregated reduction

The GHASH backend (`ghash.rs`) vendors the RustCrypto `ghash`->`polyval` mapping
and the CLMUL/PMULL multiply, and adds an aggregated reduction.

**GHASH/POLYVAL mapping.** GHASH operates in GF(2^128) with bit-reflected
ordering; POLYVAL uses the natural ordering. The standard relationship (RFC
8452 Appendix A) is realized by reversing the hash subkey, applying `mulx`
(multiply by `x`) to obtain the POLYVAL key, reversing each input block, and
reversing the final tag. `mulx` is the GF(2^128) doubling with the reduction
polynomial folded in branch-free (HRC-2026-05).

**Aggregated reduction (the novel part).** POLYVAL's per-block update is
`Y_i = (Y_{i-1} XOR X_i) * H`. By Horner's rule over a 4-block batch from
accumulator `Y`:

```
Y' = (Y XOR X1) * H^4  XOR  X2 * H^3  XOR  X3 * H^2  XOR  X4 * H^1
```

Let `W(a,b)` denote the *unreduced* (wide) carryless product and `R` the
Montgomery reduction. Because `W` is bilinear over GF(2) addition (XOR) and `R`
is GF(2)-linear:

```
Y' = R( W(Y XOR X1, H^4) XOR W(X2, H^3) XOR W(X3, H^2) XOR W(X4, H^1) )
```

i.e. the four wide products are XOR-accumulated and reduced **once**. This is
the Gueron-Kounavis aggregated reduction (Intel CLMUL whitepaper) and is
exactly what `update_blocks4_inner` implements, using precomputed key powers
`H^1..H^4` stored in the key state. The implementation precomputes the powers at
setup:

```rust
// crates/hardware-aes-gcm/src/ghash.rs (init_in_place)
let mut h2 = unsafe { imp::mul(&h1, &h1) };  // H^2
let mut h3 = unsafe { imp::mul(&h2, &h1) };  // H^3
let mut h4 = unsafe { imp::mul(&h2, &h2) };  // H^4
```

**Assurance.** Correctness rests on the algebraic identity above plus
byte-exact differential equality against the per-block upstream POLYVAL across
the boundary-dense corpus. It is **not** machine-proven (HRC-2026-08).

### 7.3 AES-256 (FIPS 197) and CTR (SP 800-38A)

Both backends implement AES-256 with the FIPS-197 key expansion (`Rcon`
sequence, `RotWord`/`SubWord`) in vector registers; `SubWord` is computed via
the AES instruction itself (`AESE`/`AESENCLAST` with a zero round key),
eliminating any in-memory S-box. GCM uses only the encryption schedule (correct
for counter mode). The 8-way interleaved CTR encrypts eight independent counter
blocks per batch; independence is structural and equivalence to serial CTR is
confirmed by the differential corpus. The AES-256-CTR keystream was
cross-validated against OpenSSL AES-256-ECB (Appendix B).

### 7.4 AES-CTR DRBG and the reseed blend (relationship to SP 800-90A Rev. 1)

`AesCtrKeyGenerator` is a CTR-mode CSPRNG over AES-256. Its reseed-with-input
path is **modeled on** `CTR_DRBG_Update` (SP 800-90A Rev. 1 section 10.2.1.2):

```
new_seed = AES-CTR_keystream(current secret state) XOR external_entropy
(rekey backend from new_seed)
```

```rust
// crates/hardware-random/src/lib.rs:422
fn reseed_blend(&mut self, cpu_entropy: &[u8; AES_CTR_SEED_SIZE]) {
    let mut seed = Zeroizing::new([0_u8; AES_CTR_SEED_SIZE]);
    for block in seed.chunks_exact_mut(AES_BLOCK_SIZE) {
        let mut keystream = Zeroizing::new([0_u8; AES_BLOCK_SIZE]);
        self.backend.fill_block(&mut keystream);
        block.copy_from_slice(keystream.as_ref());
    }
    for (s, e) in seed.iter_mut().zip(cpu_entropy.iter()) { *s ^= e; }
    ...
}
```

**Security property.** The keystream block is secret (it depends on the current
key, rooted in the original OS seed). An adversary controlling `cpu_entropy`
(A3) cannot force the new seed without also knowing the secret keystream; an
honest CPU RNG makes the new seed fresh even if the prior state had leaked. The
reseed is therefore safe unless **both** the prior state is compromised **and**
the entropy input is adversarial - strictly stronger than trusting either
source alone. This is the correct construction; the residual is HRC-2026-02.

**Non-conformance note.** This *models*, but is not a validated implementation
of, CTR_DRBG. It uses no derivation function for the input, AES-256 with a
128-bit counter rather than the spec's exact seedlen handling, no SP 800-90A
reseed-counter / `reseed_required` state machine, and no DRBG known-answer
self-tests. SP 800-90A conformance would require reimplementation and
validation. For the current threat model (a performance CSPRNG rooted in an OS
seed) the construction is appropriate. Key/nonce draws are fixed-size with no
rejection sampling, consistent with SP 800-133 Rev. 2 (no modulo bias).

### 7.5 Entropy source and health testing (relationship to SP 800-90B)

Initial seeding is always from the OS (`getrandom`). CPU-RNG entropy
(`RDSEED` on `x86_64`; `RNDRRS`/FEAT_RNG on `aarch64`) enters only on reseed,
runtime-detected with bounded retries and OS fallback, and is screened by
`stuck_output` (section HRC-2026-03). The health screen is a pragmatic continuous
stuck-output detector, not the full SP 800-90B RCT+APT suite (HRC-2026-03).

### 7.6 Generated-nonce construction (`nonce.rs`)

For callers that do not supply their own nonce, `encrypt_with_generated_nonce`
and `encrypt_nonce_appended_generated` produce a unique 96-bit nonce as
`nonce = (salt + counter) mod 2^96`:

- `salt` is a 96-bit value drawn from the OS (`getrandom`) only -- never the
  CPU RNG or the AES-CTR generator -- at first use and re-drawn on fork (and on
  the unreachable 2^64 counter wrap).
- `counter` is a per-instance 64-bit value incremented once per nonce.

A fixed random base walked by a sequential counter yields distinct values
within an instance (no collision for up to 2^64 nonces); the random base
differentiates instances across process restart, fork, and hosts. Fork is
detected by the same `pthread_atfork` generation counter used in
`hardware-random` (`fork.rs`), so a forked child re-salts before its next
nonce and never repeats its parent's sequence. The generator state lives on the
handle, not in the placed key state, so the 304-byte key-state footprint is
unchanged (asserted by test).

The residual is the cross-instance base-range overlap: for M instances of n
nonces each it is of order `M^2 * n / 2^96`, below the point-collision rate of
independent random nonces. This construction *prevents* reuse but, being plain
AES-GCM, does not *survive* it; a call site that cannot guarantee unique nonces
at all still requires a misuse-resistant mode (HRC-2026-01).

---

## 8. Constant-time and side-channel analysis

All secret-dependent computation executes either in constant-time hardware
instructions (AES rounds; PMULL/PCLMULQDQ multiply) or in straight-line
XOR/copy loops whose trip counts derive solely from public lengths. The single
secret-derived comparison - tag verification - uses `subtle::ConstantTimeEq`.
Control flow branches only on public values: input/buffer lengths, CPU-feature
availability, and the public accept/reject result.

**Assembly inspection** (Appendix B) of `KeyState::init_in_place` (which
inlines `mulx` and the AES/GHASH setup) confirmed: 213 AES/PMULL instructions
emitted (no scalar AES substitute); the `mulx` carry fold compiles to a
branch-free `eor ... lsl #62/#63/#57` cascade; and the `black_box` barrier is
present (two `InlineAsm` markers). Conditional branches in the function are on
public values only (key length, chunk-length mask).

**Statistical testing** (`tests/timing_constant_time.rs`, dudect / Welch
t-test), captured this session:

- *tag comparison vs. mismatch position*: |t| = 0.672 (means 142.6 ns /
  142.7 ns) - no early-exit leak.
- *decrypt time vs. ciphertext content* (symmetric pools): |t| = 1.229.

Both are far below the |t| ~ 267 a genuine early-exit leak produced during
development, confirming the test's sensitivity. Residual assurance limitations
are recorded as HRC-2026-05; transient-execution attacks are out of scope (section 4.4).

---

## 9. Memory safety and `unsafe` review

`unsafe_code = "deny"` is set at the workspace lint level; each crate
re-permits it locally (`#![allow(unsafe_code)]`), scoping the exception to the
SIMD/intrinsic code. The surface, measured at the reviewed commit:

| File | `unsafe` blocks | `unsafe fn` | `SAFETY:` comments |
| --- | ---: | ---: | ---: |
| `hardware-aes-gcm/aes.rs` | 35 | 9 | 35 |
| `hardware-aes-gcm/ghash.rs` | 36 | 21 | 36 |
| `hardware-aes-gcm/lib.rs` | 11 | 1 | 13 |
| `hardware-aes-gcm/fork.rs` | 1 | 0 | 1 |
| `hardware-aes-gcm/nonce.rs` | 0 | 0 | 0 |
| `hardware-random/aes_ctr.rs` | 18 | 7 | 17 |
| `hardware-random/lib.rs` | 3 | 0 | 3 |
| `hardware-random/entropy.rs` | 3 | 2 | 3 |
| `hardware-random/fork.rs` | 1 | 0 | 1 |

Every `unsafe` block carries a `SAFETY:` justification. Soundness-critical
patterns reviewed:

- **In-place initialization** (`init_in_place` on raw `NonNull`): write-before-
  read ordering verified; the GHASH-init failure path drops the
  already-initialized AES state, so no partial-init-then-error path leaves key
  material in caller storage.
- **Caller-placed aliasing model**: `OpaqueKeyState` stores `NonNull<u8>` +
  `PhantomData<&'a mut [u8]>` rather than a live `&mut` slice, so reads through
  the handle never coexist with a live mutable reference. The single-wipe drop
  path is documented to require revision if `KeyState` ever gains a
  resource-owning field.
- **`Send`/`Sync`**: manually implemented for `OpaqueKeyState` behind a
  compile-time `KeyState: Send + Sync` assertion; access outside drop is
  read-only with no interior mutability. A concurrent-use test exercises shared
  decryption across threads.
- **Target-feature gating**: every intrinsic call is reachable only after a
  runtime feature check at construction.
- **Inline assembly** (`RNDRRS`): uses the encoded system register
  `S3_3_C2_C4_1` with `cset ne` to read the success flag; `options(nostack,
  nomem)`; emission confirmed by inspection.

No `unsafe`-related defect was identified. The assurance residual (no Miri /
sanitizer coverage) is HRC-2026-04.

---

## 10. Dependency and supply-chain assessment

| Crate | Version | Role | License |
| --- | --- | --- | --- |
| `subtle` | 2.6.1 | constant-time compare | BSD-3-Clause |
| `zeroize` | 1.8.2 | memory wiping | Apache-2.0 / MIT |
| `getrandom` | 0.3.4 | OS entropy | Apache-2.0 / MIT |
| `libc` | 0.2 | `pthread_atfork`, `fork` (Unix) | Apache-2.0 / MIT |
| `cfg-if` | 1.0 | transitive (getrandom) | Apache-2.0 / MIT |

- **`cargo audit`** against the committed `Cargo.lock` (114 dependencies incl.
  dev) reports **no known vulnerabilities**; a `cargo-audit` CI job runs on
  every push.
- **Production graph is minimal and cipher-free** (section 5.2); a CI dependency-tree
  guard fails the build if `rand*`, `chacha20`, `salsa20`, `ring`, `aes*`,
  `ghash`, `polyval`, or related crates enter either production crate's normal
  graph (verified 0 on production; trips on the dev graph - positive control).
- **Vendored provenance**: `NOTICE` records upstream project, version, commit
  SHA, copyright, license, and modifications for `rand_aes` 0.7.0 (Apache-2.0),
  `ghash` 0.5.1, and `polyval` 0.6.2 (Apache-2.0 OR MIT) - satisfying
  Apache-2.0 section 4.
- **GitHub Actions** are pinned to commit SHAs.

**Observation (Informational).** Vendored upstreams are *copied*, not tracked
as dependencies, so upstream security fixes to `ghash`/`polyval`/`rand_aes` do
not flow in automatically. Recommend a documented periodic upstream re-sync
review.

---

## 11. Test coverage assessment

Executed at the reviewed commit (`--workspace --all-targets`):

| Suite | Tests | Coverage |
| --- | ---: | --- |
| `hardware-aes-gcm` unit | 20 | length/limit validation, layout, placement, wipe-on-drop, thread sharing, caller-buffer paths, generated-nonce round-trip/uniqueness |
| `hardware-random` unit | 14 | KAT, contiguity, reseed, fork (incl. real `fork()`), blend determinism, stuck-output, state size |
| `aes_gcm_interop` | 7 | RustCrypto/ring differential + cross-decrypt, NIST KAT, tamper sweep, dense length sweep |
| `random` integration | 1 | public-API smoke |
| `timing_constant_time` | 2 (ignored) | dudect harness, run manually |

**Strengths:** two independent differential oracles; boundary-dense sweeps
targeting the batch/aggregation seams; KATs cross-validated with OpenSSL; full
single-byte tamper coverage; lifecycle tests (fork, wipe, threading).

**Gaps:** Wycheproof vectors (HRC-2026-08); property/fuzz testing of the
decrypt parser (A1 surface); Miri (HRC-2026-04); `x86_64` hardware-path
execution depends on CI runners exposing AES-NI/RDSEED.

---

## 12. Standards conformance matrix

"Conforms (reviewed)" = follows the cited specification as verified by source
review and differential/known-answer testing; **not** accredited validation.

| Standard | Subject | Status |
| --- | --- | --- |
| FIPS 197 | AES-256 cipher and key schedule | Conforms (reviewed; KAT) |
| NIST SP 800-38A | CTR mode | Conforms (reviewed) |
| NIST SP 800-38D | AES-GCM, GHASH, J0, length limits | Conforms (reviewed; KAT + differential) |
| RFC 5116 / 5288 | AEAD interface; 96-bit GCM nonce | Conforms (reviewed) |
| NIST SP 800-90A Rev. 1 | CTR_DRBG | Modeled on; **not** conformant/validated (section 7.4) |
| NIST SP 800-90B | Entropy source health tests | Partial; stuck-output only (section 7.5, HRC-2026-03) |
| NIST SP 800-133 Rev. 2 | Key generation from an RBG | Consistent (direct draws, no bias) |
| FIPS 140-3 | Cryptographic module validation | **Not validated** (no CAVP/CMVP) |
| Apache-2.0 section 4 | Vendored-code attribution | Satisfied (`NOTICE`) |

---

## 13. Residual risk register

| Risk | Likelihood | Impact | Mitigation in place | Residual |
| --- | --- | --- | --- | --- |
| Nonce reuse by integrator | Medium | Critical | Random nonce generator; (recommended) docs | HRC-2026-01 - not enforced |
| Per-key invocation limit exceeded | Low-Med | High | None enforced | HRC-2026-01 - caller duty |
| Malicious CPU RNG + prior state leak | Low | High | OS-rooted seed + blend + stuck screen | HRC-2026-02 |
| Compiler reintroduces secret branch | Low | High | `subtle` + `black_box`; asm-checked | HRC-2026-05 |
| Latent `unsafe` UB | Low | Critical | Review + differential corpus | HRC-2026-04 - not Miri-proven |
| Transient-execution leak of cache tier | Low-Med | High | Out of scope by design | Documented limitation |
| Upstream vuln in vendored code | Low | Medium | Copied + attributed | Manual re-sync needed |
| Aggregated-GHASH latent defect | Low | High | Boundary-dense differential corpus | HRC-2026-08 - not formally proven |

---

## 14. Recommendations

**Before production integration**

1. **(HRC-2026-01)** Document the GCM nonce-uniqueness contract and SP 800-38D
   section 8.3 invocation limit at the API surface; define the integration's nonce strategy
   (prefer counter-based, or rotate keys before 2^32 invocations).
2. **(HRC-2026-02)** Add a periodic forced OS reseed alongside CPU-RNG
   reseeding.
3. **(HRC-2026-08)** Integrate Project Wycheproof AES-GCM vectors; add
   property/fuzz tests for the decrypt parser.

**Strongly recommended**

4. **(HRC-2026-04)** Add a Miri job over the architecture-independent logic.
5. **(HRC-2026-03)** Label the RNG health screen precisely as non-SP-800-90B,
   or extend it (APT + startup tests) if conformance is targeted.
6. **(HRC-2026-09)** Obtain independent third-party cryptographic review and,
   where required, CAVP/CMVP validation before protecting production data.

**Optional / longer-term**

7. Offer an AES-GCM-SIV (RFC 8452) misuse-resistant mode.
8. Validate benchmark and timing results on target Graviton / x86 Linux
   hardware.
9. Set `PSTATE.DIT` on `aarch64` around crypto sections once stable intrinsics
   exist (HRC-2026-05).

---

## 15. Conclusion

Within the threat model of section 4 and the scope of section 2, `hardware-rust-crypto` is a
carefully engineered, well-tested, hardware-only AES-256-GCM and
key-generation library. Its core cryptographic constructions conform to the
relevant NIST and IETF specifications as reviewed, and were verified
byte-for-byte against two independent implementations and NIST known-answer
vectors. The `unsafe` surface is large but disciplined and documented, and no
critical or high-severity vulnerability was identified.

The principal open finding (HRC-2026-01) is the standard, by-design GCM
nonce-management responsibility that every GCM deployment must address at the
integration layer. The remaining findings are low-severity residuals or
informational items appropriate to an un-certified library.

Recommended next steps before this library protects production data: resolve
HRC-2026-01 at the integration layer, address the prioritized recommendations
in section 14, and obtain independent third-party cryptographic review and (where
required) CAVP/CMVP validation.

---

## Appendix A - Rating methodology

Each finding receives an overall **Risk** derived from **Impact** (the
consequence if the issue is realized) and **Exploitability** (the difficulty
and preconditions of realizing it), in the style of NCC Group / Trail of Bits
deliverables. A CVSS 3.1 vector and base score are provided where the finding
maps cleanly to the CVSS model; for design responsibilities and
process/assurance findings, CVSS is marked N/A and the Impact/Exploitability
pair governs.

| Risk | Meaning |
| --- | --- |
| **Critical** | Directly breaks confidentiality or integrity with low attacker effort in the default configuration. |
| **High** | Breaks a security goal under realistic conditions or a common precondition. |
| **Medium** | Conditional or integrator-dependent weakness, or a by-design responsibility whose mishandling is severe. |
| **Low** | Limited impact, strong mitigations present, or unlikely preconditions; tracked residual. |
| **Informational** | No direct security impact; hygiene, documentation, defense-in-depth, or inherent limitation. |

CVSS scores are reference figures; where a score (e.g. HRC-2026-01 = 7.4)
diverges from the assessed Risk, the text explains the divergence - typically
CVSS over-weighting conditional impact for secure-by-default API gaps.

---

## Appendix B - Verification performed and captured evidence

All commands run at git `71396df`, rustc 1.96.0, on a MacBook Pro (Apple M4
Max) `aarch64` host; the
`x86_64` paths were additionally checked under the `stable-x86_64-apple-darwin`
toolchain. Both CI architectures were green at this commit. Reviewers should
re-run independently.

### B.1 Commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test --release --test aes_gcm_interop
cargo test --release -p hardware-random
cargo test --release --test timing_constant_time -- --ignored --nocapture
cargo doc --workspace --no-deps
cargo audit
cargo run --example assert_hardware
cargo run --release --example state_size
cargo asm -p hardware-aes-gcm --lib 'hardware_aes_gcm::KeyState::init_in_place'
cargo tree -p hardware-aes-gcm -e normal --prefix none
cargo tree -p hardware-random  -e normal --prefix none
```

### B.2 Test results (captured)

```
hardware-aes-gcm unit ......... 20 passed
hardware-random  unit ......... 14 passed
aes_gcm_interop ............... 7 passed
random (integration) .......... 1 passed
timing_constant_time .......... 2 ignored (run manually)
cargo audit ................... 0 vulnerabilities (114 crates scanned)
```

### B.3 NIST SP 800-38D known-answer vectors (AES-256, K = 0^32, IV = 0^12)

```
P = ""        ->  C||T = 530f8afbc74536b9a963b4f1c4cb738b
P = 0^16       ->  C||T = cea7403d4d606b6e074ec5d3baf39d18 d0d1c8a799996bf0265b98b5d48ab919
```

Both reproduced by `nist_known_answer_vectors`. The AES-256-CTR keystream was
additionally cross-checked against `openssl enc -aes-256-ecb`.

### B.4 Constant-time evidence (captured this session)

dudect (Welch t-test, 300k measurements/class after warm-up):

```
tag-mismatch-position:        |t| = 0.672   (mean0 142.6ns, mean1 142.7ns)
low-vs-high-entropy-content:  |t| = 1.229   (mean0 260.7ns, mean1 260.8ns)
```

Assembly inspection of `KeyState::init_in_place`:

```
AES/PMULL instructions emitted: 213
mulx carry fold (branch-free):  eor x8, x8, x11, lsl #62
                                eor x8, x8, x11, lsl #63
                                eor x8, x8, x11, lsl #57
black_box barrier markers:      2 (InlineAsm)
```

### B.5 Production dependency graphs (captured)

```
hardware-aes-gcm -> subtle 2.6.1, zeroize 1.8.2, getrandom 0.3.4, libc 0.2 (Unix)
hardware-random  -> getrandom 0.3.4, zeroize 1.8.2, libc 0.2 (Unix)
forbidden-crypto guard: 0 hits on both production graphs
```

---

## Appendix C - References

**Standards and specifications**

- FIPS 197, *Advanced Encryption Standard (AES)*, NIST, 2001 (updated 2023).
- NIST SP 800-38A, *Block Cipher Modes of Operation: Methods and Techniques*,
  2001.
- NIST SP 800-38D, *Galois/Counter Mode (GCM) and GMAC*, 2007.
- NIST SP 800-90A Rev. 1, *Random Number Generation Using Deterministic Random
  Bit Generators*, 2015.
- NIST SP 800-90B, *Entropy Sources Used for Random Bit Generation*, 2018.
- NIST SP 800-133 Rev. 2, *Recommendation for Cryptographic Key Generation*,
  2020.
- FIPS 140-3, *Security Requirements for Cryptographic Modules*, 2019.
- RFC 5116, *An Interface and Algorithms for Authenticated Encryption*, 2008.
- RFC 5288, *AES-GCM Cipher Suites for TLS*, 2008.
- RFC 8452, *AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption*,
  2019.

**Technical references**

- S. Gueron, M. Kounavis, *Intel Carry-Less Multiplication Instruction and its
  Usage for Computing the GCM Mode*, Intel white paper (aggregated reduction).
- O. Reparaz, J. Balasch, I. Verbauwhede, *dudect: Dude, is my code constant
  time?* (timing-leak detection methodology).
- Google Project Wycheproof - cryptographic test vectors.

**Prior art and format guidance**

- NCC Group, *Public Report - RustCrypto AES/GCM and ChaCha20+Poly1305
  Implementation Review*, 2020 (MobileCoin-funded) - direct lineage of the
  GHASH/POLYVAL code reviewed here.
- Public cryptographic review deliverables from NCC Group, Trail of Bits, and
  Cure53, and OSTIF-coordinated open-source cryptography audits, for report
  structure and rigor.

---

## Appendix D - Glossary

- **AEAD** - Authenticated Encryption with Associated Data.
- **AES-NI / PCLMULQDQ** - x86 instructions for AES rounds / carryless multiply.
- **ARMv8 AES / PMULL** - aarch64 equivalents.
- **CAVP / CMVP** - NIST Cryptographic Algorithm / Module Validation Programs.
- **CTR_DRBG** - Counter-mode Deterministic Random Bit Generator (SP 800-90A).
- **DIT** - ARM `PSTATE.DIT` (Data-Independent Timing) bit.
- **dudect** - statistical (Welch t-test) constant-time leakage test method.
- **FEAT_RNG / RNDR / RNDRRS** - ARMv8.5 hardware RNG feature and instructions.
- **GHASH / POLYVAL** - the GF(2^128) universal hashes underlying GCM / GCM-SIV.
- **J0** - the GCM pre-counter block.
- **min-entropy** - worst-case entropy measure used by SP 800-90B.
- **RCT / APT** - Repetition Count / Adaptive Proportion health tests.

---

*End of assessment. Document version 3.0, 2026-06-11, against git `71396df`.*
