# Security Policy

`hardware-rust-crypto` is a cryptographic library. We take security reports
seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not report security issues through public GitHub issues, pull
requests, or discussions.**

Report privately through GitHub's **private vulnerability reporting**:

1. Go to the repository's **Security** tab → **Report a vulnerability**
   (`https://github.com/godaddy/hardware-rust-crypto/security/advisories/new`).
2. Describe the issue, the affected version/commit, and a reproduction (a
   failing test or proof-of-concept is ideal).

If you cannot use GitHub's reporting flow, contact GoDaddy's security team via
the program at <https://www.godaddy.com/legal/agreements/security> and reference
this repository.

### What to expect

- **Acknowledgement:** within 3 business days.
- **Triage and severity assessment:** within 10 business days, using CVSS 3.1.
- **Fix and coordinated disclosure:** we aim to release a fix and a GitHub
  Security Advisory (with a CVE where warranted) within 90 days, sooner for
  actively exploited issues. We will credit reporters who wish to be named.

Please give us a reasonable window to remediate before any public disclosure.

## Scope

In scope (please report):

- Incorrect AEAD behavior: authentication bypass, tag forgery, plaintext
  recovery, nonce-handling or counter defects, or any deviation from RFC/NIST
  test vectors.
- Memory-safety defects in the `unsafe` code (out-of-bounds, use-after-free,
  uninitialized reads, data races, aliasing/provenance violations).
- Key material not being zeroized as documented, or leaking through a public
  API.
- Secret-dependent timing or other side channels reachable through the public
  API on a supported target.
- Build configurations that silently weaken the hardware-only guarantee.

Out of scope:

- Misuse the API documents as the caller's responsibility, in particular
  **nonce reuse under AES-256-GCM** (use the generated-nonce APIs or
  AES-256-GCM-SIV) and exceeding per-key invocation limits.
- Physical, power, electromagnetic, fault-injection, and microarchitectural
  transient-execution (Spectre-class) attacks, which are out of the threat
  model (see `docs/security-audit.md`).
- Vulnerabilities in dependencies that do not affect this crate's use of them
  (report those upstream; we monitor advisories via `cargo audit` in CI).
- Behavior on targets without the required AES/carryless-multiply hardware,
  where construction fails by design with `UnsupportedCpu`.

## Supported versions

This crate is pre-1.0. Security fixes are made against the latest released
version on the default branch. Once 1.0 is published, this section will record
the supported release lines.

## Assurances and limitations

This is an independent implementation that vendors and adapts audited RustCrypto
backends; it has **not** itself received an independent third-party audit or
NIST CAVP/CMVP validation (see `docs/security-audit.md`, HRC-2026-09).
Correctness is backed by RFC 8452 / NIST SP 800-38D / NIST CAVP / Project
Wycheproof known-answer vectors, differential testing against RustCrypto and
`ring`, property-based and fuzz testing, Miri and Valgrind checks of the
`unsafe` code, and dudect-style constant-time timing harnesses. Evaluate it for
your threat model before production use.
