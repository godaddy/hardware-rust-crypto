# Randomness testing (AES-CTR key/nonce generator)

The `random::AesCtrKeyGenerator` is an AES-256-CTR DRBG-style keystream
generator (modeled on SP 800-90A CTR_DRBG; **not** a validated DRBG, see
`docs/security-audit.md` section 7.4). Its output quality is tested at three
levels.

## 1. Known-answer and lifecycle tests (always on, CI)

Unit tests in `src/random/` check the AES-CTR keystream against FIPS-197 vectors
(independently verified with OpenSSL), plus block contiguity, reseed, fork
re-seeding (including a real `fork()`), CPU-RNG-blend determinism, stuck-output
detection, and state size.

## 2. Statistical sanity checks (always on, CI)

`tests/rng_statistical.rs` runs cheap deterministic guards over a 4 MiB sample:

- **Monobit frequency** - one-bit fraction must be ~0.5 (|z| < 6).
- **Byte chi-square** - 256-bucket distribution near the 255-dof expectation.
- **Lag-1 serial correlation** - must be ~0.

These catch gross breakage (a stuck or biased generator) on every run. They are
deterministic (fixed seed), so they never flake; a real defect misses the
thresholds by orders of magnitude.

## 3. Full statistical batteries

For deep validation, stream the generator into an industrial battery via
`examples/rng_dump.rs`:

```sh
# PractRand (recommended) - escalates sample size until it finds a flaw or you stop:
cargo run --release --example rng_dump | RNG_test stdin64 -tlmin 1MB -tlmax 1TB

# dieharder - the classic battery:
cargo run --release --example rng_dump | dieharder -g 200 -a
```

The `randomness-battery` CI job runs PractRand over the generator to a bounded
volume on every build (see `.github/workflows/ci.yml`); deeper runs (terabyte
scale) are manual.

**Result (PractRand 0.94, to 32 GiB, Apple M4 Max):** the AES-CTR keystream
passes cleanly. Every checkpoint from 1 MiB through 32 GiB reports no escalating
anomaly; the only flags are transient `unusual` results (p ~ 1e-4) that appear
on *different* sub-tests at different checkpoints and vanish with more data
(e.g. an `unusual` at 1 GiB, clean at 2 GiB; two at 4 GiB, clean at 8/16/32
GiB - 325 sub-tests clean at 32 GiB). That appear-and-disappear pattern is the
expected statistical noise of running hundreds of sub-tests per checkpoint, not
a defect: nothing ever reaches PractRand's `suspicious` or `FAIL` thresholds. As
expected for a CSPRNG, AES output is a standard PRG, so these batteries validate
the construction (counter handling, block stitching), not AES itself.

## Entropy source (SP 800-90B)

The statistical batteries above test the *generator's output*, not the *entropy
source*. Seeding draws from the OS (`getrandom`) and optionally blends CPU
hardware RNG (RDSEED/RNDRRS); a full SP 800-90B entropy-source assessment
(min-entropy estimation, the full health-test suite) is **not** performed - only
a stuck-output check is implemented. See `docs/security-audit.md` HRC-2026-03.
Treat the OS as the entropy authority; this generator is an output expander, not
an entropy source.
