//! Internal unique-nonce generation for the generated-nonce encrypt APIs.
//!
//! GCM is catastrophically fragile to nonce reuse under a fixed key, and nonce
//! uniqueness is otherwise the caller's responsibility. This generator removes
//! that footgun for callers that let the library choose the nonce.
//!
//! Construction: `nonce = (salt + counter) mod 2^96`, where `salt` is a 96-bit
//! value **always drawn from the OS entropy source** (never the CPU RNG or a
//! userspace generator) and `counter` is a per-instance 64-bit value that
//! increments once per nonce. A fixed random base walked by a sequential
//! counter yields distinct values within an instance; the random base
//! differentiates instances across process restart, `fork`, and hosts. The
//! base is re-drawn on fork (and on the unreachable 2^64 counter wrap), so a
//! repeat is never produced.
//!
//! Security: within an instance the counter guarantees no collision for up to
//! 2^64 nonces; across instances the only collision is a 96-bit base-range
//! overlap (`~M^2 * n / 2^96` for M instances of n nonces), which is below the
//! point-collision rate of independent random nonces. See `docs/design.md`.

use super::fork::ForkGuard;
use super::{Error, NONCE_SIZE};

const NONCE_MASK_96: u128 = (1_u128 << 96) - 1;

/// Per-instance unique 96-bit nonce sequence.
pub(crate) struct NonceGen {
    /// 96-bit random base (the salt), always from the OS.
    base: u128,
    /// Per-instance counter; `nonce = base + counter`.
    counter: u64,
    fork_guard: ForkGuard,
}

impl NonceGen {
    /// Seeds a generator with a fresh OS-drawn 96-bit base.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if the OS entropy source fails.
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            base: os_salt()?,
            counter: 0,
            fork_guard: ForkGuard::capture(),
        })
    }

    /// Returns the next unique 96-bit nonce, re-salting from the OS first if a
    /// fork has been observed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if a re-salt is required and OS entropy
    /// fails.
    pub(crate) fn next(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        if !self.fork_guard.unchanged() {
            self.resalt()?;
        }

        let nonce = nonce_value(self.base, self.counter);
        self.counter = self.counter.wrapping_add(1);
        if self.counter == 0 {
            // Unreachable in practice (2^64 nonces); re-salt so the next base
            // sequence does not repeat the one just exhausted.
            self.resalt()?;
        }

        Ok(nonce)
    }

    fn resalt(&mut self) -> Result<(), Error> {
        self.base = os_salt()?;
        self.counter = 0;
        self.fork_guard = ForkGuard::capture();
        Ok(())
    }
}

/// The unique-nonce arithmetic: `nonce = (base + counter) mod 2^96`, emitted
/// little-endian. Factored out so the uniqueness property can be model-checked
/// directly (see `kani_proofs::nonce_value_is_injective_in_counter`): for a
/// fixed `base`, this is injective in `counter` across a full `2^64` sequence,
/// which is exactly why the generated-nonce path cannot repeat a nonce within an
/// instance.
fn nonce_value(base: u128, counter: u64) -> [u8; NONCE_SIZE] {
    let value = base.wrapping_add(u128::from(counter)) & NONCE_MASK_96;
    let bytes = value.to_le_bytes();
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes[..NONCE_SIZE]);
    nonce
}

/// Draws a 96-bit salt from the OS entropy source. The salt always comes from
/// the OS, never the CPU RNG or a userspace generator.
fn os_salt() -> Result<u128, Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes[..NONCE_SIZE]).map_err(|_| Error::OsEntropy)?;
    Ok(u128::from_le_bytes(bytes) & NONCE_MASK_96)
}

/// Kani proof: the generated-nonce sequence cannot repeat within an instance.
#[cfg(kani)]
mod kani_proofs {
    use super::{nonce_value, NONCE_MASK_96};

    /// For a fixed 96-bit base, `nonce_value` is **injective in the counter**:
    /// two distinct counters (anywhere in the full `2^64` range) always produce
    /// distinct nonces. This is the core guarantee of the generated-nonce path -
    /// within one instance the per-call counter walk never reuses a nonce
    /// (mitigating the GCM nonce-reuse footgun; see HRC-2026-01). Verified over
    /// all bases and all counter pairs.
    #[kani::proof]
    fn nonce_value_is_injective_in_counter() {
        let base: u128 = kani::any();
        kani::assume(base <= NONCE_MASK_96);
        let c1: u64 = kani::any();
        let c2: u64 = kani::any();
        kani::assume(c1 != c2);
        assert!(nonce_value(base, c1) != nonce_value(base, c2));
    }
}
