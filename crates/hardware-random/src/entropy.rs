//! Optional CPU hardware-RNG entropy source for reseeding.
//!
//! When the `cpu-rng-reseed` feature is on (the default) and the running CPU
//! *and guest* expose a hardware RNG instruction, [`cpu_rng_fill`] draws
//! entropy directly from it: `RDSEED` on `x86_64`, `RNDRRS` (`FEAT_RNG`) on
//! `aarch64`. Both are runtime-detected - on a virtualized guest the
//! instruction may be hidden even where the silicon implements it, and on
//! Apple Silicon `FEAT_RNG` is not exposed at all - so a `false` return means
//! "use the OS source instead", never a panic. The output is never used
//! raw: the reseed path blends it through the current secret generator state
//! (a CTR_DRBG-style update), so a misbehaving CPU RNG cannot control the new
//! seed.

#![allow(unsafe_code)]

/// Bounded retries before giving up on the hardware instruction and letting
/// the caller fall back to the OS. Hardware RNGs occasionally signal "not
/// ready"; a handful of retries clears transient backpressure without
/// spinning unboundedly.
#[cfg(feature = "cpu-rng-reseed")]
const RETRIES: usize = 16;

/// Fills `out` from a CPU hardware-RNG instruction, then screens the result
/// with a stuck-output health check.
///
/// Returns `true` only if every byte was filled from the hardware RNG **and**
/// the result passes [`stuck_output`]. Returns `false` (wiping `out`) when the
/// feature is off, the instruction is unavailable to this guest, the retry
/// budget was exhausted, or the draw looks stuck. Callers must treat `false`
/// as "fall back to the OS entropy source".
#[cfg(feature = "cpu-rng-reseed")]
pub(crate) fn cpu_rng_fill(out: &mut [u8]) -> bool {
    use zeroize::Zeroize as _;

    if imp::fill(out) && !stuck_output(out) {
        return true;
    }
    // Never let a failed or suspect draw reach the reseed blend.
    out.zeroize();
    false
}

/// NIST SP 800-90B-style continuous "stuck output" screen: rejects a draw in
/// which any two 64-bit words are identical.
///
/// The 64-bit word is the granularity RDSEED/RNDRRS actually get stuck at, so
/// the screen works on words rather than bytes (a byte-equality check would
/// miss a source jammed at a non-uniform-byte constant like
/// `0x0123_4567_89AB_CDEF`). Flagging *any* duplicate - not just an
/// all-identical draw - also catches short-period and partially-stuck
/// sources. The seed buffer is only 48 bytes (six words), and this runs only
/// on reseed (roughly once per gigabyte of output, never on the generation
/// hot path), so the `O(words^2)` scan is free.
///
/// False positives are negligible and harmless: two of six healthy 64-bit
/// words collide with probability about `2^-60`, and a flagged draw simply
/// falls back to the OS entropy source for that one reseed. The screen does
/// not attempt to detect subtle degradation (bias, correlation) from a single
/// sample - the reseed blend already neutralizes a weak-but-live CPU RNG, so
/// this only needs to catch the gross dead/stuck case.
#[cfg(feature = "cpu-rng-reseed")]
fn stuck_output(buf: &[u8]) -> bool {
    let mut outer = 0_usize;
    while outer + 8 <= buf.len() {
        let word = &buf[outer..outer + 8];
        let mut inner = outer + 8;
        while inner + 8 <= buf.len() {
            if &buf[inner..inner + 8] == word {
                return true;
            }
            inner += 8;
        }
        outer += 8;
    }
    false
}

#[cfg(all(test, feature = "cpu-rng-reseed"))]
mod tests {
    use super::stuck_output;

    #[test]
    fn flags_constant_byte_sources() {
        assert!(stuck_output(&[0x00_u8; 48]));
        assert!(stuck_output(&[0xff_u8; 48]));
        assert!(stuck_output(&[0xfe_u8; 48]));
    }

    #[test]
    fn flags_constant_word_sources() {
        // A source stuck at a non-uniform-byte 64-bit value: a byte-equality
        // screen would miss this; the word repetition screen catches it.
        let word = 0x0123_4567_89ab_cdef_u64.to_le_bytes();
        let mut buf = [0_u8; 48];
        for chunk in buf.chunks_exact_mut(8) {
            chunk.copy_from_slice(&word);
        }
        assert!(stuck_output(&buf));
    }

    #[test]
    fn flags_any_duplicate_word() {
        // Six distinct words except two that collide: a partially-stuck or
        // short-period source. The any-duplicate screen catches it.
        let mut buf = [0_u8; 48];
        for (i, chunk) in buf.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&(i as u64).to_le_bytes());
        }
        buf[40..48].copy_from_slice(&0_u64.to_le_bytes()); // word 5 == word 0
        assert!(stuck_output(&buf));
    }

    #[test]
    fn passes_varied_output() {
        // Six distinct words: healthy draw.
        let mut buf = [0_u8; 48];
        for (i, chunk) in buf.chunks_exact_mut(8).enumerate() {
            let word = 0x1111_1111_1111_1111_u64.wrapping_mul(i as u64 + 1);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        assert!(!stuck_output(&buf));
    }
}

/// Feature-off build: no CPU RNG path, always fall back to the OS.
#[cfg(not(feature = "cpu-rng-reseed"))]
pub(crate) fn cpu_rng_fill(_out: &mut [u8]) -> bool {
    false
}

/// Whether a usable CPU hardware RNG is present on this guest. Reported for
/// diagnostics/tests; the reseed path keys off the fill result, not this.
#[must_use]
pub fn cpu_rng_available() -> bool {
    #[cfg(feature = "cpu-rng-reseed")]
    {
        imp::available()
    }
    #[cfg(not(feature = "cpu-rng-reseed"))]
    {
        false
    }
}

#[cfg(all(feature = "cpu-rng-reseed", target_arch = "x86_64"))]
mod imp {
    use core::arch::x86_64::_rdseed64_step;

    pub(super) fn available() -> bool {
        std::arch::is_x86_feature_detected!("rdseed")
    }

    pub(super) fn fill(out: &mut [u8]) -> bool {
        if !available() {
            return false;
        }
        // SAFETY: rdseed availability was checked above.
        unsafe { fill_rdseed(out) }
    }

    #[target_feature(enable = "rdseed")]
    unsafe fn fill_rdseed(out: &mut [u8]) -> bool {
        for chunk in out.chunks_mut(8) {
            let mut value = 0_u64;
            let mut ready = false;
            for _ in 0..super::RETRIES {
                // The rdseed target feature is enabled on this fn, so calling
                // the intrinsic is in-context; `_rdseed64_step` takes `&mut`.
                if _rdseed64_step(&mut value) == 1 {
                    ready = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !ready {
                return false;
            }
            // Ephemeral stack copies of seed bytes (`value`, `bytes`) are an
            // accepted residual; see docs/design.md. The reseed caller wipes
            // the assembled seed buffer.
            let bytes = value.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        true
    }
}

#[cfg(all(feature = "cpu-rng-reseed", target_arch = "aarch64"))]
mod imp {
    pub(super) fn available() -> bool {
        std::arch::is_aarch64_feature_detected!("rand")
    }

    pub(super) fn fill(out: &mut [u8]) -> bool {
        if !available() {
            return false;
        }
        // SAFETY: FEAT_RNG availability was checked above.
        unsafe { fill_rndrrs(out) }
    }

    #[target_feature(enable = "rand")]
    unsafe fn fill_rndrrs(out: &mut [u8]) -> bool {
        for chunk in out.chunks_mut(8) {
            let mut value: u64 = 0;
            let mut ready = false;
            for _ in 0..super::RETRIES {
                let ok: u64;
                // SAFETY: RNDRRS (S3_3_C2_C4_1) reads the reseeded hardware
                // RNG. It sets PSTATE.NZCV: Z is clear on success, set on
                // failure, so `cset ne` yields 1 only when a genuine random
                // value was returned. No memory or stack effects.
                unsafe {
                    core::arch::asm!(
                        "mrs {value}, S3_3_C2_C4_1",
                        "cset {ok}, ne",
                        value = out(reg) value,
                        ok = out(reg) ok,
                        options(nostack, nomem),
                    );
                }
                if ok != 0 {
                    ready = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !ready {
                return false;
            }
            let bytes = value.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        true
    }
}

/// Targets without a supported hardware RNG instruction (e.g. 32-bit x86,
/// other architectures): always fall back to the OS.
#[cfg(all(
    feature = "cpu-rng-reseed",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
mod imp {
    pub(super) fn available() -> bool {
        false
    }

    pub(super) fn fill(_out: &mut [u8]) -> bool {
        false
    }
}
