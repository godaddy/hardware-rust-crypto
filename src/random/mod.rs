//! Fast random byte generation for hot key/nonce paths.
//!
//! This crate ships only the hardware-only AES-256-CTR generator (derived
//! from the `rand_aes` AES-256-CTR-128 backend with software fallback state
//! removed): the dependency graph contains no software cipher, and OS entropy
//! for seeding comes from `getrandom` directly. Software stream ciphers used
//! for benchmark comparison live in the workspace's dev-dependencies only.
//!
//! # Constant-time notes
//!
//! Generation never branches on, or indexes memory by, generated secret
//! bytes: 32-byte keys and 12-byte nonces are direct fixed-size draws with
//! no rejection sampling, and buffer accounting depends only on requested
//! lengths and cursor positions. The AES-CTR backend is constant time by
//! construction: it runs on hardware AES instructions with no table lookups
//! or data-dependent branches (see the `aes_ctr` module docs). Lifecycle
//! branches (reseed interval, fork detection) read public counters and
//! process state only.

#![allow(unsafe_code)]

mod aes_ctr;
mod entropy;
mod fork;

pub use entropy::cpu_rng_available;

use zeroize::{Zeroize as _, Zeroizing};

/// AES-256 key size.
pub const KEY_SIZE: usize = 32;
/// AES-GCM nonce size.
pub const NONCE_SIZE: usize = 12;
/// AES-CTR generator seed size: 32-byte AES-256 key plus 16-byte counter.
pub const AES_CTR_SEED_SIZE: usize = 48;

const AES_BLOCK_SIZE: usize = 16;
const DEFAULT_RESEED_INTERVAL_BYTES: u64 = 1 << 30;

/// Random generation errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// OS entropy failed while seeding the fast CSPRNG.
    OsEntropy(getrandom::Error),
    /// Required AES hardware support is unavailable.
    UnsupportedCpu {
        /// Required CPU features for the current target.
        required: &'static str,
    },
    /// Generator state was inherited across a process fork.
    ForkDetected,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OsEntropy(err) => write!(f, "OS entropy failed: {err}"),
            Self::UnsupportedCpu { required } => {
                write!(
                    f,
                    "required AES-CTR hardware support is unavailable: {required}"
                )
            }
            Self::ForkDetected => f.write_str("random generator state crossed a process fork"),
        }
    }
}

impl std::error::Error for Error {}

/// Snapshot used to detect generator state crossing a process fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForkGuard {
    /// Fork-generation snapshot maintained by a `pthread_atfork` child
    /// handler; checking is an atomic load and survives pid reuse.
    Generation(u64),
    /// Fallback when the atfork handler is unavailable: process-id snapshot
    /// compared via `getpid` per check.
    ProcessId(u32),
}

impl ForkGuard {
    fn capture() -> Self {
        fork::generation().map_or_else(|| Self::ProcessId(current_process_id()), Self::Generation)
    }

    fn check(self) -> Result<(), Error> {
        let unchanged = match self {
            Self::Generation(seen) => fork::generation() == Some(seen),
            Self::ProcessId(seen) => current_process_id() == seen,
        };
        if unchanged {
            Ok(())
        } else {
            Err(Error::ForkDetected)
        }
    }

    #[cfg(test)]
    fn corrupted(self) -> Self {
        match self {
            Self::Generation(seen) => Self::Generation(seen.wrapping_add(1)),
            Self::ProcessId(seen) => Self::ProcessId(seen.wrapping_add(1)),
        }
    }
}

/// Common key-generation contract for benchmarked CSPRNG backends.
pub trait KeyGenerator {
    /// Fills `out` with CSPRNG output.
    ///
    /// # Errors
    ///
    /// Returns entropy, hardware, or fork-detection failures.
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Error>;

    /// Generates a 32-byte AES-256 key.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::fill_bytes`].
    fn key_32(&mut self) -> Result<[u8; KEY_SIZE], Error> {
        let mut out = [0_u8; KEY_SIZE];
        self.fill_bytes(&mut out)?;
        Ok(out)
    }

    /// Generates a 12-byte AES-GCM nonce.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::fill_bytes`].
    fn nonce_12(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        let mut out = [0_u8; NONCE_SIZE];
        self.fill_bytes(&mut out)?;
        Ok(out)
    }
}

/// Fills `out` from the operating-system entropy source.
fn fill_from_os(out: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(out).map_err(Error::OsEntropy)
}

/// Size and alignment for a reusable generator state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateLayout {
    /// State size in bytes.
    pub size: usize,
    /// State alignment in bytes.
    pub align: usize,
}

/// Hardware-only AES-256-CTR fast random generator.
///
/// The state contains a 128-bit counter, AES-256 encryption round keys, and a
/// small buffered-output block. It does not contain a software AES fallback or
/// a runtime enum that can hold one.
pub struct AesCtrKeyGenerator {
    backend: aes_ctr::Backend,
    buffer: [u8; AES_BLOCK_SIZE],
    buffer_pos: usize,
    generated_since_reseed: u64,
    reseed_interval: u64,
    fork_guard: ForkGuard,
}

impl AesCtrKeyGenerator {
    /// Returns whether this process currently exposes the required AES hardware
    /// functionality for the AES-CTR backend.
    #[must_use]
    pub fn hardware_available() -> bool {
        aes_ctr::hardware_available()
    }

    /// Returns the state layout for this owned generator type.
    #[must_use]
    pub const fn state_layout() -> StateLayout {
        StateLayout {
            size: core::mem::size_of::<Self>(),
            align: core::mem::align_of::<Self>(),
        }
    }

    /// Seeds a new AES-CTR generator from OS entropy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedCpu`] if the required AES hardware support is
    /// unavailable. Returns [`Error::OsEntropy`] if the platform entropy source
    /// cannot provide a seed.
    pub fn from_os_entropy() -> Result<Self, Error> {
        if !Self::hardware_available() {
            return Err(Error::UnsupportedCpu {
                required: aes_ctr::REQUIRED_FEATURES,
            });
        }

        let mut seed = Zeroizing::new([0_u8; AES_CTR_SEED_SIZE]);
        fill_from_os(seed.as_mut())?;
        Self::from_seed_bytes(&seed)
    }

    /// Seeds a new AES-CTR generator from explicit seed material and zeroizes
    /// the provided seed before returning.
    ///
    /// `seed[..32]` is the AES-256 key and `seed[32..]` is the initial 128-bit
    /// little-endian counter. This constructor exists for deterministic tests
    /// and benchmarks; production callers should use [`Self::from_os_entropy`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedCpu`] if the required AES hardware support is
    /// unavailable.
    pub fn from_seed(seed: &mut [u8; AES_CTR_SEED_SIZE]) -> Result<Self, Error> {
        let result = Self::from_seed_bytes(seed);
        seed.zeroize();
        result
    }

    fn from_seed_bytes(seed: &[u8; AES_CTR_SEED_SIZE]) -> Result<Self, Error> {
        if !Self::hardware_available() {
            return Err(Error::UnsupportedCpu {
                required: aes_ctr::REQUIRED_FEATURES,
            });
        }

        let (key, counter) = split_seed(seed);
        let backend = aes_ctr::Backend::new(key, counter).ok_or(Error::UnsupportedCpu {
            required: aes_ctr::REQUIRED_FEATURES,
        })?;

        Ok(Self {
            backend,
            buffer: [0_u8; AES_BLOCK_SIZE],
            buffer_pos: AES_BLOCK_SIZE,
            generated_since_reseed: 0,
            reseed_interval: DEFAULT_RESEED_INTERVAL_BYTES,
            fork_guard: ForkGuard::capture(),
        })
    }

    /// Generates a 32-byte AES-256 key.
    ///
    /// # Errors
    ///
    /// Returns entropy, hardware, or fork-detection failures.
    pub fn key_32(&mut self) -> Result<[u8; KEY_SIZE], Error> {
        KeyGenerator::key_32(self)
    }

    /// Generates a 12-byte AES-GCM nonce.
    ///
    /// # Errors
    ///
    /// Returns entropy, hardware, or fork-detection failures.
    pub fn nonce_12(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        KeyGenerator::nonce_12(self)
    }

    fn drain_buffer(&mut self, out: &mut [u8]) -> usize {
        // `available`/`take` derive from cursor positions and the requested
        // length, never from generated byte values, so this path leaks
        // nothing about the output through timing.
        let available = AES_BLOCK_SIZE - self.buffer_pos;
        let take = available.min(out.len());
        if take == 0 {
            return 0;
        }

        let end = self.buffer_pos + take;
        out[..take].copy_from_slice(&self.buffer[self.buffer_pos..end]);
        self.buffer[self.buffer_pos..end].zeroize();
        self.buffer_pos = end;
        take
    }

    /// Reseeds the generator.
    ///
    /// If a CPU hardware RNG is available (and the `cpu-rng-reseed` feature is
    /// enabled), fresh CPU entropy is blended through the current secret state
    /// instead of querying the OS - see [`Self::reseed_blend`]. Otherwise the
    /// generator is reset directly from the OS entropy source.
    fn reseed(&mut self) -> Result<(), Error> {
        let mut entropy_input = Zeroizing::new([0_u8; AES_CTR_SEED_SIZE]);
        if entropy::cpu_rng_fill(entropy_input.as_mut()) {
            self.reseed_blend(&entropy_input);
        } else {
            fill_from_os(entropy_input.as_mut())?;
            self.reset_from_seed(&entropy_input)?;
        }
        self.buffer.zeroize();
        self.buffer_pos = AES_BLOCK_SIZE;
        self.generated_since_reseed = 0;
        self.fork_guard = ForkGuard::capture();
        Ok(())
    }

    /// Resets the backend from full-entropy seed material (OS path).
    fn reset_from_seed(&mut self, seed: &[u8; AES_CTR_SEED_SIZE]) -> Result<(), Error> {
        let (key, counter) = split_seed(seed);
        self.backend = aes_ctr::Backend::new(key, counter).ok_or(Error::UnsupportedCpu {
            required: aes_ctr::REQUIRED_FEATURES,
        })?;
        Ok(())
    }

    /// CTR_DRBG-style reseed update: derive the new 48-byte seed as
    /// `AES-CTR keystream(current secret state) XOR cpu_entropy`, then rekey
    /// the backend from it.
    ///
    /// The keystream block is secret (it depends on the current key, which is
    /// rooted in the original OS seed), so a malicious CPU RNG that controls
    /// `cpu_entropy` still cannot force the new seed to a known value unless
    /// it *also* already knows the current state. Conversely, if the CPU RNG
    /// is honest, the fresh entropy makes the new seed unpredictable even if
    /// the prior state had leaked. The result is safe unless both the state
    /// is compromised and the CPU RNG is malicious - strictly stronger than
    /// trusting either source alone.
    fn reseed_blend(&mut self, cpu_entropy: &[u8; AES_CTR_SEED_SIZE]) {
        let mut seed = Zeroizing::new([0_u8; AES_CTR_SEED_SIZE]);
        // 48 bytes == 3 AES blocks of keystream from the current state.
        for block in seed.chunks_exact_mut(AES_BLOCK_SIZE) {
            let mut keystream = Zeroizing::new([0_u8; AES_BLOCK_SIZE]);
            self.backend.fill_block(&mut keystream);
            block.copy_from_slice(keystream.as_ref());
        }
        for (seed_byte, entropy_byte) in seed.iter_mut().zip(cpu_entropy.iter()) {
            *seed_byte ^= entropy_byte;
        }
        let (key, counter) = split_seed(&seed);
        // first_chunk on a 48-byte array is infallible; on the impossible
        // None we keep the existing backend rather than panic.
        if let Some(backend) = aes_ctr::Backend::new(key, counter) {
            self.backend = backend;
        }
    }

    fn fill_checked(&mut self, mut out: &mut [u8]) -> Result<(), Error> {
        self.fork_guard.check()?;
        while !out.is_empty() {
            // Clamp so a zero interval cannot stall the loop with zero-byte
            // chunks while reseeding forever.
            let reseed_interval = self.reseed_interval.max(1);
            if self.generated_since_reseed >= reseed_interval {
                self.reseed()?;
            }

            let remaining_before_reseed = reseed_interval - self.generated_since_reseed;
            let take = out
                .len()
                .min(usize::try_from(remaining_before_reseed).unwrap_or(usize::MAX));
            let (chunk, rest) = out.split_at_mut(take);
            self.fill_without_lifecycle_checks(chunk);
            self.generated_since_reseed += u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            out = rest;
        }
        Ok(())
    }

    fn fill_without_lifecycle_checks(&mut self, mut out: &mut [u8]) {
        let copied = self.drain_buffer(out);
        out = &mut out[copied..];

        let mut chunks = out.chunks_exact_mut(AES_BLOCK_SIZE);
        for chunk in &mut chunks {
            let mut block = Zeroizing::new([0_u8; AES_BLOCK_SIZE]);
            self.backend.fill_block(&mut block);
            chunk.copy_from_slice(block.as_ref());
        }

        let remainder = chunks.into_remainder();
        if !remainder.is_empty() {
            self.backend.fill_block(&mut self.buffer);
            remainder.copy_from_slice(&self.buffer[..remainder.len()]);
            self.buffer[..remainder.len()].zeroize();
            self.buffer_pos = remainder.len();
        }
    }
}

impl Drop for AesCtrKeyGenerator {
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.buffer_pos = AES_BLOCK_SIZE;
        self.generated_since_reseed = 0;
        self.reseed_interval = 0;
    }
}

impl std::fmt::Debug for AesCtrKeyGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesCtrKeyGenerator").finish_non_exhaustive()
    }
}

impl KeyGenerator for AesCtrKeyGenerator {
    /// Fills `out` with AES-CTR CSPRNG output.
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.fill_checked(out)
    }
}

fn current_process_id() -> u32 {
    std::process::id()
}

/// Splits a seed into the AES-256 key and initial counter segments.
#[allow(clippy::expect_used)] // Infallible: the const assertion pins the split.
fn split_seed(seed: &[u8; AES_CTR_SEED_SIZE]) -> (&[u8; KEY_SIZE], &[u8; AES_BLOCK_SIZE]) {
    const _: () = assert!(AES_CTR_SEED_SIZE == KEY_SIZE + AES_BLOCK_SIZE);
    let (key, counter) = seed.split_at(KEY_SIZE);
    (
        key.try_into().expect("seed key segment is KEY_SIZE bytes"),
        counter
            .try_into()
            .expect("seed counter segment is AES_BLOCK_SIZE bytes"),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{AesCtrKeyGenerator, KeyGenerator, AES_BLOCK_SIZE, AES_CTR_SEED_SIZE, KEY_SIZE};

    #[cfg(unix)]
    #[test]
    fn detects_state_inherited_across_real_fork() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let mut rng =
            AesCtrKeyGenerator::from_os_entropy().expect("OS entropy should be available");
        let mut out = [0_u8; 1];
        rng.fill_bytes(&mut out)
            .expect("parent generation should succeed");

        // SAFETY: the forked child only performs fork-safe work (atomic loads,
        // getpid, in-memory generation) and exits via _exit without running
        // atexit handlers or touching inherited locks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork should succeed");
        if pid == 0 {
            let code = match rng.fill_bytes(&mut out) {
                Err(super::Error::ForkDetected) => 0,
                Ok(()) | Err(_) => 1,
            };
            // SAFETY: _exit is the fork-safe process exit path.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        // SAFETY: pid is the child forked above and status is a valid out
        // pointer.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid, "waitpid should reap the forked child");
        assert!(libc::WIFEXITED(status), "child should exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child must observe ForkDetected from inherited generator state"
        );
    }

    #[test]
    fn reseed_blend_is_deterministic_and_entropy_dependent() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        // Two generators seeded identically, blended with the same CPU
        // entropy, must reach the same state (deterministic mixing); blending
        // with different entropy must diverge (the entropy actually feeds in).
        let entropy_a = [0x11_u8; AES_CTR_SEED_SIZE];
        let entropy_b = [0x22_u8; AES_CTR_SEED_SIZE];

        let mut seed = [0x5e_u8; AES_CTR_SEED_SIZE];
        let mut rng_a = AesCtrKeyGenerator::from_seed(&mut seed.clone())
            .expect("AES hardware should be available");
        let mut rng_a2 = AesCtrKeyGenerator::from_seed(&mut seed.clone())
            .expect("AES hardware should be available");
        let mut rng_b =
            AesCtrKeyGenerator::from_seed(&mut seed).expect("AES hardware should be available");

        rng_a.reseed_blend(&entropy_a);
        rng_a2.reseed_blend(&entropy_a);
        rng_b.reseed_blend(&entropy_b);

        let mut out_a = [0_u8; 32];
        let mut out_a2 = [0_u8; 32];
        let mut out_b = [0_u8; 32];
        rng_a.fill_without_lifecycle_checks(&mut out_a);
        rng_a2.fill_without_lifecycle_checks(&mut out_a2);
        rng_b.fill_without_lifecycle_checks(&mut out_b);

        assert_eq!(out_a, out_a2, "same seed + same entropy must blend equally");
        assert_ne!(
            out_a, out_b,
            "different entropy must change the blended state"
        );
    }

    #[test]
    fn reseed_blend_changes_state() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let mut seed = [0x33_u8; AES_CTR_SEED_SIZE];
        let mut rng =
            AesCtrKeyGenerator::from_seed(&mut seed).expect("AES hardware should be available");
        let mut before = [0_u8; 32];
        rng.fill_without_lifecycle_checks(&mut before);

        rng.reseed_blend(&[0x44_u8; AES_CTR_SEED_SIZE]);
        let mut after = [0_u8; 32];
        rng.fill_without_lifecycle_checks(&mut after);
        assert_ne!(before, after, "reseed must change subsequent output");
    }

    #[test]
    fn cpu_rng_available_does_not_panic() {
        // Result is platform-dependent (true on Graviton/x86 with RDSEED,
        // false on Apple Silicon); we only assert it runs.
        let _ = super::cpu_rng_available();
    }

    #[test]
    fn aes_ctr_matches_aes256_ctr_known_answer() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let mut seed = [0_u8; AES_CTR_SEED_SIZE];
        seed[..KEY_SIZE].copy_from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        seed[KEY_SIZE..].copy_from_slice(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);

        let mut rng =
            AesCtrKeyGenerator::from_seed(&mut seed).expect("AES hardware should be available");
        let mut out = [0_u8; AES_BLOCK_SIZE * 2];
        rng.fill_bytes(&mut out)
            .expect("AES-CTR generation should succeed");

        assert_eq!(
            out,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89, 0x81, 0xae, 0x7d, 0x5e, 0x41, 0x38, 0xbf, 0x73, 0x0d, 0x2a, 0x88, 0x71,
                0xfe, 0xc2, 0xcd, 0x0c,
            ]
        );
    }

    #[test]
    fn aes_ctr_fill_bytes_is_contiguous_across_partial_calls() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let mut seed = [7_u8; AES_CTR_SEED_SIZE];
        let mut seed_copy = seed;
        let mut one_shot =
            AesCtrKeyGenerator::from_seed(&mut seed).expect("AES hardware should be available");
        let mut split = AesCtrKeyGenerator::from_seed(&mut seed_copy)
            .expect("AES hardware should be available");

        let mut expected = [0_u8; 64];
        one_shot
            .fill_bytes(&mut expected)
            .expect("AES-CTR generation should succeed");

        let mut actual = [0_u8; 64];
        split
            .fill_bytes(&mut actual[..3])
            .expect("AES-CTR generation should succeed");
        split
            .fill_bytes(&mut actual[3..19])
            .expect("AES-CTR generation should succeed");
        split
            .fill_bytes(&mut actual[19..31])
            .expect("AES-CTR generation should succeed");
        split
            .fill_bytes(&mut actual[31..])
            .expect("AES-CTR generation should succeed");

        assert_eq!(actual, expected);
    }

    #[test]
    fn aes_ctr_from_seed_zeroizes_seed_buffer() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let mut seed = [0x5a_u8; AES_CTR_SEED_SIZE];
        let _rng =
            AesCtrKeyGenerator::from_seed(&mut seed).expect("AES hardware should be available");

        assert_eq!(seed, [0_u8; AES_CTR_SEED_SIZE]);
    }

    #[test]
    fn aes_ctr_reseeds_after_generation_interval() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let mut seed = [3_u8; AES_CTR_SEED_SIZE];
        let mut rng =
            AesCtrKeyGenerator::from_seed(&mut seed).expect("AES hardware should be available");
        rng.reseed_interval = 8;
        let mut out = [0_u8; 32];
        rng.fill_bytes(&mut out)
            .expect("fill across reseed boundary should succeed");
        assert!(rng.generated_since_reseed <= rng.reseed_interval);
    }

    #[test]
    fn aes_ctr_rejects_forked_state() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let mut seed = [3_u8; AES_CTR_SEED_SIZE];
        let mut rng =
            AesCtrKeyGenerator::from_seed(&mut seed).expect("AES hardware should be available");
        rng.fork_guard = rng.fork_guard.corrupted();
        let mut out = [0_u8; 1];
        assert!(matches!(
            rng.fill_bytes(&mut out),
            Err(super::Error::ForkDetected)
        ));
    }

    #[test]
    fn aes_ctr_state_stays_within_initial_target_size() {
        if !AesCtrKeyGenerator::hardware_available() {
            return;
        }

        let layout = AesCtrKeyGenerator::state_layout();
        assert!(
            layout.size <= 320,
            "AES-CTR state size {} exceeded 320-byte target",
            layout.size
        );
        assert!(
            layout.align >= 16,
            "AES-CTR state alignment {} should hold AES block vectors",
            layout.align
        );
    }
}
