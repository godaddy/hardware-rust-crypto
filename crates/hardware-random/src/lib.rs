//! Fast random byte generation for Asherah's hot key/nonce paths.
//!
//! This crate models the current Asherah strategy: seed a per-instance
//! `ChaCha20` CSPRNG from OS entropy, then generate DRKs and nonces without a
//! syscall per operation. It also exposes a hardware-only AES-CTR candidate
//! derived from the `rand_aes` AES-256-CTR-128 backend with software fallback
//! state removed.

#![allow(unsafe_code)]

mod aes_ctr;

use core::{mem::ManuallyDrop, ptr};
use rand::{RngCore as _, SeedableRng as _, TryRngCore as _};
use rand_chacha::ChaCha20Rng;
use zeroize::{Zeroize as _, Zeroizing};

/// AES-256 key / DRK size.
pub const KEY_SIZE: usize = 32;
/// AES-GCM nonce size.
pub const NONCE_SIZE: usize = 12;
/// AES-CTR generator seed size: 32-byte AES-256 key plus 16-byte counter.
pub const AES_CTR_SEED_SIZE: usize = 48;

const AES_BLOCK_SIZE: usize = 16;
const DEFAULT_RESEED_INTERVAL_BYTES: u64 = 1 << 30;

/// Random generation errors.
#[derive(Debug)]
pub enum Error {
    /// OS entropy failed while seeding the fast CSPRNG.
    OsEntropy(rand::rand_core::OsError),
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

/// Common key-generation contract for benchmarked CSPRNG backends.
pub trait KeyGenerator {
    /// Fills `out` with CSPRNG output.
    ///
    /// # Errors
    ///
    /// Returns entropy, hardware, or fork-detection failures.
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Error>;

    /// Generates a 32-byte AES key / DRK.
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

/// Reusable `ChaCha20` fast random generator.
///
/// One instance should be kept per thread or per worker. It is not `Sync` by
/// construction; callers should avoid sharing it behind a lock in the hot path.
pub struct ChaCha20KeyGenerator {
    rng: ManuallyDrop<ChaCha20Rng>,
    generated_since_reseed: u64,
    reseed_interval: u64,
    process_id: u32,
}

impl ChaCha20KeyGenerator {
    /// Seeds a new generator from OS entropy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if the platform entropy source cannot
    /// provide a `ChaCha20` seed.
    pub fn from_os_entropy() -> Result<Self, Error> {
        let mut seed: Zeroizing<<ChaCha20Rng as rand::SeedableRng>::Seed> =
            Zeroizing::new(Default::default());
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(Error::OsEntropy)?;
        Ok(Self {
            rng: ManuallyDrop::new(ChaCha20Rng::from_seed(*seed)),
            generated_since_reseed: 0,
            reseed_interval: DEFAULT_RESEED_INTERVAL_BYTES,
            process_id: current_process_id(),
        })
    }

    fn reseed_from_os_entropy(&mut self) -> Result<(), Error> {
        let mut seed: Zeroizing<<ChaCha20Rng as rand::SeedableRng>::Seed> =
            Zeroizing::new(Default::default());
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(Error::OsEntropy)?;
        // SAFETY: self.rng is live ChaCha20Rng storage and will be overwritten
        // before it is read again.
        unsafe { volatile_zero_value(&mut *self.rng) };
        self.rng = ManuallyDrop::new(ChaCha20Rng::from_seed(*seed));
        self.generated_since_reseed = 0;
        self.process_id = current_process_id();
        Ok(())
    }

    fn fill_after_lifecycle_checks(&mut self, mut out: &mut [u8]) -> Result<(), Error> {
        while !out.is_empty() {
            self.ensure_not_forked()?;
            if self.generated_since_reseed >= self.reseed_interval {
                self.reseed_from_os_entropy()?;
            }

            let remaining_before_reseed = self.reseed_interval - self.generated_since_reseed;
            let take = out
                .len()
                .min(usize::try_from(remaining_before_reseed).unwrap_or(usize::MAX));
            let (chunk, rest) = out.split_at_mut(take);
            self.rng.fill_bytes(chunk);
            self.generated_since_reseed += u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            out = rest;
        }
        Ok(())
    }

    fn ensure_not_forked(&self) -> Result<(), Error> {
        if self.process_id != current_process_id() {
            return Err(Error::ForkDetected);
        }
        Ok(())
    }
}

impl KeyGenerator for ChaCha20KeyGenerator {
    /// Fills `out` with CSPRNG output.
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.fill_after_lifecycle_checks(out)
    }
}

impl Drop for ChaCha20KeyGenerator {
    fn drop(&mut self) {
        // SAFETY: self.rng is live ChaCha20Rng storage and will not be used
        // again after this drop path.
        unsafe { volatile_zero_value(&mut *self.rng) };
        self.generated_since_reseed = 0;
        self.reseed_interval = 0;
        self.process_id = 0;
    }
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
    process_id: u32,
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
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(Error::OsEntropy)?;
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

        let Some(key) = seed.first_chunk::<KEY_SIZE>() else {
            return Err(Error::UnsupportedCpu {
                required: aes_ctr::REQUIRED_FEATURES,
            });
        };
        let Some(counter) = seed[KEY_SIZE..].first_chunk::<AES_BLOCK_SIZE>() else {
            return Err(Error::UnsupportedCpu {
                required: aes_ctr::REQUIRED_FEATURES,
            });
        };
        let backend = aes_ctr::Backend::new(key, counter).ok_or(Error::UnsupportedCpu {
            required: aes_ctr::REQUIRED_FEATURES,
        })?;

        Ok(Self {
            backend,
            buffer: [0_u8; AES_BLOCK_SIZE],
            buffer_pos: AES_BLOCK_SIZE,
            generated_since_reseed: 0,
            reseed_interval: DEFAULT_RESEED_INTERVAL_BYTES,
            process_id: current_process_id(),
        })
    }

    /// Generates a 32-byte AES key / DRK.
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

    fn reseed_from_os_entropy(&mut self) -> Result<(), Error> {
        let mut seed = Zeroizing::new([0_u8; AES_CTR_SEED_SIZE]);
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(Error::OsEntropy)?;
        self.backend = aes_ctr::Backend::new(
            seed[..KEY_SIZE]
                .first_chunk::<KEY_SIZE>()
                .ok_or(Error::UnsupportedCpu {
                    required: aes_ctr::REQUIRED_FEATURES,
                })?,
            seed[KEY_SIZE..]
                .first_chunk::<AES_BLOCK_SIZE>()
                .ok_or(Error::UnsupportedCpu {
                    required: aes_ctr::REQUIRED_FEATURES,
                })?,
        )
        .ok_or(Error::UnsupportedCpu {
            required: aes_ctr::REQUIRED_FEATURES,
        })?;
        self.buffer.zeroize();
        self.buffer_pos = AES_BLOCK_SIZE;
        self.generated_since_reseed = 0;
        self.process_id = current_process_id();
        Ok(())
    }

    fn ensure_not_forked(&self) -> Result<(), Error> {
        if self.process_id != current_process_id() {
            return Err(Error::ForkDetected);
        }
        Ok(())
    }

    fn fill_checked(&mut self, mut out: &mut [u8]) -> Result<(), Error> {
        while !out.is_empty() {
            self.ensure_not_forked()?;
            if self.generated_since_reseed >= self.reseed_interval {
                self.reseed_from_os_entropy()?;
            }

            let remaining_before_reseed = self.reseed_interval - self.generated_since_reseed;
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
        self.process_id = 0;
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

impl ChaCha20KeyGenerator {
    /// Generates a 32-byte AES key / DRK.
    ///
    /// # Errors
    ///
    /// Returns entropy or fork-detection failures.
    pub fn key_32(&mut self) -> Result<[u8; KEY_SIZE], Error> {
        KeyGenerator::key_32(self)
    }

    /// Generates a 12-byte AES-GCM nonce.
    ///
    /// # Errors
    ///
    /// Returns entropy or fork-detection failures.
    pub fn nonce_12(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        KeyGenerator::nonce_12(self)
    }
}

/// Backwards-compatible alias for the current default generator.
pub type FastRandom = ChaCha20KeyGenerator;

fn current_process_id() -> u32 {
    std::process::id()
}

unsafe fn volatile_zero_value<T>(value: &mut T) {
    let bytes = ptr::from_mut(value).cast::<u8>();
    for offset in 0..core::mem::size_of::<T>() {
        // SAFETY: value is live writable storage and offset stays within it.
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{
        AesCtrKeyGenerator, FastRandom, KeyGenerator, AES_BLOCK_SIZE, AES_CTR_SEED_SIZE, KEY_SIZE,
        NONCE_SIZE,
    };

    #[test]
    fn generates_key_and_nonce_lengths() {
        let mut rng = FastRandom::from_os_entropy().expect("OS entropy should be available");
        assert_eq!(
            rng.key_32().expect("key generation should succeed").len(),
            KEY_SIZE
        );
        assert_eq!(
            rng.nonce_12()
                .expect("nonce generation should succeed")
                .len(),
            NONCE_SIZE
        );
    }

    #[test]
    fn successive_outputs_differ() {
        let mut rng = FastRandom::from_os_entropy().expect("OS entropy should be available");
        let a = rng.key_32().expect("key generation should succeed");
        let b = rng.key_32().expect("key generation should succeed");
        assert_ne!(a, b);
    }

    #[test]
    fn chacha_reseeds_after_generation_interval() {
        let mut rng = FastRandom::from_os_entropy().expect("OS entropy should be available");
        rng.reseed_interval = 8;
        let mut out = [0_u8; 32];
        rng.fill_bytes(&mut out)
            .expect("fill across reseed boundary should succeed");
        assert!(rng.generated_since_reseed <= rng.reseed_interval);
    }

    #[test]
    fn chacha_rejects_forked_state() {
        let mut rng = FastRandom::from_os_entropy().expect("OS entropy should be available");
        rng.process_id = rng.process_id.wrapping_add(1);
        let mut out = [0_u8; 1];
        assert!(matches!(
            rng.fill_bytes(&mut out),
            Err(super::Error::ForkDetected)
        ));
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
        rng.process_id = rng.process_id.wrapping_add(1);
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
