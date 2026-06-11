//! Candidate AES-256-GCM API for the hardware-only `RustCrypto` fork.
//!
//! The implementation uses vendored hardware-only AES and GHASH paths on
//! supported `x86_64` and `aarch64` targets, with no software AES fallback
//! compiled into the reusable key state.

#![allow(unsafe_code)]

mod aes;
mod ghash;

use core::{
    marker::PhantomData,
    ptr::{self, NonNull},
};
use zeroize::Zeroize as _;

/// AES-256 key length in bytes.
pub const KEY_SIZE: usize = 32;
/// GCM nonce length in bytes.
pub const NONCE_SIZE: usize = 12;
/// GCM authentication tag length in bytes.
pub const TAG_SIZE: usize = 16;
const AES_BLOCK_SIZE: usize = 16;
const MAX_GCM_DATA_LEN: u64 = ((u32::MAX as u64) - 1) * AES_BLOCK_SIZE as u64;
const MAX_GHASH_INPUT_LEN: u64 = u64::MAX / 8;

/// Opaque key-state layout reported to callers before they allocate storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStateLayout {
    /// Required storage size in bytes.
    pub size: usize,
    /// Required storage alignment in bytes.
    pub align: usize,
}

/// Error type for the candidate AES-256-GCM API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The provided key is not exactly 32 bytes.
    InvalidKeyLength,
    /// The provided nonce is not exactly 12 bytes.
    InvalidNonceLength,
    /// Encryption failed.
    Encrypt,
    /// Decryption or authentication failed.
    Decrypt,
    /// The Asherah ciphertext layout is too short to contain tag plus nonce.
    CiphertextTooShort,
    /// Required AES/GHASH hardware support is unavailable.
    UnsupportedCpu,
    /// Caller-provided key-state storage is too small.
    KeyStateStorageTooSmall,
    /// Caller-provided key-state storage does not satisfy alignment.
    KeyStateStorageMisaligned,
    /// Input is too large for AES-GCM's counter or GHASH length limits.
    InputTooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength => f.write_str("invalid AES-256-GCM key length"),
            Self::InvalidNonceLength => f.write_str("invalid AES-GCM nonce length"),
            Self::Encrypt => f.write_str("AES-256-GCM encryption failed"),
            Self::Decrypt => f.write_str("AES-256-GCM authentication failed"),
            Self::CiphertextTooShort => f.write_str("ciphertext too short"),
            Self::UnsupportedCpu => {
                f.write_str("required AES-256-GCM hardware support is unavailable")
            }
            Self::KeyStateStorageTooSmall => f.write_str("key-state storage too small"),
            Self::KeyStateStorageMisaligned => f.write_str("key-state storage misaligned"),
            Self::InputTooLarge => f.write_str("AES-256-GCM input too large"),
        }
    }
}

impl std::error::Error for Error {}

struct KeyState {
    aes: aes::Aes256,
    ghash: ghash::GHashKey,
}

impl KeyState {
    fn init_in_place(dst: NonNull<Self>, key: &[u8; KEY_SIZE]) -> Result<(), Error> {
        if !HardwareAes256Gcm::hardware_available() {
            return Err(Error::UnsupportedCpu);
        }

        let dst = dst.as_ptr();
        // SAFETY: dst points to valid writable KeyState storage supplied by the
        // caller. The field pointer stays within that allocation.
        let aes_ptr = unsafe { ptr::addr_of_mut!((*dst).aes) };
        aes::Aes256::init_in_place(aes_ptr, key).ok_or(Error::UnsupportedCpu)?;

        let mut hash_subkey = [0_u8; TAG_SIZE];
        // SAFETY: aes_ptr was initialized successfully above and remains live.
        unsafe { (&*aes_ptr).encrypt_block(&mut hash_subkey) };
        // SAFETY: dst points to valid writable KeyState storage supplied by the
        // caller. The field pointer stays within that allocation.
        let ghash_ptr = unsafe { ptr::addr_of_mut!((*dst).ghash) };
        ghash::GHashKey::init_in_place(ghash_ptr, hash_subkey);
        hash_subkey.zeroize();
        Ok(())
    }

    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = nonce_from_slice(nonce)?;
        validate_gcm_lengths(aad.len(), plaintext.len())?;
        let capacity = plaintext
            .len()
            .checked_add(TAG_SIZE)
            .ok_or(Error::InputTooLarge)?;
        let mut in_out = Vec::with_capacity(capacity);
        in_out.extend_from_slice(plaintext);
        self.apply_ctr(&nonce, &mut in_out);
        let tag = self.tag(&nonce, aad, &in_out).ok_or(Error::Encrypt)?;
        in_out.extend_from_slice(&tag);
        Ok(in_out)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = nonce_from_slice(nonce)?;
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err(Error::Decrypt);
        }

        let tag_pos = ciphertext_and_tag.len() - TAG_SIZE;
        let (ciphertext, tag) = ciphertext_and_tag.split_at(tag_pos);
        validate_gcm_lengths(aad.len(), ciphertext.len())?;
        let expected = self.tag(&nonce, aad, ciphertext).ok_or(Error::Decrypt)?;
        if !constant_time_eq(&expected, tag) {
            return Err(Error::Decrypt);
        }

        let mut in_out = ciphertext.to_vec();
        self.apply_ctr(&nonce, &mut in_out);
        Ok(in_out)
    }

    fn tag(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<[u8; TAG_SIZE]> {
        let mut j0 = j0(nonce);
        let mut mask = j0;
        self.aes.encrypt_block(&mut mask);
        let mut tag = self.ghash.authenticate(aad, ciphertext)?;
        for (tag_byte, mask_byte) in tag.iter_mut().zip(mask) {
            *tag_byte ^= mask_byte;
        }
        j0.zeroize();
        mask.zeroize();
        Some(tag)
    }

    fn apply_ctr(&self, nonce: &[u8; NONCE_SIZE], data: &mut [u8]) {
        let mut counter = j0(nonce);
        increment_counter(&mut counter);

        for chunk in data.chunks_mut(16) {
            let mut keystream = counter;
            self.aes.encrypt_block(&mut keystream);
            for (byte, key_byte) in chunk.iter_mut().zip(keystream) {
                *byte ^= key_byte;
            }
            keystream.zeroize();
            increment_counter(&mut counter);
        }

        counter.zeroize();
    }
}

/// Caller-owned uninitialized storage for AES-256-GCM key state.
pub struct UninitKeyStateSlot<'a> {
    storage: &'a mut [u8],
}

impl<'a> UninitKeyStateSlot<'a> {
    /// Validates caller-provided storage for key-state initialization.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyStateStorageTooSmall`] or
    /// [`Error::KeyStateStorageMisaligned`] before any key material is touched.
    pub fn new(storage: &'a mut [u8]) -> Result<Self, Error> {
        let layout = HardwareAes256Gcm::key_state_layout();
        if storage.len() < layout.size {
            return Err(Error::KeyStateStorageTooSmall);
        }
        if !storage.as_ptr().addr().is_multiple_of(layout.align) {
            return Err(Error::KeyStateStorageMisaligned);
        }
        Ok(Self { storage })
    }
}

impl std::fmt::Debug for UninitKeyStateSlot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UninitKeyStateSlot")
            .field("len", &self.storage.len())
            .finish_non_exhaustive()
    }
}

/// Opaque initialized key-equivalent state in caller-owned storage.
pub struct OpaqueKeyState<'a> {
    ptr: NonNull<KeyState>,
    storage: &'a mut [u8],
    _marker: PhantomData<&'a mut KeyState>,
}

impl Drop for OpaqueKeyState<'_> {
    fn drop(&mut self) {
        // SAFETY: ptr was initialized by HardwareAes256GcmIn::new_in and is
        // unique for the lifetime represented by this handle.
        unsafe { core::ptr::drop_in_place(self.ptr.as_ptr()) };
        let size = HardwareAes256Gcm::key_state_layout().size;
        self.storage[..size].zeroize();
    }
}

impl std::fmt::Debug for OpaqueKeyState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueKeyState").finish_non_exhaustive()
    }
}

/// AES-256-GCM instance backed by caller-owned key-state storage.
pub struct HardwareAes256GcmIn<'a> {
    state: OpaqueKeyState<'a>,
}

impl<'a> HardwareAes256GcmIn<'a> {
    /// Initializes reusable AES-256-GCM state directly in caller-owned storage.
    ///
    /// # Errors
    ///
    /// Returns storage validation errors, [`Error::InvalidKeyLength`], or
    /// [`Error::UnsupportedCpu`].
    pub fn new_in(key: &[u8], slot: UninitKeyStateSlot<'a>) -> Result<Self, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength);
        }
        let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
        let UninitKeyStateSlot { storage } = slot;
        #[allow(clippy::cast_ptr_alignment)]
        let ptr = storage.as_mut_ptr().cast::<KeyState>();
        // SAFETY: UninitKeyStateSlot validated that storage has non-zero size,
        // sufficient length, and KeyState alignment.
        let ptr = unsafe { NonNull::new_unchecked(ptr) };
        KeyState::init_in_place(ptr, key)?;

        Ok(Self {
            state: OpaqueKeyState {
                ptr,
                storage,
                _marker: PhantomData,
            },
        })
    }

    /// Encrypts `plaintext` and returns `ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`] or [`Error::Encrypt`].
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().encrypt(nonce, aad, plaintext)
    }

    /// Decrypts `ciphertext || tag` and returns plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`] or [`Error::Decrypt`].
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.state_ref().decrypt(nonce, aad, ciphertext_and_tag)
    }

    /// Encrypts using Asherah's current wire layout: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt`].
    pub fn encrypt_asherah_layout(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = self.encrypt(nonce, &[], plaintext)?;
        out.extend_from_slice(nonce);
        Ok(out)
    }

    /// Decrypts Asherah's current wire layout: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`] if the input cannot contain a tag
    /// and nonce. Returns [`Error::InvalidNonceLength`] or [`Error::Decrypt`].
    pub fn decrypt_asherah_layout(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt(nonce, &[], ciphertext_and_tag)
    }

    fn state_ref(&self) -> &KeyState {
        // SAFETY: OpaqueKeyState owns a live initialized KeyState until drop.
        unsafe { self.state.ptr.as_ref() }
    }
}

impl std::fmt::Debug for HardwareAes256GcmIn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareAes256GcmIn")
            .finish_non_exhaustive()
    }
}

/// Owned reusable hardware-only AES-256-GCM key state.
pub struct HardwareAes256Gcm {
    state: Box<KeyState>,
}

impl HardwareAes256Gcm {
    /// Creates reusable AES-256-GCM state from a raw 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] if `key` is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength);
        }
        let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
        let mut state = Box::<KeyState>::new_uninit();
        // SAFETY: Box::new_uninit returns a non-null allocation for KeyState.
        let ptr = unsafe { NonNull::new_unchecked(state.as_mut_ptr()) };
        KeyState::init_in_place(ptr, key)?;
        // SAFETY: KeyState::init_in_place initialized the allocation on success.
        let state = unsafe { state.assume_init() };
        Ok(Self { state })
    }

    /// Returns whether all required AES-GCM hardware features are available.
    #[must_use]
    pub fn hardware_available() -> bool {
        aes::hardware_available() && ghash::hardware_available()
    }

    /// Returns the current size of the reusable key state.
    ///
    /// This is a benchmark/validation hook for the compact hardware-only state.
    #[must_use]
    pub const fn state_size() -> usize {
        std::mem::size_of::<KeyState>()
    }

    /// Returns the current opaque key-state layout.
    ///
    /// Reports the exact layout required for caller-provided opaque storage.
    #[must_use]
    pub const fn key_state_layout() -> KeyStateLayout {
        KeyStateLayout {
            size: std::mem::size_of::<KeyState>(),
            align: std::mem::align_of::<KeyState>(),
        }
    }

    /// Encrypts `plaintext` and returns `ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`] if `nonce` is not exactly 12 bytes.
    /// Returns [`Error::Encrypt`] if the backend rejects encryption.
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.encrypt(nonce, aad, plaintext)
    }

    /// Decrypts `ciphertext || tag` and returns plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`] if `nonce` is not exactly 12 bytes.
    /// Returns [`Error::Decrypt`] if authentication fails.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.state.decrypt(nonce, aad, ciphertext_and_tag)
    }

    /// Encrypts using Asherah's current wire layout: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt`].
    pub fn encrypt_asherah_layout(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = self.encrypt(nonce, &[], plaintext)?;
        out.extend_from_slice(nonce);
        Ok(out)
    }

    /// Decrypts Asherah's current wire layout: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`] if the input cannot contain a tag
    /// and nonce. Returns [`Error::InvalidNonceLength`] or [`Error::Decrypt`]
    /// for malformed nonce/authentication failures.
    pub fn decrypt_asherah_layout(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt(nonce, &[], ciphertext_and_tag)
    }
}

impl std::fmt::Debug for HardwareAes256Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareAes256Gcm").finish_non_exhaustive()
    }
}

fn nonce_from_slice(nonce: &[u8]) -> Result<[u8; NONCE_SIZE], Error> {
    nonce.try_into().map_err(|_| Error::InvalidNonceLength)
}

fn validate_gcm_lengths(aad_len: usize, data_len: usize) -> Result<(), Error> {
    if len_exceeds_u64_limit(data_len, MAX_GCM_DATA_LEN)
        || len_exceeds_u64_limit(aad_len, MAX_GHASH_INPUT_LEN)
        || len_exceeds_u64_limit(data_len, MAX_GHASH_INPUT_LEN)
    {
        return Err(Error::InputTooLarge);
    }
    Ok(())
}

fn len_exceeds_u64_limit(len: usize, limit: u64) -> bool {
    u64::try_from(len).map_or(true, |len| len > limit)
}

fn j0(nonce: &[u8; NONCE_SIZE]) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..NONCE_SIZE].copy_from_slice(nonce);
    out[15] = 1;
    out
}

fn increment_counter(counter: &mut [u8; 16]) {
    let mut low_bytes = [0_u8; 4];
    low_bytes.copy_from_slice(&counter[12..]);
    let mut low = u32::from_be_bytes(low_bytes);
    low = low.wrapping_add(1);
    counter[12..].copy_from_slice(&low.to_be_bytes());
    low_bytes.zeroize();
}

fn constant_time_eq(expected: &[u8; TAG_SIZE], actual: &[u8]) -> bool {
    if actual.len() != TAG_SIZE {
        return false;
    }

    let mut diff = 0_u8;
    for (left, right) in expected.iter().zip(actual) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::{Error, HardwareAes256Gcm, HardwareAes256GcmIn, UninitKeyStateSlot, NONCE_SIZE};

    #[repr(align(64))]
    struct AlignedStorage<const N: usize>([u8; N]);

    #[test]
    fn rejects_wrong_key_length() {
        let Err(err) = HardwareAes256Gcm::new(&[0_u8; 31]) else {
            panic!("31-byte key should be rejected");
        };
        assert_eq!(err, Error::InvalidKeyLength);
    }

    #[test]
    fn rejects_wrong_nonce_length() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let Err(err) = key.encrypt(&[0_u8; NONCE_SIZE - 1], &[], b"data") else {
            panic!("short nonce should be rejected");
        };
        assert_eq!(err, Error::InvalidNonceLength);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn rejects_inputs_that_exceed_gcm_counter_limit() {
        let max_data_len =
            usize::try_from(super::MAX_GCM_DATA_LEN).expect("64-bit usize holds GCM data limit");
        assert_eq!(
            super::validate_gcm_lengths(0, max_data_len + 1),
            Err(Error::InputTooLarge)
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn accepts_inputs_at_gcm_counter_limit() {
        let max_data_len =
            usize::try_from(super::MAX_GCM_DATA_LEN).expect("64-bit usize holds GCM data limit");
        assert_eq!(super::validate_gcm_lengths(0, max_data_len), Ok(()));
    }

    #[test]
    fn asherah_layout_round_trips() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let ciphertext = key
            .encrypt_asherah_layout(&nonce, b"plaintext")
            .expect("encryption should succeed");
        assert_eq!(
            key.decrypt_asherah_layout(&ciphertext)
                .expect("decryption should succeed"),
            b"plaintext"
        );
    }

    #[test]
    fn reports_nonzero_key_state_layout() {
        let layout = HardwareAes256Gcm::key_state_layout();
        assert!(layout.size >= super::KEY_SIZE);
        assert!(layout.align.is_power_of_two());
        assert!(layout.size <= 384);
        assert_eq!(layout.size, HardwareAes256Gcm::state_size());
    }

    #[test]
    fn caller_placed_key_state_round_trips_and_wipes_storage() {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut storage = AlignedStorage::<512>([0xa5; 512]);
        let nonce = [9_u8; NONCE_SIZE];

        {
            let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).expect("valid slot");
            let key = HardwareAes256GcmIn::new_in(&[7_u8; 32], slot).expect("valid test key");
            let ciphertext = key
                .encrypt_asherah_layout(&nonce, b"plaintext")
                .expect("encryption should succeed");
            assert_eq!(
                key.decrypt_asherah_layout(&ciphertext)
                    .expect("decryption should succeed"),
                b"plaintext"
            );
        }

        assert!(storage.0[..layout.size].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn caller_placed_key_state_validates_storage_before_key() {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut short = AlignedStorage::<512>([0_u8; 512]);
        let err = UninitKeyStateSlot::new(&mut short.0[..layout.size - 1])
            .expect_err("short storage should fail");
        assert_eq!(err, Error::KeyStateStorageTooSmall);

        let mut misaligned = AlignedStorage::<512>([0_u8; 512]);
        let start = 1;
        let end = start + layout.size;
        let err = UninitKeyStateSlot::new(&mut misaligned.0[start..end])
            .expect_err("misaligned storage should fail");
        assert_eq!(err, Error::KeyStateStorageMisaligned);
    }
}
