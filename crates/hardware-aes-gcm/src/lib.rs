//! Candidate AES-256-GCM API for the hardware-only `RustCrypto` fork.
//!
//! The implementation uses vendored hardware-only AES and GHASH paths on
//! supported `x86_64` and `aarch64` targets, with no software AES fallback
//! compiled into the reusable key state. See the repository `NOTICE` file for
//! upstream attribution of the vendored backends.
//!
//! # Constant-time notes
//!
//! All secret-dependent computation happens in the hardware AES and
//! carryless-multiply backends (see the `aes` and `ghash` module docs) or in
//! straight-line XOR/copy loops whose trip counts derive from public
//! lengths. Control flow in this module branches only on public values:
//! input and buffer lengths, CPU feature availability, and the accept/reject
//! outcome of the tag check - which is itself computed in constant time via
//! `subtle` and is public by definition (the caller learns it from the
//! `Result`). Nonces, counter blocks, and lengths are not secret in GCM;
//! keystream and tag material never feed a branch condition or memory index.
//! Data-independent instruction timing is taken as a hardware-vendor
//! guarantee; see `docs/design.md` for the full constant-time basis.

#![allow(unsafe_code)]

mod aes;
mod fork;
mod ghash;
mod nonce;

use core::{
    marker::PhantomData,
    ptr::{self, NonNull},
};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

/// AES-256 key length in bytes.
pub const KEY_SIZE: usize = 32;
/// GCM nonce length in bytes.
pub const NONCE_SIZE: usize = 12;
/// GCM authentication tag length in bytes.
pub const TAG_SIZE: usize = 16;
const AES_BLOCK_SIZE: usize = 16;
const PAR_BLOCKS: usize = aes::PAR_BLOCKS;
const PAR_BYTES: usize = PAR_BLOCKS * AES_BLOCK_SIZE;
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
#[non_exhaustive]
pub enum Error {
    /// The provided key is not exactly 32 bytes.
    InvalidKeyLength,
    /// The provided nonce is not exactly 12 bytes.
    InvalidNonceLength,
    /// Encryption failed.
    Encrypt,
    /// Decryption or authentication failed.
    Decrypt,
    /// The nonce-appended ciphertext layout is too short to contain tag plus nonce.
    CiphertextTooShort,
    /// Required AES/GHASH hardware support is unavailable.
    UnsupportedCpu,
    /// Caller-provided key-state storage is too small.
    KeyStateStorageTooSmall,
    /// Caller-provided key-state storage does not satisfy alignment.
    KeyStateStorageMisaligned,
    /// Input is too large for AES-GCM's counter or GHASH length limits.
    InputTooLarge,
    /// Caller-provided output buffer is too small for the plaintext.
    OutputTooSmall,
    /// The OS entropy source failed while generating a nonce.
    OsEntropy,
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
            Self::OutputTooSmall => f.write_str("plaintext output buffer too small"),
            Self::OsEntropy => f.write_str("OS entropy source failed during nonce generation"),
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
        if ghash::GHashKey::init_in_place(ghash_ptr, &mut hash_subkey).is_none() {
            // Unreachable: hardware_available() covered GHASH features above.
            // Defensively wipe the AES state already expanded in caller
            // storage before reporting failure.
            hash_subkey.zeroize();
            // SAFETY: aes_ptr was initialized above and is not used again.
            unsafe { ptr::drop_in_place(aes_ptr) };
            return Err(Error::UnsupportedCpu);
        }
        Ok(())
    }

    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let total = plaintext
            .len()
            .checked_add(TAG_SIZE)
            .ok_or(Error::InputTooLarge)?;
        let mut out = vec![0_u8; total];
        self.encrypt_to(nonce, aad, plaintext, &mut out)?;
        Ok(out)
    }

    fn encrypt_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = nonce_from_slice(nonce)?;
        validate_gcm_lengths(aad.len(), plaintext.len())?;
        let total = plaintext
            .len()
            .checked_add(TAG_SIZE)
            .ok_or(Error::InputTooLarge)?;
        if out.len() < total {
            return Err(Error::OutputTooSmall);
        }

        let (ciphertext, rest) = out.split_at_mut(plaintext.len());
        let tag = self
            .seal(&nonce, aad, plaintext, ciphertext)
            .ok_or(Error::Encrypt)?;
        rest[..TAG_SIZE].copy_from_slice(&tag);
        Ok(total)
    }

    /// Fused encrypt-and-authenticate: each ciphertext chunk feeds GHASH as
    /// soon as it is produced, so the message is traversed once.
    ///
    /// Constant time with respect to secrets: chunking and tail handling
    /// branch only on the public message length; the keystream is combined
    /// by straight-line XOR.
    fn seal(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Option<[u8; TAG_SIZE]> {
        debug_assert_eq!(plaintext.len(), ciphertext.len());
        let mut ghasher = ghash::Ghasher::new(&self.ghash)?;
        ghasher.absorb_padded(aad);

        let mut counter = j0(nonce);
        increment_counter(&mut counter);

        // The bulk region's AES keystream and GHASH run in one fused,
        // software-pipelined loop so the AES and carryless-multiply pipelines
        // overlap; the sub-batch tail is handled serially.
        let bulk = (plaintext.len() / PAR_BYTES) * PAR_BYTES;
        let (plaintext_bulk, plaintext_tail) = plaintext.split_at(bulk);
        let (ciphertext_bulk, ciphertext_tail) = ciphertext.split_at_mut(bulk);
        if !plaintext_bulk.is_empty() {
            ghasher.seal_bulk(
                self.aes.round_keys(),
                &mut counter,
                plaintext_bulk,
                ciphertext_bulk,
            );
        }
        if !plaintext_tail.is_empty() {
            ciphertext_tail.copy_from_slice(plaintext_tail);
            self.apply_ctr_serial(&mut counter, ciphertext_tail);
            ghasher.absorb_padded(ciphertext_tail);
        }

        let mut tag = ghasher.finalize(aad.len(), plaintext.len())?;
        let mut mask = j0(nonce);
        self.aes.encrypt_block(&mut mask);
        for (tag_byte, mask_byte) in tag.iter_mut().zip(mask.iter()) {
            *tag_byte ^= mask_byte;
        }
        mask.zeroize();
        Some(tag)
    }

    /// Generates the next eight keystream blocks with interleaved AES chains.
    fn keystream_batch(
        &self,
        counter: &mut [u8; AES_BLOCK_SIZE],
        keystream: &mut [[u8; AES_BLOCK_SIZE]; PAR_BLOCKS],
    ) {
        for block in keystream.iter_mut() {
            block.copy_from_slice(counter);
            increment_counter(counter);
        }
        self.aes.encrypt_blocks8(keystream);
    }

    /// Single-block in-place CTR for sub-batch tails.
    fn apply_ctr_serial(&self, counter: &mut [u8; AES_BLOCK_SIZE], data: &mut [u8]) {
        let mut keystream = Zeroizing::new([0_u8; AES_BLOCK_SIZE]);
        for block in data.chunks_mut(AES_BLOCK_SIZE) {
            keystream.copy_from_slice(counter);
            self.aes.encrypt_block(&mut keystream);
            for (byte, key_byte) in block.iter_mut().zip(keystream.iter()) {
                *byte ^= key_byte;
            }
            increment_counter(counter);
        }
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let plaintext_len = ciphertext_and_tag.len().saturating_sub(TAG_SIZE);
        let mut out = vec![0_u8; plaintext_len];
        let written = self.decrypt_to(nonce, aad, ciphertext_and_tag, &mut out)?;
        out.truncate(written);
        Ok(out)
    }

    fn decrypt_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = nonce_from_slice(nonce)?;
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err(Error::Decrypt);
        }

        let tag_pos = ciphertext_and_tag.len() - TAG_SIZE;
        let (ciphertext, tag) = ciphertext_and_tag.split_at(tag_pos);
        validate_gcm_lengths(aad.len(), ciphertext.len())?;
        if out.len() < ciphertext.len() {
            return Err(Error::OutputTooSmall);
        }
        let expected = self.tag(&nonce, aad, ciphertext).ok_or(Error::Decrypt)?;
        // The comparison itself is constant time (subtle); branching on its
        // result is sound because accept/reject is public output - the
        // caller observes it through the Result either way.
        if !constant_time_eq(&expected, tag) {
            return Err(Error::Decrypt);
        }

        let out = &mut out[..ciphertext.len()];
        out.copy_from_slice(ciphertext);
        self.apply_ctr(&nonce, out);
        Ok(ciphertext.len())
    }

    fn tag(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<[u8; TAG_SIZE]> {
        // j0 is derived from the public nonce; only the encrypted mask is
        // keystream-equivalent secret material.
        let mut mask = j0(nonce);
        self.aes.encrypt_block(&mut mask);
        let mut tag = self.ghash.authenticate(aad, ciphertext)?;
        // Iterate by reference: by-value array iteration would leave another
        // ephemeral copy of the secret mask on the stack.
        for (tag_byte, mask_byte) in tag.iter_mut().zip(mask.iter()) {
            *tag_byte ^= mask_byte;
        }
        mask.zeroize();
        Some(tag)
    }

    /// In-place CTR over `data` in interleaved eight-block batches.
    ///
    /// The counter is derived from the public nonce; only the keystream is
    /// secret, and the batch buffer wipes on drop.
    fn apply_ctr(&self, nonce: &[u8; NONCE_SIZE], data: &mut [u8]) {
        let mut counter = j0(nonce);
        increment_counter(&mut counter);

        let mut chunks = data.chunks_exact_mut(PAR_BYTES);
        if chunks.len() > 0 {
            // The batch buffer (and its wipe on drop) is scoped to messages
            // that actually use the interleaved path.
            let mut keystream = Zeroizing::new([[0_u8; AES_BLOCK_SIZE]; PAR_BLOCKS]);
            for chunk in &mut chunks {
                self.keystream_batch(&mut counter, &mut keystream);
                xor_blocks_in_place(chunk, &keystream);
            }
        }

        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            self.apply_ctr_serial(&mut counter, tail);
        }
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
///
/// The handle stores a raw pointer into the caller's storage instead of the
/// caller's `&mut` slice itself, so reads through the handle never coexist
/// with a live mutable reference under strict aliasing models.
pub struct OpaqueKeyState<'a> {
    storage: NonNull<u8>,
    _marker: PhantomData<&'a mut [u8]>,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    // Compile-time proof that KeyState stays thread-safe; the unsafe Send/Sync
    // impls below rely on it.
    assert_send_sync::<KeyState>();
};

// SAFETY: OpaqueKeyState exclusively owns the KeyState in the caller storage
// for 'a (the storage `&mut` borrow is consumed on construction). KeyState is
// Send + Sync (asserted above), there is no interior mutability, and all
// access outside drop is read-only, so moving the handle across threads is
// sound.
unsafe impl Send for OpaqueKeyState<'_> {}
// SAFETY: see the Send impl; a shared OpaqueKeyState only permits shared reads
// of a Sync pointee.
unsafe impl Sync for OpaqueKeyState<'_> {}

impl OpaqueKeyState<'_> {
    fn state_ptr(&self) -> *mut KeyState {
        // UninitKeyStateSlot validated KeyState alignment before this handle
        // could be constructed.
        #[allow(clippy::cast_ptr_alignment)]
        self.storage.as_ptr().cast::<KeyState>()
    }
}

impl Drop for OpaqueKeyState<'_> {
    fn drop(&mut self) {
        let size = HardwareAes256Gcm::key_state_layout().size;
        // KeyState's field Drop impls (Aes256, GHashKey) exist only to wipe
        // their own bytes and release no heap or handle resources, so they
        // are deliberately not run here: one volatile wipe of the whole
        // storage supersedes them and avoids a redundant second pass. If
        // KeyState ever gains a resource-owning field, this must go back to
        // drop_in_place before the wipe.
        // SAFETY: the caller storage remains borrowed for 'a, holds at least
        // `size` bytes, and is KeyState-aligned (validated at slot
        // construction).
        unsafe { volatile_wipe(self.storage.as_ptr(), size) };
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
    /// Lazily initialized on first use of a generated-nonce method, so
    /// caller-supplied-nonce users never draw OS entropy. Not part of the
    /// caller-placed key state, so it does not affect `key_state_layout`.
    nonce_gen: Option<nonce::NonceGen>,
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
        // The raw pointer is taken once and the `&mut` slice ends here, so the
        // handle never aliases a live mutable reference.
        // SAFETY: UninitKeyStateSlot validated that storage has non-zero size,
        // sufficient length, and KeyState alignment, so the pointer is
        // non-null.
        let storage = unsafe { NonNull::new_unchecked(storage.as_mut_ptr()) };
        #[allow(clippy::cast_ptr_alignment)]
        let state_ptr = storage.cast::<KeyState>();
        KeyState::init_in_place(state_ptr, key)?;

        Ok(Self {
            state: OpaqueKeyState {
                storage,
                _marker: PhantomData,
            },
            nonce_gen: None,
        })
    }

    /// Encrypts `plaintext` and returns `ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`], [`Error::InputTooLarge`], or
    /// [`Error::Encrypt`].
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().encrypt(nonce, aad, plaintext)
    }

    /// Encrypts `plaintext` into a caller-provided buffer as
    /// `ciphertext || tag` and returns the written length.
    ///
    /// No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE`, plus the same errors as [`Self::encrypt`].
    pub fn encrypt_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state_ref().encrypt_to(nonce, aad, plaintext, out)
    }

    /// Decrypts `ciphertext || tag` and returns plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`], [`Error::InputTooLarge`], or
    /// [`Error::Decrypt`].
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.state_ref().decrypt(nonce, aad, ciphertext_and_tag)
    }

    /// Decrypts `ciphertext || tag` into a caller-provided buffer and returns
    /// the plaintext length.
    ///
    /// The tag is verified before any plaintext is written, and only the
    /// caller-controlled `out` buffer receives plaintext bytes, so callers can
    /// keep decrypted key material in zeroizing or locked storage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than the
    /// plaintext, plus the same errors as [`Self::decrypt`].
    pub fn decrypt_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state_ref()
            .decrypt_to(nonce, aad, ciphertext_and_tag, out)
    }

    /// Encrypts and appends the nonce: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt`].
    pub fn encrypt_nonce_appended(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = self.encrypt(nonce, &[], plaintext)?;
        out.extend_from_slice(nonce);
        Ok(out)
    }

    /// Encrypts into a caller-provided buffer with the nonce appended and
    /// returns the written length. No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE + NONCE_SIZE`, plus the same errors as
    /// [`Self::encrypt`].
    pub fn encrypt_nonce_appended_to(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        encrypt_nonce_appended_to(self.state_ref(), nonce, plaintext, out)
    }

    /// Decrypts the nonce-appended layout: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`] if the input cannot contain a tag
    /// and nonce. Returns [`Error::InvalidNonceLength`],
    /// [`Error::InputTooLarge`], or [`Error::Decrypt`].
    pub fn decrypt_nonce_appended(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt(nonce, &[], ciphertext_and_tag)
    }

    /// Decrypts the nonce-appended layout into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decrypt_nonce_appended`] plus
    /// [`Error::OutputTooSmall`].
    pub fn decrypt_nonce_appended_to(&self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt_to(nonce, &[], ciphertext_and_tag, out)
    }

    /// Encrypts `plaintext` under a library-generated unique nonce, returning
    /// the nonce alongside `ciphertext || tag`.
    ///
    /// The nonce is drawn from a per-instance sequence (96-bit OS-seeded salt
    /// plus a 64-bit counter, re-salted on fork; see [`crate`]); callers do
    /// not manage nonce uniqueness. The returned nonce must be retained to
    /// decrypt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if seeding the nonce sequence fails, plus
    /// the same errors as [`Self::encrypt`].
    pub fn encrypt_with_generated_nonce(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_SIZE], Vec<u8>), Error> {
        let nonce = self.next_nonce()?;
        let ciphertext = self.state_ref().encrypt(&nonce, aad, plaintext)?;
        Ok((nonce, ciphertext))
    }

    /// Encrypts `plaintext` under a library-generated unique nonce and returns
    /// the self-framed `ciphertext || tag || nonce` layout (empty AAD).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt_with_generated_nonce`].
    pub fn encrypt_nonce_appended_generated(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        let mut out = self.state_ref().encrypt(&nonce, &[], plaintext)?;
        out.extend_from_slice(&nonce);
        Ok(out)
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        match self.nonce_gen {
            Some(ref mut g) => g.next(),
            None => self.nonce_gen.insert(nonce::NonceGen::new()?).next(),
        }
    }

    fn state_ref(&self) -> &KeyState {
        // SAFETY: OpaqueKeyState owns a live initialized KeyState until drop.
        unsafe { &*self.state.state_ptr() }
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
    /// Lazily initialized on first use of a generated-nonce method. Held
    /// outside `KeyState`, so it does not affect `state_size`/the boxed
    /// key-state footprint.
    nonce_gen: Option<nonce::NonceGen>,
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
        Ok(Self {
            state,
            nonce_gen: None,
        })
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
    /// Returns [`Error::InputTooLarge`] if `plaintext` or `aad` exceed the
    /// AES-GCM limits. Returns [`Error::Encrypt`] if the backend rejects
    /// encryption.
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.encrypt(nonce, aad, plaintext)
    }

    /// Encrypts `plaintext` into a caller-provided buffer as
    /// `ciphertext || tag` and returns the written length.
    ///
    /// No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE`, plus the same errors as [`Self::encrypt`].
    pub fn encrypt_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state.encrypt_to(nonce, aad, plaintext, out)
    }

    /// Decrypts `ciphertext || tag` and returns plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`] if `nonce` is not exactly 12 bytes.
    /// Returns [`Error::InputTooLarge`] if the ciphertext or `aad` exceed the
    /// AES-GCM limits. Returns [`Error::Decrypt`] if authentication fails.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.state.decrypt(nonce, aad, ciphertext_and_tag)
    }

    /// Decrypts `ciphertext || tag` into a caller-provided buffer and returns
    /// the plaintext length.
    ///
    /// The tag is verified before any plaintext is written, and only the
    /// caller-controlled `out` buffer receives plaintext bytes, so callers can
    /// keep decrypted key material in zeroizing or locked storage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than the
    /// plaintext, plus the same errors as [`Self::decrypt`].
    pub fn decrypt_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state.decrypt_to(nonce, aad, ciphertext_and_tag, out)
    }

    /// Encrypts and appends the nonce: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt`].
    pub fn encrypt_nonce_appended(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = self.encrypt(nonce, &[], plaintext)?;
        out.extend_from_slice(nonce);
        Ok(out)
    }

    /// Encrypts into a caller-provided buffer with the nonce appended and
    /// returns the written length. No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE + NONCE_SIZE`, plus the same errors as
    /// [`Self::encrypt`].
    pub fn encrypt_nonce_appended_to(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        encrypt_nonce_appended_to(&self.state, nonce, plaintext, out)
    }

    /// Decrypts the nonce-appended layout: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`] if the input cannot contain a tag
    /// and nonce. Returns [`Error::InvalidNonceLength`],
    /// [`Error::InputTooLarge`], or [`Error::Decrypt`] for malformed
    /// nonce/authentication failures.
    pub fn decrypt_nonce_appended(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt(nonce, &[], ciphertext_and_tag)
    }

    /// Decrypts the nonce-appended layout into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decrypt_nonce_appended`] plus
    /// [`Error::OutputTooSmall`].
    pub fn decrypt_nonce_appended_to(&self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt_to(nonce, &[], ciphertext_and_tag, out)
    }

    /// Encrypts `plaintext` under a library-generated unique nonce, returning
    /// the nonce alongside `ciphertext || tag`.
    ///
    /// The nonce is drawn from a per-instance sequence (96-bit OS-seeded salt
    /// plus a 64-bit counter, re-salted on fork; see [`crate`]); callers do
    /// not manage nonce uniqueness. The returned nonce must be retained to
    /// decrypt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if seeding the nonce sequence fails, plus
    /// the same errors as [`Self::encrypt`].
    pub fn encrypt_with_generated_nonce(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_SIZE], Vec<u8>), Error> {
        let nonce = self.next_nonce()?;
        let ciphertext = self.state.encrypt(&nonce, aad, plaintext)?;
        Ok((nonce, ciphertext))
    }

    /// Encrypts `plaintext` under a library-generated unique nonce and returns
    /// the self-framed `ciphertext || tag || nonce` layout (empty AAD).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt_with_generated_nonce`].
    pub fn encrypt_nonce_appended_generated(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        let mut out = self.state.encrypt(&nonce, &[], plaintext)?;
        out.extend_from_slice(&nonce);
        Ok(out)
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        match self.nonce_gen {
            Some(ref mut g) => g.next(),
            None => self.nonce_gen.insert(nonce::NonceGen::new()?).next(),
        }
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

/// Volatile wipe of caller-placed key-state storage using the widest stores
/// the pointer alignment allows.
///
/// # Safety
///
/// `bytes..bytes + len` must be writable.
#[allow(clippy::cast_ptr_alignment)] // Wide stores are alignment-checked at runtime.
unsafe fn volatile_wipe(bytes: *mut u8, len: usize) {
    let mut offset = 0_usize;
    if bytes.addr().is_multiple_of(core::mem::align_of::<u128>()) {
        while offset + core::mem::size_of::<u128>() <= len {
            // SAFETY: in bounds per the caller contract and aligned per the
            // check above.
            unsafe { ptr::write_volatile(bytes.add(offset).cast::<u128>(), 0) };
            offset += core::mem::size_of::<u128>();
        }
    }
    for offset in offset..len {
        // SAFETY: in bounds per the caller contract.
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Shared no-alloc nonce-appended encryption: `ciphertext || tag || nonce`.
fn encrypt_nonce_appended_to(
    state: &KeyState,
    nonce: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let total = plaintext
        .len()
        .checked_add(TAG_SIZE + NONCE_SIZE)
        .ok_or(Error::InputTooLarge)?;
    if out.len() < total {
        return Err(Error::OutputTooSmall);
    }
    let written = state.encrypt_to(nonce, &[], plaintext, out)?;
    // encrypt_to validated the nonce length, so this copy is exactly
    // NONCE_SIZE bytes.
    out[written..total].copy_from_slice(nonce);
    Ok(total)
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

/// Operates on the public nonce-derived counter block; constant time anyway
/// (`wrapping_add` carries without branching).
pub(crate) fn increment_counter(counter: &mut [u8; 16]) {
    let mut low_bytes = [0_u8; 4];
    low_bytes.copy_from_slice(&counter[12..]);
    let low = u32::from_be_bytes(low_bytes).wrapping_add(1);
    counter[12..].copy_from_slice(&low.to_be_bytes());
}

/// XORs one batch of keystream blocks into `data` (whole batch, in place).
///
/// Keystream blocks are iterated by reference so no extra ephemeral copy of
/// the secret keystream lands on the stack.
fn xor_blocks_in_place(data: &mut [u8], keystream: &[[u8; AES_BLOCK_SIZE]; PAR_BLOCKS]) {
    debug_assert_eq!(data.len(), PAR_BYTES);
    for (block, key_block) in data.chunks_mut(AES_BLOCK_SIZE).zip(keystream.iter()) {
        for (byte, key_byte) in block.iter_mut().zip(key_block.iter()) {
            *byte ^= key_byte;
        }
    }
}

fn constant_time_eq(expected: &[u8; TAG_SIZE], actual: &[u8]) -> bool {
    // subtle's slice impl compares lengths first (length is public) and then
    // the contents in constant time behind optimization barriers, so the
    // compiler cannot reintroduce an early-exit byte comparison. This is the
    // one place in the crate where secret-derived values are compared.
    expected.as_slice().ct_eq(actual).into()
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
    fn caller_placed_key_state_rejects_wrong_key_length() {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut storage = AlignedStorage::<512>([0_u8; 512]);
        let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).expect("valid slot");
        let Err(err) = HardwareAes256GcmIn::new_in(&[0_u8; 31], slot) else {
            panic!("31-byte key should be rejected");
        };
        assert_eq!(err, Error::InvalidKeyLength);
    }

    #[test]
    fn rejects_ciphertext_shorter_than_tag() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let Err(err) = key.decrypt(&[0_u8; NONCE_SIZE], &[], &[0_u8; super::TAG_SIZE - 1]) else {
            panic!("input shorter than the tag should be rejected");
        };
        assert_eq!(err, Error::Decrypt);
    }

    #[test]
    fn rejects_nonce_appended_shorter_than_tag_and_nonce() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let short = [0_u8; super::TAG_SIZE + NONCE_SIZE - 1];
        let Err(err) = key.decrypt_nonce_appended(&short) else {
            panic!("input shorter than tag plus nonce should be rejected");
        };
        assert_eq!(err, Error::CiphertextTooShort);

        let mut out = [0_u8; 64];
        let Err(err) = key.decrypt_nonce_appended_to(&short, &mut out) else {
            panic!("input shorter than tag plus nonce should be rejected");
        };
        assert_eq!(err, Error::CiphertextTooShort);
    }

    #[test]
    fn decrypt_to_writes_plaintext_into_caller_buffer() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let ciphertext = key
            .encrypt(&nonce, b"aad", b"plaintext")
            .expect("encryption should succeed");

        let mut exact = [0_u8; 9];
        let written = key
            .decrypt_to(&nonce, b"aad", &ciphertext, &mut exact)
            .expect("decryption into an exact-size buffer should succeed");
        assert_eq!(written, 9);
        assert_eq!(&exact, b"plaintext");

        let mut oversized = [0xff_u8; 32];
        let written = key
            .decrypt_to(&nonce, b"aad", &ciphertext, &mut oversized)
            .expect("decryption into a larger buffer should succeed");
        assert_eq!(&oversized[..written], b"plaintext");

        let mut short = [0_u8; 8];
        let Err(err) = key.decrypt_to(&nonce, b"aad", &ciphertext, &mut short) else {
            panic!("short output buffer should be rejected");
        };
        assert_eq!(err, Error::OutputTooSmall);
        assert_eq!(short, [0_u8; 8], "no plaintext may leak into short buffers");
    }

    #[test]
    fn encrypt_to_matches_allocating_encrypt() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let plaintext = [0x5a_u8; 200];
        let expected = key
            .encrypt(&nonce, b"aad", &plaintext)
            .expect("encryption should succeed");

        let mut exact = [0_u8; 200 + super::TAG_SIZE];
        let written = key
            .encrypt_to(&nonce, b"aad", &plaintext, &mut exact)
            .expect("encryption into an exact-size buffer should succeed");
        assert_eq!(written, exact.len());
        assert_eq!(exact.as_slice(), expected.as_slice());

        let mut oversized = [0_u8; 256];
        let written = key
            .encrypt_to(&nonce, b"aad", &plaintext, &mut oversized)
            .expect("encryption into a larger buffer should succeed");
        assert_eq!(&oversized[..written], expected.as_slice());

        let mut short = [0_u8; 200 + super::TAG_SIZE - 1];
        let Err(err) = key.encrypt_to(&nonce, b"aad", &plaintext, &mut short) else {
            panic!("short output buffer should be rejected");
        };
        assert_eq!(err, Error::OutputTooSmall);
        assert!(
            short.iter().all(|byte| *byte == 0),
            "no ciphertext may be written into short buffers"
        );
    }

    #[test]
    fn encrypt_nonce_appended_to_matches_allocating_variant() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let expected = key
            .encrypt_nonce_appended(&nonce, b"plaintext")
            .expect("encryption should succeed");

        let mut out = [0_u8; 9 + super::TAG_SIZE + NONCE_SIZE];
        let written = key
            .encrypt_nonce_appended_to(&nonce, b"plaintext", &mut out)
            .expect("encryption should succeed");
        assert_eq!(written, out.len());
        assert_eq!(out.as_slice(), expected.as_slice());

        let mut short = [0_u8; 9 + super::TAG_SIZE + NONCE_SIZE - 1];
        let Err(err) = key.encrypt_nonce_appended_to(&nonce, b"plaintext", &mut short) else {
            panic!("short output buffer should be rejected");
        };
        assert_eq!(err, Error::OutputTooSmall);
    }

    #[test]
    fn decrypt_nonce_appended_to_round_trips() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let data = key
            .encrypt_nonce_appended(&nonce, b"plaintext")
            .expect("encryption should succeed");

        let mut out = [0_u8; 32];
        let written = key
            .decrypt_nonce_appended_to(&data, &mut out)
            .expect("decryption should succeed");
        assert_eq!(&out[..written], b"plaintext");
    }

    #[test]
    fn generated_nonce_round_trips_and_is_unique() {
        let mut key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");

        let (nonce_a, ct_a) = key
            .encrypt_with_generated_nonce(b"aad", b"plaintext")
            .expect("encryption should succeed");
        let (nonce_b, _ct_b) = key
            .encrypt_with_generated_nonce(b"aad", b"plaintext")
            .expect("encryption should succeed");

        // Same key + same plaintext must not reuse a nonce.
        assert_ne!(nonce_a, nonce_b, "generated nonces must be unique");
        // The returned nonce decrypts its ciphertext.
        assert_eq!(
            key.decrypt(&nonce_a, b"aad", &ct_a)
                .expect("decryption should succeed"),
            b"plaintext"
        );
    }

    #[test]
    fn generated_nonce_appended_layout_round_trips() {
        let mut key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let blob = key
            .encrypt_nonce_appended_generated(b"plaintext")
            .expect("encryption should succeed");
        assert_eq!(
            blob.len(),
            b"plaintext".len() + super::TAG_SIZE + NONCE_SIZE
        );
        assert_eq!(
            key.decrypt_nonce_appended(&blob)
                .expect("decryption should succeed"),
            b"plaintext"
        );
    }

    #[test]
    fn caller_placed_generated_nonce_round_trips() {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut storage = AlignedStorage::<512>([0_u8; 512]);
        let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).expect("valid slot");
        let mut key = HardwareAes256GcmIn::new_in(&[7_u8; 32], slot).expect("valid test key");
        let (nonce, ct) = key
            .encrypt_with_generated_nonce(&[], b"plaintext")
            .expect("encryption should succeed");
        assert_eq!(
            key.decrypt(&nonce, &[], &ct)
                .expect("decryption should succeed"),
            b"plaintext"
        );
    }

    #[test]
    fn generated_nonce_does_not_change_key_state_size() {
        // The nonce generator lives on the handle, not the placed key state.
        assert_eq!(HardwareAes256Gcm::key_state_layout().size, 368);
        assert_eq!(HardwareAes256Gcm::state_size(), 368);
    }

    #[test]
    fn caller_placed_key_state_is_usable_across_threads() {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut storage = AlignedStorage::<512>([0_u8; 512]);
        let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).expect("valid slot");
        let key = HardwareAes256GcmIn::new_in(&[7_u8; 32], slot).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let ciphertext = key
            .encrypt(&nonce, &[], b"plaintext")
            .expect("encryption should succeed");

        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    assert_eq!(
                        key.decrypt(&nonce, &[], &ciphertext)
                            .expect("shared decryption should succeed"),
                        b"plaintext"
                    );
                });
            }
        });
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
    fn nonce_appended_round_trips() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let ciphertext = key
            .encrypt_nonce_appended(&nonce, b"plaintext")
            .expect("encryption should succeed");
        assert_eq!(
            key.decrypt_nonce_appended(&ciphertext)
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
                .encrypt_nonce_appended(&nonce, b"plaintext")
                .expect("encryption should succeed");
            assert_eq!(
                key.decrypt_nonce_appended(&ciphertext)
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
