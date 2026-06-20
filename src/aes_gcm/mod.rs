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
mod siv;

/// Re-exported only under `ct-verify` so the constant-time verifier can reach
/// the `mulx` wrapper and its non-vacuity control as public symbols; not part of
/// the shipped API.
#[cfg(feature = "ct-verify")]
pub use ghash::{ct_verify_leaky_control, ct_verify_mulx};

/// Re-exported only under `saw-verify` so SAW can reach the field-multiply
/// wrappers as public symbols; not part of the shipped API.
#[cfg(feature = "saw-verify")]
pub use ghash::{
    saw_field_mul, saw_field_mul_commutes, saw_field_mul_left_linear, saw_field_mul_right_linear,
};

pub use siv::{
    HardwareAes256GcmSiv, HardwareAes256GcmSivIn, HardwareAes256GcmSivKeyState,
    SivUninitKeyStateSlot,
};

use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{self, NonNull},
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

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

    fn encrypt_nonce_appended(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.encrypt_envelope(nonce, &[], plaintext)
    }

    fn encrypt_envelope(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = nonce_from_slice(nonce)?;
        validate_gcm_lengths(aad.len(), plaintext.len())?;
        let total = plaintext
            .len()
            .checked_add(TAG_SIZE + NONCE_SIZE)
            .ok_or(Error::InputTooLarge)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(plaintext);
        let Some(tag) = self.seal_in_place(&nonce, aad, &mut out) else {
            out.zeroize();
            return Err(Error::Encrypt);
        };
        append_tag_nonce(&mut out, &tag, &nonce);
        Ok(out)
    }

    fn encrypt_envelope_to(
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
            .checked_add(TAG_SIZE + NONCE_SIZE)
            .ok_or(Error::InputTooLarge)?;
        if out.len() < total {
            return Err(Error::OutputTooSmall);
        }

        let ciphertext_tag_len = plaintext.len() + TAG_SIZE;
        self.encrypt_to(&nonce, aad, plaintext, &mut out[..ciphertext_tag_len])?;
        out[ciphertext_tag_len..total].copy_from_slice(&nonce);
        Ok(total)
    }

    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    fn encrypt_nonce_appended_in_place(
        &self,
        nonce: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let nonce = nonce_from_slice(nonce)?;
        validate_gcm_lengths(0, in_out.len())?;
        let total = in_out
            .len()
            .checked_add(TAG_SIZE + NONCE_SIZE)
            .ok_or(Error::InputTooLarge)?;
        if in_out.capacity() < total {
            in_out.reserve_exact(total - in_out.len());
        }
        let Some(tag) = self.seal_in_place(&nonce, &[], in_out.as_mut_slice()) else {
            in_out.zeroize();
            return Err(Error::Encrypt);
        };
        append_tag_nonce(in_out, &tag, &nonce);
        Ok(())
    }

    fn decrypt_envelope(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt(nonce, aad, ciphertext_and_tag)
    }

    fn decrypt_envelope_to(&self, aad: &[u8], data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if data.len() < TAG_SIZE + NONCE_SIZE {
            return Err(Error::CiphertextTooShort);
        }
        let nonce_pos = data.len() - NONCE_SIZE;
        let (ciphertext_and_tag, nonce) = data.split_at(nonce_pos);
        self.decrypt_to(nonce, aad, ciphertext_and_tag, out)
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
        Some(tag)
    }

    /// In-place encrypt-and-authenticate. `data` enters as plaintext and exits
    /// as ciphertext, so allocating APIs can avoid zero-filling an output Vec
    /// before immediately overwriting it.
    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
    ) -> Option<[u8; TAG_SIZE]> {
        let mut ghasher = ghash::Ghasher::new(&self.ghash)?;
        ghasher.absorb_padded(aad);

        let mut counter = j0(nonce);
        increment_counter(&mut counter);

        let bulk = (data.len() / PAR_BYTES) * PAR_BYTES;
        let (data_bulk, data_tail) = data.split_at_mut(bulk);
        if !data_bulk.is_empty() {
            ghasher.seal_in_place_bulk(self.aes.round_keys(), &mut counter, data_bulk);
        }
        if !data_tail.is_empty() {
            let full = (data_tail.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
            let (data_tail_blocks, data_partial) = data_tail.split_at_mut(full);
            if !data_tail_blocks.is_empty() {
                ghasher.seal_in_place_tail_blocks(
                    self.aes.round_keys(),
                    &mut counter,
                    data_tail_blocks,
                );
            }
            if !data_partial.is_empty() {
                self.apply_ctr_serial(&mut counter, data_partial);
                ghasher.absorb_padded(data_partial);
            }
        }

        let mut tag = ghasher.finalize(aad.len(), data.len())?;
        let mut mask = j0(nonce);
        self.aes.encrypt_block(&mut mask);
        for (tag_byte, mask_byte) in tag.iter_mut().zip(mask.iter()) {
            *tag_byte ^= mask_byte;
        }
        Some(tag)
    }

    /// Single-block in-place CTR for sub-batch tails.
    fn apply_ctr_serial(&self, counter: &mut [u8; AES_BLOCK_SIZE], data: &mut [u8]) {
        let mut keystream = [0_u8; AES_BLOCK_SIZE];
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
        let nonce = nonce_from_slice(nonce)?;
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err(Error::Decrypt);
        }

        let tag_pos = ciphertext_and_tag.len() - TAG_SIZE;
        let (ciphertext, tag) = ciphertext_and_tag.split_at(tag_pos);
        validate_gcm_lengths(aad.len(), ciphertext.len())?;
        let mut out = Vec::with_capacity(ciphertext.len());
        out.extend_from_slice(ciphertext);
        let Some(expected) = self.open_in_place(&nonce, aad, &mut out) else {
            out.zeroize();
            return Err(Error::Decrypt);
        };
        if !constant_time_eq(&expected, tag) {
            out.zeroize();
            return Err(Error::Decrypt);
        }
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
        let out = &mut out[..ciphertext.len()];
        let Some(expected) = self.open(&nonce, aad, ciphertext, out) else {
            out.zeroize();
            return Err(Error::Decrypt);
        };
        // The comparison itself is constant time (subtle); branching on its
        // result is sound because accept/reject is public output - the
        // caller observes it through the Result either way. On rejection, wipe
        // the transient plaintext written before authentication completed.
        if !constant_time_eq(&expected, tag) {
            out.zeroize();
            return Err(Error::Decrypt);
        }

        Ok(ciphertext.len())
    }

    /// Detached seal: encrypt `plaintext` under a caller-supplied `nonce` and
    /// `aad`, returning `(ciphertext, tag)` separately with no nonce appended.
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    fn seal_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_SIZE]), Error> {
        let nonce = nonce_from_slice(nonce)?;
        validate_gcm_lengths(aad.len(), plaintext.len())?;
        let mut ciphertext = vec![0_u8; plaintext.len()];
        let Some(tag) = self.seal(&nonce, aad, plaintext, &mut ciphertext) else {
            ciphertext.zeroize();
            return Err(Error::Encrypt);
        };
        Ok((ciphertext, tag))
    }

    /// In-place detached seal: `data` enters as plaintext and exits as
    /// ciphertext; the authentication tag is returned. No nonce is appended.
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    fn seal_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_SIZE], Error> {
        let nonce = nonce_from_slice(nonce)?;
        validate_gcm_lengths(aad.len(), data.len())?;
        let Some(tag) = self.seal_in_place(&nonce, aad, data) else {
            data.zeroize();
            return Err(Error::Encrypt);
        };
        Ok(tag)
    }

    /// Detached open: authenticate `ciphertext` against the supplied `tag`
    /// (constant time) under `nonce`/`aad` and return the plaintext. The
    /// transient plaintext is zeroized on authentication failure.
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    fn open_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = nonce_from_slice(nonce)?;
        if tag.len() != TAG_SIZE {
            return Err(Error::Decrypt);
        }
        validate_gcm_lengths(aad.len(), ciphertext.len())?;
        let mut out = vec![0_u8; ciphertext.len()];
        let Some(expected) = self.open(&nonce, aad, ciphertext, &mut out) else {
            out.zeroize();
            return Err(Error::Decrypt);
        };
        if !constant_time_eq(&expected, tag) {
            out.zeroize();
            return Err(Error::Decrypt);
        }
        Ok(out)
    }

    /// In-place detached open: `data` enters as ciphertext and exits as
    /// plaintext once authenticated against `tag` (constant time). On
    /// authentication failure `data` is zeroized and `Err` returned.
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    fn open_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let nonce = nonce_from_slice(nonce)?;
        if tag.len() != TAG_SIZE {
            return Err(Error::Decrypt);
        }
        validate_gcm_lengths(aad.len(), data.len())?;
        let Some(expected) = self.open_in_place(&nonce, aad, data) else {
            data.zeroize();
            return Err(Error::Decrypt);
        };
        if !constant_time_eq(&expected, tag) {
            data.zeroize();
            return Err(Error::Decrypt);
        }
        Ok(())
    }

    /// Fused authenticate-and-decrypt: bulk ciphertext chunks feed GHASH while
    /// their CTR plaintext is written to the caller's buffer. The caller must
    /// zeroize `plaintext` if the returned tag does not match the supplied tag.
    fn open(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Option<[u8; TAG_SIZE]> {
        debug_assert_eq!(ciphertext.len(), plaintext.len());
        let mut ghasher = ghash::Ghasher::new(&self.ghash)?;
        ghasher.absorb_padded(aad);

        let mut counter = j0(nonce);
        increment_counter(&mut counter);

        // Decrypt writes plaintext before the final tag check. This matches
        // high-performance AEAD APIs such as ring's in-place open path; the
        // public wrapper wipes the written range on authentication failure.
        let bulk = (ciphertext.len() / PAR_BYTES) * PAR_BYTES;
        let (ciphertext_bulk, ciphertext_tail) = ciphertext.split_at(bulk);
        let (plaintext_bulk, plaintext_tail) = plaintext.split_at_mut(bulk);
        if !ciphertext_bulk.is_empty() {
            ghasher.open_bulk(
                self.aes.round_keys(),
                &mut counter,
                ciphertext_bulk,
                plaintext_bulk,
            );
        }
        if !ciphertext_tail.is_empty() {
            ghasher.absorb_padded(ciphertext_tail);
            plaintext_tail.copy_from_slice(ciphertext_tail);
            self.apply_ctr_serial(&mut counter, plaintext_tail);
        }

        let mut tag = ghasher.finalize(aad.len(), ciphertext.len())?;
        let mut mask = j0(nonce);
        self.aes.encrypt_block(&mut mask);
        for (tag_byte, mask_byte) in tag.iter_mut().zip(mask.iter()) {
            *tag_byte ^= mask_byte;
        }
        Some(tag)
    }

    /// In-place authenticate-and-decrypt. `data` enters as ciphertext and
    /// exits as plaintext. The caller must zeroize `data` if the returned tag
    /// does not match the supplied tag.
    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
    ) -> Option<[u8; TAG_SIZE]> {
        let mut ghasher = ghash::Ghasher::new(&self.ghash)?;
        ghasher.absorb_padded(aad);

        let mut counter = j0(nonce);
        increment_counter(&mut counter);

        let bulk = (data.len() / PAR_BYTES) * PAR_BYTES;
        let (data_bulk, data_tail) = data.split_at_mut(bulk);
        if !data_bulk.is_empty() {
            ghasher.open_in_place_bulk(self.aes.round_keys(), &mut counter, data_bulk);
        }
        if !data_tail.is_empty() {
            ghasher.absorb_padded(data_tail);
            self.apply_ctr_serial(&mut counter, data_tail);
        }

        let mut tag = ghasher.finalize(aad.len(), data.len())?;
        let mut mask = j0(nonce);
        self.aes.encrypt_block(&mut mask);
        for (tag_byte, mask_byte) in tag.iter_mut().zip(mask.iter()) {
            *tag_byte ^= mask_byte;
        }
        Some(tag)
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

#[inline]
fn init_key_state_at(key: &[u8], state: NonNull<KeyState>) -> Result<(), Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeyLength);
    }
    let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
    KeyState::init_in_place(state, key)
}

fn init_key_state_in_slot(key: &[u8], slot: UninitKeyStateSlot<'_>) -> Result<NonNull<u8>, Error> {
    let UninitKeyStateSlot { storage } = slot;
    // The raw pointer is taken once and the `&mut` slice ends here, so the
    // handle never aliases a live mutable reference.
    // SAFETY: UninitKeyStateSlot validated that storage has non-zero size,
    // sufficient length, and KeyState alignment, so the pointer is non-null.
    let storage = unsafe { NonNull::new_unchecked(storage.as_mut_ptr()) };
    #[allow(clippy::cast_ptr_alignment)]
    let state = storage.cast::<KeyState>();
    init_key_state_at(key, state)?;
    Ok(storage)
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
    /// Lazily initialized on the first encrypting default API call. Not part
    /// of the caller-placed key state, so it does not affect
    /// `key_state_layout`.
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
        let storage = init_key_state_in_slot(key, slot)?;
        Ok(Self {
            state: OpaqueKeyState {
                storage,
                _marker: PhantomData,
            },
            nonce_gen: None,
        })
    }

    /// Encrypts `plaintext` and returns `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails, plus
    /// [`Error::InputTooLarge`] or [`Error::Encrypt`].
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        self.state_ref().encrypt_envelope(&nonce, aad, plaintext)
    }

    /// Encrypts `plaintext` into a caller-provided buffer as
    /// `ciphertext || tag || nonce` and returns the written length.
    ///
    /// No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails,
    /// [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE + NONCE_SIZE`, plus [`Error::InputTooLarge`]
    /// or [`Error::Encrypt`].
    pub fn encrypt_to(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = self.next_nonce()?;
        self.state_ref()
            .encrypt_envelope_to(&nonce, aad, plaintext, out)
    }

    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_with_nonce(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
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
    /// `plaintext.len() + TAG_SIZE`, plus the same errors as
    /// [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_with_nonce_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state_ref().encrypt_to(nonce, aad, plaintext, out)
    }

    /// Decrypts `ciphertext || tag || nonce` and returns plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`], [`Error::InputTooLarge`], or
    /// [`Error::Decrypt`].
    pub fn decrypt(&self, aad: &[u8], ciphertext_tag_nonce: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().decrypt_envelope(aad, ciphertext_tag_nonce)
    }

    /// Decrypts `ciphertext || tag || nonce` into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// Decrypts into `out` before the final tag comparison so CTR and GHASH can
    /// run in one fused pass. If authentication fails, the plaintext-length
    /// prefix of `out` is zeroized before returning [`Error::Decrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`], [`Error::OutputTooSmall`],
    /// [`Error::InputTooLarge`], or [`Error::Decrypt`].
    pub fn decrypt_to(
        &self,
        aad: &[u8],
        ciphertext_tag_nonce: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state_ref()
            .decrypt_envelope_to(aad, ciphertext_tag_nonce, out)
    }

    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn decrypt_with_nonce(
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
    /// Decrypts into `out` before the final tag comparison so CTR and GHASH can
    /// run in one fused pass. If authentication fails, the plaintext-length
    /// prefix of `out` is zeroized before returning [`Error::Decrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than the
    /// plaintext, plus the same errors as [`Self::decrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn decrypt_with_nonce_to(
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
    /// Returns the same errors as [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_nonce_appended(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().encrypt_nonce_appended(nonce, plaintext)
    }

    /// Encrypts the plaintext already in `in_out` in place, then appends the
    /// tag and nonce so the final layout is `ciphertext || tag || nonce`.
    ///
    /// If `in_out` has capacity for `plaintext.len() + TAG_SIZE + NONCE_SIZE`,
    /// this performs no heap allocation. The buffer is zeroized before
    /// returning [`Error::Encrypt`] if encryption fails after mutating it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_nonce_appended_in_place(
        &self,
        nonce: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.state_ref()
            .encrypt_nonce_appended_in_place(nonce, in_out)
    }

    /// Encrypts into a caller-provided buffer with the nonce appended and
    /// returns the written length. No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE + NONCE_SIZE`, plus the same errors as
    /// [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
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
    #[doc(hidden)]
    pub fn decrypt_nonce_appended(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().decrypt_envelope(&[], data)
    }

    /// Decrypts the nonce-appended layout into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decrypt_nonce_appended`] plus
    /// [`Error::OutputTooSmall`].
    #[doc(hidden)]
    pub fn decrypt_nonce_appended_to(&self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.state_ref().decrypt_envelope_to(&[], data, out)
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
    #[doc(hidden)]
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
    #[doc(hidden)]
    pub fn encrypt_nonce_appended_generated(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        self.state_ref().encrypt_nonce_appended(&nonce, plaintext)
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

#[repr(transparent)]
struct AlignedKeyStateStorage(MaybeUninit<KeyState>);

impl AlignedKeyStateStorage {
    #[inline]
    const fn uninit() -> Self {
        Self(MaybeUninit::uninit())
    }

    #[inline]
    fn state_ptr(&self) -> *const KeyState {
        self.0.as_ptr()
    }

    #[inline]
    fn state_ptr_mut(&mut self) -> NonNull<KeyState> {
        // SAFETY: MaybeUninit<KeyState> is non-null and aligned for KeyState.
        unsafe { NonNull::new_unchecked(self.0.as_mut_ptr()) }
    }

    #[inline]
    fn bytes_ptr_mut(&mut self) -> *mut u8 {
        self.0.as_mut_ptr().cast::<u8>()
    }
}

/// Allocation-free owned reusable AES-256-GCM key state.
///
/// This stores the same opaque key-equivalent bytes reported by
/// [`HardwareAes256Gcm::key_state_layout`] inline in the value, avoiding the
/// heap allocation used by [`HardwareAes256Gcm`] while still wiping the key
/// state on drop. The nonce generator is held outside the inline key state.
pub struct HardwareAes256GcmKeyState {
    storage: AlignedKeyStateStorage,
    nonce_gen: Option<nonce::NonceGen>,
}

impl HardwareAes256GcmKeyState {
    /// Creates reusable AES-256-GCM state from a raw 32-byte key without heap
    /// allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] if `key` is not exactly 32 bytes,
    /// or [`Error::UnsupportedCpu`] if required AES-GCM hardware is absent.
    #[inline]
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let mut storage = AlignedKeyStateStorage::uninit();
        init_key_state_at(key, storage.state_ptr_mut())?;
        Ok(Self {
            storage,
            nonce_gen: None,
        })
    }

    /// Returns the current size of the reusable inline key state.
    #[must_use]
    pub const fn state_size() -> usize {
        std::mem::size_of::<KeyState>()
    }

    /// Encrypts `plaintext` and returns `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails,
    /// [`Error::InputTooLarge`] if `plaintext` or `aad` exceed the AES-GCM
    /// limits, or [`Error::Encrypt`] if the backend rejects encryption.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        self.state_ref().encrypt_envelope(&nonce, aad, plaintext)
    }

    /// Encrypts `plaintext` into a caller-provided buffer as
    /// `ciphertext || tag || nonce` and returns the written length.
    ///
    /// No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails,
    /// [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE + NONCE_SIZE`, [`Error::InputTooLarge`] if
    /// `plaintext` or `aad` exceed the AES-GCM limits, or [`Error::Encrypt`]
    /// if the backend rejects encryption.
    pub fn encrypt_to(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = self.next_nonce()?;
        self.state_ref()
            .encrypt_envelope_to(&nonce, aad, plaintext, out)
    }

    /// Decrypts `ciphertext || tag || nonce` and returns plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`], [`Error::InputTooLarge`], or
    /// [`Error::Decrypt`] if authentication fails.
    pub fn decrypt(&self, aad: &[u8], ciphertext_tag_nonce: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().decrypt_envelope(aad, ciphertext_tag_nonce)
    }

    /// Decrypts `ciphertext || tag || nonce` into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// Decrypts into `out` before the final tag comparison so CTR and GHASH can
    /// run in one fused pass. If authentication fails, the plaintext-length
    /// prefix of `out` is zeroized before returning [`Error::Decrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`], [`Error::OutputTooSmall`],
    /// [`Error::InputTooLarge`], or [`Error::Decrypt`] if authentication fails.
    pub fn decrypt_to(
        &self,
        aad: &[u8],
        ciphertext_tag_nonce: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state_ref()
            .decrypt_envelope_to(aad, ciphertext_tag_nonce, out)
    }

    /// Encrypts and appends the nonce: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`], [`Error::InputTooLarge`], or
    /// [`Error::Encrypt`].
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_nonce_appended(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().encrypt_nonce_appended(nonce, plaintext)
    }

    /// Encrypts the plaintext already in `in_out` in place, then appends the
    /// tag and nonce so the final layout is `ciphertext || tag || nonce`.
    ///
    /// If `in_out` has capacity for `plaintext.len() + TAG_SIZE + NONCE_SIZE`,
    /// this performs no heap allocation. The buffer is zeroized before
    /// returning [`Error::Encrypt`] if encryption fails after mutating it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt_nonce_appended`].
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_nonce_appended_in_place(
        &self,
        nonce: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.state_ref()
            .encrypt_nonce_appended_in_place(nonce, in_out)
    }

    /// Decrypts the nonce-appended layout: `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`] if the input cannot contain a tag
    /// and nonce. Returns [`Error::InvalidNonceLength`],
    /// [`Error::InputTooLarge`], or [`Error::Decrypt`].
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn decrypt_nonce_appended(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().decrypt_envelope(&[], data)
    }

    /// Detached AES-256-GCM seal with a caller-supplied nonce and AAD.
    ///
    /// Returns `(ciphertext, tag)` separately and does **not** append the
    /// nonce — the caller owns nonce construction, AAD, and output framing.
    /// This is the protocol-neutral primitive a record layer (for example a
    /// rustls AEAD provider) or a standards known-answer test needs.
    ///
    /// The caller is responsible for nonce uniqueness under the key. For
    /// general use prefer [`Self::encrypt`], which generates a proven
    /// non-repeating nonce internally.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`], [`Error::InputTooLarge`], or
    /// [`Error::Encrypt`].
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn seal_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_SIZE]), Error> {
        self.state_ref().seal_detached(nonce, aad, plaintext)
    }

    /// In-place detached seal: `data` enters as plaintext and exits as
    /// ciphertext of equal length; the authentication tag is returned. No
    /// nonce is appended. See [`Self::seal_detached`] for semantics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`], [`Error::InputTooLarge`], or
    /// [`Error::Encrypt`] (the buffer is zeroized before an `Encrypt` error).
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn seal_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_SIZE], Error> {
        self.state_ref().seal_in_place_detached(nonce, aad, data)
    }

    /// Detached open: authenticate `ciphertext` against `tag` (constant time)
    /// under the caller-supplied `nonce`/`aad` and return the plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`], [`Error::InputTooLarge`], or
    /// [`Error::Decrypt`] if authentication fails (the transient plaintext is
    /// zeroized first).
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn open_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.state_ref().open_detached(nonce, aad, ciphertext, tag)
    }

    /// In-place detached open: `data` enters as ciphertext and exits as
    /// plaintext once authenticated against `tag` (constant time). On
    /// authentication failure `data` is zeroized and `Err` is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNonceLength`], [`Error::InputTooLarge`], or
    /// [`Error::Decrypt`] if authentication fails.
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn open_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        self.state_ref()
            .open_in_place_detached(nonce, aad, data, tag)
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        match self.nonce_gen {
            Some(ref mut g) => g.next(),
            None => self.nonce_gen.insert(nonce::NonceGen::new()?).next(),
        }
    }

    fn state_ref(&self) -> &KeyState {
        // SAFETY: HardwareAes256GcmKeyState::new initializes storage before
        // constructing Self, and the storage is never mutated except during
        // Drop after all shared borrows have ended.
        unsafe { &*self.storage.state_ptr() }
    }
}

impl Drop for HardwareAes256GcmKeyState {
    fn drop(&mut self) {
        let size = Self::state_size();
        // KeyState's field Drop impls exist only to wipe their own bytes and
        // release no heap or handle resources, so one volatile wipe of the
        // inline storage supersedes those per-field wipes. If KeyState ever
        // gains a resource-owning field, this must run drop_in_place first.
        // SAFETY: storage is inline in self, writable for `size` bytes, and
        // aligned for KeyState by AlignedKeyStateStorage.
        unsafe { volatile_wipe(self.storage.bytes_ptr_mut(), size) };
    }
}

impl std::fmt::Debug for HardwareAes256GcmKeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareAes256GcmKeyState")
            .finish_non_exhaustive()
    }
}

/// Owned reusable hardware-only AES-256-GCM key state.
pub struct HardwareAes256Gcm {
    state: Box<KeyState>,
    /// Lazily initialized on the first encrypting default API call. Held
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
        let mut state = Box::<KeyState>::new_uninit();
        // SAFETY: Box::new_uninit returns a non-null allocation for KeyState.
        let ptr = unsafe { NonNull::new_unchecked(state.as_mut_ptr()) };
        init_key_state_at(key, ptr)?;
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

    /// Encrypts `plaintext` and returns `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails,
    /// [`Error::InputTooLarge`] if `plaintext` or `aad` exceed the AES-GCM
    /// limits, or [`Error::Encrypt`] if the backend rejects encryption.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        self.state.encrypt_envelope(&nonce, aad, plaintext)
    }

    /// Encrypts `plaintext` into a caller-provided buffer as
    /// `ciphertext || tag || nonce` and returns the written length.
    ///
    /// No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails,
    /// [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE + NONCE_SIZE`, [`Error::InputTooLarge`] if
    /// `plaintext` or `aad` exceed the AES-GCM limits, or [`Error::Encrypt`]
    /// if the backend rejects encryption.
    pub fn encrypt_to(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = self.next_nonce()?;
        self.state.encrypt_envelope_to(&nonce, aad, plaintext, out)
    }

    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_with_nonce(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
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
    /// `plaintext.len() + TAG_SIZE`, plus the same errors as
    /// [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_with_nonce_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state.encrypt_to(nonce, aad, plaintext, out)
    }

    /// Decrypts `ciphertext || tag || nonce` and returns plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`], [`Error::InputTooLarge`], or
    /// [`Error::Decrypt`] if authentication fails.
    pub fn decrypt(&self, aad: &[u8], ciphertext_tag_nonce: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.decrypt_envelope(aad, ciphertext_tag_nonce)
    }

    /// Decrypts `ciphertext || tag || nonce` into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// Decrypts into `out` before the final tag comparison so CTR and GHASH can
    /// run in one fused pass. If authentication fails, the plaintext-length
    /// prefix of `out` is zeroized before returning [`Error::Decrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::CiphertextTooShort`], [`Error::OutputTooSmall`],
    /// [`Error::InputTooLarge`], or [`Error::Decrypt`] if authentication fails.
    pub fn decrypt_to(
        &self,
        aad: &[u8],
        ciphertext_tag_nonce: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.state
            .decrypt_envelope_to(aad, ciphertext_tag_nonce, out)
    }

    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn decrypt_with_nonce(
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
    /// Decrypts into `out` before the final tag comparison so CTR and GHASH can
    /// run in one fused pass. If authentication fails, the plaintext-length
    /// prefix of `out` is zeroized before returning [`Error::Decrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than the
    /// plaintext, plus the same errors as [`Self::decrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn decrypt_with_nonce_to(
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
    /// Returns the same errors as [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_nonce_appended(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.encrypt_nonce_appended(nonce, plaintext)
    }

    /// Encrypts the plaintext already in `in_out` in place, then appends the
    /// tag and nonce so the final layout is `ciphertext || tag || nonce`.
    ///
    /// If `in_out` has capacity for `plaintext.len() + TAG_SIZE + NONCE_SIZE`,
    /// this performs no heap allocation. The buffer is zeroized before
    /// returning [`Error::Encrypt`] if encryption fails after mutating it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn encrypt_nonce_appended_in_place(
        &self,
        nonce: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.state.encrypt_nonce_appended_in_place(nonce, in_out)
    }

    /// Encrypts into a caller-provided buffer with the nonce appended and
    /// returns the written length. No heap allocation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputTooSmall`] if `out` is shorter than
    /// `plaintext.len() + TAG_SIZE + NONCE_SIZE`, plus the same errors as
    /// [`Self::encrypt_with_nonce`].
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
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
    #[doc(hidden)]
    pub fn decrypt_nonce_appended(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.decrypt_envelope(&[], data)
    }

    /// Decrypts the nonce-appended layout into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decrypt_nonce_appended`] plus
    /// [`Error::OutputTooSmall`].
    #[doc(hidden)]
    pub fn decrypt_nonce_appended_to(&self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.state.decrypt_envelope_to(&[], data, out)
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
    #[doc(hidden)]
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
    #[doc(hidden)]
    pub fn encrypt_nonce_appended_generated(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        self.state.encrypt_nonce_appended(&nonce, plaintext)
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

fn append_tag_nonce(out: &mut Vec<u8>, tag: &[u8; TAG_SIZE], nonce: &[u8; NONCE_SIZE]) {
    debug_assert!(out.capacity() >= out.len() + TAG_SIZE + NONCE_SIZE);

    let start = out.len();
    let trailer = &mut out.spare_capacity_mut()[..TAG_SIZE + NONCE_SIZE];
    for (slot, byte) in trailer[..TAG_SIZE].iter_mut().zip(tag) {
        slot.write(*byte);
    }
    for (slot, byte) in trailer[TAG_SIZE..].iter_mut().zip(nonce) {
        slot.write(*byte);
    }

    // SAFETY: the TAG_SIZE + NONCE_SIZE spare bytes immediately after the
    // original length were initialized above, and capacity was ensured by the
    // caller before encryption mutated the buffer.
    unsafe { out.set_len(start + TAG_SIZE + NONCE_SIZE) };
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
#[cfg(any(test, feature = "hazmat-explicit-nonce"))]
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

/// Stable-symbol `extern "C"` wrapper so the SAW LLVM-bitcode verifier can prove
/// the *compiled* `increment_counter` matches its Cryptol spec (`proofs/saw/`).
/// Build-time only; `saw-verify` is never a shipped feature.
#[cfg(feature = "saw-verify")]
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn saw_increment_counter(counter: *mut u8) {
    // SAFETY: SAW calls this with a valid, writable 16-byte buffer.
    let c = unsafe { &mut *(counter.cast::<[u8; 16]>()) };
    increment_counter(c);
}

/// Stable-symbol `extern "C"` wrapper around `j0` for SAW (`proofs/saw/`).
/// Build-time only; never shipped.
#[cfg(feature = "saw-verify")]
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn saw_j0(nonce: *const u8, out: *mut u8) {
    // SAFETY: SAW calls this with a readable 12-byte `nonce` and writable 16-byte `out`.
    let n = unsafe { &*(nonce.cast::<[u8; NONCE_SIZE]>()) };
    let block = j0(n);
    // SAFETY: `out` is a writable 16-byte buffer.
    unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), out, 16) };
}

fn constant_time_eq(expected: &[u8; TAG_SIZE], actual: &[u8]) -> bool {
    // subtle's slice impl compares lengths first (length is public) and then
    // the contents in constant time behind optimization barriers, so the
    // compiler cannot reintroduce an early-exit byte comparison. This is the
    // one place in the crate where secret-derived values are compared.
    expected.as_slice().ct_eq(actual).into()
}

/// Non-inlined wrapper so the constant-time verifier can disassemble the tag
/// comparison as a named symbol and confirm it compiles branch-free, with the
/// loop length fixed to `TAG_SIZE` (see `proofs/constant-time/verify.sh`).
/// Build-time only; `ct-verify` is never a shipped feature.
#[cfg(feature = "ct-verify")]
#[inline(never)]
#[must_use]
pub fn ct_verify_constant_time_eq(expected: &[u8; TAG_SIZE], actual: &[u8; TAG_SIZE]) -> bool {
    constant_time_eq(
        core::hint::black_box(expected),
        core::hint::black_box(actual.as_slice()),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::{
        increment_counter, j0, Error, HardwareAes256Gcm, HardwareAes256GcmIn,
        HardwareAes256GcmKeyState, UninitKeyStateSlot, NONCE_SIZE, TAG_SIZE,
    };
    use core::mem::ManuallyDrop;

    #[repr(align(64))]
    struct AlignedStorage<const N: usize>([u8; N]);

    /// Anchors the Z3 model in `proofs/prove_composition.py` to the real compiled
    /// code: `increment_counter` is the SP 800-38D `inc_32` (big-endian counter in
    /// the trailing four bytes, wrapping mod 2^32, leading 96 bits preserved).
    #[test]
    fn increment_counter_is_be32_inc_leaving_high_96_bits() {
        // Wrap across the 32-bit boundary; the leading 12 bytes must not change.
        let mut counter = [0_u8; 16];
        counter[..12].copy_from_slice(&[0xAA; 12]);
        counter[12..].copy_from_slice(&u32::MAX.to_be_bytes());
        increment_counter(&mut counter);
        assert_eq!(
            &counter[..12],
            &[0xAA; 12],
            "leading 96 bits must be preserved"
        );
        assert_eq!(
            &counter[12..],
            &0_u32.to_be_bytes(),
            "low 32 bits must wrap to 0"
        );

        // Plain carry into the next byte, big-endian.
        let mut counter = [0_u8; 16];
        counter[12..].copy_from_slice(&0x0000_00FF_u32.to_be_bytes());
        increment_counter(&mut counter);
        assert_eq!(&counter[12..], &0x0000_0100_u32.to_be_bytes());

        // J0 for a 96-bit nonce is IV || 0^31 || 1 (SP 800-38D).
        let nonce = [0x11_u8; NONCE_SIZE];
        let block = j0(&nonce);
        assert_eq!(&block[..NONCE_SIZE], &nonce);
        assert_eq!(&block[NONCE_SIZE..], &[0, 0, 0, 1]);
    }

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
    fn inline_owned_key_state_rejects_wrong_key_length() {
        let Err(err) = HardwareAes256GcmKeyState::new(&[0_u8; 31]) else {
            panic!("31-byte key should be rejected");
        };
        assert_eq!(err, Error::InvalidKeyLength);
    }

    #[test]
    fn rejects_ciphertext_shorter_than_tag() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let Err(err) =
            key.decrypt_with_nonce(&[0_u8; NONCE_SIZE], &[], &[0_u8; super::TAG_SIZE - 1])
        else {
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
            .encrypt_with_nonce(&nonce, b"aad", b"plaintext")
            .expect("encryption should succeed");

        let mut exact = [0_u8; 9];
        let written = key
            .decrypt_with_nonce_to(&nonce, b"aad", &ciphertext, &mut exact)
            .expect("decryption into an exact-size buffer should succeed");
        assert_eq!(written, 9);
        assert_eq!(&exact, b"plaintext");

        let mut oversized = [0xff_u8; 32];
        let written = key
            .decrypt_with_nonce_to(&nonce, b"aad", &ciphertext, &mut oversized)
            .expect("decryption into a larger buffer should succeed");
        assert_eq!(&oversized[..written], b"plaintext");

        let mut short = [0_u8; 8];
        let Err(err) = key.decrypt_with_nonce_to(&nonce, b"aad", &ciphertext, &mut short) else {
            panic!("short output buffer should be rejected");
        };
        assert_eq!(err, Error::OutputTooSmall);
        assert_eq!(short, [0_u8; 8], "no plaintext may leak into short buffers");

        let mut tampered = ciphertext;
        *tampered.last_mut().expect("tag byte") ^= 1;
        let mut invalid_out = [0xff_u8; 9];
        let Err(err) = key.decrypt_with_nonce_to(&nonce, b"aad", &tampered, &mut invalid_out)
        else {
            panic!("invalid authentication tag should be rejected");
        };
        assert_eq!(err, Error::Decrypt);
        assert_eq!(
            invalid_out, [0_u8; 9],
            "transient plaintext must be wiped on authentication failure"
        );
    }

    #[test]
    fn encrypt_to_matches_allocating_encrypt() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let plaintext = [0x5a_u8; 200];
        let expected = key
            .encrypt_with_nonce(&nonce, b"aad", &plaintext)
            .expect("encryption should succeed");

        let mut exact = [0_u8; 200 + super::TAG_SIZE];
        let written = key
            .encrypt_with_nonce_to(&nonce, b"aad", &plaintext, &mut exact)
            .expect("encryption into an exact-size buffer should succeed");
        assert_eq!(written, exact.len());
        assert_eq!(exact.as_slice(), expected.as_slice());

        let mut oversized = [0_u8; 256];
        let written = key
            .encrypt_with_nonce_to(&nonce, b"aad", &plaintext, &mut oversized)
            .expect("encryption into a larger buffer should succeed");
        assert_eq!(&oversized[..written], expected.as_slice());

        let mut short = [0_u8; 200 + super::TAG_SIZE - 1];
        let Err(err) = key.encrypt_with_nonce_to(&nonce, b"aad", &plaintext, &mut short) else {
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
    fn encrypt_nonce_appended_in_place_uses_existing_vec_capacity() {
        let key = HardwareAes256Gcm::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let expected = key
            .encrypt_nonce_appended(&nonce, b"plaintext")
            .expect("encryption should succeed");

        let mut in_out = Vec::with_capacity(b"plaintext".len() + super::TAG_SIZE + NONCE_SIZE);
        in_out.extend_from_slice(b"plaintext");
        let ptr_before = in_out.as_ptr();
        key.encrypt_nonce_appended_in_place(&nonce, &mut in_out)
            .expect("in-place encryption should succeed");

        assert_eq!(in_out, expected);
        assert_eq!(
            in_out.as_ptr(),
            ptr_before,
            "pre-reserved in-place encryption should not reallocate"
        );
        assert_eq!(
            key.decrypt_nonce_appended(&in_out)
                .expect("decryption should succeed"),
            b"plaintext"
        );
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
            key.decrypt_with_nonce(&nonce_a, b"aad", &ct_a)
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
            key.decrypt_with_nonce(&nonce, &[], &ct)
                .expect("decryption should succeed"),
            b"plaintext"
        );
    }

    /// Exercises *every* `HardwareAes256GcmIn` explicit-buffer / nonce-appended
    /// method with a verified round trip (and byte-exact cross-validation against
    /// `HardwareAes256Gcm` for the explicit-nonce paths). Without this, the thin
    /// delegations to the underlying key state are called but their output is
    /// never checked, so a wrong (or stubbed) wrapper survives - a gap surfaced
    /// by mutation testing (see docs/mutation-testing.md).
    #[test]
    fn caller_placed_in_buffer_methods_round_trip() {
        const KEY: [u8; 32] = [7_u8; 32];
        const NONCE: [u8; NONCE_SIZE] = [0x24; NONCE_SIZE];
        let pt = b"caller-placed in-buffer methods".to_vec();
        let aad = b"header".as_slice();

        let layout = HardwareAes256Gcm::key_state_layout();
        let mut storage = AlignedStorage::<512>([0_u8; 512]);
        let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).expect("valid slot");
        let mut key = HardwareAes256GcmIn::new_in(&KEY, slot).expect("valid test key");
        // Independent reference for byte-exact cross-validation.
        let reference = HardwareAes256Gcm::new(&KEY).expect("reference key");

        // --- explicit nonce: byte-identical to the reference, and round-trips ---
        let ct = key
            .encrypt_with_nonce(&NONCE, aad, &pt)
            .expect("encrypt_with_nonce");
        assert_eq!(
            ct,
            reference.encrypt_with_nonce(&NONCE, aad, &pt).unwrap(),
            "encrypt_with_nonce diverged from the reference cipher"
        );
        assert_eq!(key.decrypt_with_nonce(&NONCE, aad, &ct).unwrap(), pt);

        let mut buf = vec![0_u8; pt.len() + TAG_SIZE];
        let n = key
            .encrypt_with_nonce_to(&NONCE, aad, &pt, &mut buf)
            .expect("encrypt_with_nonce_to");
        assert_eq!(n, pt.len() + TAG_SIZE);
        assert_eq!(&buf[..n], &ct[..]);
        let mut out = vec![0_u8; pt.len()];
        let m = key
            .decrypt_with_nonce_to(&NONCE, aad, &buf[..n], &mut out)
            .expect("decrypt_with_nonce_to");
        assert_eq!(&out[..m], &pt[..]);

        // --- nonce-appended (empty AAD), explicit nonce ---
        let env = key
            .encrypt_nonce_appended(&NONCE, &pt)
            .expect("encrypt_nonce_appended");
        assert_eq!(key.decrypt_nonce_appended(&env).unwrap(), pt);

        let mut env_buf = vec![0_u8; pt.len() + TAG_SIZE + NONCE_SIZE];
        let n = key
            .encrypt_nonce_appended_to(&NONCE, &pt, &mut env_buf)
            .expect("encrypt_nonce_appended_to");
        assert_eq!(n, env_buf.len());
        assert_eq!(env_buf, env);
        let mut out = vec![0_u8; pt.len()];
        let m = key
            .decrypt_nonce_appended_to(&env_buf, &mut out)
            .expect("decrypt_nonce_appended_to");
        assert_eq!(&out[..m], &pt[..]);

        // In-place encrypt: from an under-capacity Vec (forces the reserve path)
        // and from an exact-capacity Vec; both must round-trip.
        for prealloc in [0_usize, pt.len() + TAG_SIZE + NONCE_SIZE] {
            let mut in_out = Vec::with_capacity(prealloc);
            in_out.extend_from_slice(&pt);
            key.encrypt_nonce_appended_in_place(&NONCE, &mut in_out)
                .expect("encrypt_nonce_appended_in_place");
            assert_eq!(in_out, env, "in-place layout must match");
            assert_eq!(key.decrypt_nonce_appended(&in_out).unwrap(), pt);
        }

        // --- generated nonce: round-trips, and successive outputs differ ----
        let mut out = vec![0_u8; pt.len() + TAG_SIZE + NONCE_SIZE];
        let n = key.encrypt_to(aad, &pt, &mut out).expect("encrypt_to");
        assert_eq!(n, out.len());
        let mut dec = vec![0_u8; pt.len()];
        let m = key.decrypt_to(aad, &out, &mut dec).expect("decrypt_to");
        assert_eq!(&dec[..m], &pt[..]);

        let g1 = key.encrypt_nonce_appended_generated(&pt).unwrap();
        let g2 = key.encrypt_nonce_appended_generated(&pt).unwrap();
        assert_ne!(g1, g2, "generated nonces must differ between calls");
        assert_eq!(key.decrypt_nonce_appended(&g1).unwrap(), pt);
        assert_eq!(key.decrypt_nonce_appended(&g2).unwrap(), pt);

        drop(reference);
    }

    /// The owned-key-state `encrypt_to` must write a real envelope that decrypts
    /// back (a delegation previously not output-verified; mutation testing).
    #[test]
    fn owned_key_state_encrypt_to_round_trips() {
        let mut key = HardwareAes256GcmKeyState::new(&[9_u8; 32]).expect("valid key");
        let pt = b"owned key state encrypt_to path";
        let mut out = vec![0_u8; pt.len() + TAG_SIZE + NONCE_SIZE];
        let n = key.encrypt_to(b"aad", pt, &mut out).expect("encrypt_to");
        assert_eq!(n, out.len());
        assert_eq!(key.decrypt(b"aad", &out).expect("decrypt"), pt);
    }

    /// `validate_gcm_lengths` must reject an input that exceeds *any one* of the
    /// length limits (not only all of them) - exercised with length *values*, so
    /// no allocation is needed. Pins the `||` chain against a `&&` regression
    /// (mutation testing) and complements the Kani harness, which `cargo test`
    /// does not run.
    #[test]
    fn gcm_length_validation_rejects_each_over_limit() {
        use super::{validate_gcm_lengths, MAX_GCM_DATA_LEN, MAX_GHASH_INPUT_LEN};
        assert!(validate_gcm_lengths(16, 16).is_ok());
        // Over the GCM counter limit on the data (AAD in range).
        if let Ok(over) = usize::try_from(MAX_GCM_DATA_LEN + 1) {
            assert_eq!(validate_gcm_lengths(16, over), Err(Error::InputTooLarge));
        }
        // Over the GHASH 64-bit length-field limit on the AAD (data in range).
        if let Ok(over) = usize::try_from(MAX_GHASH_INPUT_LEN + 1) {
            assert_eq!(validate_gcm_lengths(over, 16), Err(Error::InputTooLarge));
        }
        // Exactly at the GCM data limit is accepted.
        if let Ok(lim) = usize::try_from(MAX_GCM_DATA_LEN) {
            assert!(validate_gcm_lengths(0, lim).is_ok());
        }
    }

    #[test]
    fn generated_nonce_does_not_change_key_state_size() {
        // The nonce generator lives on the handle, not the placed key state.
        assert_eq!(HardwareAes256Gcm::key_state_layout().size, 368);
        assert_eq!(HardwareAes256Gcm::state_size(), 368);
    }

    #[test]
    fn inline_owned_key_state_layout_matches_reported_layout() {
        let layout = HardwareAes256Gcm::key_state_layout();
        assert!(std::mem::size_of::<HardwareAes256GcmKeyState>() >= layout.size);
        assert!(std::mem::align_of::<HardwareAes256GcmKeyState>() >= layout.align);
        assert_eq!(HardwareAes256GcmKeyState::state_size(), layout.size);
    }

    #[test]
    fn inline_owned_key_state_default_envelope_round_trips() {
        let mut key = HardwareAes256GcmKeyState::new(&[7_u8; 32]).expect("valid test key");
        let first = key
            .encrypt(b"aad", b"plaintext")
            .expect("encryption should succeed");
        let second = key
            .encrypt(b"aad", b"plaintext")
            .expect("encryption should succeed");

        assert_eq!(
            key.decrypt(b"aad", &first)
                .expect("decryption should succeed"),
            b"plaintext"
        );
        assert_eq!(
            key.decrypt(b"aad", &second)
                .expect("decryption should succeed"),
            b"plaintext"
        );
        assert_ne!(
            &first[first.len() - NONCE_SIZE..],
            &second[second.len() - NONCE_SIZE..],
            "generated nonces must be unique"
        );

        let mut out = [0_u8; 9];
        let written = key
            .decrypt_to(b"aad", &first, &mut out)
            .expect("decryption into caller buffer should succeed");
        assert_eq!(written, out.len());
        assert_eq!(&out, b"plaintext");
    }

    #[test]
    fn inline_owned_key_state_round_trips_and_uses_existing_vec_capacity() {
        let key = HardwareAes256GcmKeyState::new(&[7_u8; 32]).expect("valid test key");
        let nonce = [9_u8; NONCE_SIZE];
        let expected = key
            .encrypt_nonce_appended(&nonce, b"plaintext")
            .expect("encryption should succeed");
        assert_eq!(
            key.decrypt_nonce_appended(&expected)
                .expect("decryption should succeed"),
            b"plaintext"
        );

        let mut in_out = Vec::with_capacity(b"plaintext".len() + super::TAG_SIZE + NONCE_SIZE);
        in_out.extend_from_slice(b"plaintext");
        let ptr_before = in_out.as_ptr();
        key.encrypt_nonce_appended_in_place(&nonce, &mut in_out)
            .expect("in-place encryption should succeed");
        assert_eq!(in_out, expected);
        assert_eq!(
            in_out.as_ptr(),
            ptr_before,
            "pre-reserved in-place encryption should not reallocate"
        );
    }

    #[test]
    fn inline_owned_key_state_wipes_storage_on_drop() {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut key =
            ManuallyDrop::new(HardwareAes256GcmKeyState::new(&[7_u8; 32]).expect("valid test key"));

        // SAFETY: key lives in this stack frame and ManuallyDrop keeps the
        // backing bytes valid after its Drop impl runs (the value is logically
        // dropped but not freed). The storage pointer is taken *after* the drop
        // so its provenance is not invalidated by the `&mut key` the drop uses -
        // reading the just-wiped bytes through a freshly-derived pointer.
        unsafe {
            ManuallyDrop::drop(&mut key);
            let storage = key.storage.bytes_ptr_mut();
            let bytes = std::slice::from_raw_parts(storage.cast_const(), layout.size);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn caller_placed_key_state_is_usable_across_threads() {
        let layout = HardwareAes256Gcm::key_state_layout();
        let mut storage = AlignedStorage::<512>([0_u8; 512]);
        let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).expect("valid slot");
        let mut key = HardwareAes256GcmIn::new_in(&[7_u8; 32], slot).expect("valid test key");
        let ciphertext = key
            .encrypt(&[], b"plaintext")
            .expect("encryption should succeed");

        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    assert_eq!(
                        key.decrypt(&[], &ciphertext)
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
        let Err(err) = key.encrypt_with_nonce(&[0_u8; NONCE_SIZE - 1], &[], b"data") else {
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

        {
            let slot = UninitKeyStateSlot::new(&mut storage.0[..layout.size]).expect("valid slot");
            let mut key = HardwareAes256GcmIn::new_in(&[7_u8; 32], slot).expect("valid test key");
            let ciphertext = key
                .encrypt(&[], b"plaintext")
                .expect("encryption should succeed");
            assert_eq!(
                key.decrypt(&[], &ciphertext)
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

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn detached_round_trips_and_matches_nonce_appended_path() {
        const KEY: [u8; 32] = [0x5b; 32];
        const NONCE: [u8; NONCE_SIZE] = [0x42; NONCE_SIZE];
        let key = HardwareAes256GcmKeyState::new(&KEY).expect("valid key");
        let pt = b"detached seal/open round-trip payload".to_vec();
        let aad = b"associated-data".as_slice();

        // Allocating detached seal/open with AAD.
        let (ct, tag) = key.seal_detached(&NONCE, aad, &pt).expect("seal_detached");
        assert_eq!(ct.len(), pt.len(), "ciphertext is plaintext-length");
        assert_eq!(key.open_detached(&NONCE, aad, &ct, &tag).unwrap(), pt);

        // In-place detached seal/open must agree with the allocating variant.
        let mut buf = pt.clone();
        let tag2 = key
            .seal_in_place_detached(&NONCE, aad, &mut buf)
            .expect("seal_in_place_detached");
        assert_eq!(buf, ct, "in-place ciphertext matches allocating");
        assert_eq!(tag2, tag, "in-place tag matches allocating");
        key.open_in_place_detached(&NONCE, aad, &mut buf, &tag2)
            .expect("open_in_place_detached");
        assert_eq!(buf, pt, "in-place open recovers plaintext");

        // Detached output (empty AAD) must equal the validated nonce-appended
        // envelope minus its trailing nonce — ties the new primitive to the
        // existing explicit-nonce path byte-for-byte.
        let env = key.encrypt_nonce_appended(&NONCE, &pt).expect("appended");
        let (ct0, tag0) = key.seal_detached(&NONCE, &[], &pt).expect("seal_detached");
        let mut joined = ct0;
        joined.extend_from_slice(&tag0);
        assert_eq!(joined, env[..env.len() - NONCE_SIZE]);
    }

    #[test]
    fn detached_seal_reproduces_nist_vector() {
        // NIST CAVP AES-256-GCM, AADlen=0, Taglen=128. The detached, explicit-
        // nonce path must reproduce a published (key, nonce, pt) -> (ct, tag)
        // vector exactly — the core reason this primitive exists.
        let key = HardwareAes256GcmKeyState::new(&hx(
            "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
        ))
        .expect("valid key");
        let nonce = hx("0d18e06c7c725ac9e362e1ce");
        let pt = hx("2db5168e932556f8089a0622981d017d");
        let (ct, tag) = key.seal_detached(&nonce, &[], &pt).expect("seal_detached");
        assert_eq!(ct, hx("fa4362189661d163fcd6a56d8bf0405a"));
        assert_eq!(tag.as_slice(), hx("d636ac1bbedd5cc3ee727dc2ab4a9489"));
        // And the open side authenticates the same vector.
        assert_eq!(key.open_detached(&nonce, &[], &ct, &tag).unwrap(), pt);
    }

    #[test]
    fn detached_open_rejects_wrong_tag_and_aad() {
        const KEY: [u8; 32] = [0x11; 32];
        const NONCE: [u8; NONCE_SIZE] = [0x22; NONCE_SIZE];
        let key = HardwareAes256GcmKeyState::new(&KEY).expect("valid key");
        let pt = b"authenticate me".to_vec();
        let (ct, mut tag) = key.seal_detached(&NONCE, b"aad", &pt).expect("seal");

        // Wrong AAD fails.
        assert_eq!(
            key.open_detached(&NONCE, b"other", &ct, &tag),
            Err(Error::Decrypt)
        );
        // Tampered tag fails.
        tag[0] ^= 0xff;
        assert_eq!(
            key.open_detached(&NONCE, b"aad", &ct, &tag),
            Err(Error::Decrypt)
        );
        // Wrong-length tag fails.
        assert_eq!(
            key.open_detached(&NONCE, b"aad", &ct, &tag[..15]),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn detached_rejects_bad_nonce_length() {
        let key = HardwareAes256GcmKeyState::new(&[3_u8; 32]).expect("valid key");
        assert_eq!(
            key.seal_detached(&[0_u8; 11], &[], b"x"),
            Err(Error::InvalidNonceLength)
        );
    }
}

/// Kani bounded-model-checking harnesses for the intrinsic-free GCM logic.
///
/// Unlike the Z3 proofs in `proofs/`, which reason about a faithful *model* of
/// the code, Kani (CBMC) verifies the **actual compiled Rust** symbolically over
/// all inputs (bounded where noted) - so these are extraction-grade proofs of
/// the counter increment, the length validation, and the nonce parser. Run with
/// `cargo kani` (see docs/assurance.md). Compiled only under `cfg(kani)`.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        constant_time_eq, increment_counter, j0, nonce_from_slice, validate_gcm_lengths, Error,
        MAX_GCM_DATA_LEN, MAX_GHASH_INPUT_LEN, NONCE_SIZE, TAG_SIZE,
    };

    /// The compiled `increment_counter` is exactly SP 800-38D `inc_32`: the
    /// trailing 32 bits increment big-endian (wrapping), the leading 96 bits are
    /// untouched. Verified over all 2^128 counter blocks.
    #[kani::proof]
    fn increment_counter_is_be32_inc() {
        let mut counter: [u8; 16] = kani::any();
        let original = counter;
        increment_counter(&mut counter);
        assert!(counter[..12] == original[..12]);
        let low = u32::from_be_bytes([original[12], original[13], original[14], original[15]]);
        assert!(counter[12..] == low.wrapping_add(1).to_be_bytes());
    }

    /// `j0` builds `IV || 0^31 || 1` for any 96-bit nonce.
    #[kani::proof]
    fn j0_layout() {
        let nonce: [u8; NONCE_SIZE] = kani::any();
        let block = j0(&nonce);
        assert!(block[..NONCE_SIZE] == nonce);
        assert!(block[NONCE_SIZE..] == [0, 0, 0, 1]);
    }

    /// `validate_gcm_lengths` never panics and accepts exactly the lengths within
    /// both the GCM counter limit and the GHASH 64-bit length field.
    #[kani::proof]
    fn validate_gcm_lengths_matches_limits() {
        let aad_len: usize = kani::any();
        let data_len: usize = kani::any();
        let result = validate_gcm_lengths(aad_len, data_len);
        let aad = aad_len as u64;
        let data = data_len as u64;
        let in_range =
            data <= MAX_GCM_DATA_LEN && aad <= MAX_GHASH_INPUT_LEN && data <= MAX_GHASH_INPUT_LEN;
        assert!(result.is_ok() == in_range);
    }

    /// `nonce_from_slice` never panics and returns Ok exactly when the slice is
    /// the 12-byte nonce length. Bounded to lengths 0..=24.
    #[kani::proof]
    fn nonce_from_slice_accepts_only_correct_length() {
        let len: usize = kani::any();
        kani::assume(len <= 24);
        let buf = [0_u8; 24];
        let result = nonce_from_slice(&buf[..len]);
        match result {
            Ok(n) => assert!(len == NONCE_SIZE && n.len() == NONCE_SIZE),
            Err(e) => assert!(len != NONCE_SIZE && matches!(e, Error::InvalidNonceLength)),
        }
    }

    /// The authentication decision is functionally exact: for equal-length
    /// inputs `constant_time_eq` is bytewise equality. (Constant-*time*-ness is
    /// covered separately by the dudect harnesses; this proves *correctness* -
    /// that the masking/folding never accepts a wrong tag or rejects a right one.)
    /// Verified over all tag-pairs.
    ///
    /// Only the equal-length case is model-checked: callers always pass a
    /// `TAG_SIZE` slice (`split_ciphertext_tag`/the decrypt split are proven to
    /// hand over exactly `TAG_SIZE` bytes), and `subtle`'s variable-length slice
    /// loop does not bound under CBMC.
    #[kani::proof]
    fn constant_time_eq_equals_bytewise_equality() {
        let expected: [u8; TAG_SIZE] = kani::any();
        let actual: [u8; TAG_SIZE] = kani::any();
        assert!(constant_time_eq(&expected, &actual) == (expected == actual));
    }
}
