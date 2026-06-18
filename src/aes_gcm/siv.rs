//! Hardware-only AES-256-GCM-SIV (RFC 8452).
//!
//! This is the nonce-misuse-resistant sibling of the AES-256-GCM API. It uses
//! the same vendored hardware-only AES backend (`aes`) and the same
//! carryless-multiply backend (`ghash`); the authentication uses POLYVAL,
//! which is the field operation that backend computes natively (the GCM path
//! reaches GHASH by byte-reversing blocks and applying `mulX` to the hash key;
//! GCM-SIV simply omits both). No software AES or software multiply is
//! compiled in.
//!
//! # How it differs from AES-256-GCM
//!
//! GCM-SIV is not an online cipher, so the stitched single-pass encrypt loop
//! does not apply. Per message:
//!
//! 1. **Key derivation.** A 16-byte message-authentication key and a 32-byte
//!    message-encryption key are derived from the key-generating key and the
//!    nonce via six AES blocks ([`derive_keys`]). A fresh AES-256 schedule is
//!    expanded from the derived encryption key.
//! 2. **Authenticate, then encrypt.** POLYVAL runs over the AAD and plaintext;
//!    its output is combined with the nonce and AES-encrypted into the tag; the
//!    plaintext is then CTR-encrypted using the tag as the initial counter.
//!    Because the counter is derived from the full POLYVAL result, the two
//!    passes cannot be fused.
//!
//! The reusable key state is therefore only the key-generating AES schedule;
//! the per-message work runs on the hot path. That hot path is still fully
//! hardware: POLYVAL reuses the eight-block aggregated reduction, and the CTR
//! pass drives eight interleaved AES chains ([`aes::Aes256::encrypt8`]), so
//! both the AES and carryless-multiply pipelines stay busy.
//!
//! # Constant-time notes
//!
//! As in the GCM module, all secret-dependent computation happens in the
//! hardware AES and carryless-multiply backends or in straight-line XOR/copy
//! loops whose trip counts derive from public lengths. Control flow branches
//! only on public values: input and buffer lengths, CPU feature availability,
//! and the accept/reject outcome of the tag check (computed in constant time
//! via `subtle` and public by definition). The CTR counter, derive-key
//! counters, and length block are not secret; keystream and tag material never
//! feed a branch condition or memory index.

#![allow(unsafe_code)]

use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{self, NonNull},
};
use zeroize::Zeroize as _;

use super::{
    aes, append_tag_nonce, constant_time_eq, ghash, nonce, nonce_from_slice, volatile_wipe, Error,
    KeyStateLayout, KEY_SIZE, NONCE_SIZE, TAG_SIZE,
};

const AES_BLOCK_SIZE: usize = 16;
const PAR_BLOCKS: usize = aes::PAR_BLOCKS;
const PAR_BYTES: usize = PAR_BLOCKS * AES_BLOCK_SIZE;

/// Derived message-authentication key length (POLYVAL key).
const AUTH_KEY_SIZE: usize = 16;
/// Derived message-encryption key length (AES-256).
const ENC_KEY_SIZE: usize = 32;

/// RFC 8452 caps both the plaintext and the AAD at 2^36 bytes.
const MAX_SIV_LEN: u64 = 1 << 36;

fn hardware_available() -> bool {
    aes::hardware_available() && ghash::hardware_available()
}

fn len_exceeds_siv_limit(len: usize) -> bool {
    u64::try_from(len).map_or(true, |len| len > MAX_SIV_LEN)
}

fn validate_siv_lengths(aad_len: usize, data_len: usize) -> Result<(), Error> {
    if len_exceeds_siv_limit(aad_len) || len_exceeds_siv_limit(data_len) {
        return Err(Error::InputTooLarge);
    }
    Ok(())
}

/// Derives the per-message authentication and encryption keys from the
/// key-generating key and nonce (RFC 8452 section 4).
///
/// Each derived key is assembled from the low 8 bytes of AES encryptions of
/// `LE32(counter) || nonce`: counters 0-1 form the 16-byte authentication key,
/// counters 2-5 the 32-byte AES-256 encryption key. The transient block holds
/// key material and is wiped after each use; the returned keys are the
/// caller's to wipe.
fn derive_keys(
    master: &aes::Aes256,
    nonce: &[u8; NONCE_SIZE],
) -> ([u8; AUTH_KEY_SIZE], [u8; ENC_KEY_SIZE]) {
    let mut input = [0_u8; AES_BLOCK_SIZE];
    input[4..].copy_from_slice(nonce);

    // Counters run 0,1 for the authentication key, then 2,3,4,5 for the
    // encryption key, each contributing the low 8 bytes of its AES output.
    let mut counter: u32 = 0;
    let mut derive_into = |slot: &mut [u8]| {
        input[..4].copy_from_slice(&counter.to_le_bytes());
        let mut block = input;
        master.encrypt_block(&mut block);
        slot.copy_from_slice(&block[..8]);
        block.zeroize();
        counter += 1;
    };

    let mut auth_key = [0_u8; AUTH_KEY_SIZE];
    for slot in auth_key.chunks_mut(8) {
        derive_into(slot);
    }

    let mut enc_key = [0_u8; ENC_KEY_SIZE];
    for slot in enc_key.chunks_mut(8) {
        derive_into(slot);
    }

    (auth_key, enc_key)
}

/// Expands a fresh AES-256 schedule from the derived message-encryption key.
/// Returns `None` only if the AES hardware vanished between construction and
/// here (unreachable once a key-generating schedule exists).
fn build_message_cipher(enc_key: &[u8; ENC_KEY_SIZE]) -> Option<aes::Aes256> {
    let mut slot = MaybeUninit::<aes::Aes256>::uninit();
    aes::Aes256::init_in_place(slot.as_mut_ptr(), enc_key)?;
    // SAFETY: init_in_place initialized the storage on success. The returned
    // Aes256 owns the schedule and wipes it on drop.
    Some(unsafe { slot.assume_init() })
}

/// POLYVAL over the AAD and message under the derived authentication key,
/// returning the unmasked SIV digest `S_s`.
fn polyval_digest(
    auth_key: &[u8; AUTH_KEY_SIZE],
    aad: &[u8],
    message: &[u8],
) -> Option<[u8; AES_BLOCK_SIZE]> {
    let mut powers = ghash::Polyval::key_powers(auth_key)?;
    let polyval = ghash::Polyval::new(&powers);
    powers.zeroize();
    let mut polyval = polyval?;
    polyval.absorb_padded(aad);
    polyval.absorb_padded(message);
    polyval.finalize_with_lengths(aad.len(), message.len())
}

/// SIV little-endian 32-bit counter increment over the low four bytes of the
/// counter block. Operates on the public, tag-derived counter; constant time
/// (`wrapping_add` carries without branching).
fn increment_siv_counter(counter: &mut [u8; AES_BLOCK_SIZE]) {
    let mut low = [0_u8; 4];
    low.copy_from_slice(&counter[..4]);
    let next = u32::from_le_bytes(low).wrapping_add(1);
    counter[..4].copy_from_slice(&next.to_le_bytes());
}

/// In-place AES-CTR over `data` in the GCM-SIV counter convention (LE32 in the
/// low four bytes). Full 128-byte batches drive eight interleaved AES chains;
/// the sub-batch tail is handled one block at a time. XOR is symmetric, so this
/// serves both encryption and decryption.
fn ctr_apply(cipher: &aes::Aes256, counter: &mut [u8; AES_BLOCK_SIZE], data: &mut [u8]) {
    let mut batches = data.chunks_exact_mut(PAR_BYTES);
    for batch in &mut batches {
        let mut keystream = [[0_u8; AES_BLOCK_SIZE]; PAR_BLOCKS];
        for block in &mut keystream {
            *block = *counter;
            increment_siv_counter(counter);
        }
        cipher.encrypt8(&mut keystream);
        for (key_block, data_block) in keystream.iter().zip(batch.chunks_exact_mut(AES_BLOCK_SIZE))
        {
            for (byte, key_byte) in data_block.iter_mut().zip(key_block.iter()) {
                *byte ^= key_byte;
            }
        }
    }

    for data_block in batches.into_remainder().chunks_mut(AES_BLOCK_SIZE) {
        let mut keystream = *counter;
        cipher.encrypt_block(&mut keystream);
        increment_siv_counter(counter);
        for (byte, key_byte) in data_block.iter_mut().zip(keystream.iter()) {
            *byte ^= key_byte;
        }
    }
}

/// Derives the SIV tag from the POLYVAL digest: XOR the nonce into the low 12
/// bytes, clear the top bit of the last byte, and AES-encrypt under the
/// message-encryption key.
fn siv_tag(
    cipher: &aes::Aes256,
    nonce: &[u8; NONCE_SIZE],
    mut digest: [u8; AES_BLOCK_SIZE],
) -> [u8; TAG_SIZE] {
    for (byte, nonce_byte) in digest[..NONCE_SIZE].iter_mut().zip(nonce.iter()) {
        *byte ^= nonce_byte;
    }
    digest[AES_BLOCK_SIZE - 1] &= 0x7f;
    cipher.encrypt_block(&mut digest);
    digest
}

/// In-place authenticated encryption. `data` enters as plaintext and exits as
/// ciphertext; the SIV tag is returned. POLYVAL runs over the plaintext before
/// CTR overwrites it. Returns `None` only on the unreachable loss of hardware.
fn siv_seal(
    master: &aes::Aes256,
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    data: &mut [u8],
) -> Option<[u8; TAG_SIZE]> {
    let (mut auth_key, mut enc_key) = derive_keys(master, nonce);
    let cipher = build_message_cipher(&enc_key);
    enc_key.zeroize();
    let Some(cipher) = cipher else {
        auth_key.zeroize();
        return None;
    };

    let digest = polyval_digest(&auth_key, aad, data);
    auth_key.zeroize();
    let digest = digest?;

    let tag = siv_tag(&cipher, nonce, digest);

    let mut counter = tag;
    counter[AES_BLOCK_SIZE - 1] |= 0x80;
    ctr_apply(&cipher, &mut counter, data);

    Some(tag)
}

/// In-place authenticated decryption. `data` enters as ciphertext and exits as
/// plaintext; returns whether the recomputed tag matches `tag` in constant
/// time. The caller must wipe `data` when this returns `false`.
fn siv_open(
    master: &aes::Aes256,
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_SIZE],
) -> bool {
    let (mut auth_key, mut enc_key) = derive_keys(master, nonce);
    let cipher = build_message_cipher(&enc_key);
    enc_key.zeroize();
    let Some(cipher) = cipher else {
        auth_key.zeroize();
        return false;
    };

    let mut counter = *tag;
    counter[AES_BLOCK_SIZE - 1] |= 0x80;
    ctr_apply(&cipher, &mut counter, data);

    let digest = polyval_digest(&auth_key, aad, data);
    auth_key.zeroize();
    let Some(digest) = digest else {
        return false;
    };

    let expected = siv_tag(&cipher, nonce, digest);
    constant_time_eq(&expected, tag)
}

/// Reusable AES-256-GCM-SIV key state: the key-generating AES schedule.
struct SivKeyState {
    master: aes::Aes256,
}

impl SivKeyState {
    fn init_in_place(dst: NonNull<Self>, key: &[u8; KEY_SIZE]) -> Result<(), Error> {
        if !hardware_available() {
            return Err(Error::UnsupportedCpu);
        }

        let dst = dst.as_ptr();
        // SAFETY: dst points to valid writable SivKeyState storage supplied by
        // the caller. The field pointer stays within that allocation.
        let master_ptr = unsafe { ptr::addr_of_mut!((*dst).master) };
        aes::Aes256::init_in_place(master_ptr, key).ok_or(Error::UnsupportedCpu)?;
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
        validate_siv_lengths(aad.len(), plaintext.len())?;
        let total = plaintext
            .len()
            .checked_add(TAG_SIZE)
            .ok_or(Error::InputTooLarge)?;
        if out.len() < total {
            return Err(Error::OutputTooSmall);
        }

        let (ciphertext, rest) = out.split_at_mut(plaintext.len());
        ciphertext.copy_from_slice(plaintext);
        if let Some(tag) = siv_seal(&self.master, &nonce, aad, ciphertext) {
            rest[..TAG_SIZE].copy_from_slice(&tag);
            Ok(total)
        } else {
            ciphertext.zeroize();
            Err(Error::Encrypt)
        }
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = nonce_from_slice(nonce)?;
        let (ciphertext, tag) = split_ciphertext_tag(ciphertext_and_tag)?;
        validate_siv_lengths(aad.len(), ciphertext.len())?;

        let mut out = vec![0_u8; ciphertext.len()];
        out.copy_from_slice(ciphertext);
        if siv_open(&self.master, &nonce, aad, &mut out, tag) {
            Ok(out)
        } else {
            out.zeroize();
            Err(Error::Decrypt)
        }
    }

    fn decrypt_to(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let nonce = nonce_from_slice(nonce)?;
        let (ciphertext, tag) = split_ciphertext_tag(ciphertext_and_tag)?;
        validate_siv_lengths(aad.len(), ciphertext.len())?;
        if out.len() < ciphertext.len() {
            return Err(Error::OutputTooSmall);
        }

        let out = &mut out[..ciphertext.len()];
        out.copy_from_slice(ciphertext);
        if siv_open(&self.master, &nonce, aad, out, tag) {
            Ok(ciphertext.len())
        } else {
            out.zeroize();
            Err(Error::Decrypt)
        }
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
        validate_siv_lengths(aad.len(), plaintext.len())?;
        let total = plaintext
            .len()
            .checked_add(TAG_SIZE + NONCE_SIZE)
            .ok_or(Error::InputTooLarge)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(plaintext);
        let Some(tag) = siv_seal(&self.master, &nonce, aad, out.as_mut_slice()) else {
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
        validate_siv_lengths(aad.len(), plaintext.len())?;
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
        validate_siv_lengths(0, in_out.len())?;
        let total = in_out
            .len()
            .checked_add(TAG_SIZE + NONCE_SIZE)
            .ok_or(Error::InputTooLarge)?;
        if in_out.capacity() < total {
            in_out.reserve_exact(total - in_out.len());
        }
        let Some(tag) = siv_seal(&self.master, &nonce, &[], in_out.as_mut_slice()) else {
            in_out.zeroize();
            return Err(Error::Encrypt);
        };
        append_tag_nonce(in_out, &tag, &nonce);
        Ok(())
    }

    fn decrypt_envelope(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        let (ciphertext_and_tag, nonce) = split_trailing_nonce(data)?;
        self.decrypt(nonce, aad, ciphertext_and_tag)
    }

    fn decrypt_envelope_to(&self, aad: &[u8], data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let (ciphertext_and_tag, nonce) = split_trailing_nonce(data)?;
        self.decrypt_to(nonce, aad, ciphertext_and_tag, out)
    }
}

fn split_ciphertext_tag(input: &[u8]) -> Result<(&[u8], &[u8; TAG_SIZE]), Error> {
    if input.len() < TAG_SIZE {
        return Err(Error::Decrypt);
    }
    let tag_pos = input.len() - TAG_SIZE;
    let (ciphertext, tag) = input.split_at(tag_pos);
    let tag: &[u8; TAG_SIZE] = tag.try_into().map_err(|_| Error::Decrypt)?;
    Ok((ciphertext, tag))
}

fn init_siv_key_state_at(key: &[u8], state: NonNull<SivKeyState>) -> Result<(), Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeyLength);
    }
    let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
    SivKeyState::init_in_place(state, key)
}

/// Shared no-alloc nonce-appended encryption: `ciphertext || tag || nonce`.
#[cfg(any(test, feature = "hazmat-explicit-nonce"))]
fn encrypt_nonce_appended_to(
    state: &SivKeyState,
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

fn split_trailing_nonce(data: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if data.len() < TAG_SIZE + NONCE_SIZE {
        return Err(Error::CiphertextTooShort);
    }
    let nonce_pos = data.len() - NONCE_SIZE;
    Ok(data.split_at(nonce_pos))
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    // Compile-time proof that SivKeyState stays thread-safe; the unsafe
    // Send/Sync impls on the caller-placed handle below rely on it.
    assert_send_sync::<SivKeyState>();
};

// ---------------------------------------------------------------------------
// Owned, boxed key state.
// ---------------------------------------------------------------------------

/// Owned reusable hardware-only AES-256-GCM-SIV key state.
pub struct HardwareAes256GcmSiv {
    state: Box<SivKeyState>,
    /// Lazily initialized on the first encrypting default API call. Held
    /// outside `SivKeyState`, so it does not affect the boxed key-state
    /// footprint.
    nonce_gen: Option<nonce::NonceGen>,
}

impl HardwareAes256GcmSiv {
    /// Creates reusable AES-256-GCM-SIV state from a raw 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] if `key` is not exactly 32 bytes, or
    /// [`Error::UnsupportedCpu`] if required AES/carryless-multiply hardware is
    /// absent.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength);
        }
        let mut state = Box::<SivKeyState>::new_uninit();
        // SAFETY: Box::new_uninit returns a non-null allocation for SivKeyState.
        let ptr = unsafe { NonNull::new_unchecked(state.as_mut_ptr()) };
        init_siv_key_state_at(key, ptr)?;
        // SAFETY: init_siv_key_state_at initialized the allocation on success.
        let state = unsafe { state.assume_init() };
        Ok(Self {
            state,
            nonce_gen: None,
        })
    }

    /// Returns whether all required AES-GCM-SIV hardware features are available.
    #[must_use]
    pub fn hardware_available() -> bool {
        hardware_available()
    }

    /// Returns the current size of the reusable key state.
    #[must_use]
    pub const fn state_size() -> usize {
        std::mem::size_of::<SivKeyState>()
    }

    /// Returns the current opaque key-state layout for caller-provided storage.
    #[must_use]
    pub const fn key_state_layout() -> KeyStateLayout {
        KeyStateLayout {
            size: std::mem::size_of::<SivKeyState>(),
            align: std::mem::align_of::<SivKeyState>(),
        }
    }

    /// Encrypts `plaintext` and returns `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails,
    /// [`Error::InputTooLarge`] if `plaintext` or `aad` exceed the GCM-SIV
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
    /// `plaintext` or `aad` exceed the GCM-SIV limits, or [`Error::Encrypt`]
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

    /// Encrypts `plaintext` into a caller-provided buffer as `ciphertext || tag`
    /// and returns the written length. No heap allocation is performed.
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
    /// [`Error::Decrypt`].
    pub fn decrypt(&self, aad: &[u8], ciphertext_tag_nonce: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.decrypt_envelope(aad, ciphertext_tag_nonce)
    }

    /// Decrypts `ciphertext || tag || nonce` into a caller-provided buffer and
    /// returns the plaintext length.
    ///
    /// Decrypts into `out` before the tag comparison; if authentication fails,
    /// the written prefix of `out` is zeroized before returning
    /// [`Error::Decrypt`].
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
    /// Decrypts into `out` before the tag comparison; if authentication fails,
    /// the written prefix of `out` is zeroized before returning
    /// [`Error::Decrypt`].
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

    /// Encrypts the plaintext already in `in_out` in place, then appends the tag
    /// and nonce so the final layout is `ciphertext || tag || nonce`.
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
    /// and nonce, plus [`Error::InvalidNonceLength`], [`Error::InputTooLarge`],
    /// or [`Error::Decrypt`].
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

    /// Encrypts `plaintext` under a library-generated nonce, returning the nonce
    /// alongside `ciphertext || tag`.
    ///
    /// GCM-SIV tolerates accidental nonce reuse far more gracefully than GCM,
    /// but the generated sequence still yields distinct nonces (see [`crate`]).
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

    /// Encrypts `plaintext` under a library-generated nonce and returns the
    /// self-framed `ciphertext || tag || nonce` layout (empty AAD).
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

impl std::fmt::Debug for HardwareAes256GcmSiv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareAes256GcmSiv")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Allocation-free inline key state.
// ---------------------------------------------------------------------------

#[repr(transparent)]
struct AlignedSivStorage(MaybeUninit<SivKeyState>);

impl AlignedSivStorage {
    #[inline]
    const fn uninit() -> Self {
        Self(MaybeUninit::uninit())
    }

    #[inline]
    fn state_ptr(&self) -> *const SivKeyState {
        self.0.as_ptr()
    }

    #[inline]
    fn state_ptr_mut(&mut self) -> NonNull<SivKeyState> {
        // SAFETY: MaybeUninit<SivKeyState> is non-null and aligned for it.
        unsafe { NonNull::new_unchecked(self.0.as_mut_ptr()) }
    }

    #[inline]
    fn bytes_ptr_mut(&mut self) -> *mut u8 {
        self.0.as_mut_ptr().cast::<u8>()
    }
}

/// Allocation-free owned reusable AES-256-GCM-SIV key state.
///
/// Stores the key-generating AES schedule inline in the value, avoiding the
/// heap allocation used by [`HardwareAes256GcmSiv`] while still wiping the key
/// state on drop. The nonce generator is held outside the inline key state.
pub struct HardwareAes256GcmSivKeyState {
    storage: AlignedSivStorage,
    nonce_gen: Option<nonce::NonceGen>,
}

impl HardwareAes256GcmSivKeyState {
    /// Creates reusable AES-256-GCM-SIV state from a raw 32-byte key without
    /// heap allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] if `key` is not exactly 32 bytes, or
    /// [`Error::UnsupportedCpu`] if required hardware is absent.
    #[inline]
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let mut storage = AlignedSivStorage::uninit();
        init_siv_key_state_at(key, storage.state_ptr_mut())?;
        Ok(Self {
            storage,
            nonce_gen: None,
        })
    }

    /// Returns the current size of the reusable inline key state.
    #[must_use]
    pub const fn state_size() -> usize {
        std::mem::size_of::<SivKeyState>()
    }

    /// Encrypts `plaintext` and returns `ciphertext || tag || nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OsEntropy`] if nonce generation fails,
    /// [`Error::InputTooLarge`] if `plaintext` or `aad` exceed the GCM-SIV
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
    /// `plaintext` or `aad` exceed the GCM-SIV limits, or [`Error::Encrypt`]
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
    /// Decrypts into `out` before the tag comparison; if authentication fails,
    /// the written prefix of `out` is zeroized before returning
    /// [`Error::Decrypt`].
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

    /// Encrypts the plaintext already in `in_out` in place, then appends the tag
    /// and nonce so the final layout is `ciphertext || tag || nonce`.
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
    /// and nonce, plus [`Error::InvalidNonceLength`], [`Error::InputTooLarge`],
    /// or [`Error::Decrypt`].
    #[inline]
    #[cfg(any(test, feature = "hazmat-explicit-nonce"))]
    #[doc(hidden)]
    pub fn decrypt_nonce_appended(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.state_ref().decrypt_envelope(&[], data)
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_SIZE], Error> {
        match self.nonce_gen {
            Some(ref mut g) => g.next(),
            None => self.nonce_gen.insert(nonce::NonceGen::new()?).next(),
        }
    }

    fn state_ref(&self) -> &SivKeyState {
        // SAFETY: new initialized storage before constructing Self, and the
        // storage is never mutated except during Drop after all shared borrows
        // have ended.
        unsafe { &*self.storage.state_ptr() }
    }
}

impl Drop for HardwareAes256GcmSivKeyState {
    fn drop(&mut self) {
        let size = Self::state_size();
        // SivKeyState's only field (Aes256) has a Drop impl that wipes its own
        // bytes and releases no other resource, so one volatile wipe of the
        // inline storage supersedes it. If SivKeyState ever gains a
        // resource-owning field, this must run drop_in_place first.
        // SAFETY: storage is inline in self, writable for `size` bytes, and
        // aligned for SivKeyState by AlignedSivStorage.
        unsafe { volatile_wipe(self.storage.bytes_ptr_mut(), size) };
    }
}

impl std::fmt::Debug for HardwareAes256GcmSivKeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareAes256GcmSivKeyState")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Caller-placed key state.
// ---------------------------------------------------------------------------

/// Caller-owned uninitialized storage for AES-256-GCM-SIV key state.
pub struct SivUninitKeyStateSlot<'a> {
    storage: &'a mut [u8],
}

impl<'a> SivUninitKeyStateSlot<'a> {
    /// Validates caller-provided storage for key-state initialization.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyStateStorageTooSmall`] or
    /// [`Error::KeyStateStorageMisaligned`] before any key material is touched.
    pub fn new(storage: &'a mut [u8]) -> Result<Self, Error> {
        let layout = HardwareAes256GcmSiv::key_state_layout();
        if storage.len() < layout.size {
            return Err(Error::KeyStateStorageTooSmall);
        }
        if !storage.as_ptr().addr().is_multiple_of(layout.align) {
            return Err(Error::KeyStateStorageMisaligned);
        }
        Ok(Self { storage })
    }
}

impl std::fmt::Debug for SivUninitKeyStateSlot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SivUninitKeyStateSlot")
            .field("len", &self.storage.len())
            .finish_non_exhaustive()
    }
}

fn init_siv_key_state_in_slot(
    key: &[u8],
    slot: SivUninitKeyStateSlot<'_>,
) -> Result<NonNull<u8>, Error> {
    let SivUninitKeyStateSlot { storage } = slot;
    // The raw pointer is taken once and the `&mut` slice ends here, so the
    // handle never aliases a live mutable reference.
    // SAFETY: SivUninitKeyStateSlot validated that storage has sufficient
    // length and SivKeyState alignment, so the pointer is non-null.
    let storage = unsafe { NonNull::new_unchecked(storage.as_mut_ptr()) };
    #[allow(clippy::cast_ptr_alignment)]
    let state = storage.cast::<SivKeyState>();
    init_siv_key_state_at(key, state)?;
    Ok(storage)
}

/// Opaque initialized key-equivalent state in caller-owned storage.
struct OpaqueSivState<'a> {
    storage: NonNull<u8>,
    _marker: PhantomData<&'a mut [u8]>,
}

// SAFETY: OpaqueSivState exclusively owns the SivKeyState in the caller storage
// for 'a (the storage `&mut` borrow is consumed on construction). SivKeyState
// is Send + Sync (asserted above), there is no interior mutability, and all
// access outside drop is read-only, so moving the handle across threads is
// sound.
unsafe impl Send for OpaqueSivState<'_> {}
// SAFETY: see the Send impl; a shared OpaqueSivState only permits shared reads
// of a Sync pointee.
unsafe impl Sync for OpaqueSivState<'_> {}

impl OpaqueSivState<'_> {
    fn state_ptr(&self) -> *mut SivKeyState {
        // SivUninitKeyStateSlot validated SivKeyState alignment before this
        // handle could be constructed.
        #[allow(clippy::cast_ptr_alignment)]
        self.storage.as_ptr().cast::<SivKeyState>()
    }
}

impl Drop for OpaqueSivState<'_> {
    fn drop(&mut self) {
        let size = HardwareAes256GcmSiv::key_state_layout().size;
        // See HardwareAes256GcmSivKeyState::drop: one volatile wipe supersedes
        // the field Drop impl, which owns no other resource.
        // SAFETY: the caller storage remains borrowed for 'a, holds at least
        // `size` bytes, and is SivKeyState-aligned (validated at slot
        // construction).
        unsafe { volatile_wipe(self.storage.as_ptr(), size) };
    }
}

/// AES-256-GCM-SIV instance backed by caller-owned key-state storage.
pub struct HardwareAes256GcmSivIn<'a> {
    state: OpaqueSivState<'a>,
    /// Lazily initialized on the first encrypting default API call. Not part
    /// of the caller-placed key state, so it does not affect
    /// `key_state_layout`.
    nonce_gen: Option<nonce::NonceGen>,
}

impl<'a> HardwareAes256GcmSivIn<'a> {
    /// Initializes reusable AES-256-GCM-SIV state directly in caller-owned
    /// storage.
    ///
    /// # Errors
    ///
    /// Returns storage validation errors, [`Error::InvalidKeyLength`], or
    /// [`Error::UnsupportedCpu`].
    pub fn new_in(key: &[u8], slot: SivUninitKeyStateSlot<'a>) -> Result<Self, Error> {
        let storage = init_siv_key_state_in_slot(key, slot)?;
        Ok(Self {
            state: OpaqueSivState {
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

    /// Encrypts `plaintext` into a caller-provided buffer as `ciphertext || tag`
    /// and returns the written length. No heap allocation is performed.
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

    /// Encrypts the plaintext already in `in_out` in place, then appends the tag
    /// and nonce so the final layout is `ciphertext || tag || nonce`.
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
    /// and nonce, plus [`Error::InvalidNonceLength`], [`Error::InputTooLarge`],
    /// or [`Error::Decrypt`].
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

    /// Encrypts `plaintext` under a library-generated nonce, returning the nonce
    /// alongside `ciphertext || tag`.
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

    /// Encrypts `plaintext` under a library-generated nonce and returns the
    /// self-framed `ciphertext || tag || nonce` layout (empty AAD).
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

    fn state_ref(&self) -> &SivKeyState {
        // SAFETY: OpaqueSivState owns a live initialized SivKeyState until drop.
        unsafe { &*self.state.state_ptr() }
    }
}

impl std::fmt::Debug for HardwareAes256GcmSivIn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareAes256GcmSivIn")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::{
        aes, build_message_cipher, ctr_apply, derive_keys, increment_siv_counter, polyval_digest,
        AES_BLOCK_SIZE, NONCE_SIZE,
    };

    fn cipher() -> aes::Aes256 {
        build_message_cipher(&[0x42_u8; 32]).expect("hardware AES available in tests")
    }

    /// The SIV counter is a 32-bit little-endian counter in the low four bytes
    /// only; it must wrap mod 2^32 and never carry into the remaining twelve
    /// bytes (which carry the high bits of the tag, including the 0x80 marker).
    #[test]
    fn counter_wraps_low_32_bits_only() {
        let mut counter = [0_u8; AES_BLOCK_SIZE];
        counter[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        counter[8] = 0xAB;
        counter[AES_BLOCK_SIZE - 1] = 0x80;

        increment_siv_counter(&mut counter);

        assert_eq!(
            &counter[..4],
            &0_u32.to_le_bytes(),
            "low 32 bits must wrap to 0"
        );
        assert_eq!(counter[8], 0xAB, "high bytes must be preserved");
        assert_eq!(
            counter[AES_BLOCK_SIZE - 1],
            0x80,
            "0x80 marker must be preserved"
        );
    }

    #[test]
    fn counter_increments_without_carry_into_high_bytes() {
        let mut counter = [0_u8; AES_BLOCK_SIZE];
        counter[..4].copy_from_slice(&0x00FF_FFFF_u32.to_le_bytes());
        counter[4] = 0x99; // first high byte; must never change
        increment_siv_counter(&mut counter);
        assert_eq!(&counter[..4], &0x0100_0000_u32.to_le_bytes());
        assert_eq!(counter[4], 0x99);
    }

    /// Deterministic end-to-end exercise of the 32-bit counter wrap through the
    /// real hardware AES: a five-block CTR pass started two below the boundary
    /// crosses 0xFFFFFFFF -> 0x00000000. Compared against an independent
    /// block-by-block CTR built from `encrypt_block`.
    #[test]
    fn ctr_apply_matches_blockwise_across_32bit_wrap() {
        let cipher = cipher();

        let mut start = [0_u8; AES_BLOCK_SIZE];
        start[..4].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes());
        start[4..].copy_from_slice(&[0x11_u8; 12]);
        start[AES_BLOCK_SIZE - 1] = 0x80;

        let plaintext = [0xA5_u8; AES_BLOCK_SIZE * 5];

        // Independent reference CTR: counters 0xFFFFFFFE, 0xFFFFFFFF,
        // 0x00000000, 0x00000001, 0x00000002 with the high bytes fixed.
        let mut expected = plaintext;
        let mut ctr = 0xFFFF_FFFE_u32;
        for block in expected.chunks_mut(AES_BLOCK_SIZE) {
            let mut keystream = start;
            keystream[..4].copy_from_slice(&ctr.to_le_bytes());
            cipher.encrypt_block(&mut keystream);
            for (byte, key_byte) in block.iter_mut().zip(keystream.iter()) {
                *byte ^= key_byte;
            }
            ctr = ctr.wrapping_add(1);
        }

        let mut got = plaintext;
        let mut counter = start;
        ctr_apply(&cipher, &mut counter, &mut got);

        assert_eq!(got, expected, "CTR output must match across the wrap");
        // 0xFFFFFFFE + 5 = 0x1_0000_0003 -> low 32 bits = 3, high bytes intact.
        assert_eq!(&counter[..4], &3_u32.to_le_bytes());
        assert_eq!(&counter[4..], &start[4..]);
    }

    /// The 8-way batch path and the serial tail must agree: a length that is
    /// neither block- nor batch-aligned still round-trips (CTR is its own
    /// inverse) and actually transforms the data.
    #[test]
    fn ctr_apply_batch_and_tail_round_trip() {
        let cipher = cipher();
        let plaintext = [0x5A_u8; AES_BLOCK_SIZE * 9 + 7]; // one 8-block batch + 1 block + 7 bytes

        let mut data = plaintext;
        let mut counter = [0_u8; AES_BLOCK_SIZE];
        counter[AES_BLOCK_SIZE - 1] = 0x80;
        ctr_apply(&cipher, &mut counter, &mut data);
        assert_ne!(data, plaintext, "CTR must transform the data");

        let mut counter = [0_u8; AES_BLOCK_SIZE];
        counter[AES_BLOCK_SIZE - 1] = 0x80;
        ctr_apply(&cipher, &mut counter, &mut data);
        assert_eq!(data, plaintext, "applying CTR twice must restore the input");
    }

    /// Key derivation is a deterministic function of (key, nonce): the same
    /// inputs yield the same keys, and changing only the nonce changes both
    /// derived keys.
    #[test]
    fn derive_keys_is_deterministic_and_nonce_dependent() {
        let master = cipher();
        let nonce_a = [0x07_u8; NONCE_SIZE];
        let mut nonce_b = nonce_a;
        nonce_b[0] ^= 1;

        let (auth_a, enc_a) = derive_keys(&master, &nonce_a);
        let (auth_a2, enc_a2) = derive_keys(&master, &nonce_a);
        assert_eq!(auth_a, auth_a2);
        assert_eq!(enc_a, enc_a2);

        let (auth_b, enc_b) = derive_keys(&master, &nonce_b);
        assert_ne!(auth_a, auth_b, "auth key must depend on the nonce");
        assert_ne!(enc_a, enc_b, "encryption key must depend on the nonce");
    }

    /// POLYVAL over the message is deterministic and sensitive to both AAD and
    /// message content.
    #[test]
    fn polyval_digest_is_deterministic_and_input_sensitive() {
        let auth_key = [0x33_u8; 16];
        let aad = b"metadata";
        let message = b"the quick brown fox";

        let d1 = polyval_digest(&auth_key, aad, message).expect("hardware");
        let d2 = polyval_digest(&auth_key, aad, message).expect("hardware");
        assert_eq!(d1, d2);

        let d_aad = polyval_digest(&auth_key, b"metadatb", message).expect("hardware");
        assert_ne!(d1, d_aad, "digest must depend on AAD");

        let d_msg = polyval_digest(&auth_key, aad, b"the quick brown FOX").expect("hardware");
        assert_ne!(d1, d_msg, "digest must depend on the message");
    }
}

/// Kani bounded-model-checking harnesses for the intrinsic-free SIV logic.
///
/// Verifies the **actual compiled Rust** (CBMC) over all inputs (bounded where
/// noted): the SIV counter increment, the length validation, and the two
/// attacker-facing envelope parsers (ciphertext/tag and trailing-nonce splits)
/// never panic and compute the correct boundaries. Run with `cargo kani`.
/// Compiled only under `cfg(kani)`.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        increment_siv_counter, split_ciphertext_tag, split_trailing_nonce, validate_siv_lengths,
        Error, MAX_SIV_LEN, NONCE_SIZE, TAG_SIZE,
    };

    /// The compiled `increment_siv_counter` is the RFC 8452 little-endian 32-bit
    /// increment of the leading four bytes; the trailing twelve are untouched.
    /// Verified over all 2^128 counter blocks.
    #[kani::proof]
    fn increment_siv_counter_is_le32_inc() {
        let mut counter: [u8; 16] = kani::any();
        let original = counter;
        increment_siv_counter(&mut counter);
        assert!(counter[4..] == original[4..]);
        let low = u32::from_le_bytes([original[0], original[1], original[2], original[3]]);
        assert!(counter[..4] == low.wrapping_add(1).to_le_bytes());
    }

    /// `validate_siv_lengths` never panics and accepts exactly the lengths within
    /// the RFC 8452 2^36-byte cap on both the AAD and the message.
    #[kani::proof]
    fn validate_siv_lengths_matches_limits() {
        let aad_len: usize = kani::any();
        let data_len: usize = kani::any();
        let result = validate_siv_lengths(aad_len, data_len);
        let in_range = (aad_len as u64) <= MAX_SIV_LEN && (data_len as u64) <= MAX_SIV_LEN;
        assert!(result.is_ok() == in_range);
    }

    /// `split_ciphertext_tag` never panics and splits at `len - TAG_SIZE`, exactly
    /// when the input is at least one tag long. Bounded to lengths 0..=48.
    #[kani::proof]
    fn split_ciphertext_tag_boundary() {
        let len: usize = kani::any();
        kani::assume(len <= 48);
        let buf = [0_u8; 48];
        match split_ciphertext_tag(&buf[..len]) {
            Ok((ct, tag)) => {
                assert!(len >= TAG_SIZE);
                assert!(ct.len() == len - TAG_SIZE);
                assert!(tag.len() == TAG_SIZE);
            }
            Err(e) => {
                assert!(len < TAG_SIZE);
                assert!(matches!(e, Error::Decrypt));
            }
        }
    }

    /// `split_trailing_nonce` never panics and splits at `len - NONCE_SIZE`,
    /// exactly when the input holds at least a tag and a nonce. Bounded 0..=48.
    #[kani::proof]
    fn split_trailing_nonce_boundary() {
        let len: usize = kani::any();
        kani::assume(len <= 48);
        let buf = [0_u8; 48];
        match split_trailing_nonce(&buf[..len]) {
            Ok((body, nonce)) => {
                assert!(len >= TAG_SIZE + NONCE_SIZE);
                assert!(nonce.len() == NONCE_SIZE);
                assert!(body.len() == len - NONCE_SIZE);
            }
            Err(e) => {
                assert!(len < TAG_SIZE + NONCE_SIZE);
                assert!(matches!(e, Error::CiphertextTooShort));
            }
        }
    }
}
