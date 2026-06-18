//! Minimal hardware-only GHASH backend.
//!
//! This vendors the `ghash 0.5.1` GHASH-to-POLYVAL mapping and the
//! `polyval 0.6.2` CLMUL/PMULL backends (Apache-2.0 OR MIT, The `RustCrypto`
//! Project Developers; see the repository `NOTICE` file for full
//! attribution), without the software fallback or autodetect enum. On top of
//! the vendored single-block multiply it adds the standard aggregated
//! reduction: eight precomputed Montgomery-form key powers let eight blocks be
//! folded with one field reduction (the wide carryless products are XOR-linear,
//! so they are summed before a single reduction), with four- and one-block
//! reductions for the sub-batch tail.
//!
//! # Constant-time notes
//!
//! Every GF(2^128) multiplication executes via PMULL/PMULL2 (aarch64) or
//! PCLMULQDQ (x86) carryless-multiply instructions with data-independent
//! timing; the field reduction is a fixed sequence
//! of shifts, shuffles, and XORs. Block staging (copy plus byte reversal for
//! the GHASH-to-POLYVAL mapping) touches fixed-size 16-byte buffers at
//! offsets derived from loop indices. The only data-dependent control flow
//! in this module branches on input *lengths*, which are public in GCM; no
//! branch or memory index depends on key material, message contents, or the
//! accumulator.

#![allow(unsafe_code)]

use core::ptr;
use zeroize::Zeroize as _;

/// Number of precomputed Montgomery-form key powers held in the key state.
/// Eight powers let a full eight-block batch fold with one field reduction,
/// matching the stitched encrypt batch width.
const KEY_POWERS: usize = 8;

/// Reusable GHASH key material: POLYVAL-domain Montgomery powers
/// `[H^1, H^2, ..., H^8]`.
pub(crate) struct GHashKey {
    polyval_key_powers: [[u8; 16]; KEY_POWERS],
}

impl GHashKey {
    /// Initializes the key powers in place. Returns `None` when the required
    /// carryless-multiply hardware is unavailable (callers check
    /// `hardware_available` first, so this is defensive).
    pub(crate) fn init_in_place(dst: *mut Self, hash_subkey: &mut [u8; 16]) -> Option<()> {
        if !hardware_available() {
            return None;
        }

        hash_subkey.reverse();
        let h1 = mulx(hash_subkey);
        hash_subkey.zeroize();
        // SAFETY: hardware_available verified the carryless-multiply features
        // required by imp::mul above.
        let h2 = unsafe { imp::mul(&h1, &h1) };
        // SAFETY: as above.
        let h3 = unsafe { imp::mul(&h2, &h1) };
        // SAFETY: as above.
        let h4 = unsafe { imp::mul(&h2, &h2) };
        // SAFETY: as above.
        let h5 = unsafe { imp::mul(&h4, &h1) };
        // SAFETY: as above.
        let h6 = unsafe { imp::mul(&h4, &h2) };
        // SAFETY: as above.
        let h7 = unsafe { imp::mul(&h4, &h3) };
        // SAFETY: as above.
        let h8 = unsafe { imp::mul(&h4, &h4) };
        let mut powers = [h1, h2, h3, h4, h5, h6, h7, h8];
        // SAFETY: caller provides valid writable storage for Self and the field
        // pointer stays within that allocation.
        unsafe { ptr::addr_of_mut!((*dst).polyval_key_powers).write(powers) };
        powers.zeroize();
        Some(())
    }
}

impl Drop for GHashKey {
    fn drop(&mut self) {
        // SAFETY: polyval_key_powers is live writable key material.
        unsafe { volatile_zero(ptr::addr_of_mut!(self.polyval_key_powers)) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Streaming GHASH state over one message (AAD section, then data section).
pub(crate) struct Ghasher {
    backend: imp::Backend,
}

impl Ghasher {
    pub(crate) fn new(key: &GHashKey) -> Option<Self> {
        Some(Self {
            backend: imp::Backend::new(&key.polyval_key_powers)?,
        })
    }

    /// Stitched CTR-encrypt + GHASH over the eight-block-aligned bulk region,
    /// advancing the GHASH accumulator and the CTR `counter`. The caller
    /// absorbs AAD first, handles the sub-128-byte tail afterward, and then
    /// finalizes. `plaintext` and `ciphertext` must be equal length and a
    /// whole number of 128-byte batches.
    pub(crate) fn seal_bulk(
        &mut self,
        round_keys: &crate::aes_gcm::aes::RoundKeys,
        counter: &mut [u8; 16],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) {
        self.backend
            .seal_bulk(round_keys, counter, plaintext, ciphertext);
    }

    /// Stitched CTR-encrypt + GHASH over an eight-block-aligned bulk region
    /// held in one mutable buffer. The buffer enters as plaintext and exits as
    /// ciphertext.
    pub(crate) fn seal_in_place_bulk(
        &mut self,
        round_keys: &crate::aes_gcm::aes::RoundKeys,
        counter: &mut [u8; 16],
        data: &mut [u8],
    ) {
        self.backend.seal_in_place_bulk(round_keys, counter, data);
    }

    /// Stitched CTR-encrypt + GHASH over the full-block tail below the
    /// eight-block bulk width. The buffer enters as plaintext and exits as
    /// ciphertext.
    pub(crate) fn seal_in_place_tail_blocks(
        &mut self,
        round_keys: &crate::aes_gcm::aes::RoundKeys,
        counter: &mut [u8; 16],
        data: &mut [u8],
    ) {
        self.backend
            .seal_in_place_tail_blocks(round_keys, counter, data);
    }

    /// Stitched GHASH + CTR-decrypt over the eight-block-aligned bulk region,
    /// advancing the GHASH accumulator and the CTR `counter`. The caller
    /// absorbs AAD first, handles the sub-128-byte tail afterward, and then
    /// finalizes. `ciphertext` and `plaintext` must be equal length and a
    /// whole number of 128-byte batches.
    pub(crate) fn open_bulk(
        &mut self,
        round_keys: &crate::aes_gcm::aes::RoundKeys,
        counter: &mut [u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) {
        self.backend
            .open_bulk(round_keys, counter, ciphertext, plaintext);
    }

    /// Stitched GHASH + CTR-decrypt over an eight-block-aligned bulk region
    /// held in one mutable buffer. The buffer enters as ciphertext and exits as
    /// plaintext.
    pub(crate) fn open_in_place_bulk(
        &mut self,
        round_keys: &crate::aes_gcm::aes::RoundKeys,
        counter: &mut [u8; 16],
        data: &mut [u8],
    ) {
        self.backend.open_in_place_bulk(round_keys, counter, data);
    }

    /// Absorbs a 16-byte-multiple run of bytes, eight blocks per reduction
    /// where possible, then four, then one.
    ///
    /// Callers stream section bytes through this in block-aligned chunks and
    /// close the section with [`Self::absorb_padded`] for any partial tail.
    pub(crate) fn absorb_blocks(&mut self, data: &[u8]) {
        debug_assert!(
            data.len().is_multiple_of(16),
            "absorb_blocks needs whole blocks"
        );

        let mut octets = data.chunks_exact(128);
        for octet in &mut octets {
            let mut blocks = [[0_u8; 16]; 8];
            for (block, chunk) in blocks.iter_mut().zip(octet.chunks_exact(16)) {
                block.copy_from_slice(chunk);
                block.reverse();
            }
            self.backend.update_blocks8(&blocks);
        }

        let mut quads = octets.remainder().chunks_exact(64);
        for quad in &mut quads {
            let mut blocks = [[0_u8; 16]; 4];
            for (block, chunk) in blocks.iter_mut().zip(quad.chunks_exact(16)) {
                block.copy_from_slice(chunk);
                block.reverse();
            }
            self.backend.update_blocks4(&blocks);
        }

        for chunk in quads.remainder().chunks_exact(16) {
            let mut block = [0_u8; 16];
            block.copy_from_slice(chunk);
            block.reverse();
            self.backend.update_block(&block);
        }
    }

    /// Absorbs the remaining bytes of a section, zero-padding the final
    /// partial block.
    pub(crate) fn absorb_padded(&mut self, data: &[u8]) {
        let full = data.len() - data.len() % 16;
        self.absorb_blocks(&data[..full]);

        let remainder = &data[full..];
        if !remainder.is_empty() {
            let mut block = [0_u8; 16];
            block[..remainder.len()].copy_from_slice(remainder);
            block.reverse();
            self.backend.update_block(&block);
        }
    }

    /// Absorbs the length block and returns the GHASH output.
    ///
    /// Returns `None` if a length does not fit the 64-bit GCM length field
    /// (already excluded by the public-API length validation).
    pub(crate) fn finalize(self, aad_len: usize, data_len: usize) -> Option<[u8; 16]> {
        let mut length_block = [0_u8; 16];
        length_block[..8].copy_from_slice(&bit_len(aad_len)?.to_be_bytes());
        length_block[8..].copy_from_slice(&bit_len(data_len)?.to_be_bytes());
        length_block.reverse();

        let mut backend = self.backend;
        backend.update_block(&length_block);
        let mut tag = backend.finalize();
        tag.reverse();
        Some(tag)
    }
}

pub(crate) fn hardware_available() -> bool {
    imp::hardware_available()
}

/// POLYVAL (RFC 8452) over one AES-256-GCM-SIV message, built on the same
/// carryless-multiply backend as GHASH.
///
/// POLYVAL is the field operation the backend computes natively: the GHASH
/// path above adapts it with per-block byte reversal and a `mulX` on the hash
/// key, and POLYVAL simply omits both. Blocks enter in their natural
/// little-endian byte order, the message-authentication key is used directly
/// (no `mulX`), and the length block is little-endian. The aggregated eight-,
/// four-, and one-block reductions are shared verbatim, so POLYVAL runs at the
/// same rate as the GHASH authentication pass.
pub(crate) struct Polyval {
    backend: imp::Backend,
}

impl Polyval {
    /// Builds the eight Montgomery-form POLYVAL key powers
    /// `[H^1, ..., H^8]` directly from the 16-byte message-authentication key.
    ///
    /// Unlike [`GHashKey::init_in_place`], the key is consumed as-is: no byte
    /// reversal and no `mulX`, because POLYVAL is already the backend's native
    /// domain. Returns `None` when the carryless-multiply hardware is absent.
    pub(crate) fn key_powers(auth_key: &[u8; 16]) -> Option<[[u8; 16]; KEY_POWERS]> {
        if !hardware_available() {
            return None;
        }

        let h1 = *auth_key;
        // SAFETY: hardware_available verified the carryless-multiply features
        // required by imp::mul.
        let h2 = unsafe { imp::mul(&h1, &h1) };
        // SAFETY: as above.
        let h3 = unsafe { imp::mul(&h2, &h1) };
        // SAFETY: as above.
        let h4 = unsafe { imp::mul(&h2, &h2) };
        // SAFETY: as above.
        let h5 = unsafe { imp::mul(&h4, &h1) };
        // SAFETY: as above.
        let h6 = unsafe { imp::mul(&h4, &h2) };
        // SAFETY: as above.
        let h7 = unsafe { imp::mul(&h4, &h3) };
        // SAFETY: as above.
        let h8 = unsafe { imp::mul(&h4, &h4) };
        Some([h1, h2, h3, h4, h5, h6, h7, h8])
    }

    pub(crate) fn new(powers: &[[u8; 16]; KEY_POWERS]) -> Option<Self> {
        Some(Self {
            backend: imp::Backend::new(powers)?,
        })
    }

    /// Absorbs a 16-byte-multiple run, eight blocks per reduction where
    /// possible, then four, then one. POLYVAL consumes blocks in their natural
    /// little-endian order, so unlike GHASH there is no per-block reversal.
    pub(crate) fn absorb_blocks(&mut self, data: &[u8]) {
        debug_assert!(
            data.len().is_multiple_of(16),
            "absorb_blocks needs whole blocks"
        );

        let mut octets = data.chunks_exact(128);
        for octet in &mut octets {
            let mut blocks = [[0_u8; 16]; 8];
            for (block, chunk) in blocks.iter_mut().zip(octet.chunks_exact(16)) {
                block.copy_from_slice(chunk);
            }
            self.backend.update_blocks8(&blocks);
        }

        let mut quads = octets.remainder().chunks_exact(64);
        for quad in &mut quads {
            let mut blocks = [[0_u8; 16]; 4];
            for (block, chunk) in blocks.iter_mut().zip(quad.chunks_exact(16)) {
                block.copy_from_slice(chunk);
            }
            self.backend.update_blocks4(&blocks);
        }

        for chunk in quads.remainder().chunks_exact(16) {
            let mut block = [0_u8; 16];
            block.copy_from_slice(chunk);
            self.backend.update_block(&block);
        }
    }

    /// Absorbs the remaining bytes of a section, zero-padding the final partial
    /// block.
    pub(crate) fn absorb_padded(&mut self, data: &[u8]) {
        let full = data.len() - data.len() % 16;
        self.absorb_blocks(&data[..full]);

        let remainder = &data[full..];
        if !remainder.is_empty() {
            let mut block = [0_u8; 16];
            block[..remainder.len()].copy_from_slice(remainder);
            self.backend.update_block(&block);
        }
    }

    /// Absorbs the little-endian length block `LE64(aad_bits) || LE64(data_bits)`
    /// and returns the POLYVAL output directly (no GHASH output reversal).
    ///
    /// Returns `None` if a length does not fit the 64-bit length field.
    pub(crate) fn finalize_with_lengths(self, aad_len: usize, data_len: usize) -> Option<[u8; 16]> {
        let mut length_block = [0_u8; 16];
        length_block[..8].copy_from_slice(&bit_len(aad_len)?.to_le_bytes());
        length_block[8..].copy_from_slice(&bit_len(data_len)?.to_le_bytes());

        let mut backend = self.backend;
        backend.update_block(&length_block);
        Some(backend.finalize())
    }
}

#[allow(clippy::cast_ptr_alignment)] // Wide stores are alignment-checked at runtime.
unsafe fn volatile_zero<T>(value: *mut T) {
    let len = core::mem::size_of::<T>();
    let bytes = value.cast::<u8>();
    let mut offset = 0_usize;

    // Wipe with the widest volatile stores the pointer alignment allows;
    // byte-wide stores make drop wipes disproportionately expensive.
    if bytes.addr().is_multiple_of(core::mem::align_of::<u128>()) {
        while offset + core::mem::size_of::<u128>() <= len {
            // SAFETY: in bounds of the T behind value and aligned per the
            // check above.
            unsafe { ptr::write_volatile(bytes.add(offset).cast::<u128>(), 0) };
            offset += core::mem::size_of::<u128>();
        }
    } else if bytes.addr().is_multiple_of(core::mem::align_of::<u64>()) {
        while offset + core::mem::size_of::<u64>() <= len {
            // SAFETY: in bounds of the T behind value and aligned per the
            // check above.
            unsafe { ptr::write_volatile(bytes.add(offset).cast::<u64>(), 0) };
            offset += core::mem::size_of::<u64>();
        }
    }

    for offset in offset..len {
        // SAFETY: caller guarantees value points to a live writable T. Every
        // byte offset within size_of::<T>() is within that object.
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
}

fn bit_len(len: usize) -> Option<u64> {
    u64::try_from(len).ok()?.checked_mul(8)
}

/// Constant time despite operating on the secret hash subkey in scalar code:
/// the carry-out (`v_hi`) is folded back in with fixed-distance shifts and
/// XORs, never a branch. `v_hi` is routed through an optimization barrier so
/// the compiler cannot prove it is 0/1 and specialize this into a conditional
/// (it can only ever be those two values, which is exactly what would tempt a
/// branch).
fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = core::hint::black_box(v >> 127);

    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

/// Non-inlined wrapper so the constant-time verifier can disassemble `mulx` as a
/// named symbol and confirm its carry fold compiles branch-free (see
/// `proofs/constant-time/verify.sh`). Build-time only; `ct-verify` is never a
/// shipped feature.
#[cfg(feature = "ct-verify")]
#[inline(never)]
#[must_use]
pub fn ct_verify_mulx(block: &[u8; 16]) -> [u8; 16] {
    mulx(core::hint::black_box(block))
}

/// NON-VACUITY CONTROL for the constant-time verifier. This is a deliberately
/// **leaky** byte comparison - an early-return on a secret-dependent mismatch,
/// the classic timing oracle - that `proofs/constant-time/verify.sh` must
/// *reject*. It proves the check has teeth (it would catch a real regression).
/// Never used by the crate; `ct-verify` is never shipped.
#[cfg(feature = "ct-verify")]
#[inline(never)]
#[must_use]
pub fn ct_verify_leaky_control(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 16 {
        if core::hint::black_box(a[i]) != core::hint::black_box(b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Stable-symbol `extern "C"` wrapper around the carryless-multiply field
/// product (`imp::mul`) so SAW can prove properties of the *compiled* intrinsic
/// code - it reaches through PCLMULQDQ / PMULL, which SAW models. Build-time
/// only; `saw-verify` is never shipped. See `proofs/saw/`.
#[cfg(feature = "saw-verify")]
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn saw_field_mul(a: *const u8, b: *const u8, out: *mut u8) {
    // SAFETY: SAW provides three valid 16-byte buffers; the hardware contract
    // for `imp::mul` is assumed (SAW models the carryless-multiply intrinsic).
    let a = unsafe { &*(a.cast::<[u8; 16]>()) };
    let b = unsafe { &*(b.cast::<[u8; 16]>()) };
    let r = unsafe { imp::mul(a, b) };
    // SAFETY: `out` is a writable 16-byte buffer (direct store; no ub-check).
    unsafe { *(out.cast::<[u8; 16]>()) = r };
}

#[cfg(feature = "saw-verify")]
fn saw_xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut r = [0_u8; 16];
    let mut i = 0;
    while i < 16 {
        r[i] = a[i] ^ b[i];
        i += 1;
    }
    r
}

#[cfg(feature = "saw-verify")]
unsafe fn saw_read16(p: *const u8) -> [u8; 16] {
    // SAFETY: callers (the SAW harnesses) pass valid 16-byte buffers.
    unsafe { *(p.cast::<[u8; 16]>()) }
}

/// Bilinearity residual in the FIRST argument:
/// `mul(a^a', b) ^ mul(a, b) ^ mul(a', b)`. SAW proves this is always zero, i.e.
/// the carryless-multiply field product is GF(2)-linear in its first argument -
/// the property the basis-determination proof (`prove_multiply.py`) relies on,
/// here confirmed over the *compiled* PCLMULQDQ/PMULL code. Build-time only.
#[cfg(feature = "saw-verify")]
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn saw_field_mul_left_linear(
    a: *const u8,
    a2: *const u8,
    b: *const u8,
    out: *mut u8,
) {
    // SAFETY: SAW provides four valid 16-byte buffers.
    let (a, a2, b) = unsafe { (saw_read16(a), saw_read16(a2), saw_read16(b)) };
    let r = unsafe {
        saw_xor16(
            &saw_xor16(&imp::mul(&saw_xor16(&a, &a2), &b), &imp::mul(&a, &b)),
            &imp::mul(&a2, &b),
        )
    };
    // SAFETY: `out` is a writable 16-byte buffer (direct store; no ub-check).
    unsafe { *(out.cast::<[u8; 16]>()) = r };
}

/// Bilinearity residual in the SECOND argument:
/// `mul(a, b^b') ^ mul(a, b) ^ mul(a, b')`. SAW proves this is always zero.
#[cfg(feature = "saw-verify")]
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn saw_field_mul_right_linear(
    a: *const u8,
    b: *const u8,
    b2: *const u8,
    out: *mut u8,
) {
    // SAFETY: SAW provides four valid 16-byte buffers.
    let (a, b, b2) = unsafe { (saw_read16(a), saw_read16(b), saw_read16(b2)) };
    let r = unsafe {
        saw_xor16(
            &saw_xor16(&imp::mul(&a, &saw_xor16(&b, &b2)), &imp::mul(&a, &b)),
            &imp::mul(&a, &b2),
        )
    };
    // SAFETY: `out` is a writable 16-byte buffer (direct store; no ub-check).
    unsafe { *(out.cast::<[u8; 16]>()) = r };
}

/// Commutativity residual: `mul(a, b) ^ mul(b, a)`. SAW proves this is always
/// zero (the field product is symmetric).
#[cfg(feature = "saw-verify")]
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn saw_field_mul_commutes(a: *const u8, b: *const u8, out: *mut u8) {
    // SAFETY: SAW provides three valid 16-byte buffers.
    let (a, b) = unsafe { (saw_read16(a), saw_read16(b)) };
    let r = unsafe { saw_xor16(&imp::mul(&a, &b), &imp::mul(&b, &a)) };
    // SAFETY: `out` is a writable 16-byte buffer (direct store; no ub-check).
    unsafe { *(out.cast::<[u8; 16]>()) = r };
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::volatile_zero;
    use core::{
        arch::aarch64::{
            uint8x16_t, vdupq_n_u8, veorq_u8, vextq_u8, vgetq_lane_u64, vld1q_u8, vmull_p64,
            vreinterpretq_u64_u8, vreinterpretq_u8_p128, vst1q_u8,
        },
        mem,
    };
    // AES round and byte-reverse intrinsics for the fused encrypt loop.
    use core::arch::aarch64::{vaeseq_u8, vaesmcq_u8, vrev64q_u8};

    pub(super) struct Backend {
        /// Montgomery-form key powers `[H^1, H^2, ..., H^8]`.
        h_pows: [uint8x16_t; super::KEY_POWERS],
        y: uint8x16_t,
    }

    impl Backend {
        pub(super) fn new(powers: &[[u8; 16]; super::KEY_POWERS]) -> Option<Self> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: hardware_available checked the target features required
            // by new_inner before this call.
            Some(unsafe { Self::new_inner(powers) })
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn new_inner(powers: &[[u8; 16]; super::KEY_POWERS]) -> Self {
            let mut h_pows = [vdupq_n_u8(0); super::KEY_POWERS];
            for (h_pow, power) in h_pows.iter_mut().zip(powers) {
                // SAFETY: power is a valid 16-byte initialized buffer.
                *h_pow = unsafe { vld1q_u8(power.as_ptr()) };
            }
            Self {
                h_pows,
                y: vdupq_n_u8(0),
            }
        }

        pub(super) fn update_block(&mut self, block: &[u8; 16]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by update_block_inner.
            unsafe { self.update_block_inner(block) };
        }

        pub(super) fn update_blocks4(&mut self, blocks: &[[u8; 16]; 4]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by the inner method.
            unsafe { self.update_blocks4_inner(blocks) };
        }

        pub(super) fn update_blocks8(&mut self, blocks: &[[u8; 16]; super::KEY_POWERS]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by the inner method.
            unsafe { self.update_blocks8_inner(blocks) };
        }

        pub(super) fn finalize(self) -> [u8; 16] {
            let mut out = [0_u8; 16];
            // SAFETY: out is a valid 16-byte writable buffer.
            unsafe { vst1q_u8(out.as_mut_ptr(), self.y) };
            out
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn update_block_inner(&mut self, block: &[u8; 16]) {
            // SAFETY: block is a valid 16-byte initialized buffer.
            let y = veorq_u8(self.y, unsafe { vld1q_u8(block.as_ptr()) });
            let (h, m, l) = karatsuba1(self.h_pows[0], y);
            let (h, l) = karatsuba2(h, m, l);
            self.y = mont_reduce(h, l);
        }

        /// Folds four blocks with one Montgomery reduction:
        /// `y' = reduce(K(y^x1, H^4) ^ K(x2, H^3) ^ K(x3, H^2) ^ K(x4, H^1))`.
        /// Valid because the reduction is linear over XOR of the wide
        /// carryless products.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn update_blocks4_inner(&mut self, blocks: &[[u8; 16]; 4]) {
            // SAFETY: each block is a valid 16-byte initialized buffer.
            let x0 = veorq_u8(self.y, unsafe { vld1q_u8(blocks[0].as_ptr()) });
            let (mut h, mut m, mut l) = karatsuba1(self.h_pows[3], x0);

            for (power_index, block) in [(2_usize, 1_usize), (1, 2), (0, 3)] {
                // SAFETY: each block is a valid 16-byte initialized buffer.
                let x = unsafe { vld1q_u8(blocks[block].as_ptr()) };
                let (hh, mm, ll) = karatsuba1(self.h_pows[power_index], x);
                h = veorq_u8(h, hh);
                m = veorq_u8(m, mm);
                l = veorq_u8(l, ll);
            }

            let (h, l) = karatsuba2(h, m, l);
            self.y = mont_reduce(h, l);
        }

        /// Folds eight blocks with one Montgomery reduction:
        /// `y' = reduce(K(y^x1, H^8) ^ K(x2, H^7) ^ ... ^ K(x8, H^1))`.
        /// Valid because the reduction is linear over XOR of the wide
        /// carryless products.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn update_blocks8_inner(&mut self, blocks: &[[u8; 16]; 8]) {
            // SAFETY: each block is a valid 16-byte initialized buffer.
            let x0 = veorq_u8(self.y, unsafe { vld1q_u8(blocks[0].as_ptr()) });
            let (mut h, mut m, mut l) = karatsuba1(self.h_pows[7], x0);

            for (power_index, block) in [
                (6_usize, 1_usize),
                (5, 2),
                (4, 3),
                (3, 4),
                (2, 5),
                (1, 6),
                (0, 7),
            ] {
                // SAFETY: each block is a valid 16-byte initialized buffer.
                let x = unsafe { vld1q_u8(blocks[block].as_ptr()) };
                let (hh, mm, ll) = karatsuba1(self.h_pows[power_index], x);
                h = veorq_u8(h, hh);
                m = veorq_u8(m, mm);
                l = veorq_u8(l, ll);
            }

            let (h, l) = karatsuba2(h, m, l);
            self.y = mont_reduce(h, l);
        }

        pub(super) fn seal_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the aes/neon/pmull features the inner method needs;
            // the AES round keys it borrows were built under the same check.
            unsafe { self.seal_bulk_inner(round_keys, counter, plaintext, ciphertext) };
        }

        pub(super) fn seal_in_place_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the aes/neon/pmull features the inner method needs;
            // the AES round keys it borrows were built under the same check.
            unsafe { self.seal_in_place_bulk_inner(round_keys, counter, data) };
        }

        pub(super) fn seal_in_place_tail_blocks(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the aes/neon/pmull features the inner method needs;
            // the AES round keys it borrows were built under the same check.
            unsafe { self.seal_in_place_tail_blocks_inner(round_keys, counter, data) };
        }

        pub(super) fn open_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the aes/neon/pmull features the inner method needs;
            // the AES round keys it borrows were built under the same check.
            unsafe { self.open_bulk_inner(round_keys, counter, ciphertext, plaintext) };
        }

        pub(super) fn open_in_place_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the aes/neon/pmull features the inner method needs;
            // the AES round keys it borrows were built under the same check.
            unsafe { self.open_in_place_bulk_inner(round_keys, counter, data) };
        }

        /// Stitched CTR-encrypt + GHASH over the eight-block-aligned bulk
        /// region. The current batch's eight interleaved AES chains and the
        /// previous batch's eight-block GHASH are emitted as two independent
        /// instruction sequences in one body, so the scheduler overlaps the
        /// AES and PMULL pipelines instead of draining them in sequence.
        ///
        /// Constant time: every instruction here (AESE/AESMC, PMULL/PMULL2,
        /// EOR, EXT, REV) has data-independent latency; the only control flow
        /// is the public batch count, and no memory index depends on a secret.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn seal_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) {
            debug_assert_eq!(plaintext.len(), ciphertext.len());
            debug_assert!(plaintext.len().is_multiple_of(128));

            let batches = plaintext.len() / 128;
            if batches == 0 {
                return;
            }

            let mut y = self.y;
            // Byte-reversed (POLYVAL-domain) ciphertext of the previous batch,
            // GHASHed one iteration later so it overlaps the next AES batch.
            let mut prev = [vdupq_n_u8(0); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                // Build eight counter blocks (public counter arithmetic).
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                // Eight interleaved AES-256 chains -> keystream.
                let mut state = [vdupq_n_u8(0); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    *lane = unsafe { vld1q_u8(block.as_ptr()) };
                }
                for round_key in &round_keys[..13] {
                    for lane in &mut state {
                        *lane = vaesmcq_u8(vaeseq_u8(*lane, *round_key));
                    }
                }
                for lane in &mut state {
                    *lane = veorq_u8(vaeseq_u8(*lane, round_keys[13]), round_keys[14]);
                }

                // GHASH the previous batch while this batch's AES is in flight.
                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                // Fuse: load plaintext, XOR keystream, store ciphertext once;
                // keep a byte-reversed copy for the next iteration's GHASH.
                let base = batch * 128;
                let pt = &plaintext[base..base + 128];
                let ct = &mut ciphertext[base..base + 128];
                for i in 0..8 {
                    // SAFETY: pt/ct are 128-byte windows; i*16 stays in bounds.
                    let p = unsafe { vld1q_u8(pt[i * 16..].as_ptr()) };
                    let c = veorq_u8(state[i], p);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { vst1q_u8(ct[i * 16..].as_mut_ptr(), c) };
                    prev[i] = byte_reverse(c);
                }
                have_prev = true;
            }

            // Epilogue: fold the final batch.
            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }

        /// Stitched CTR-encrypt + GHASH over a mutable eight-block-aligned
        /// bulk region. The buffer enters as plaintext and exits as
        /// ciphertext.
        ///
        /// Constant time: every instruction here (AESE/AESMC, PMULL/PMULL2,
        /// EOR, EXT, REV) has data-independent latency; the only control flow
        /// is the public batch count, and no memory index depends on a secret.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn seal_in_place_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            debug_assert!(data.len().is_multiple_of(128));

            let batches = data.len() / 128;
            if batches == 0 {
                return;
            }

            let mut y = self.y;
            let mut prev = [vdupq_n_u8(0); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                let mut state = [vdupq_n_u8(0); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    *lane = unsafe { vld1q_u8(block.as_ptr()) };
                }
                for round_key in &round_keys[..13] {
                    for lane in &mut state {
                        *lane = vaesmcq_u8(vaeseq_u8(*lane, *round_key));
                    }
                }
                for lane in &mut state {
                    *lane = veorq_u8(vaeseq_u8(*lane, round_keys[13]), round_keys[14]);
                }

                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                let base = batch * 128;
                let chunk = &mut data[base..base + 128];
                for i in 0..8 {
                    // SAFETY: chunk is a 128-byte window; i*16 stays in bounds.
                    let p = unsafe { vld1q_u8(chunk[i * 16..].as_ptr()) };
                    let c = veorq_u8(state[i], p);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { vst1q_u8(chunk[i * 16..].as_mut_ptr(), c) };
                    prev[i] = byte_reverse(c);
                }
                have_prev = true;
            }

            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }

        /// Stitched CTR-encrypt + GHASH over whole tail blocks below the
        /// eight-block bulk width.
        ///
        /// Constant time: all branches depend only on the public block count.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn seal_in_place_tail_blocks_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            debug_assert!(data.len().is_multiple_of(16));
            debug_assert!(data.len() < 128);

            let mut quads = data.chunks_exact_mut(64);
            for chunk in &mut quads {
                let mut ctr = [[0_u8; 16]; 4];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                let mut state = [vdupq_n_u8(0); 4];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    *lane = unsafe { vld1q_u8(block.as_ptr()) };
                }
                for round_key in &round_keys[..13] {
                    for lane in &mut state {
                        *lane = vaesmcq_u8(vaeseq_u8(*lane, *round_key));
                    }
                }
                for lane in &mut state {
                    *lane = veorq_u8(vaeseq_u8(*lane, round_keys[13]), round_keys[14]);
                }

                let mut blocks = [vdupq_n_u8(0); 4];
                for i in 0..4 {
                    // SAFETY: chunk is a 64-byte window; i*16 stays in bounds.
                    let p = unsafe { vld1q_u8(chunk[i * 16..].as_ptr()) };
                    let c = veorq_u8(state[i], p);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { vst1q_u8(chunk[i * 16..].as_mut_ptr(), c) };
                    blocks[i] = byte_reverse(c);
                }
                self.y = ghash4_regs(self.y, &self.h_pows, &blocks);
            }

            for chunk in quads.into_remainder().chunks_exact_mut(16) {
                let ctr = *counter;
                crate::aes_gcm::increment_counter(counter);
                // SAFETY: ctr is a valid 16-byte buffer.
                let mut state = unsafe { vld1q_u8(ctr.as_ptr()) };
                for round_key in &round_keys[..13] {
                    state = vaesmcq_u8(vaeseq_u8(state, *round_key));
                }
                state = veorq_u8(vaeseq_u8(state, round_keys[13]), round_keys[14]);

                // SAFETY: chunk is exactly 16 bytes.
                let p = unsafe { vld1q_u8(chunk.as_ptr()) };
                let c = veorq_u8(state, p);
                // SAFETY: chunk is exactly 16 writable bytes.
                unsafe { vst1q_u8(chunk.as_mut_ptr(), c) };
                self.y = ghash1_reg(self.y, self.h_pows[0], byte_reverse(c));
            }
        }

        /// Stitched GHASH + CTR-decrypt over the eight-block-aligned bulk
        /// region. This mirrors `seal_bulk_inner`, but GHASH consumes the
        /// input ciphertext while the caller-visible output receives plaintext.
        ///
        /// Constant time: every instruction here (AESE/AESMC, PMULL/PMULL2,
        /// EOR, EXT, REV) has data-independent latency; the only control flow
        /// is the public batch count, and no memory index depends on a secret.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn open_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) {
            debug_assert_eq!(ciphertext.len(), plaintext.len());
            debug_assert!(ciphertext.len().is_multiple_of(128));

            let batches = ciphertext.len() / 128;
            if batches == 0 {
                return;
            }

            let mut y = self.y;
            // Byte-reversed (POLYVAL-domain) ciphertext of the previous batch,
            // GHASHed one iteration later so it overlaps the next AES batch.
            let mut prev = [vdupq_n_u8(0); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                // Build eight counter blocks (public counter arithmetic).
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                // Eight interleaved AES-256 chains -> keystream.
                let mut state = [vdupq_n_u8(0); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    *lane = unsafe { vld1q_u8(block.as_ptr()) };
                }
                for round_key in &round_keys[..13] {
                    for lane in &mut state {
                        *lane = vaesmcq_u8(vaeseq_u8(*lane, *round_key));
                    }
                }
                for lane in &mut state {
                    *lane = veorq_u8(vaeseq_u8(*lane, round_keys[13]), round_keys[14]);
                }

                // GHASH the previous ciphertext batch while this batch's AES
                // work is available to the out-of-order scheduler.
                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                let base = batch * 128;
                let ct = &ciphertext[base..base + 128];
                let pt = &mut plaintext[base..base + 128];
                for i in 0..8 {
                    // SAFETY: ct/pt are 128-byte windows; i*16 stays in bounds.
                    let c = unsafe { vld1q_u8(ct[i * 16..].as_ptr()) };
                    prev[i] = byte_reverse(c);
                    let p = veorq_u8(state[i], c);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { vst1q_u8(pt[i * 16..].as_mut_ptr(), p) };
                }
                have_prev = true;
            }

            // Epilogue: fold the final ciphertext batch.
            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }

        /// Stitched GHASH + CTR-decrypt over a mutable eight-block-aligned
        /// bulk region. The buffer enters as ciphertext and exits as
        /// plaintext.
        ///
        /// Constant time: every instruction here (AESE/AESMC, PMULL/PMULL2,
        /// EOR, EXT, REV) has data-independent latency; the only control flow
        /// is the public batch count, and no memory index depends on a secret.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn open_in_place_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            debug_assert!(data.len().is_multiple_of(128));

            let batches = data.len() / 128;
            if batches == 0 {
                return;
            }

            let mut y = self.y;
            let mut prev = [vdupq_n_u8(0); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                let mut state = [vdupq_n_u8(0); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    *lane = unsafe { vld1q_u8(block.as_ptr()) };
                }
                for round_key in &round_keys[..13] {
                    for lane in &mut state {
                        *lane = vaesmcq_u8(vaeseq_u8(*lane, *round_key));
                    }
                }
                for lane in &mut state {
                    *lane = veorq_u8(vaeseq_u8(*lane, round_keys[13]), round_keys[14]);
                }

                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                let base = batch * 128;
                let chunk = &mut data[base..base + 128];
                for i in 0..8 {
                    // SAFETY: chunk is a 128-byte window; i*16 stays in bounds.
                    let c = unsafe { vld1q_u8(chunk[i * 16..].as_ptr()) };
                    prev[i] = byte_reverse(c);
                    let p = veorq_u8(state[i], c);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { vst1q_u8(chunk[i * 16..].as_mut_ptr(), p) };
                }
                have_prev = true;
            }

            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }
    }

    /// Single-block GHASH update over input already resident in a register and
    /// in POLYVAL byte order.
    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    #[allow(clippy::many_single_char_names)]
    unsafe fn ghash1_reg(y: uint8x16_t, h: uint8x16_t, block: uint8x16_t) -> uint8x16_t {
        let x = veorq_u8(y, block);
        let (h, m, l) = karatsuba1(h, x);
        let (h, l) = karatsuba2(h, m, l);
        mont_reduce(h, l)
    }

    /// Four-block GHASH aggregation over inputs already resident in registers
    /// and in POLYVAL byte order.
    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn ghash4_regs(
        y: uint8x16_t,
        h_pows: &[uint8x16_t; super::KEY_POWERS],
        blocks: &[uint8x16_t; 4],
    ) -> uint8x16_t {
        let x0 = veorq_u8(y, blocks[0]);
        let (mut h, mut m, mut l) = karatsuba1(h_pows[3], x0);
        for (power_index, block) in [(2_usize, 1_usize), (1, 2), (0, 3)] {
            let (hh, mm, ll) = karatsuba1(h_pows[power_index], blocks[block]);
            h = veorq_u8(h, hh);
            m = veorq_u8(m, mm);
            l = veorq_u8(l, ll);
        }
        let (h, l) = karatsuba2(h, m, l);
        mont_reduce(h, l)
    }

    /// Eight-block GHASH aggregation over inputs already resident in registers
    /// and in POLYVAL byte order. Mirrors `update_blocks8_inner` but avoids the
    /// memory round-trip so it can be stitched into the encrypt loop.
    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn ghash8_regs(
        y: uint8x16_t,
        h_pows: &[uint8x16_t; super::KEY_POWERS],
        blocks: &[uint8x16_t; 8],
    ) -> uint8x16_t {
        let x0 = veorq_u8(y, blocks[0]);
        let (mut h, mut m, mut l) = karatsuba1(h_pows[7], x0);
        for (power_index, block) in [
            (6_usize, 1_usize),
            (5, 2),
            (4, 3),
            (3, 4),
            (2, 5),
            (1, 6),
            (0, 7),
        ] {
            let (hh, mm, ll) = karatsuba1(h_pows[power_index], blocks[block]);
            h = veorq_u8(h, hh);
            m = veorq_u8(m, mm);
            l = veorq_u8(l, ll);
        }
        let (h, l) = karatsuba2(h, m, l);
        mont_reduce(h, l)
    }

    /// Full 16-byte reversal of a vector (the GHASH-to-POLYVAL byte mapping)
    /// done in-register: reverse within each 64-bit half, then swap the halves.
    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn byte_reverse(x: uint8x16_t) -> uint8x16_t {
        let halves = vrev64q_u8(x);
        vextq_u8(halves, halves, 8)
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            // SAFETY: self.h_pows and self.y are live writable GHASH state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.h_pows)) };
            // SAFETY: self.h_pows and self.y are live writable GHASH state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.y)) };
        }
    }

    /// One Montgomery-form POLYVAL multiplication (used for key powers).
    ///
    /// # Safety
    ///
    /// Caller must ensure `hardware_available` returned true.
    pub(super) unsafe fn mul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        // SAFETY: caller upholds the hardware contract for mul_inner.
        unsafe { mul_inner(a, b) }
    }

    #[target_feature(enable = "aes", enable = "neon")]
    #[allow(clippy::many_single_char_names)]
    unsafe fn mul_inner(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        // SAFETY: a and b are valid 16-byte initialized buffers.
        let (va, vb) = unsafe { (vld1q_u8(a.as_ptr()), vld1q_u8(b.as_ptr())) };
        let (h, m, l) = karatsuba1(va, vb);
        let (h, l) = karatsuba2(h, m, l);
        let product = mont_reduce(h, l);

        let mut out = [0_u8; 16];
        // SAFETY: out is a valid 16-byte writable buffer.
        unsafe { vst1q_u8(out.as_mut_ptr(), product) };
        out
    }

    pub(super) fn hardware_available() -> bool {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("neon")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }

    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    #[allow(clippy::many_single_char_names)]
    unsafe fn karatsuba1(x: uint8x16_t, y: uint8x16_t) -> (uint8x16_t, uint8x16_t, uint8x16_t) {
        let m = pmull(
            veorq_u8(x, vextq_u8(x, x, 8)),
            veorq_u8(y, vextq_u8(y, y, 8)),
        );
        let h = pmull2(x, y);
        let l = pmull(x, y);
        (h, m, l)
    }

    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn karatsuba2(h: uint8x16_t, m: uint8x16_t, l: uint8x16_t) -> (uint8x16_t, uint8x16_t) {
        let t0 = veorq_u8(m, vextq_u8(l, h, 8));
        let t1 = veorq_u8(h, l);
        let t = veorq_u8(t0, t1);

        let x01 = vextq_u8(vextq_u8(l, l, 8), t, 8);
        let x23 = vextq_u8(t, vextq_u8(h, h, 8), 8);

        (x23, x01)
    }

    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn mont_reduce(x23: uint8x16_t, x01: uint8x16_t) -> uint8x16_t {
        let poly =
            vreinterpretq_u8_p128(1 << 127 | 1 << 126 | 1 << 121 | 1 << 63 | 1 << 62 | 1 << 57);
        let a = pmull(x01, poly);
        let b = veorq_u8(x01, vextq_u8(a, a, 8));
        let c = pmull2(b, poly);
        veorq_u8(x23, veorq_u8(c, b))
    }

    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn pmull(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        // SAFETY: uint8x16_t and the vmull_p64 result are both 128-bit vector
        // values. This matches the upstream POLYVAL PMULL backend conversion.
        unsafe {
            mem::transmute(vmull_p64(
                vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
                vgetq_lane_u64(vreinterpretq_u64_u8(b), 0),
            ))
        }
    }

    #[inline]
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn pmull2(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        // SAFETY: uint8x16_t and the vmull_p64 result are both 128-bit vector
        // values. This matches the upstream POLYVAL PMULL backend conversion.
        unsafe {
            mem::transmute(vmull_p64(
                vgetq_lane_u64(vreinterpretq_u64_u8(a), 1),
                vgetq_lane_u64(vreinterpretq_u64_u8(b), 1),
            ))
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod imp {
    use super::volatile_zero;

    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_setzero_si128, _mm_shuffle_epi32,
        _mm_slli_epi64, _mm_srli_epi64, _mm_storeu_si128, _mm_unpacklo_epi64, _mm_xor_si128,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_setzero_si128, _mm_shuffle_epi32,
        _mm_slli_epi64, _mm_srli_epi64, _mm_storeu_si128, _mm_unpacklo_epi64, _mm_xor_si128,
    };
    // AES round and byte-shuffle intrinsics for the fused encrypt loop.
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{_mm_aesenc_si128, _mm_aesenclast_si128, _mm_set_epi8, _mm_shuffle_epi8};
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        _mm_aesenc_si128, _mm_aesenclast_si128, _mm_set_epi8, _mm_shuffle_epi8,
    };

    pub(super) struct Backend {
        /// Montgomery-form key powers `[H^1, H^2, ..., H^8]`.
        h_pows: [__m128i; super::KEY_POWERS],
        y: __m128i,
    }

    impl Backend {
        pub(super) fn new(powers: &[[u8; 16]; super::KEY_POWERS]) -> Option<Self> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: hardware_available checked the target features required
            // by new_inner before this call.
            Some(unsafe { Self::new_inner(powers) })
        }

        pub(super) fn update_block(&mut self, block: &[u8; 16]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by update_block_inner.
            unsafe { self.update_block_inner(block) };
        }

        pub(super) fn update_blocks4(&mut self, blocks: &[[u8; 16]; 4]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by the inner method.
            unsafe { self.update_blocks4_inner(blocks) };
        }

        pub(super) fn update_blocks8(&mut self, blocks: &[[u8; 16]; super::KEY_POWERS]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by the inner method.
            unsafe { self.update_blocks8_inner(blocks) };
        }

        pub(super) fn finalize(self) -> [u8; 16] {
            let mut out = [0_u8; 16];
            // SAFETY: out is a valid 16-byte writable buffer.
            unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), self.y) };
            out
        }

        #[target_feature(enable = "sse2", enable = "pclmulqdq")]
        unsafe fn new_inner(powers: &[[u8; 16]; super::KEY_POWERS]) -> Self {
            let mut h_pows = [_mm_setzero_si128(); super::KEY_POWERS];
            for (h_pow, power) in h_pows.iter_mut().zip(powers) {
                // SAFETY: power points to an initialized 16-byte range.
                *h_pow = unsafe { _mm_loadu_si128(power.as_ptr().cast()) };
            }
            Self {
                h_pows,
                y: _mm_setzero_si128(),
            }
        }

        #[target_feature(enable = "sse2", enable = "pclmulqdq")]
        unsafe fn update_block_inner(&mut self, block: &[u8; 16]) {
            // SAFETY: block points to an initialized 16-byte range.
            let x = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
            let (t0, t1, t2) = clmul_wide(_mm_xor_si128(self.y, x), self.h_pows[0]);
            self.y = reduce(t0, t1, t2);
        }

        /// Folds four blocks with one reduction:
        /// `y' = reduce(W(y^x1, H^4) ^ W(x2, H^3) ^ W(x3, H^2) ^ W(x4, H^1))`,
        /// where `W` is the wide carryless product. Valid because the
        /// reduction is linear over XOR of the wide products.
        #[target_feature(enable = "sse2", enable = "pclmulqdq")]
        unsafe fn update_blocks4_inner(&mut self, blocks: &[[u8; 16]; 4]) {
            // SAFETY: each block points to an initialized 16-byte range.
            let x0 = unsafe { _mm_loadu_si128(blocks[0].as_ptr().cast()) };
            let (mut t0, mut t1, mut t2) = clmul_wide(_mm_xor_si128(self.y, x0), self.h_pows[3]);

            for (power_index, block) in [(2_usize, 1_usize), (1, 2), (0, 3)] {
                // SAFETY: each block points to an initialized 16-byte range.
                let x = unsafe { _mm_loadu_si128(blocks[block].as_ptr().cast()) };
                let (u0, u1, u2) = clmul_wide(x, self.h_pows[power_index]);
                t0 = _mm_xor_si128(t0, u0);
                t1 = _mm_xor_si128(t1, u1);
                t2 = _mm_xor_si128(t2, u2);
            }

            self.y = reduce(t0, t1, t2);
        }

        /// Folds eight blocks with one reduction:
        /// `y' = reduce(W(y^x1, H^8) ^ W(x2, H^7) ^ ... ^ W(x8, H^1))`,
        /// where `W` is the wide carryless product. Valid because the
        /// reduction is linear over XOR of the wide products.
        #[target_feature(enable = "sse2", enable = "pclmulqdq")]
        unsafe fn update_blocks8_inner(&mut self, blocks: &[[u8; 16]; 8]) {
            // SAFETY: each block points to an initialized 16-byte range.
            let x0 = unsafe { _mm_loadu_si128(blocks[0].as_ptr().cast()) };
            let (mut t0, mut t1, mut t2) = clmul_wide(_mm_xor_si128(self.y, x0), self.h_pows[7]);

            for (power_index, block) in [
                (6_usize, 1_usize),
                (5, 2),
                (4, 3),
                (3, 4),
                (2, 5),
                (1, 6),
                (0, 7),
            ] {
                // SAFETY: each block points to an initialized 16-byte range.
                let x = unsafe { _mm_loadu_si128(blocks[block].as_ptr().cast()) };
                let (u0, u1, u2) = clmul_wide(x, self.h_pows[power_index]);
                t0 = _mm_xor_si128(t0, u0);
                t1 = _mm_xor_si128(t1, u1);
                t2 = _mm_xor_si128(t2, u2);
            }

            self.y = reduce(t0, t1, t2);
        }

        pub(super) fn seal_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the sse2/pclmulqdq/ssse3 features; the AES round keys
            // it borrows were built under an aes-feature check.
            unsafe { self.seal_bulk_inner(round_keys, counter, plaintext, ciphertext) };
        }

        pub(super) fn seal_in_place_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the sse2/pclmulqdq/ssse3 features; the AES round keys
            // it borrows were built under an aes-feature check.
            unsafe { self.seal_in_place_bulk_inner(round_keys, counter, data) };
        }

        pub(super) fn seal_in_place_tail_blocks(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the sse2/pclmulqdq/ssse3 features; the AES round keys
            // it borrows were built under an aes-feature check.
            unsafe { self.seal_in_place_tail_blocks_inner(round_keys, counter, data) };
        }

        pub(super) fn open_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the sse2/pclmulqdq/ssse3 features; the AES round keys
            // it borrows were built under an aes-feature check.
            unsafe { self.open_bulk_inner(round_keys, counter, ciphertext, plaintext) };
        }

        pub(super) fn open_in_place_bulk(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the sse2/pclmulqdq/ssse3 features; the AES round keys
            // it borrows were built under an aes-feature check.
            unsafe { self.open_in_place_bulk_inner(round_keys, counter, data) };
        }

        /// Stitched CTR-encrypt + GHASH over the eight-block-aligned bulk
        /// region. The current batch's eight interleaved AES chains and the
        /// previous batch's eight-block GHASH are emitted as two independent
        /// instruction sequences in one body, so the scheduler overlaps the
        /// AES and PCLMULQDQ pipelines instead of draining them in sequence.
        ///
        /// Constant time: every instruction here (AESENC/AESENCLAST,
        /// PCLMULQDQ, PXOR, PSHUFB) has data-independent latency; the only
        /// control flow is the public batch count, and no memory index depends
        /// on a secret.
        #[target_feature(
            enable = "sse2",
            enable = "ssse3",
            enable = "aes",
            enable = "pclmulqdq"
        )]
        unsafe fn seal_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) {
            debug_assert_eq!(plaintext.len(), ciphertext.len());
            debug_assert!(plaintext.len().is_multiple_of(128));

            let batches = plaintext.len() / 128;
            if batches == 0 {
                return;
            }

            // PSHUFB mask reversing all 16 bytes: result byte i = input 15 - i.
            let bswap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let mut y = self.y;
            let mut prev = [_mm_setzero_si128(); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                // Build eight counter blocks (public counter arithmetic).
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                // Eight interleaved AES-256 chains -> keystream.
                let mut state = [_mm_setzero_si128(); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
                    *lane = _mm_xor_si128(input, round_keys[0]);
                }
                for round_key in &round_keys[1..14] {
                    for lane in &mut state {
                        *lane = _mm_aesenc_si128(*lane, *round_key);
                    }
                }
                for lane in &mut state {
                    *lane = _mm_aesenclast_si128(*lane, round_keys[14]);
                }

                // GHASH the previous batch while this batch's AES is in flight.
                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                // Fuse: load plaintext, XOR keystream, store ciphertext once;
                // keep a byte-reversed copy for the next iteration's GHASH.
                let base = batch * 128;
                let pt = &plaintext[base..base + 128];
                let ct = &mut ciphertext[base..base + 128];
                for i in 0..8 {
                    // SAFETY: pt/ct are 128-byte windows; i*16 stays in bounds.
                    let p = unsafe { _mm_loadu_si128(pt[i * 16..].as_ptr().cast()) };
                    let c = _mm_xor_si128(state[i], p);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { _mm_storeu_si128(ct[i * 16..].as_mut_ptr().cast(), c) };
                    prev[i] = _mm_shuffle_epi8(c, bswap);
                }
                have_prev = true;
            }

            // Epilogue: fold the final batch.
            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }

        /// Stitched CTR-encrypt + GHASH over a mutable eight-block-aligned
        /// bulk region. The buffer enters as plaintext and exits as
        /// ciphertext.
        ///
        /// Constant time: every instruction here (AESENC/AESENCLAST,
        /// PCLMULQDQ, PXOR, PSHUFB) has data-independent latency; the only
        /// control flow is the public batch count, and no memory index depends
        /// on a secret.
        #[target_feature(
            enable = "sse2",
            enable = "ssse3",
            enable = "aes",
            enable = "pclmulqdq"
        )]
        unsafe fn seal_in_place_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            debug_assert!(data.len().is_multiple_of(128));

            let batches = data.len() / 128;
            if batches == 0 {
                return;
            }

            let bswap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let mut y = self.y;
            let mut prev = [_mm_setzero_si128(); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                let mut state = [_mm_setzero_si128(); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
                    *lane = _mm_xor_si128(input, round_keys[0]);
                }
                for round_key in &round_keys[1..14] {
                    for lane in &mut state {
                        *lane = _mm_aesenc_si128(*lane, *round_key);
                    }
                }
                for lane in &mut state {
                    *lane = _mm_aesenclast_si128(*lane, round_keys[14]);
                }

                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                let base = batch * 128;
                let chunk = &mut data[base..base + 128];
                for i in 0..8 {
                    // SAFETY: chunk is a 128-byte window; i*16 stays in bounds.
                    let p = unsafe { _mm_loadu_si128(chunk[i * 16..].as_ptr().cast()) };
                    let c = _mm_xor_si128(state[i], p);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { _mm_storeu_si128(chunk[i * 16..].as_mut_ptr().cast(), c) };
                    prev[i] = _mm_shuffle_epi8(c, bswap);
                }
                have_prev = true;
            }

            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }

        /// Stitched CTR-encrypt + GHASH over whole tail blocks below the
        /// eight-block bulk width.
        ///
        /// Constant time: all branches depend only on the public block count.
        #[target_feature(
            enable = "sse2",
            enable = "ssse3",
            enable = "aes",
            enable = "pclmulqdq"
        )]
        unsafe fn seal_in_place_tail_blocks_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            debug_assert!(data.len().is_multiple_of(16));
            debug_assert!(data.len() < 128);

            let bswap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let mut quads = data.chunks_exact_mut(64);
            for chunk in &mut quads {
                let mut ctr = [[0_u8; 16]; 4];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                let mut state = [_mm_setzero_si128(); 4];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
                    *lane = _mm_xor_si128(input, round_keys[0]);
                }
                for round_key in &round_keys[1..14] {
                    for lane in &mut state {
                        *lane = _mm_aesenc_si128(*lane, *round_key);
                    }
                }
                for lane in &mut state {
                    *lane = _mm_aesenclast_si128(*lane, round_keys[14]);
                }

                let mut blocks = [_mm_setzero_si128(); 4];
                for i in 0..4 {
                    // SAFETY: chunk is a 64-byte window; i*16 stays in bounds.
                    let p = unsafe { _mm_loadu_si128(chunk[i * 16..].as_ptr().cast()) };
                    let c = _mm_xor_si128(state[i], p);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { _mm_storeu_si128(chunk[i * 16..].as_mut_ptr().cast(), c) };
                    blocks[i] = _mm_shuffle_epi8(c, bswap);
                }
                self.y = ghash4_regs(self.y, &self.h_pows, &blocks);
            }

            for chunk in quads.into_remainder().chunks_exact_mut(16) {
                let ctr = *counter;
                crate::aes_gcm::increment_counter(counter);
                // SAFETY: ctr is a valid 16-byte buffer.
                let input = unsafe { _mm_loadu_si128(ctr.as_ptr().cast()) };
                let mut state = _mm_xor_si128(input, round_keys[0]);
                for round_key in &round_keys[1..14] {
                    state = _mm_aesenc_si128(state, *round_key);
                }
                state = _mm_aesenclast_si128(state, round_keys[14]);

                // SAFETY: chunk is exactly 16 bytes.
                let p = unsafe { _mm_loadu_si128(chunk.as_ptr().cast()) };
                let c = _mm_xor_si128(state, p);
                // SAFETY: chunk is exactly 16 writable bytes.
                unsafe { _mm_storeu_si128(chunk.as_mut_ptr().cast(), c) };
                self.y = ghash1_reg(self.y, self.h_pows[0], _mm_shuffle_epi8(c, bswap));
            }
        }

        /// Stitched GHASH + CTR-decrypt over the eight-block-aligned bulk
        /// region. This mirrors `seal_bulk_inner`, but GHASH consumes the
        /// input ciphertext while the caller-visible output receives plaintext.
        ///
        /// Constant time: every instruction here (AESENC/AESENCLAST,
        /// PCLMULQDQ, PXOR, PSHUFB) has data-independent latency; the only
        /// control flow is the public batch count, and no memory index depends
        /// on a secret.
        #[target_feature(
            enable = "sse2",
            enable = "ssse3",
            enable = "aes",
            enable = "pclmulqdq"
        )]
        unsafe fn open_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) {
            debug_assert_eq!(ciphertext.len(), plaintext.len());
            debug_assert!(ciphertext.len().is_multiple_of(128));

            let batches = ciphertext.len() / 128;
            if batches == 0 {
                return;
            }

            // PSHUFB mask reversing all 16 bytes: result byte i = input 15 - i.
            let bswap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let mut y = self.y;
            let mut prev = [_mm_setzero_si128(); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                // Build eight counter blocks (public counter arithmetic).
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                // Eight interleaved AES-256 chains -> keystream.
                let mut state = [_mm_setzero_si128(); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
                    *lane = _mm_xor_si128(input, round_keys[0]);
                }
                for round_key in &round_keys[1..14] {
                    for lane in &mut state {
                        *lane = _mm_aesenc_si128(*lane, *round_key);
                    }
                }
                for lane in &mut state {
                    *lane = _mm_aesenclast_si128(*lane, round_keys[14]);
                }

                // GHASH the previous ciphertext batch while this batch's AES
                // work is available to the out-of-order scheduler.
                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                let base = batch * 128;
                let ct = &ciphertext[base..base + 128];
                let pt = &mut plaintext[base..base + 128];
                for i in 0..8 {
                    // SAFETY: ct/pt are 128-byte windows; i*16 stays in bounds.
                    let c = unsafe { _mm_loadu_si128(ct[i * 16..].as_ptr().cast()) };
                    prev[i] = _mm_shuffle_epi8(c, bswap);
                    let p = _mm_xor_si128(state[i], c);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { _mm_storeu_si128(pt[i * 16..].as_mut_ptr().cast(), p) };
                }
                have_prev = true;
            }

            // Epilogue: fold the final ciphertext batch.
            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }

        /// Stitched GHASH + CTR-decrypt over a mutable eight-block-aligned
        /// bulk region. The buffer enters as ciphertext and exits as
        /// plaintext.
        ///
        /// Constant time: every instruction here (AESENC/AESENCLAST,
        /// PCLMULQDQ, PXOR, PSHUFB) has data-independent latency; the only
        /// control flow is the public batch count, and no memory index depends
        /// on a secret.
        #[target_feature(
            enable = "sse2",
            enable = "ssse3",
            enable = "aes",
            enable = "pclmulqdq"
        )]
        unsafe fn open_in_place_bulk_inner(
            &mut self,
            round_keys: &crate::aes_gcm::aes::RoundKeys,
            counter: &mut [u8; 16],
            data: &mut [u8],
        ) {
            debug_assert!(data.len().is_multiple_of(128));

            let batches = data.len() / 128;
            if batches == 0 {
                return;
            }

            let bswap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let mut y = self.y;
            let mut prev = [_mm_setzero_si128(); 8];
            let mut have_prev = false;

            for batch in 0..batches {
                let mut ctr = [[0_u8; 16]; 8];
                for block in &mut ctr {
                    *block = *counter;
                    crate::aes_gcm::increment_counter(counter);
                }

                let mut state = [_mm_setzero_si128(); 8];
                for (lane, block) in state.iter_mut().zip(ctr.iter()) {
                    // SAFETY: each counter block is a valid 16-byte buffer.
                    let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
                    *lane = _mm_xor_si128(input, round_keys[0]);
                }
                for round_key in &round_keys[1..14] {
                    for lane in &mut state {
                        *lane = _mm_aesenc_si128(*lane, *round_key);
                    }
                }
                for lane in &mut state {
                    *lane = _mm_aesenclast_si128(*lane, round_keys[14]);
                }

                if have_prev {
                    y = ghash8_regs(y, &self.h_pows, &prev);
                }

                let base = batch * 128;
                let chunk = &mut data[base..base + 128];
                for i in 0..8 {
                    // SAFETY: chunk is a 128-byte window; i*16 stays in bounds.
                    let c = unsafe { _mm_loadu_si128(chunk[i * 16..].as_ptr().cast()) };
                    prev[i] = _mm_shuffle_epi8(c, bswap);
                    let p = _mm_xor_si128(state[i], c);
                    // SAFETY: as above, writable 16-byte lane.
                    unsafe { _mm_storeu_si128(chunk[i * 16..].as_mut_ptr().cast(), p) };
                }
                have_prev = true;
            }

            y = ghash8_regs(y, &self.h_pows, &prev);
            self.y = y;
        }
    }

    /// Single-block GHASH update over input already resident in a register and
    /// in POLYVAL byte order.
    #[inline]
    #[target_feature(enable = "sse2", enable = "pclmulqdq")]
    #[allow(clippy::many_single_char_names)]
    unsafe fn ghash1_reg(y: __m128i, h: __m128i, block: __m128i) -> __m128i {
        let (t0, t1, t2) = clmul_wide(_mm_xor_si128(y, block), h);
        reduce(t0, t1, t2)
    }

    /// Four-block GHASH aggregation over inputs already resident in registers
    /// and in POLYVAL byte order.
    #[inline]
    #[target_feature(enable = "sse2", enable = "pclmulqdq")]
    unsafe fn ghash4_regs(
        y: __m128i,
        h_pows: &[__m128i; super::KEY_POWERS],
        blocks: &[__m128i; 4],
    ) -> __m128i {
        let (mut t0, mut t1, mut t2) = clmul_wide(_mm_xor_si128(y, blocks[0]), h_pows[3]);
        for (power_index, block) in [(2_usize, 1_usize), (1, 2), (0, 3)] {
            let (u0, u1, u2) = clmul_wide(blocks[block], h_pows[power_index]);
            t0 = _mm_xor_si128(t0, u0);
            t1 = _mm_xor_si128(t1, u1);
            t2 = _mm_xor_si128(t2, u2);
        }
        reduce(t0, t1, t2)
    }

    /// Eight-block GHASH aggregation over inputs already resident in registers
    /// and in POLYVAL byte order. Mirrors `update_blocks8_inner` but avoids the
    /// memory round-trip so it can be stitched into the encrypt loop.
    #[inline]
    #[target_feature(enable = "sse2", enable = "pclmulqdq")]
    unsafe fn ghash8_regs(
        y: __m128i,
        h_pows: &[__m128i; super::KEY_POWERS],
        blocks: &[__m128i; 8],
    ) -> __m128i {
        let (mut t0, mut t1, mut t2) = clmul_wide(_mm_xor_si128(y, blocks[0]), h_pows[7]);
        for (power_index, block) in [
            (6_usize, 1_usize),
            (5, 2),
            (4, 3),
            (3, 4),
            (2, 5),
            (1, 6),
            (0, 7),
        ] {
            let (u0, u1, u2) = clmul_wide(blocks[block], h_pows[power_index]);
            t0 = _mm_xor_si128(t0, u0);
            t1 = _mm_xor_si128(t1, u1);
            t2 = _mm_xor_si128(t2, u2);
        }
        reduce(t0, t1, t2)
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            // SAFETY: self.h_pows and self.y are live writable GHASH state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.h_pows)) };
            // SAFETY: self.h_pows and self.y are live writable GHASH state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.y)) };
        }
    }

    /// One Montgomery-form POLYVAL multiplication (used for key powers).
    ///
    /// # Safety
    ///
    /// Caller must ensure `hardware_available` returned true.
    pub(super) unsafe fn mul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        // SAFETY: caller upholds the hardware contract for mul_inner.
        unsafe { mul_inner(a, b) }
    }

    #[target_feature(enable = "sse2", enable = "pclmulqdq")]
    unsafe fn mul_inner(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        // SAFETY: a and b point to initialized 16-byte ranges.
        let (va, vb) = unsafe {
            (
                _mm_loadu_si128(a.as_ptr().cast()),
                _mm_loadu_si128(b.as_ptr().cast()),
            )
        };
        let (t0, t1, t2) = clmul_wide(va, vb);
        let product = reduce(t0, t1, t2);

        let mut out = [0_u8; 16];
        // SAFETY: out is a valid 16-byte writable buffer.
        unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), product) };
        out
    }

    pub(super) fn hardware_available() -> bool {
        std::arch::is_x86_feature_detected!("sse2")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("ssse3")
    }

    /// Schoolbook + Karatsuba wide carryless product of `x` and `h` as the
    /// three 128-bit partials of the upstream POLYVAL CLMUL backend.
    #[inline]
    #[target_feature(enable = "sse2", enable = "pclmulqdq")]
    unsafe fn clmul_wide(x: __m128i, h: __m128i) -> (__m128i, __m128i, __m128i) {
        let h0 = h;
        let h1 = _mm_shuffle_epi32(h, 0x0E);
        let h2 = _mm_xor_si128(h0, h1);
        let y0 = x;
        let y1 = _mm_shuffle_epi32(x, 0x0E);
        let y2 = _mm_xor_si128(y0, y1);

        let t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
        let t1 = _mm_clmulepi64_si128(x, h, 0x11);
        let t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
        (t0, t1, t2)
    }

    /// Montgomery reduction of the accumulated wide partials. This is the
    /// upstream POLYVAL CLMUL reduction, split out so the multi-block
    /// aggregations can share it.
    #[inline]
    #[target_feature(enable = "sse2", enable = "pclmulqdq")]
    unsafe fn reduce(t0: __m128i, t1: __m128i, t2: __m128i) -> __m128i {
        let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
        let v0 = t0;
        let v1 = _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2);
        let v2 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
        let v3 = _mm_shuffle_epi32(t1, 0x0E);

        let v2 = xor5(
            v2,
            v0,
            _mm_srli_epi64(v0, 1),
            _mm_srli_epi64(v0, 2),
            _mm_srli_epi64(v0, 7),
        );

        let v1 = xor4(
            v1,
            _mm_slli_epi64(v0, 63),
            _mm_slli_epi64(v0, 62),
            _mm_slli_epi64(v0, 57),
        );

        let v3 = xor5(
            v3,
            v1,
            _mm_srli_epi64(v1, 1),
            _mm_srli_epi64(v1, 2),
            _mm_srli_epi64(v1, 7),
        );

        let v2 = xor4(
            v2,
            _mm_slli_epi64(v1, 63),
            _mm_slli_epi64(v1, 62),
            _mm_slli_epi64(v1, 57),
        );

        _mm_unpacklo_epi64(v2, v3)
    }

    #[inline]
    unsafe fn xor4(e1: __m128i, e2: __m128i, e3: __m128i, e4: __m128i) -> __m128i {
        _mm_xor_si128(_mm_xor_si128(e1, e2), _mm_xor_si128(e3, e4))
    }

    #[inline]
    unsafe fn xor5(e1: __m128i, e2: __m128i, e3: __m128i, e4: __m128i, e5: __m128i) -> __m128i {
        _mm_xor_si128(
            e1,
            _mm_xor_si128(_mm_xor_si128(e2, e3), _mm_xor_si128(e4, e5)),
        )
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")))]
mod imp {
    pub(super) enum Backend {}

    impl Backend {
        pub(super) fn new(_powers: &[[u8; 16]; super::KEY_POWERS]) -> Option<Self> {
            None
        }

        pub(super) fn update_block(&mut self, _block: &[u8; 16]) {
            match *self {}
        }

        pub(super) fn update_blocks4(&mut self, _blocks: &[[u8; 16]; 4]) {
            match *self {}
        }

        pub(super) fn update_blocks8(&mut self, _blocks: &[[u8; 16]; super::KEY_POWERS]) {
            match *self {}
        }

        pub(super) fn seal_bulk(
            &mut self,
            _round_keys: &crate::aes_gcm::aes::RoundKeys,
            _counter: &mut [u8; 16],
            _plaintext: &[u8],
            _ciphertext: &mut [u8],
        ) {
            match *self {}
        }

        pub(super) fn seal_in_place_bulk(
            &mut self,
            _round_keys: &crate::aes_gcm::aes::RoundKeys,
            _counter: &mut [u8; 16],
            _data: &mut [u8],
        ) {
            match *self {}
        }

        pub(super) fn seal_in_place_tail_blocks(
            &mut self,
            _round_keys: &crate::aes_gcm::aes::RoundKeys,
            _counter: &mut [u8; 16],
            _data: &mut [u8],
        ) {
            match *self {}
        }

        pub(super) fn open_bulk(
            &mut self,
            _round_keys: &crate::aes_gcm::aes::RoundKeys,
            _counter: &mut [u8; 16],
            _ciphertext: &[u8],
            _plaintext: &mut [u8],
        ) {
            match *self {}
        }

        pub(super) fn open_in_place_bulk(
            &mut self,
            _round_keys: &crate::aes_gcm::aes::RoundKeys,
            _counter: &mut [u8; 16],
            _data: &mut [u8],
        ) {
            match *self {}
        }

        pub(super) fn finalize(self) -> [u8; 16] {
            match self {}
        }
    }

    /// Unreachable on targets without a hardware backend: `hardware_available`
    /// is false, so `GHashKey::init_in_place` returns before calling this.
    ///
    /// # Safety
    ///
    /// Never called; present so the shared init code compiles.
    pub(super) unsafe fn mul(_a: &[u8; 16], _b: &[u8; 16]) -> [u8; 16] {
        [0_u8; 16]
    }

    pub(super) const fn hardware_available() -> bool {
        false
    }
}

#[cfg(all(
    test,
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
))]
mod aggregation_tests {
    //! Direct correctness check of the multi-block aggregated reduction.
    //!
    //! The 8- and 4-block aggregations fold several carryless products and
    //! reduce once, which is valid only because the Montgomery reduction is
    //! linear over the XOR of the wide products. These tests prove that
    //! identity against the per-block path it replaces: for the same key
    //! powers and the same blocks, `update_blocks8`/`update_blocks4` must equal
    //! a sequence of single-block `update_block` calls (the textbook Horner
    //! GHASH/POLYVAL evaluation). The `Backend` is domain-agnostic, so this
    //! covers both the GHASH and the GCM-SIV POLYVAL use of the same code.
    #![allow(clippy::unwrap_used)]

    use super::{imp::Backend, Polyval, KEY_POWERS};

    /// Deterministic, dependency-free pseudo-random 16-byte block stream.
    struct Xs(u64);
    impl Xs {
        fn block(&mut self) -> [u8; 16] {
            let mut out = [0_u8; 16];
            for chunk in out.chunks_mut(8) {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                chunk.copy_from_slice(&self.0.to_le_bytes());
            }
            out
        }
    }

    fn powers(seed: u64) -> [[u8; 16]; KEY_POWERS] {
        let mut xs = Xs(seed);
        // Any nonzero hash key yields a valid power ladder H^1..H^8.
        Polyval::key_powers(&xs.block()).unwrap()
    }

    fn naive(powers: &[[u8; 16]; KEY_POWERS], blocks: &[[u8; 16]]) -> [u8; 16] {
        let mut backend = Backend::new(powers).unwrap();
        for block in blocks {
            backend.update_block(block);
        }
        backend.finalize()
    }

    #[test]
    fn eight_block_aggregation_equals_per_block() {
        for seed in [1_u64, 0x9e37_79b9_7f4a_7c15, 0xdead_beef_cafe_d00d] {
            let powers = powers(seed);
            let mut xs = Xs(seed ^ 0xa5a5_a5a5);
            for _round in 0..64 {
                let mut blocks = [[0_u8; 16]; KEY_POWERS];
                for b in &mut blocks {
                    *b = xs.block();
                }
                let mut agg = Backend::new(&powers).unwrap();
                agg.update_blocks8(&blocks);
                assert_eq!(
                    agg.finalize(),
                    naive(&powers, &blocks),
                    "8-block aggregation diverged from the per-block reduction"
                );
            }
        }
    }

    #[test]
    fn four_block_aggregation_equals_per_block() {
        for seed in [2_u64, 0x1234_5678_9abc_def0] {
            let powers = powers(seed);
            let mut xs = Xs(seed ^ 0x5a5a_5a5a);
            for _round in 0..64 {
                let mut blocks = [[0_u8; 16]; 4];
                for b in &mut blocks {
                    *b = xs.block();
                }
                let mut agg = Backend::new(&powers).unwrap();
                agg.update_blocks4(&blocks);
                assert_eq!(
                    agg.finalize(),
                    naive(&powers, &blocks),
                    "4-block aggregation diverged from the per-block reduction"
                );
            }
        }
    }

    #[test]
    fn mixed_batch_and_tail_equals_per_block() {
        // A full 8-block batch, then a 4-block group, then singles - the exact
        // shape `absorb_blocks` produces - must still equal the flat per-block
        // evaluation over the concatenation.
        let powers = powers(7);
        let mut xs = Xs(0xfeed_face);
        let mut all = Vec::new();
        for _ in 0..8 {
            all.push(xs.block());
        }
        for _ in 0..4 {
            all.push(xs.block());
        }
        for _ in 0..3 {
            all.push(xs.block());
        }

        let mut agg = Backend::new(&powers).unwrap();
        let mut eight = [[0_u8; 16]; KEY_POWERS];
        eight.copy_from_slice(&all[..8]);
        agg.update_blocks8(&eight);
        let mut four = [[0_u8; 16]; 4];
        four.copy_from_slice(&all[8..12]);
        agg.update_blocks4(&four);
        for block in &all[12..] {
            agg.update_block(block);
        }

        assert_eq!(agg.finalize(), naive(&powers, &all));
    }
}

/// Silicon anchor for the formal field-multiply proofs.
///
/// The `proofs/` suite reasons about a Python model of the exact intrinsic
/// multiply sequence (`field_model.py`), and pins that model to reality by
/// reproducing reference outputs of the running backend `imp::mul`. Those
/// reference vectors were originally captured on aarch64. This test re-derives
/// them from `imp::mul` on whatever architecture it runs on, so the CI matrix
/// confirms - on real x86 AES-NI/PCLMULQDQ silicon, not just aarch64 - that the
/// hardware produces exactly the products the x86 proof model
/// (`field_mul_x86_int`) is validated against. Keep these byte-for-byte in sync
/// with `REFERENCE_VECTORS` in `proofs/field_model.py`.
#[cfg(test)]
mod mul_reference_anchor {
    #![allow(clippy::unwrap_used)]

    /// `(a, b, a*b)` in little-endian byte order, identical to
    /// `proofs/field_model.py::REFERENCE_VECTORS`.
    const REFERENCE_VECTORS: &[(&str, &str, &str)] = &[
        (
            "41208240000000004114010c06410010",
            "2926866e2f841e9b25805d5503f554f5",
            "a466d404a7df230146bd094d6c19fca2",
        ),
        (
            "ad4df30bae771bdc76606e02b9eef064",
            "366190e591ce077b74cc8d360c055f30",
            "055fe5bec6717fd3a7331331366d31de",
        ),
        (
            "ed8e046d8246dc27b09c408075613b88",
            "8931e30b3d2b6310aab55d84465d4573",
            "23578745031c5659ede3ce9940043ee5",
        ),
    ];

    fn hex16(s: &str) -> [u8; 16] {
        let mut out = [0_u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn imp_mul_matches_proof_reference_vectors() {
        if !super::hardware_available() {
            return;
        }
        for (a_hex, b_hex, product_hex) in REFERENCE_VECTORS {
            let a = hex16(a_hex);
            let b = hex16(b_hex);
            // SAFETY: hardware_available() returned true above.
            let got = unsafe { super::imp::mul(&a, &b) };
            assert_eq!(
                got,
                hex16(product_hex),
                "imp::mul diverged from the captured field-multiply reference \
                 vector the formal proof model is anchored to"
            );
        }
    }
}
