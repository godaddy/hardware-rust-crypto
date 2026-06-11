//! Minimal hardware-only GHASH backend.
//!
//! This vendors the `ghash 0.5.1` GHASH-to-POLYVAL mapping and the
//! `polyval 0.6.2` CLMUL/PMULL backends (Apache-2.0 OR MIT, The `RustCrypto`
//! Project Developers; see the repository `NOTICE` file for full
//! attribution), without the software fallback or autodetect enum. On top of
//! the vendored single-block multiply it adds the standard aggregated
//! reduction: four precomputed Montgomery-form key powers let four blocks be
//! folded with one field reduction (the wide carryless products are XOR-linear,
//! so they are summed before a single reduction).
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
const KEY_POWERS: usize = 4;

/// Reusable GHASH key material: POLYVAL-domain Montgomery powers
/// `[H^1, H^2, H^3, H^4]`.
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
        let mut h1 = mulx(hash_subkey);
        hash_subkey.zeroize();
        // SAFETY: hardware_available verified the carryless-multiply features
        // required by imp::mul above.
        let mut h2 = unsafe { imp::mul(&h1, &h1) };
        // SAFETY: as above.
        let mut h3 = unsafe { imp::mul(&h2, &h1) };
        // SAFETY: as above.
        let mut h4 = unsafe { imp::mul(&h2, &h2) };
        // SAFETY: caller provides valid writable storage for Self and the field
        // pointer stays within that allocation.
        unsafe { ptr::addr_of_mut!((*dst).polyval_key_powers).write([h1, h2, h3, h4]) };
        h1.zeroize();
        h2.zeroize();
        h3.zeroize();
        h4.zeroize();
        Some(())
    }

    pub(crate) fn authenticate(&self, aad: &[u8], ciphertext: &[u8]) -> Option<[u8; 16]> {
        let mut ghasher = Ghasher::new(self)?;
        ghasher.absorb_padded(aad);
        ghasher.absorb_padded(ciphertext);
        ghasher.finalize(aad.len(), ciphertext.len())
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

    /// Absorbs a 16-byte-multiple run of bytes, four blocks per reduction.
    ///
    /// Callers stream section bytes through this in block-aligned chunks and
    /// close the section with [`Self::absorb_padded`] for any partial tail.
    pub(crate) fn absorb_blocks(&mut self, data: &[u8]) {
        debug_assert!(
            data.len().is_multiple_of(16),
            "absorb_blocks needs whole blocks"
        );

        let mut quads = data.chunks_exact(64);
        for quad in &mut quads {
            let mut blocks = [[0_u8; 16]; KEY_POWERS];
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

    pub(super) struct Backend {
        /// Montgomery-form key powers `[H^1, H^2, H^3, H^4]`.
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

        pub(super) fn update_block(&mut self, block: &[u8; 16]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by update_block_inner.
            unsafe { self.update_block_inner(block) };
        }

        pub(super) fn update_blocks4(&mut self, blocks: &[[u8; 16]; super::KEY_POWERS]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by the inner method.
            unsafe { self.update_blocks4_inner(blocks) };
        }

        pub(super) fn finalize(self) -> [u8; 16] {
            let mut out = [0_u8; 16];
            // SAFETY: out is a valid 16-byte writable buffer.
            unsafe { vst1q_u8(out.as_mut_ptr(), self.y) };
            out
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
        unsafe fn update_blocks4_inner(&mut self, blocks: &[[u8; 16]; super::KEY_POWERS]) {
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

    pub(super) struct Backend {
        /// Montgomery-form key powers `[H^1, H^2, H^3, H^4]`.
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

        pub(super) fn update_blocks4(&mut self, blocks: &[[u8; 16]; super::KEY_POWERS]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by the inner method.
            unsafe { self.update_blocks4_inner(blocks) };
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
        unsafe fn update_blocks4_inner(&mut self, blocks: &[[u8; 16]; super::KEY_POWERS]) {
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
    /// upstream POLYVAL CLMUL reduction, split out so four-block aggregation
    /// can share it.
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

        pub(super) fn update_blocks4(&mut self, _blocks: &[[u8; 16]; super::KEY_POWERS]) {
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
