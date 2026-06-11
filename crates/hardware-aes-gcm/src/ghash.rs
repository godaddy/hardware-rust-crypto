//! Minimal hardware-only GHASH backend.
//!
//! This vendors the `ghash 0.5.1` GHASH-to-POLYVAL mapping and the
//! `polyval 0.6.2` CLMUL/PMULL backends, without the software fallback or
//! autodetect enum.

#![allow(unsafe_code)]

use core::ptr;
use zeroize::Zeroize as _;

/// Reusable GHASH key material.
pub(crate) struct GHashKey {
    polyval_key: [u8; 16],
}

impl GHashKey {
    pub(crate) fn init_in_place(dst: *mut Self, hash_subkey: &mut [u8; 16]) {
        hash_subkey.reverse();
        let polyval_key = mulx(hash_subkey);
        hash_subkey.zeroize();
        // SAFETY: caller provides valid writable storage for Self and the field
        // pointer stays within that allocation.
        unsafe { ptr::addr_of_mut!((*dst).polyval_key).write(polyval_key) };
    }

    pub(crate) fn authenticate(&self, aad: &[u8], ciphertext: &[u8]) -> Option<[u8; 16]> {
        let mut backend = imp::Backend::new(&self.polyval_key)?;
        update_padded(&mut backend, aad);
        update_padded(&mut backend, ciphertext);

        let mut length_block = [0_u8; 16];
        length_block[..8].copy_from_slice(&bit_len(aad.len())?.to_be_bytes());
        length_block[8..].copy_from_slice(&bit_len(ciphertext.len())?.to_be_bytes());
        length_block.reverse();
        backend.update_block(&length_block);
        length_block.zeroize();

        let mut tag = backend.finalize();
        tag.reverse();
        Some(tag)
    }
}

impl Drop for GHashKey {
    fn drop(&mut self) {
        self.polyval_key.zeroize();
    }
}

pub(crate) fn hardware_available() -> bool {
    imp::hardware_available()
}

unsafe fn volatile_zero<T>(value: *mut T) {
    let bytes = value.cast::<u8>();
    for offset in 0..core::mem::size_of::<T>() {
        // SAFETY: caller guarantees value points to a live writable T. Every
        // byte offset within size_of::<T>() is within that object.
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
}

fn bit_len(len: usize) -> Option<u64> {
    u64::try_from(len).ok()?.checked_mul(8)
}

fn update_padded(backend: &mut imp::Backend, input: &[u8]) {
    let mut chunks = input.chunks_exact(16);
    for chunk in &mut chunks {
        let mut block = [0_u8; 16];
        block.copy_from_slice(chunk);
        block.reverse();
        backend.update_block(&block);
        block.zeroize();
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut block = [0_u8; 16];
        block[..remainder.len()].copy_from_slice(remainder);
        block.reverse();
        backend.update_block(&block);
        block.zeroize();
    }
}

fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;

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
        h: uint8x16_t,
        y: uint8x16_t,
    }

    impl Backend {
        pub(super) fn new(h: &[u8; 16]) -> Option<Self> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: hardware_available checked the target features required
            // by new_inner before this call.
            Some(unsafe { Self::new_inner(h) })
        }

        pub(super) fn update_block(&mut self, block: &[u8; 16]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by update_block_inner.
            unsafe { self.update_block_inner(block) };
        }

        pub(super) fn finalize(self) -> [u8; 16] {
            let mut out = [0_u8; 16];
            // SAFETY: out is a valid 16-byte writable buffer.
            unsafe { vst1q_u8(out.as_mut_ptr(), self.y) };
            out
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn new_inner(h: &[u8; 16]) -> Self {
            Self {
                // SAFETY: h is a valid 16-byte initialized buffer.
                h: unsafe { vld1q_u8(h.as_ptr()) },
                y: vdupq_n_u8(0),
            }
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn update_block_inner(&mut self, block: &[u8; 16]) {
            // SAFETY: block is a valid 16-byte initialized buffer.
            let y = veorq_u8(self.y, unsafe { vld1q_u8(block.as_ptr()) });
            let (h, m, l) = karatsuba1(self.h, y);
            let (h, l) = karatsuba2(h, m, l);
            self.y = mont_reduce(h, l);
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            // SAFETY: self.h and self.y are live writable GHASH backend state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.h)) };
            // SAFETY: self.h and self.y are live writable GHASH backend state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.y)) };
        }
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
        h: __m128i,
        y: __m128i,
    }

    impl Backend {
        pub(super) fn new(h: &[u8; 16]) -> Option<Self> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: hardware_available checked the target features required
            // by new_inner before this call.
            Some(unsafe { Self::new_inner(h) })
        }

        pub(super) fn update_block(&mut self, block: &[u8; 16]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by update_block_inner.
            unsafe { self.update_block_inner(block) };
        }

        pub(super) fn finalize(self) -> [u8; 16] {
            let mut out = [0_u8; 16];
            // SAFETY: out is a valid 16-byte writable buffer.
            unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), self.y) };
            out
        }

        #[target_feature(enable = "sse2", enable = "pclmulqdq")]
        unsafe fn new_inner(h: &[u8; 16]) -> Self {
            Self {
                // SAFETY: h points to an initialized 16-byte range.
                h: unsafe { _mm_loadu_si128(h.as_ptr().cast()) },
                y: _mm_setzero_si128(),
            }
        }

        #[target_feature(enable = "sse2", enable = "pclmulqdq")]
        unsafe fn update_block_inner(&mut self, block: &[u8; 16]) {
            let h = self.h;

            // SAFETY: block points to an initialized 16-byte range.
            let x = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
            let y = _mm_xor_si128(self.y, x);

            let h0 = h;
            let h1 = _mm_shuffle_epi32(h, 0x0E);
            let h2 = _mm_xor_si128(h0, h1);
            let y0 = y;

            let y1 = _mm_shuffle_epi32(y, 0x0E);
            let y2 = _mm_xor_si128(y0, y1);
            let t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
            let t1 = _mm_clmulepi64_si128(y, h, 0x11);
            let t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
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

            self.y = _mm_unpacklo_epi64(v2, v3);
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            // SAFETY: self.h and self.y are live writable GHASH backend state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.h)) };
            // SAFETY: self.h and self.y are live writable GHASH backend state.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.y)) };
        }
    }

    pub(super) fn hardware_available() -> bool {
        std::arch::is_x86_feature_detected!("sse2")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
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
        pub(super) fn new(_h: &[u8; 16]) -> Option<Self> {
            None
        }

        pub(super) fn update_block(&mut self, _block: &[u8; 16]) {
            match *self {}
        }

        pub(super) fn finalize(self) -> [u8; 16] {
            match self {}
        }
    }

    pub(super) const fn hardware_available() -> bool {
        false
    }
}
