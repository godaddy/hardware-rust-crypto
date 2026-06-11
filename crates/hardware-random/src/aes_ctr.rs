//! Minimal hardware-only AES-256-CTR-128 backend.
//!
//! This is adapted from `rand_aes 0.7.0`'s x86 AES-NI and aarch64 `ARMv8` AES
//! backends (Apache-2.0, Nils Hasenbanck; see the repository `NOTICE` file
//! for full attribution). The software backend, runtime fallback enum, boxed
//! dispatch state, jump APIs, and non-AES-256 variants are intentionally not
//! vendored.
//!
//! # Constant-time notes
//!
//! Block generation is a fixed sequence of AESE/AESMC (aarch64) or
//! AESENC/AESENCLAST (x86) instructions with data-independent timing; no
//! S-box table exists in memory. The 128-bit counter increment is a
//! `wrapping_add` (no carry-dependent branching), and key expansion derives
//! every round key in vector registers with constant loop bounds. No branch
//! or memory index in this module depends on the key, the counter, or
//! generated output.

#![allow(unsafe_code)]

use core::ptr;

/// Required CPU features for the AES-CTR backend on this target.
#[cfg(target_arch = "aarch64")]
pub(crate) const REQUIRED_FEATURES: &str = "aarch64 aes, neon";
/// Required CPU features for the AES-CTR backend on this target.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) const REQUIRED_FEATURES: &str = "x86 AES-NI, SSE2";
/// Required CPU features for the AES-CTR backend on this target.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")))]
pub(crate) const REQUIRED_FEATURES: &str = "unsupported target architecture";

/// Hardware AES-CTR backend state.
pub(crate) struct Backend(imp::Backend);

impl Backend {
    pub(crate) fn new(key: &[u8; 32], counter: &[u8; 16]) -> Option<Self> {
        imp::Backend::new(key, counter).map(Self)
    }

    pub(crate) fn fill_block(&mut self, out: &mut [u8; 16]) {
        self.0.fill_block(out);
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

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::volatile_zero;
    use core::arch::aarch64::{
        uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u32, vdupq_n_u8, veorq_u8, vextq_u8,
        vgetq_lane_u32, vld1q_u8, vreinterpretq_u32_u8, vreinterpretq_u8_u32, vst1q_u8,
    };
    use core::sync::atomic::{compiler_fence, Ordering};
    use zeroize::Zeroizing;

    const AES256_ROUND_KEY_COUNT: usize = 15;
    const AES_RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

    pub(super) struct Backend {
        counter: u128,
        round_keys: [uint8x16_t; AES256_ROUND_KEY_COUNT],
    }

    impl Backend {
        pub(super) fn new(key: &[u8; 32], counter: &[u8; 16]) -> Option<Self> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: hardware_available checked the target features required
            // by new_inner before this call.
            Some(unsafe { Self::new_inner(key, counter) })
        }

        pub(super) fn fill_block(&mut self, out: &mut [u8; 16]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by fill_block_inner.
            unsafe { self.fill_block_inner(out) };
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn new_inner(key: &[u8; 32], counter: &[u8; 16]) -> Self {
            Self {
                counter: u128::from_le_bytes(*counter),
                round_keys: aes256_key_expansion(key),
            }
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn fill_block_inner(&mut self, out: &mut [u8; 16]) {
            let counter = self.counter;
            self.counter = self.counter.wrapping_add(1);

            let counter_bytes = Zeroizing::new(counter.to_le_bytes());
            // SAFETY: counter_bytes is a valid 16-byte initialized buffer.
            let mut state = unsafe { vld1q_u8(counter_bytes.as_ptr()) };
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[0]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[1]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[2]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[3]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[4]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[5]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[6]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[7]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[8]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[9]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[10]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[11]));
            state = vaesmcq_u8(vaeseq_u8(state, self.round_keys[12]));
            state = vaeseq_u8(state, self.round_keys[13]);
            state = veorq_u8(state, self.round_keys[14]);

            // SAFETY: out is a valid 16-byte writable buffer.
            unsafe { vst1q_u8(out.as_mut_ptr(), state) };
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            self.counter = 0;
            // SAFETY: self.round_keys is live writable key-schedule storage.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.round_keys)) };
            compiler_fence(Ordering::SeqCst);
        }
    }

    pub(super) fn hardware_available() -> bool {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("neon")
    }

    /// Register-resident expansion mirroring the x86 `AESKEYGENASSIST`
    /// structure: each round key is derived in NEON registers, with no
    /// scalar word array or stack staging buffers to wipe.
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn aes256_key_expansion(key: &[u8; 32]) -> [uint8x16_t; AES256_ROUND_KEY_COUNT] {
        // SAFETY: key points to two initialized 16-byte ranges.
        let mut even = unsafe { vld1q_u8(key.as_ptr()) };
        // SAFETY: key points to two initialized 16-byte ranges.
        let mut odd = unsafe { vld1q_u8(key[16..].as_ptr()) };

        let mut round_keys = [vdupq_n_u8(0); AES256_ROUND_KEY_COUNT];
        round_keys[0] = even;
        round_keys[1] = odd;
        for (index, rcon) in AES_RCON.iter().enumerate() {
            even = next_even_key(even, odd, *rcon);
            round_keys[(index * 2) + 2] = even;
            if index < 6 {
                odd = next_odd_key(odd, even);
                round_keys[(index * 2) + 3] = odd;
            }
        }
        round_keys
    }

    /// Even-numbered round key: the word-prefix cascade of the grandparent
    /// key combined by XOR with `RotWord(SubWord(w3(parent))) ^ rcon` in every word.
    #[target_feature(enable = "aes", enable = "neon")]
    fn next_even_key(prev_even: uint8x16_t, prev_odd: uint8x16_t, rcon: u32) -> uint8x16_t {
        let word = vgetq_lane_u32::<3>(vreinterpretq_u32_u8(prev_odd));
        let derived = sub_word(word).rotate_right(8) ^ rcon;
        veorq_u8(
            prefix_cascade(prev_even),
            vreinterpretq_u8_u32(vdupq_n_u32(derived)),
        )
    }

    /// Odd-numbered round key: the cascade of the grandparent key combined by XOR with
    /// `SubWord(w3(new_even))` (no rotate, no rcon) in every word.
    #[target_feature(enable = "aes", enable = "neon")]
    fn next_odd_key(prev_odd: uint8x16_t, new_even: uint8x16_t) -> uint8x16_t {
        let word = vgetq_lane_u32::<3>(vreinterpretq_u32_u8(new_even));
        let derived = sub_word(word);
        veorq_u8(
            prefix_cascade(prev_odd),
            vreinterpretq_u8_u32(vdupq_n_u32(derived)),
        )
    }

    /// AES key expansion's word-prefix XOR,
    /// `k ^ (k << 32) ^ (k << 64) ^ (k << 96)` with byte shifts toward
    /// higher lanes, via the doubled shift-XOR cascade.
    #[target_feature(enable = "aes", enable = "neon")]
    fn prefix_cascade(key: uint8x16_t) -> uint8x16_t {
        let zero = vdupq_n_u8(0);
        let mut key = veorq_u8(key, vextq_u8(zero, key, 12));
        key = veorq_u8(key, vextq_u8(zero, key, 12));
        veorq_u8(key, vextq_u8(zero, key, 12))
    }

    /// `SubWord` via the AES instruction itself: AESE with a zero round key
    /// performs `AddRoundKey(0) + SubBytes + ShiftRows`, and with all four
    /// words equal `ShiftRows` is the identity, so lane 0 is
    /// `SubWord(input)`. Constant time: no S-box table is consulted and the
    /// surrounding scalar rotate/XOR are fixed-distance operations.
    #[target_feature(enable = "aes", enable = "neon")]
    fn sub_word(input: u32) -> u32 {
        let input = vreinterpretq_u8_u32(vdupq_n_u32(input));
        vgetq_lane_u32::<0>(vreinterpretq_u32_u8(vaeseq_u8(input, vdupq_n_u8(0))))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod imp {
    use super::volatile_zero;
    use core::sync::atomic::{compiler_fence, Ordering};
    use zeroize::Zeroizing;

    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
        _mm_loadu_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_storeu_si128, _mm_xor_si128,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
        _mm_loadu_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_storeu_si128, _mm_xor_si128,
    };

    const AES256_ROUND_KEY_COUNT: usize = 15;

    pub(super) struct Backend {
        counter: u128,
        round_keys: [__m128i; AES256_ROUND_KEY_COUNT],
    }

    impl Backend {
        pub(super) fn new(key: &[u8; 32], counter: &[u8; 16]) -> Option<Self> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: hardware_available checked the target features required
            // by new_inner before this call.
            Some(unsafe { Self::new_inner(key, counter) })
        }

        pub(super) fn fill_block(&mut self, out: &mut [u8; 16]) {
            // SAFETY: Backend can only be constructed after hardware_available
            // has checked the target features required by fill_block_inner.
            unsafe { self.fill_block_inner(out) };
        }

        #[target_feature(enable = "sse2", enable = "aes")]
        unsafe fn new_inner(key: &[u8; 32], counter: &[u8; 16]) -> Self {
            Self {
                counter: u128::from_le_bytes(*counter),
                round_keys: aes256_key_expansion(key),
            }
        }

        #[target_feature(enable = "sse2", enable = "aes")]
        unsafe fn fill_block_inner(&mut self, out: &mut [u8; 16]) {
            let counter = self.counter;
            self.counter = self.counter.wrapping_add(1);

            let counter_bytes = Zeroizing::new(counter.to_le_bytes());
            // SAFETY: counter_bytes is a valid 16-byte initialized buffer.
            let counter = unsafe { _mm_loadu_si128(counter_bytes.as_ptr().cast()) };
            let mut state = _mm_xor_si128(counter, self.round_keys[0]);
            state = _mm_aesenc_si128(state, self.round_keys[1]);
            state = _mm_aesenc_si128(state, self.round_keys[2]);
            state = _mm_aesenc_si128(state, self.round_keys[3]);
            state = _mm_aesenc_si128(state, self.round_keys[4]);
            state = _mm_aesenc_si128(state, self.round_keys[5]);
            state = _mm_aesenc_si128(state, self.round_keys[6]);
            state = _mm_aesenc_si128(state, self.round_keys[7]);
            state = _mm_aesenc_si128(state, self.round_keys[8]);
            state = _mm_aesenc_si128(state, self.round_keys[9]);
            state = _mm_aesenc_si128(state, self.round_keys[10]);
            state = _mm_aesenc_si128(state, self.round_keys[11]);
            state = _mm_aesenc_si128(state, self.round_keys[12]);
            state = _mm_aesenc_si128(state, self.round_keys[13]);
            state = _mm_aesenclast_si128(state, self.round_keys[14]);

            // SAFETY: out is a valid 16-byte writable buffer.
            unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), state) };
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            self.counter = 0;
            // SAFETY: self.round_keys is live writable key-schedule storage.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.round_keys)) };
            compiler_fence(Ordering::SeqCst);
        }
    }

    pub(super) fn hardware_available() -> bool {
        std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2")
    }

    #[target_feature(enable = "sse2", enable = "aes")]
    unsafe fn aes256_key_expansion(key: &[u8; 32]) -> [__m128i; AES256_ROUND_KEY_COUNT] {
        #[target_feature(enable = "sse2", enable = "aes")]
        fn generate_round_keys<const RCON: i32, const RNUM: usize>(
            expanded_keys: &mut [__m128i; AES256_ROUND_KEY_COUNT],
        ) {
            let prev_key_0 = expanded_keys[RNUM * 2];
            let prev_key_1 = expanded_keys[(RNUM * 2) + 1];

            let mut temp = _mm_aeskeygenassist_si128::<RCON>(prev_key_1);
            temp = _mm_shuffle_epi32::<0xFF>(temp);

            let mut key = _mm_xor_si128(prev_key_0, _mm_slli_si128::<0x4>(prev_key_0));
            key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
            key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
            key = _mm_xor_si128(temp, key);
            expanded_keys[(RNUM * 2) + 2] = key;

            if RNUM < 6 {
                let mut temp = _mm_aeskeygenassist_si128::<0x00>(key);
                temp = _mm_shuffle_epi32::<0xAA>(temp);

                let mut key = _mm_xor_si128(prev_key_1, _mm_slli_si128::<0x4>(prev_key_1));
                key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
                key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
                key = _mm_xor_si128(temp, key);
                expanded_keys[(RNUM * 2) + 3] = key;
            }
        }

        // SAFETY: all-zero bytes are a valid __m128i bit pattern.
        let mut expanded_keys: [__m128i; AES256_ROUND_KEY_COUNT] = unsafe { core::mem::zeroed() };

        // SAFETY: key points to two initialized 16-byte ranges.
        expanded_keys[0] = unsafe { _mm_loadu_si128(key.as_ptr().cast()) };
        expanded_keys[1] = unsafe { _mm_loadu_si128(key[16..].as_ptr().cast()) };

        generate_round_keys::<0x01, 0>(&mut expanded_keys);
        generate_round_keys::<0x02, 1>(&mut expanded_keys);
        generate_round_keys::<0x04, 2>(&mut expanded_keys);
        generate_round_keys::<0x08, 3>(&mut expanded_keys);
        generate_round_keys::<0x10, 4>(&mut expanded_keys);
        generate_round_keys::<0x20, 5>(&mut expanded_keys);
        generate_round_keys::<0x40, 6>(&mut expanded_keys);

        expanded_keys
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")))]
mod imp {
    pub(super) enum Backend {}

    impl Backend {
        pub(super) fn new(_key: &[u8; 32], _counter: &[u8; 16]) -> Option<Self> {
            None
        }

        pub(super) fn fill_block(&mut self, _out: &mut [u8; 16]) {
            match *self {}
        }
    }

    pub(super) const fn hardware_available() -> bool {
        false
    }
}
