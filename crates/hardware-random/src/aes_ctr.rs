//! Minimal hardware-only AES-256-CTR-128 backend.
//!
//! This is adapted from `rand_aes 0.7.0`'s x86 AES-NI and aarch64 `ARMv8` AES
//! backends. The software backend, runtime fallback enum, boxed dispatch state,
//! jump APIs, and non-AES-256 variants are intentionally not vendored.

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

unsafe fn volatile_zero<T>(value: *mut T) {
    let bytes = value.cast::<u8>();
    for offset in 0..core::mem::size_of::<T>() {
        // SAFETY: caller guarantees value points to a live writable T. Every
        // byte offset within size_of::<T>() is within that object.
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::volatile_zero;
    use core::arch::aarch64::{
        uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u32, vdupq_n_u8, veorq_u8, vgetq_lane_u32,
        vld1q_u8, vreinterpretq_u32_u8, vreinterpretq_u8_u32, vst1q_u8,
    };
    use core::sync::atomic::{compiler_fence, Ordering};
    use zeroize::Zeroizing;

    const AES_BLOCK_WORDS: usize = 4;
    const AES_WORD_SIZE: usize = 4;
    const AES256_KEY_WORDS: usize = 8;
    const AES256_ROUND_KEY_COUNT: usize = 15;
    const AES256_EXPANDED_WORDS: usize = AES256_ROUND_KEY_COUNT * AES_BLOCK_WORDS;
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

    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn aes256_key_expansion(key: &[u8; 32]) -> [uint8x16_t; AES256_ROUND_KEY_COUNT] {
        let mut words = Zeroizing::new([0_u32; AES256_EXPANDED_WORDS]);
        for (i, word) in words.iter_mut().take(AES256_KEY_WORDS).enumerate() {
            let offset = i * AES_WORD_SIZE;
            *word = u32::from_ne_bytes([
                key[offset],
                key[offset + 1],
                key[offset + 2],
                key[offset + 3],
            ]);
        }

        for i in AES256_KEY_WORDS..AES256_EXPANDED_WORDS {
            let mut word = words[i - 1];
            if i % AES256_KEY_WORDS == 0 {
                word = sub_word(word).rotate_right(8) ^ AES_RCON[(i / AES256_KEY_WORDS) - 1];
            } else if i % AES256_KEY_WORDS == 4 {
                word = sub_word(word);
            }
            words[i] = words[i - AES256_KEY_WORDS] ^ word;
        }

        let zero = vdupq_n_u8(0);
        let mut round_keys = [zero; AES256_ROUND_KEY_COUNT];
        for (round, round_key) in round_keys.iter_mut().enumerate() {
            let mut bytes = Zeroizing::new([0_u8; 16]);
            for word in 0..AES_BLOCK_WORDS {
                let offset = word * AES_WORD_SIZE;
                bytes[offset..offset + AES_WORD_SIZE]
                    .copy_from_slice(&words[(round * AES_BLOCK_WORDS) + word].to_ne_bytes());
            }
            // SAFETY: bytes is a valid 16-byte initialized buffer.
            *round_key = unsafe { vld1q_u8(bytes.as_ptr()) };
        }
        round_keys
    }

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
