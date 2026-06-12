//! Minimal hardware-only AES-256 block backend.
//!
//! This is adapted from `rand_aes 0.7.0`'s AES-256 key expansion and block
//! encryption paths (Apache-2.0, Nils Hasenbanck; see the repository `NOTICE`
//! file for full attribution). Software fallback state and runtime fallback
//! dispatch are intentionally not vendored.
//!
//! # Constant-time notes
//!
//! Every AES round executes via AESE/AESMC (aarch64) or AESENC/AESENCLAST
//! (x86) instructions with data-independent timing; no S-box table exists
//! in memory, so there is no cache-timing surface. Key expansion derives
//! every round key in vector
//! registers through a fixed instruction sequence: `SubWord` uses the AES
//! instruction itself rather than a lookup table, loop bounds are
//! compile-time constants, and no branch or memory index in this module
//! depends on key material. The only conditionals are the public
//! hardware-feature check at construction and pointer-alignment checks in
//! the wipe helper.

#![allow(unsafe_code)]

use core::ptr;

/// Number of independent blocks encrypted per interleaved batch. Eight
/// in-flight AES round chains hide the AESE/AESENC instruction latency that a
/// single dependent chain cannot.
pub(crate) const PAR_BLOCKS: usize = 8;

/// Architecture-specific AES-256 round-key array (15 expanded round keys held
/// as native vector registers). Exposed crate-internally so the stitched
/// GCM encrypt loop can interleave AES rounds with GHASH multiplies in one
/// `#[target_feature]` body.
pub(crate) use imp::RoundKeys;

/// Hardware-only AES-256 encryption state.
#[repr(transparent)]
pub(crate) struct Aes256(imp::Aes256);

impl Aes256 {
    pub(crate) fn init_in_place(dst: *mut Self, key: &[u8; 32]) -> Option<()> {
        imp::Aes256::init_in_place(dst.cast(), key)
    }

    pub(crate) fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.0.encrypt_block(block);
    }

    /// Borrows the expanded round keys for the stitched encrypt path.
    pub(crate) fn round_keys(&self) -> &RoundKeys {
        self.0.round_keys()
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
    // key schedules are hundreds of bytes and byte-wide stores make drop
    // wipes disproportionately expensive.
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

    const AES256_ROUND_KEY_COUNT: usize = 15;
    const AES_RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

    pub(crate) type RoundKeys = [uint8x16_t; AES256_ROUND_KEY_COUNT];

    pub(super) struct Aes256 {
        round_keys: [uint8x16_t; AES256_ROUND_KEY_COUNT],
    }

    impl Aes256 {
        pub(crate) fn round_keys(&self) -> &RoundKeys {
            &self.round_keys
        }

        pub(super) fn init_in_place(dst: *mut Self, key: &[u8; 32]) -> Option<()> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: caller provides suitably aligned writable storage for
            // Self. hardware_available checked init_inner target features.
            unsafe { Self::init_inner(dst, key) };
            Some(())
        }

        pub(super) fn encrypt_block(&self, block: &mut [u8; 16]) {
            // SAFETY: Aes256 can only be constructed after hardware_available
            // has checked the target features required by encrypt_block_inner.
            unsafe { self.encrypt_block_inner(block) };
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn init_inner(dst: *mut Self, key: &[u8; 32]) {
            // SAFETY: dst is valid writable storage for Self and the field
            // pointer stays within that allocation.
            let round_keys = unsafe { core::ptr::addr_of_mut!((*dst).round_keys) };
            aes256_key_expansion(round_keys, key);
        }

        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn encrypt_block_inner(&self, block: &mut [u8; 16]) {
            // SAFETY: block is a valid 16-byte initialized buffer.
            let mut state = unsafe { vld1q_u8(block.as_ptr()) };
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

            // SAFETY: block is a valid 16-byte writable buffer.
            unsafe { vst1q_u8(block.as_mut_ptr(), state) };
        }
    }

    impl Drop for Aes256 {
        fn drop(&mut self) {
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
    /// structure: each round key is derived in NEON registers and written
    /// once, with no scalar word array or stack staging buffers to wipe.
    #[target_feature(enable = "aes", enable = "neon")]
    unsafe fn aes256_key_expansion(
        round_keys: *mut [uint8x16_t; AES256_ROUND_KEY_COUNT],
        key: &[u8; 32],
    ) {
        // SAFETY: key points to two initialized 16-byte ranges.
        let mut even = unsafe { vld1q_u8(key.as_ptr()) };
        // SAFETY: key points to two initialized 16-byte ranges.
        let mut odd = unsafe { vld1q_u8(key[16..].as_ptr()) };
        // SAFETY: round_keys points to writable storage for the whole array.
        unsafe { core::ptr::addr_of_mut!((*round_keys)[0]).write(even) };
        // SAFETY: round_keys points to writable storage for the whole array.
        unsafe { core::ptr::addr_of_mut!((*round_keys)[1]).write(odd) };

        for (index, rcon) in AES_RCON.iter().enumerate() {
            even = next_even_key(even, odd, *rcon);
            // SAFETY: destination indices 2..=14 are within the array.
            unsafe { core::ptr::addr_of_mut!((*round_keys)[(index * 2) + 2]).write(even) };
            if index < 6 {
                odd = next_odd_key(odd, even);
                // SAFETY: destination indices 3..=13 are within the array.
                unsafe { core::ptr::addr_of_mut!((*round_keys)[(index * 2) + 3]).write(odd) };
            }
        }
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

    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
        _mm_loadu_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_storeu_si128, _mm_xor_si128,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
        _mm_loadu_si128, _mm_setzero_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_storeu_si128,
        _mm_xor_si128,
    };

    const AES256_ROUND_KEY_COUNT: usize = 15;

    pub(crate) type RoundKeys = [__m128i; AES256_ROUND_KEY_COUNT];

    pub(super) struct Aes256 {
        round_keys: [__m128i; AES256_ROUND_KEY_COUNT],
    }

    impl Aes256 {
        pub(crate) fn round_keys(&self) -> &RoundKeys {
            &self.round_keys
        }

        pub(super) fn init_in_place(dst: *mut Self, key: &[u8; 32]) -> Option<()> {
            if !hardware_available() {
                return None;
            }

            // SAFETY: caller provides suitably aligned writable storage for
            // Self. hardware_available checked init_inner target features.
            unsafe { Self::init_inner(dst, key) };
            Some(())
        }

        pub(super) fn encrypt_block(&self, block: &mut [u8; 16]) {
            // SAFETY: Aes256 can only be constructed after hardware_available
            // has checked the target features required by encrypt_block_inner.
            unsafe { self.encrypt_block_inner(block) };
        }

        #[target_feature(enable = "sse2", enable = "aes")]
        unsafe fn init_inner(dst: *mut Self, key: &[u8; 32]) {
            // SAFETY: dst is valid writable storage for Self and the field
            // pointer stays within that allocation.
            let round_keys = unsafe { core::ptr::addr_of_mut!((*dst).round_keys) };
            aes256_key_expansion(round_keys, key);
        }

        #[target_feature(enable = "sse2", enable = "aes")]
        unsafe fn encrypt_block_inner(&self, block: &mut [u8; 16]) {
            // SAFETY: block points to an initialized 16-byte range.
            let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
            let mut state = _mm_xor_si128(input, self.round_keys[0]);
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

            // SAFETY: block points to a writable 16-byte range.
            unsafe { _mm_storeu_si128(block.as_mut_ptr().cast(), state) };
        }
    }

    impl Drop for Aes256 {
        fn drop(&mut self) {
            // SAFETY: self.round_keys is live writable key-schedule storage.
            unsafe { volatile_zero(core::ptr::addr_of_mut!(self.round_keys)) };
            compiler_fence(Ordering::SeqCst);
        }
    }

    pub(super) fn hardware_available() -> bool {
        std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2")
    }

    #[target_feature(enable = "sse2", enable = "aes")]
    unsafe fn aes256_key_expansion(
        expanded_keys: *mut [__m128i; AES256_ROUND_KEY_COUNT],
        key: &[u8; 32],
    ) {
        #[target_feature(enable = "sse2", enable = "aes")]
        fn generate_round_keys<const RCON: i32, const RNUM: usize>(
            expanded_keys: *mut [__m128i; AES256_ROUND_KEY_COUNT],
        ) {
            // SAFETY: caller initializes previous round keys before each call.
            let prev_key_0 = unsafe { core::ptr::addr_of!((*expanded_keys)[RNUM * 2]).read() };
            // SAFETY: caller initializes previous round keys before each call.
            let prev_key_1 =
                unsafe { core::ptr::addr_of!((*expanded_keys)[(RNUM * 2) + 1]).read() };

            let mut temp = _mm_aeskeygenassist_si128::<RCON>(prev_key_1);
            temp = _mm_shuffle_epi32::<0xFF>(temp);

            let mut key = _mm_xor_si128(prev_key_0, _mm_slli_si128::<0x4>(prev_key_0));
            key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
            key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
            key = _mm_xor_si128(temp, key);
            // SAFETY: destination index is in the AES-256 round-key array.
            unsafe { core::ptr::addr_of_mut!((*expanded_keys)[(RNUM * 2) + 2]).write(key) };

            if RNUM < 6 {
                let mut temp = _mm_aeskeygenassist_si128::<0x00>(key);
                temp = _mm_shuffle_epi32::<0xAA>(temp);

                let mut key = _mm_xor_si128(prev_key_1, _mm_slli_si128::<0x4>(prev_key_1));
                key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
                key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
                key = _mm_xor_si128(temp, key);
                // SAFETY: destination index is in the AES-256 round-key array.
                unsafe { core::ptr::addr_of_mut!((*expanded_keys)[(RNUM * 2) + 3]).write(key) };
            }
        }

        // SAFETY: key points to two initialized 16-byte ranges.
        let first = unsafe { _mm_loadu_si128(key.as_ptr().cast()) };
        // SAFETY: key points to two initialized 16-byte ranges.
        let second = unsafe { _mm_loadu_si128(key[16..].as_ptr().cast()) };
        // SAFETY: expanded_keys points to writable storage for the array.
        unsafe { core::ptr::addr_of_mut!((*expanded_keys)[0]).write(first) };
        // SAFETY: expanded_keys points to writable storage for the array.
        unsafe { core::ptr::addr_of_mut!((*expanded_keys)[1]).write(second) };

        generate_round_keys::<0x01, 0>(expanded_keys);
        generate_round_keys::<0x02, 1>(expanded_keys);
        generate_round_keys::<0x04, 2>(expanded_keys);
        generate_round_keys::<0x08, 3>(expanded_keys);
        generate_round_keys::<0x10, 4>(expanded_keys);
        generate_round_keys::<0x20, 5>(expanded_keys);
        generate_round_keys::<0x40, 6>(expanded_keys);
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")))]
mod imp {
    /// Placeholder round-key array on targets without a hardware backend.
    /// Never constructed at runtime (`hardware_available` is false).
    pub(crate) type RoundKeys = [[u8; 16]; 15];

    pub(super) enum Aes256 {}

    impl Aes256 {
        pub(crate) fn round_keys(&self) -> &RoundKeys {
            match *self {}
        }

        pub(super) fn init_in_place(_dst: *mut Self, _key: &[u8; 32]) -> Option<()> {
            None
        }

        pub(super) fn encrypt_block(&self, _block: &mut [u8; 16]) {
            match *self {}
        }
    }

    pub(super) const fn hardware_available() -> bool {
        false
    }
}
