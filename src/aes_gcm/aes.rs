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

    /// Encrypts eight independent 16-byte blocks in place through eight
    /// interleaved AES chains, hiding the AESE/AESENC latency a serial loop
    /// cannot. Used to generate the AES-256-GCM-SIV CTR keystream a full
    /// 128-byte batch at a time.
    pub(crate) fn encrypt8(&self, blocks: &mut [[u8; 16]; PAR_BLOCKS]) {
        self.0.encrypt8(blocks);
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

// ---------------------------------------------------------------------------
// Software AES-256 key schedule - TEST/MIRI ONLY.
//
// This is gated `#[cfg(any(test, miri))]` and is NEVER compiled into a normal
// build (debug or release), so it does not affect the shipped library's
// "hardware-only, no S-box in memory" guarantee in any way. It exists for two
// reasons:
//   * the host test below validates it against the real hardware key schedule;
//   * under Miri (`cargo miri test`), which does not implement the
//     `aeskeygenassist` / NEON `aese` key-expansion intrinsics, the x86 backend
//     routes key expansion through it so that Miri can execute the entire
//     key-state lifecycle and the real AES rounds (`_mm_aesenc_si128`, which
//     Miri *does* implement) under its undefined-behavior checker.
// It produces byte-identical round keys to the hardware path (asserted by
// `software_schedule_matches_hardware`).
#[cfg(any(test, miri))]
pub(crate) const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Standard FIPS-197 AES-256 key expansion in portable software. Returns the 15
/// round keys in the byte order the hardware backends store them (validated by
/// `software_schedule_matches_hardware`). TEST/MIRI only.
#[cfg(any(test, miri))]
pub(crate) fn software_key_schedule(key: &[u8; 32]) -> [[u8; 16]; 15] {
    const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    let sub = |w: [u8; 4]| {
        [
            AES_SBOX[w[0] as usize],
            AES_SBOX[w[1] as usize],
            AES_SBOX[w[2] as usize],
            AES_SBOX[w[3] as usize],
        ]
    };
    let mut w = [[0_u8; 4]; 60];
    for i in 0..8 {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for i in 8..60 {
        let mut t = w[i - 1];
        if i % 8 == 0 {
            t = sub([t[1], t[2], t[3], t[0]]); // RotWord then SubWord
            t[0] ^= RCON[i / 8 - 1];
        } else if i % 8 == 4 {
            t = sub(t);
        }
        for j in 0..4 {
            w[i][j] = w[i - 8][j] ^ t[j];
        }
    }
    let mut rk = [[0_u8; 16]; 15];
    for r in 0..15 {
        for c in 0..4 {
            rk[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    rk
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

        pub(super) fn encrypt8(&self, blocks: &mut [[u8; 16]; 8]) {
            // SAFETY: Aes256 can only be constructed after hardware_available
            // has checked the target features required by encrypt8_inner.
            unsafe { self.encrypt8_inner(blocks) };
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

        /// Eight interleaved AES-256 chains. The eight round chains are emitted
        /// as one instruction stream so the scheduler keeps the AESE/AESMC
        /// pipeline full; constant time, with no data-dependent control flow.
        #[target_feature(enable = "aes", enable = "neon")]
        unsafe fn encrypt8_inner(&self, blocks: &mut [[u8; 16]; 8]) {
            let mut state = [vdupq_n_u8(0); 8];
            for (lane, block) in state.iter_mut().zip(blocks.iter()) {
                // SAFETY: each block is a valid 16-byte initialized buffer.
                *lane = unsafe { vld1q_u8(block.as_ptr()) };
            }
            for round_key in &self.round_keys[..13] {
                for lane in &mut state {
                    *lane = vaesmcq_u8(vaeseq_u8(*lane, *round_key));
                }
            }
            for lane in &mut state {
                *lane = veorq_u8(vaeseq_u8(*lane, self.round_keys[13]), self.round_keys[14]);
            }
            for (lane, block) in state.iter().zip(blocks.iter_mut()) {
                // SAFETY: each block is a valid 16-byte writable buffer.
                unsafe { vst1q_u8(block.as_mut_ptr(), *lane) };
            }
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
        // A statically-enabled target feature is guaranteed present at runtime.
        if cfg!(target_feature = "aes") && cfg!(target_feature = "neon") {
            return true;
        }
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
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_loadu_si128, _mm_storeu_si128,
        _mm_xor_si128,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_loadu_si128, _mm_storeu_si128,
        _mm_xor_si128,
    };
    // Key-expansion-only intrinsics. Under Miri the key schedule is computed in
    // software (Miri lacks aeskeygenassist), so these are not used there.
    #[cfg(all(not(miri), target_arch = "x86"))]
    use core::arch::x86::{_mm_aeskeygenassist_si128, _mm_shuffle_epi32, _mm_slli_si128};
    #[cfg(all(not(miri), target_arch = "x86_64"))]
    use core::arch::x86_64::{_mm_aeskeygenassist_si128, _mm_shuffle_epi32, _mm_slli_si128};

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

        pub(super) fn encrypt8(&self, blocks: &mut [[u8; 16]; 8]) {
            // SAFETY: Aes256 can only be constructed after hardware_available
            // has checked the target features required by encrypt8_inner.
            unsafe { self.encrypt8_inner(blocks) };
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

        /// Eight interleaved AES-256 chains. The eight round chains are emitted
        /// as one instruction stream so the scheduler keeps the AESENC pipeline
        /// full; constant time, with no data-dependent control flow.
        #[target_feature(enable = "sse2", enable = "aes")]
        unsafe fn encrypt8_inner(&self, blocks: &mut [[u8; 16]; 8]) {
            // Seed the lane array with a Copy __m128i so no zero-init intrinsic
            // import is needed; every lane is overwritten immediately below.
            let mut state = [self.round_keys[0]; 8];
            for (lane, block) in state.iter_mut().zip(blocks.iter()) {
                // SAFETY: each block points to an initialized 16-byte range.
                let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
                *lane = _mm_xor_si128(input, self.round_keys[0]);
            }
            for round_key in &self.round_keys[1..14] {
                for lane in &mut state {
                    *lane = _mm_aesenc_si128(*lane, *round_key);
                }
            }
            for lane in &mut state {
                *lane = _mm_aesenclast_si128(*lane, self.round_keys[14]);
            }
            for (lane, block) in state.iter().zip(blocks.iter_mut()) {
                // SAFETY: each block points to a writable 16-byte range.
                unsafe { _mm_storeu_si128(block.as_mut_ptr().cast(), *lane) };
            }
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
        // A statically-enabled target feature is guaranteed present at runtime
        // (the compiler emits those instructions unconditionally), so trust it
        // without any runtime query.
        if cfg!(target_feature = "aes") && cfg!(target_feature = "sse2") {
            return true;
        }
        // A *positive* `is_x86_feature_detected!` result is authoritative, so the
        // common path is unchanged. Only when it reports the feature *absent* do
        // we double-check CPUID: rebuilding `std_detect` from source
        // (`cargo -Zbuild-std`, used by the sanitizer CI) has been observed to
        // produce false negatives on CPUs that do support AES.
        if std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2")
        {
            return true;
        }
        cpuid_confirms_aes_sse2()
    }

    // Miri models `is_x86_feature_detected!` but cannot execute a raw `CPUID`, so
    // trust the negative result it just produced.
    #[cfg(miri)]
    fn cpuid_confirms_aes_sse2() -> bool {
        false
    }

    // CPUID leaf 1 is the architectural source of truth and is always available
    // on x86/x86-64, unaffected by `-Zbuild-std`. `#[cold]`/`#[inline(never)]`
    // keep this fallback out of the common-path code layout. `__cpuid` is a safe
    // intrinsic on x86-64 but `unsafe` on 32-bit x86, so the block is unused on
    // the former.
    #[cfg(not(miri))]
    #[cold]
    #[inline(never)]
    #[allow(unused_unsafe)]
    fn cpuid_confirms_aes_sse2() -> bool {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::__cpuid;
        const ECX_AES: u32 = 1 << 25;
        const EDX_SSE2: u32 = 1 << 26;
        // SAFETY: CPUID leaf 1 is unconditionally valid on x86/x86-64.
        let info = unsafe { __cpuid(1) };
        (info.ecx & ECX_AES) != 0 && (info.edx & EDX_SSE2) != 0
    }

    // Under Miri only, expand the key with the portable software schedule
    // (Miri lacks `_mm_aeskeygenassist_si128`). Byte-identical to the hardware
    // path; the AES rounds still use the real `_mm_aesenc_si128`. Never compiled
    // outside `cargo miri`.
    #[cfg(miri)]
    #[target_feature(enable = "sse2", enable = "aes")]
    unsafe fn aes256_key_expansion(
        expanded_keys: *mut [__m128i; AES256_ROUND_KEY_COUNT],
        key: &[u8; 32],
    ) {
        let schedule = super::software_key_schedule(key);
        for (i, rk) in schedule.iter().enumerate() {
            // SAFETY: i in 0..15 is within the round-key array; rk is a valid
            // 16-byte buffer; expanded_keys is writable per the caller.
            unsafe {
                core::ptr::addr_of_mut!((*expanded_keys)[i])
                    .write(_mm_loadu_si128(rk.as_ptr().cast()));
            }
        }
    }

    #[cfg(not(miri))]
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

        pub(super) fn encrypt8(&self, _blocks: &mut [[u8; 16]; 8]) {
            match *self {}
        }
    }

    pub(super) const fn hardware_available() -> bool {
        false
    }
}

#[cfg(all(
    test,
    any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")
))]
mod tests {
    #![allow(clippy::cast_possible_truncation, clippy::expect_used)]

    use super::{software_key_schedule, Aes256, AES_SBOX};
    use core::mem::MaybeUninit;

    /// Reads the real hardware-expanded round keys back as bytes.
    fn hardware_round_keys(key: &[u8; 32]) -> [[u8; 16]; 15] {
        let mut slot = MaybeUninit::<Aes256>::uninit();
        Aes256::init_in_place(slot.as_mut_ptr(), key).expect("hardware AES available");
        // SAFETY: init_in_place initialized the storage on success.
        let aes = unsafe { slot.assume_init() };
        let mut out = [[0_u8; 16]; 15];
        for (dst, rk) in out.iter_mut().zip(aes.round_keys().iter()) {
            #[cfg(target_arch = "aarch64")]
            // SAFETY: dst is a writable 16-byte buffer; neon is baseline.
            unsafe {
                core::arch::aarch64::vst1q_u8(dst.as_mut_ptr(), *rk);
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            // SAFETY: dst is a writable 16-byte buffer; sse2 is baseline on x86_64.
            unsafe {
                #[cfg(target_arch = "x86")]
                use core::arch::x86::_mm_storeu_si128;
                #[cfg(target_arch = "x86_64")]
                use core::arch::x86_64::_mm_storeu_si128;
                _mm_storeu_si128(dst.as_mut_ptr().cast(), *rk);
            }
        }
        out
    }

    /// The TEST/MIRI software key schedule must produce byte-identical round keys
    /// to the shipped hardware key expansion - the invariant that makes the
    /// `cfg(miri)` key-expansion path sound (it lets Miri run the real lifecycle
    /// and AES rounds while computing the same keys).
    #[test]
    fn software_schedule_matches_hardware() {
        // FIPS-197 AES-256 sample key plus pseudo-random keys.
        let mut keys = vec![[0_u8; 32]];
        let mut fips = [0_u8; 32];
        for (i, b) in fips.iter_mut().enumerate() {
            *b = i as u8;
        }
        keys.push(fips);
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..16 {
            let mut k = [0_u8; 32];
            for b in &mut k {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = (state >> 24) as u8;
            }
            keys.push(k);
        }
        for key in &keys {
            assert_eq!(
                software_key_schedule(key),
                hardware_round_keys(key),
                "software key schedule diverged from hardware"
            );
        }
    }

    /// Proves the shipped `AES_SBOX` table is the genuine FIPS-197 S-box -
    /// `affine(inverse_GF(2^8)(x))` - for **all 256 inputs**, not merely a table
    /// that happens to pass the known-answer tests. This rules out a transcription
    /// error in the 256-byte constant (which feeds both the `cfg(miri)` software
    /// key schedule and, transitively via `software_schedule_matches_hardware`,
    /// validates the shipped hardware key expansion). FIPS-197 section 5.1.1.
    #[test]
    fn aes_sbox_is_fips197_affine_inverse() {
        // GF(2^8) multiplication with the AES reduction polynomial x^8+x^4+x^3+x+1.
        fn gf_mul(mut a: u8, mut b: u8) -> u8 {
            let mut p = 0_u8;
            for _ in 0..8 {
                if b & 1 != 0 {
                    p ^= a;
                }
                let carry = a & 0x80;
                a <<= 1;
                if carry != 0 {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            p
        }
        // Multiplicative inverse in GF(2^8); inv(0) = 0 by FIPS-197 convention.
        fn gf_inv(x: u8) -> u8 {
            if x == 0 {
                return 0;
            }
            (1_u16..256)
                .map(|y| y as u8)
                .find(|&y| gf_mul(x, y) == 1)
                .expect("every nonzero element of GF(2^8) is invertible")
        }
        // The AES affine map: s = b ^ (b<<<1) ^ (b<<<2) ^ (b<<<3) ^ (b<<<4) ^ 0x63.
        fn sbox_construct(x: u8) -> u8 {
            let b = gf_inv(x);
            b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
        }

        for x in 0..=255_u8 {
            assert_eq!(
                AES_SBOX[x as usize],
                sbox_construct(x),
                "AES_SBOX[{x:#04x}] is not affine(inverse(x))"
            );
        }

        // It is also a bijection (a second, independent guard on the constant).
        let mut seen = [false; 256];
        for &v in &AES_SBOX {
            assert!(!seen[v as usize], "AES_SBOX is not a permutation");
            seen[v as usize] = true;
        }
    }
}
