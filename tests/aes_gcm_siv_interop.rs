//! Interoperability and correctness tests for the hardware AES-256-GCM-SIV
//! path: RFC 8452 known-answer vectors, byte compatibility with `RustCrypto`
//! once the generated nonce is parsed from the default envelope, exhaustive
//! length/tamper sweeps, error-path coverage, and the zeroize-on-failure
//! security guarantee.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aes_gcm_siv::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as RustCryptoNonce};
use hardware_rust_crypto::aes_gcm::{
    Error, HardwareAes256GcmSiv, HardwareAes256GcmSivIn, HardwareAes256GcmSivKeyState,
    SivUninitKeyStateSlot, NONCE_SIZE, TAG_SIZE,
};
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;

const KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];
const NONCE: [u8; NONCE_SIZE] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];
const AAD: &[u8] = b"authenticated metadata";
const PLAINTEXT: &[u8] = b"hardware aes-gcm-siv interop plaintext";

fn reference_encrypt(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(key).unwrap();
    cipher
        .encrypt(RustCryptoNonce::from_slice(nonce), Payload { msg, aad })
        .unwrap()
}

fn reference_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, aes_gcm_siv::Error> {
    let cipher = Aes256GcmSiv::new_from_slice(key).unwrap();
    cipher.decrypt(RustCryptoNonce::from_slice(nonce), Payload { msg: ct, aad })
}

fn envelope_ciphertext_tag(envelope: &[u8]) -> &[u8] {
    assert!(envelope.len() >= TAG_SIZE + NONCE_SIZE);
    &envelope[..envelope.len() - NONCE_SIZE]
}

fn envelope_nonce(envelope: &[u8]) -> [u8; NONCE_SIZE] {
    assert!(envelope.len() >= TAG_SIZE + NONCE_SIZE);
    envelope[envelope.len() - NONCE_SIZE..]
        .try_into()
        .expect("nonce length")
}

fn envelope_from_parts(ciphertext_tag: &[u8], nonce: &[u8; NONCE_SIZE]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(ciphertext_tag.len() + NONCE_SIZE);
    envelope.extend_from_slice(ciphertext_tag);
    envelope.extend_from_slice(nonce);
    envelope
}

fn assert_default_envelope_matches_reference(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
    envelope: &[u8],
    context: &str,
) {
    let nonce = envelope_nonce(envelope);
    assert_eq!(
        envelope.len(),
        plaintext.len() + TAG_SIZE + NONCE_SIZE,
        "{context}: envelope length"
    );
    assert_eq!(
        envelope_ciphertext_tag(envelope),
        reference_encrypt(key, &nonce, aad, plaintext),
        "{context}: ciphertext || tag mismatch"
    );
    assert_eq!(
        reference_decrypt(key, &nonce, aad, envelope_ciphertext_tag(envelope)).unwrap(),
        plaintext,
        "{context}: RustCrypto could not decrypt candidate envelope"
    );
}

// ---------------------------------------------------------------------------
// RFC 8452 Appendix C.2 known-answer vectors.
// ---------------------------------------------------------------------------

struct Kat {
    key: &'static str,
    nonce: &'static str,
    aad: &'static str,
    plaintext: &'static str,
    result: &'static str,
}

// The structured-key vectors (key 0x01.. / nonce 0x03..) plus one different-key
// vector, all from RFC 8452 C.2. Each result is independently checked against
// the RustCrypto reference in the test, so a transcription error would surface
// as a clear "hardcoded vs reference" mismatch rather than passing silently.
const STRUCT_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
const STRUCT_NONCE: &str = "030000000000000000000000";

const RFC8452_VECTORS: &[Kat] = &[
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "", plaintext: "",
          result: "07f5f4169bbf55a8400cd47ea6fd400f" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "", plaintext: "0100000000000000",
          result: "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "", plaintext: "010000000000000000000000",
          result: "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "", plaintext: "01000000000000000000000000000000",
          result: "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "",
          plaintext: "0100000000000000000000000000000002000000000000000000000000000000",
          result: "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "",
          plaintext: "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000",
          result: "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "",
          plaintext: "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
          result: "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "01", plaintext: "0200000000000000",
          result: "1de22967237a813291213f267e3b452f02d01ae33e4ec854" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "01", plaintext: "020000000000000000000000",
          result: "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "01", plaintext: "02000000000000000000000000000000",
          result: "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "01",
          plaintext: "0200000000000000000000000000000003000000000000000000000000000000",
          result: "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc" },
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "01",
          plaintext: "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
          result: "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb" },
    // Non-block-multiple plaintext with a 12-byte AAD.
    Kat { key: STRUCT_KEY, nonce: STRUCT_NONCE, aad: "010000000000000000000000", plaintext: "02000000",
          result: "22b3f4cd1835e517741dfddccfa07fa4661b74cf" },
    // Different key-generating key, empty plaintext: exercises key derivation
    // and tag for a second key.
    Kat { key: "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
          nonce: "e0eaf5284d884a0e77d31646", aad: "", plaintext: "",
          result: "169fbb2fbf389a995f6390af22228a62" },
];

#[test]
fn rfc8452_known_answer_vectors_decrypt_from_envelope() {
    for (index, kat) in RFC8452_VECTORS.iter().enumerate() {
        let key = hex32(kat.key);
        let nonce = hex12(kat.nonce);
        let aad = hex(kat.aad);
        let pt = hex(kat.plaintext);
        let expected = hex(kat.result);

        assert_eq!(
            expected.len(),
            pt.len() + TAG_SIZE,
            "vector {index}: result length must be plaintext + tag"
        );
        assert_eq!(
            expected,
            reference_encrypt(&key, &nonce, &aad, &pt),
            "vector {index}: hardcoded vector != RustCrypto reference"
        );

        let mut candidate = HardwareAes256GcmSiv::new(&key).unwrap();
        let vector_envelope = envelope_from_parts(&expected, &nonce);
        assert_eq!(
            candidate.decrypt(&aad, &vector_envelope).unwrap(),
            pt,
            "vector {index}: decrypt"
        );

        let generated = candidate.encrypt(&aad, &pt).unwrap();
        assert_default_envelope_matches_reference(
            &key,
            &aad,
            &pt,
            &generated,
            &format!("vector {index}: generated envelope"),
        );
        assert_eq!(candidate.decrypt(&aad, &generated).unwrap(), pt);
    }
}

// ---------------------------------------------------------------------------
// Byte compatibility with RustCrypto aes-gcm-siv.
// ---------------------------------------------------------------------------

#[test]
fn default_encrypt_matches_rustcrypto_for_embedded_nonce() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let envelope = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    assert_default_envelope_matches_reference(&KEY, AAD, PLAINTEXT, &envelope, "default encrypt");
    assert_eq!(candidate.decrypt(AAD, &envelope).unwrap(), PLAINTEXT);
}

#[test]
fn candidate_and_rustcrypto_decrypt_each_other() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();

    let candidate_envelope = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    let candidate_nonce = envelope_nonce(&candidate_envelope);
    assert_eq!(
        reference_decrypt(
            &KEY,
            &candidate_nonce,
            AAD,
            envelope_ciphertext_tag(&candidate_envelope)
        )
        .unwrap(),
        PLAINTEXT
    );

    let reference_ct = reference_encrypt(&KEY, &NONCE, AAD, PLAINTEXT);
    let reference_envelope = envelope_from_parts(&reference_ct, &NONCE);
    assert_eq!(
        candidate.decrypt(AAD, &reference_envelope).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn default_layout_is_ciphertext_tag_nonce() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let envelope = candidate.encrypt(&[], PLAINTEXT).unwrap();
    let nonce = envelope_nonce(&envelope);

    assert_eq!(envelope.len(), PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE);
    assert_eq!(candidate.decrypt(&[], &envelope).unwrap(), PLAINTEXT);

    let prefix = reference_encrypt(&KEY, &nonce, &[], PLAINTEXT);
    assert_eq!(envelope_ciphertext_tag(&envelope), prefix.as_slice());
}

#[test]
fn default_encrypt_generates_distinct_nonces() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let first = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    let second = candidate.encrypt(AAD, PLAINTEXT).unwrap();

    assert_ne!(envelope_nonce(&first), envelope_nonce(&second));
    assert_ne!(first, second);
    assert_eq!(candidate.decrypt(AAD, &first).unwrap(), PLAINTEXT);
    assert_eq!(candidate.decrypt(AAD, &second).unwrap(), PLAINTEXT);
}

// ---------------------------------------------------------------------------
// Explicit-nonce escape hatch coverage.
// ---------------------------------------------------------------------------

#[cfg(feature = "hazmat-explicit-nonce")]
#[test]
fn explicit_nonce_encryption_is_deterministic() {
    let a = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let b = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let ct1 = a.encrypt_with_nonce(&NONCE, AAD, PLAINTEXT).unwrap();
    let ct2 = a.encrypt_with_nonce(&NONCE, AAD, PLAINTEXT).unwrap();
    let ct3 = b.encrypt_with_nonce(&NONCE, AAD, PLAINTEXT).unwrap();
    assert_eq!(ct1, ct2);
    assert_eq!(ct1, ct3);

    let mut other_nonce = NONCE;
    other_nonce[0] ^= 1;
    assert_ne!(
        a.encrypt_with_nonce(&other_nonce, AAD, PLAINTEXT).unwrap(),
        ct1
    );
}

#[cfg(feature = "hazmat-explicit-nonce")]
#[test]
fn explicit_nonce_appended_layout_and_in_place_round_trip() {
    let candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let layout = candidate.encrypt_nonce_appended(&NONCE, PLAINTEXT).unwrap();

    assert_eq!(envelope_nonce(&layout), NONCE);
    assert_eq!(layout.len(), PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE);
    assert_eq!(
        candidate.decrypt_nonce_appended(&layout).unwrap(),
        PLAINTEXT
    );
    assert_eq!(
        envelope_ciphertext_tag(&layout),
        reference_encrypt(&KEY, &NONCE, &[], PLAINTEXT)
    );

    let mut in_place = PLAINTEXT.to_vec();
    candidate
        .encrypt_nonce_appended_in_place(&NONCE, &mut in_place)
        .unwrap();
    assert_eq!(in_place, layout);
}

#[cfg(feature = "hazmat-explicit-nonce")]
#[test]
fn rejects_invalid_explicit_nonce_length() {
    let candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    assert_eq!(
        candidate
            .encrypt_with_nonce(&[0_u8; NONCE_SIZE - 1], AAD, PLAINTEXT)
            .err(),
        Some(Error::InvalidNonceLength)
    );
    assert_eq!(
        candidate
            .encrypt_with_nonce(&[0_u8; NONCE_SIZE + 1], AAD, PLAINTEXT)
            .err(),
        Some(Error::InvalidNonceLength)
    );
    let ct = candidate
        .encrypt_with_nonce(&NONCE, AAD, PLAINTEXT)
        .unwrap();
    assert_eq!(
        candidate
            .decrypt_with_nonce(&[0_u8; NONCE_SIZE + 1], AAD, &ct)
            .err(),
        Some(Error::InvalidNonceLength)
    );
}

// ---------------------------------------------------------------------------
// Allocation and caller-placed API variants.
// ---------------------------------------------------------------------------

#[test]
fn inline_and_caller_placed_default_envelopes_round_trip() {
    let mut owned = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let owned_envelope = owned.encrypt(AAD, PLAINTEXT).unwrap();
    assert_default_envelope_matches_reference(
        &KEY,
        AAD,
        PLAINTEXT,
        &owned_envelope,
        "owned default",
    );
    assert_eq!(owned.decrypt(AAD, &owned_envelope).unwrap(), PLAINTEXT);

    let mut inline = HardwareAes256GcmSivKeyState::new(&KEY).unwrap();
    let inline_envelope = inline.encrypt(AAD, PLAINTEXT).unwrap();
    assert_default_envelope_matches_reference(
        &KEY,
        AAD,
        PLAINTEXT,
        &inline_envelope,
        "inline default",
    );
    assert_eq!(inline.decrypt(AAD, &inline_envelope).unwrap(), PLAINTEXT);

    with_placed_state(|placed| {
        let placed_envelope = placed.encrypt(AAD, PLAINTEXT).unwrap();
        assert_default_envelope_matches_reference(
            &KEY,
            AAD,
            PLAINTEXT,
            &placed_envelope,
            "caller-placed default",
        );
        assert_eq!(placed.decrypt(AAD, &placed_envelope).unwrap(), PLAINTEXT);
    });
}

fn with_placed_state<R>(f: impl FnOnce(&mut HardwareAes256GcmSivIn<'_>) -> R) -> R {
    let layout = HardwareAes256GcmSiv::key_state_layout();
    let mut storage = vec![0_u8; layout.size + layout.align];
    let offset = storage.as_ptr().align_offset(layout.align);
    let slot = SivUninitKeyStateSlot::new(&mut storage[offset..offset + layout.size]).unwrap();
    let mut placed = HardwareAes256GcmSivIn::new_in(&KEY, slot).unwrap();
    f(&mut placed)
}

// ---------------------------------------------------------------------------
// Authentication: tampering, wrong key/nonce/AAD, and zeroize-on-failure.
// ---------------------------------------------------------------------------

#[test]
fn every_single_byte_tamper_fails_across_sizes() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    for size in [0_usize, 1, 15, 16, 17, 31, 32, 64, 127, 128, 129] {
        let plaintext = vec![0xa5_u8; size];
        let envelope = candidate.encrypt(AAD, &plaintext).unwrap();

        for byte_index in 0..envelope.len() {
            for bit in [0x01_u8, 0x80] {
                let mut tampered = envelope.clone();
                tampered[byte_index] ^= bit;
                assert!(
                    candidate.decrypt(AAD, &tampered).is_err(),
                    "size {size}: tampered byte {byte_index} bit {bit:#x} authenticated"
                );
            }
        }

        if !AAD.is_empty() {
            let mut tampered_aad = AAD.to_vec();
            tampered_aad[0] ^= 0x80;
            assert!(candidate.decrypt(&tampered_aad, &envelope).is_err());
        }
    }
}

#[test]
fn wrong_key_nonce_or_aad_is_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5749_4e44_5752_4f4e);
    for _ in 0..256 {
        let mut key = [0_u8; 32];
        let mut plaintext = vec![0_u8; 1 + (rng.next_u32() as usize % 200)];
        let mut aad = vec![0_u8; rng.next_u32() as usize % 64];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut plaintext);
        rng.fill_bytes(&mut aad);

        let mut cipher = HardwareAes256GcmSiv::new(&key).unwrap();
        let envelope = cipher.encrypt(&aad, &plaintext).unwrap();

        let mut wrong_key = key;
        wrong_key[rng.next_u32() as usize % 32] ^= 1;
        let wrong = HardwareAes256GcmSiv::new(&wrong_key).unwrap();
        assert_eq!(wrong.decrypt(&aad, &envelope), Err(Error::Decrypt));

        let mut wrong_nonce = envelope.clone();
        let nonce_pos = wrong_nonce.len() - NONCE_SIZE + (rng.next_u32() as usize % NONCE_SIZE);
        wrong_nonce[nonce_pos] ^= 1;
        assert_eq!(cipher.decrypt(&aad, &wrong_nonce), Err(Error::Decrypt));

        let mut wrong_aad = aad.clone();
        wrong_aad.push(0xff);
        assert_eq!(cipher.decrypt(&wrong_aad, &envelope), Err(Error::Decrypt));

        assert_eq!(cipher.decrypt(&aad, &envelope).unwrap(), plaintext);
    }
}

#[test]
fn decrypt_to_zeroizes_output_on_authentication_failure() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();
    let plaintext = vec![0xab_u8; 200];
    let mut envelope = candidate.encrypt(AAD, &plaintext).unwrap();
    let last_tag_byte = envelope.len() - NONCE_SIZE - 1;
    envelope[last_tag_byte] ^= 0x80;

    let mut out = vec![0x11_u8; plaintext.len()];
    let result = candidate.decrypt_to(AAD, &envelope, &mut out);
    assert_eq!(result, Err(Error::Decrypt));
    assert!(
        out.iter().all(|&b| b == 0),
        "plaintext-length prefix of the output buffer must be zeroized on failure"
    );
}

// ---------------------------------------------------------------------------
// Error paths.
// ---------------------------------------------------------------------------

#[test]
fn rejects_invalid_key_length() {
    assert_eq!(
        HardwareAes256GcmSiv::new(&[0_u8; 31]).err(),
        Some(Error::InvalidKeyLength)
    );
    assert_eq!(
        HardwareAes256GcmSiv::new(&[0_u8; 33]).err(),
        Some(Error::InvalidKeyLength)
    );
    assert_eq!(
        HardwareAes256GcmSivKeyState::new(&[0_u8; 16]).err(),
        Some(Error::InvalidKeyLength)
    );
    let layout = HardwareAes256GcmSiv::key_state_layout();
    let mut storage = vec![0_u8; layout.size + layout.align];
    let offset = storage.as_ptr().align_offset(layout.align);
    let slot = SivUninitKeyStateSlot::new(&mut storage[offset..offset + layout.size]).unwrap();
    assert_eq!(
        HardwareAes256GcmSivIn::new_in(&[0_u8; 8], slot).err(),
        Some(Error::InvalidKeyLength)
    );
}

#[test]
fn rejects_short_and_undersized_buffers() {
    let mut candidate = HardwareAes256GcmSiv::new(&KEY).unwrap();

    assert_eq!(
        candidate
            .decrypt(AAD, &[0_u8; TAG_SIZE + NONCE_SIZE - 1])
            .err(),
        Some(Error::CiphertextTooShort)
    );

    let mut too_small = vec![0_u8; PLAINTEXT.len() + TAG_SIZE + NONCE_SIZE - 1];
    assert_eq!(
        candidate.encrypt_to(AAD, PLAINTEXT, &mut too_small).err(),
        Some(Error::OutputTooSmall)
    );

    let envelope = candidate.encrypt(AAD, PLAINTEXT).unwrap();
    let mut small_pt = vec![0_u8; PLAINTEXT.len() - 1];
    assert_eq!(
        candidate.decrypt_to(AAD, &envelope, &mut small_pt).err(),
        Some(Error::OutputTooSmall)
    );
}

// ---------------------------------------------------------------------------
// Length sweeps against the reference, exercising POLYVAL aggregation and the
// CTR batch boundaries for both message and AAD.
// ---------------------------------------------------------------------------

#[test]
fn randomized_differential_against_rustcrypto() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5349_565f_5241_4e44);
    for plaintext_len in [
        0_usize, 1, 2, 3, 7, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023,
        1024, 1025, 4096, 8192, 16384,
    ] {
        for aad_len in [
            0_usize, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 255, 256,
        ] {
            let mut key = [0_u8; 32];
            let mut inbound_nonce = [0_u8; NONCE_SIZE];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut inbound_nonce);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let mut candidate = HardwareAes256GcmSiv::new(&key).unwrap();
            let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
            assert_default_envelope_matches_reference(
                &key,
                &aad,
                &plaintext,
                &envelope,
                &format!("plaintext_len={plaintext_len} aad_len={aad_len}"),
            );
            assert_eq!(candidate.decrypt(&aad, &envelope).unwrap(), plaintext);

            let inbound_ct = reference_encrypt(&key, &inbound_nonce, &aad, &plaintext);
            assert_eq!(
                candidate
                    .decrypt(&aad, &envelope_from_parts(&inbound_ct, &inbound_nonce))
                    .unwrap(),
                plaintext
            );
        }
    }
}

/// Dense plaintext sweep across the 128 B interleaved-batch and 64/16 B POLYVAL
/// aggregation boundaries, round-tripping through every buffer-based API.
#[test]
fn dense_plaintext_sweep() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5349_565f_5357_4550);
    let lengths = (0..=288_usize).chain([511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097]);
    for plaintext_len in lengths {
        for aad_len in [0_usize, 17] {
            let mut key = [0_u8; 32];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let mut candidate = HardwareAes256GcmSiv::new(&key).unwrap();
            let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
            assert_default_envelope_matches_reference(
                &key,
                &aad,
                &plaintext,
                &envelope,
                &format!("alloc plaintext_len={plaintext_len} aad_len={aad_len}"),
            );

            let mut to_buffer = vec![0_u8; plaintext_len + TAG_SIZE + NONCE_SIZE];
            let written = candidate
                .encrypt_to(&aad, &plaintext, &mut to_buffer)
                .unwrap();
            assert_eq!(written, to_buffer.len());
            assert_default_envelope_matches_reference(
                &key,
                &aad,
                &plaintext,
                &to_buffer,
                &format!("encrypt_to plaintext_len={plaintext_len} aad_len={aad_len}"),
            );

            let mut pt_buffer = vec![0_u8; plaintext_len];
            let pt_written = candidate
                .decrypt_to(&aad, &to_buffer, &mut pt_buffer)
                .unwrap();
            assert_eq!(pt_written, plaintext_len);
            assert_eq!(
                pt_buffer, plaintext,
                "decrypt_to mismatch at {plaintext_len}"
            );
        }
    }
}

/// Dense AAD sweep across the same POLYVAL aggregation boundaries the plaintext
/// path exercises. AAD runs through the identical 8/4/1-block + partial logic.
#[test]
fn dense_aad_sweep() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5349_565f_4141_4453);
    for aad_len in 0..=288_usize {
        for plaintext_len in [0_usize, 16, 37] {
            let mut key = [0_u8; 32];
            let mut plaintext = vec![0_u8; plaintext_len];
            let mut aad = vec![0_u8; aad_len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut plaintext);
            rng.fill_bytes(&mut aad);

            let mut candidate = HardwareAes256GcmSiv::new(&key).unwrap();
            let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
            assert_default_envelope_matches_reference(
                &key,
                &aad,
                &plaintext,
                &envelope,
                &format!("aad_len={aad_len} plaintext_len={plaintext_len}"),
            );
            assert_eq!(candidate.decrypt(&aad, &envelope).unwrap(), plaintext);
        }
    }
}

/// Large AAD combined with large plaintext, beyond the small fixed sizes above.
#[test]
fn large_aad_and_plaintext() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4c52_4745_5f49_4f4e);
    let mut key = [0_u8; 32];
    let mut plaintext = vec![0_u8; 9000];
    let mut aad = vec![0_u8; 5000];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut plaintext);
    rng.fill_bytes(&mut aad);

    let mut candidate = HardwareAes256GcmSiv::new(&key).unwrap();
    let envelope = candidate.encrypt(&aad, &plaintext).unwrap();
    assert_default_envelope_matches_reference(&key, &aad, &plaintext, &envelope, "large input");
    assert_eq!(candidate.decrypt(&aad, &envelope).unwrap(), plaintext);
}

// ---------------------------------------------------------------------------
// Hex helpers.
// ---------------------------------------------------------------------------

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length in vector");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32-byte hex")
}

fn hex12(s: &str) -> [u8; NONCE_SIZE] {
    hex(s).try_into().expect("12-byte hex")
}
