#![allow(clippy::unwrap_used)]

use hardware_random::{AesCtrKeyGenerator, FastRandom, KEY_SIZE, NONCE_SIZE};

#[test]
fn fast_random_produces_key_and_nonce_material() {
    let mut rng = FastRandom::from_os_entropy().unwrap();
    let key = rng.key_32().unwrap();
    let nonce = rng.nonce_12().unwrap();

    assert_eq!(key.len(), KEY_SIZE);
    assert_eq!(nonce.len(), NONCE_SIZE);
    assert_ne!(key, [0_u8; KEY_SIZE]);
    assert_ne!(nonce, [0_u8; NONCE_SIZE]);
}

#[test]
fn aes_ctr_key_generator_produces_key_and_nonce_material() {
    if !AesCtrKeyGenerator::hardware_available() {
        return;
    }

    let mut rng = AesCtrKeyGenerator::from_os_entropy().unwrap();
    let key = rng.key_32().unwrap();
    let nonce = rng.nonce_12().unwrap();

    assert_eq!(key.len(), KEY_SIZE);
    assert_eq!(nonce.len(), NONCE_SIZE);
    assert_ne!(key, [0_u8; KEY_SIZE]);
    assert_ne!(nonce, [0_u8; NONCE_SIZE]);
}
