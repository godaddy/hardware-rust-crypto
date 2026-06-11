//! Fails when the hardware AES-GCM / AES-CTR backends are unavailable.
//!
//! CI runs this before the test suites so a green build cannot mean
//! "hardware-gated tests silently skipped on a runner without AES support".

fn main() {
    let aes_gcm = hardware_rust_crypto::aes_gcm::HardwareAes256Gcm::hardware_available();
    let aes_ctr = hardware_rust_crypto::random::AesCtrKeyGenerator::hardware_available();
    if !(aes_gcm && aes_ctr) {
        eprintln!("hardware crypto unavailable: aes_gcm={aes_gcm} aes_ctr={aes_ctr}");
        std::process::exit(1);
    }
    println!("hardware AES-GCM and AES-CTR backends available");
}
