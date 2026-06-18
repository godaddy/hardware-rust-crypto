//! Forces the `ct-verify` wrappers around the two scalar secret-handling
//! functions into a binary the constant-time verifier
//! (`proofs/constant-time/verify.sh`) can disassemble and check for
//! branch-freedom. Build with `--features ct-verify`; otherwise it is a no-op.

fn main() {
    #[cfg(feature = "ct-verify")]
    {
        use core::hint::black_box;
        let m = hardware_rust_crypto::aes_gcm::ct_verify_mulx(black_box(&[0x42_u8; 16]));
        black_box(m);
        let eq = hardware_rust_crypto::aes_gcm::ct_verify_constant_time_eq(
            black_box(&[0_u8; 16]),
            black_box(&[0_u8; 16]),
        );
        black_box(eq);
        let leak = hardware_rust_crypto::aes_gcm::ct_verify_leaky_control(
            black_box(&[0_u8; 16]),
            black_box(&[1_u8; 16]),
        );
        black_box(leak);
    }
}
