//! crux-mir proof that the SP 800-38D `inc_32` logic is correct for all inputs,
//! over Rust MIR (a fourth verification toolchain alongside Z3, Kani/CBMC, and
//! SAW-LLVM). Unlike SAW-LLVM, crux-mir works on MIR, so it sidesteps the LLVM
//! `poison` values that blocked the SAW field-multiply proof.
//!
//! `increment_counter` here is byte-identical to `src/aes_gcm/mod.rs`. Verifying
//! the crate's own function in place needs `cfg(crux)` exclusion of the intrinsic
//! backends (the same crate-ingestibility step hax needs); this standalone module
//! verifies the logic and demonstrates the toolchain. Run via `proofs/crux-mir/run.sh`.

fn increment_counter(counter: &mut [u8; 16]) {
    let mut low = [0_u8; 4];
    low.copy_from_slice(&counter[12..]);
    let v = u32::from_be_bytes(low).wrapping_add(1);
    counter[12..].copy_from_slice(&v.to_be_bytes());
}

#[cfg(crux)]
#[macro_use]
extern crate crucible;

#[cfg(crux)]
#[crux::test]
fn increment_counter_is_inc32() {
    use crucible::Symbolic;
    let mut c = <[u8; 16]>::symbolic("c");
    let orig = c;
    increment_counter(&mut c);
    // Leading 96 bits unchanged.
    let mut i = 0;
    while i < 12 {
        crucible_assert!(c[i] == orig[i]);
        i += 1;
    }
    // Trailing 32 bits are the big-endian increment.
    let lo = u32::from_be_bytes([orig[12], orig[13], orig[14], orig[15]]);
    let e = lo.wrapping_add(1).to_be_bytes();
    crucible_assert!(c[12] == e[0] && c[13] == e[1] && c[14] == e[2] && c[15] == e[3]);
}
