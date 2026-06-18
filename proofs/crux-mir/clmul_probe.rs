//! Probe: can crux-mir reach THROUGH the carryless-multiply intrinsic?
//!
//! Result: NO. crux-mir has no model for the PMULL/PCLMULQDQ LLVM intrinsic, so
//! it cannot symbolically execute `vmull_p64`. Running this prints:
//!
//!   Translation error in ...::vmull_p64: callExp: Don't know how to call
//!   ...::vmull_p64::{extern#0}::_vmull_p64
//!   Overall status: Invalid.   (a spurious "counterexample" - the intrinsic
//!                                returns an unconstrained value)
//!
//! This is the SAME boundary SAW-LLVM hit (there via a `poison` panic): no
//! source/bitcode-level tool here models the hardware SIMD crypto instructions.
//! They must be AXIOMATIZED (crux-mir's `cryptol_override!`, SAW's Cryptol
//! override) to reason about code that calls them - which is exactly why the
//! field arithmetic is proven via a model anchored to the *captured real output*
//! of the running backend (`proofs/field_model.py` + `prove_multiply.py`),
//! rather than by direct intrinsic verification.

#[cfg(crux)]
#[macro_use]
extern crate crucible;

// Carryless multiply is GF(2)-linear in its first argument. crux-mir cannot
// evaluate the carryless-multiply intrinsic, so these goals are reported Invalid
// (unmodeled intrinsic), NOT because the maths is wrong. One arm per supported
// architecture so the probe exercises the real intrinsic on whatever runner runs
// it (PMULL on aarch64, PCLMULQDQ on x86_64) rather than discharging vacuously.

#[cfg(all(crux, target_arch = "aarch64"))]
#[crux::test]
fn clmul_is_left_linear_aarch64() {
    use core::arch::aarch64::vmull_p64;
    use crucible::Symbolic;
    let a = u64::symbolic("a");
    let a2 = u64::symbolic("a2");
    let b = u64::symbolic("b");
    let lhs: u128 = unsafe { vmull_p64(a ^ a2, b) };
    let rhs: u128 = unsafe { vmull_p64(a, b) ^ vmull_p64(a2, b) };
    crucible_assert!(lhs == rhs);
}

#[cfg(all(crux, target_arch = "x86_64"))]
#[crux::test]
fn clmul_is_left_linear_x86_64() {
    use core::arch::x86_64::{_mm_clmulepi64_si128, _mm_set_epi64x};
    use crucible::Symbolic;
    let a = u64::symbolic("a");
    let a2 = u64::symbolic("a2");
    let b = u64::symbolic("b");
    // PCLMULQDQ of the low 64-bit lanes (imm 0x00), the same primitive the GHASH
    // backend uses; reached here so the x86_64 CI runner hits the real intrinsic.
    unsafe {
        let bv = _mm_set_epi64x(0, b as i64);
        let lhs: u128 =
            core::mem::transmute(_mm_clmulepi64_si128(_mm_set_epi64x(0, (a ^ a2) as i64), bv, 0x00));
        let r1: u128 =
            core::mem::transmute(_mm_clmulepi64_si128(_mm_set_epi64x(0, a as i64), bv, 0x00));
        let r2: u128 =
            core::mem::transmute(_mm_clmulepi64_si128(_mm_set_epi64x(0, a2 as i64), bv, 0x00));
        crucible_assert!(lhs == r1 ^ r2);
    }
}
