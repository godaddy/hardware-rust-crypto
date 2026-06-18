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

#[cfg(all(crux, target_arch = "aarch64"))]
#[crux::test]
fn clmul_is_left_linear() {
    use core::arch::aarch64::vmull_p64;
    use crucible::Symbolic;
    let a = u64::symbolic("a");
    let a2 = u64::symbolic("a2");
    let b = u64::symbolic("b");
    // Carryless multiply is GF(2)-linear in its first argument. crux-mir cannot
    // evaluate vmull_p64, so this goal is reported Invalid (unmodeled intrinsic),
    // NOT because the maths is wrong.
    let lhs: u128 = unsafe { vmull_p64(a ^ a2, b) };
    let rhs: u128 = unsafe { vmull_p64(a, b) ^ vmull_p64(a2, b) };
    crucible_assert!(lhs == rhs);
}
