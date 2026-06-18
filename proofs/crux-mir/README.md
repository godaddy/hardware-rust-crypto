# crux-mir proofs (symbolic execution of Rust MIR)

[crux-mir](https://github.com/GaloisInc/crucible/tree/master/crux-mir) (Galois)
symbolically executes Rust at the **MIR** level — a fourth independent
verification toolchain alongside the Z3/sympy model proofs, the Kani/CBMC
compiled-code proofs, and the SAW LLVM-bitcode proofs. Because it works on MIR,
it sidesteps the LLVM `poison` values that blocked the SAW field-multiply proof
(`proofs/saw/field_bilinearity.saw`).

## What it shows

`increment_counter.rs` — crux-mir **proves** the SP 800-38D `inc_32` logic
correct for all inputs:

```
test ...::increment_counter_is_inc32: [Crux] Attempting to prove ...
[Crux] Goal status:  Proved: 1   Disproved: 0
[Crux] Overall status: Valid.
```

That is the same property the Z3, Kani, and SAW proofs establish — cross-tool
agreement across four solvers reduces the "trust one prover" risk.

## The intrinsic boundary (the important finding)

`clmul_probe.rs` asks crux-mir to reason about `vmull_p64` (the PMULL carryless
multiply). It **cannot**:

```
Translation error in ...::vmull_p64: Don't know how to call ..._vmull_p64
Overall status: Invalid.
```

crux-mir has no model for the PMULL/PCLMULQDQ LLVM intrinsic — the **same
boundary SAW-LLVM hit** (there as a `poison` panic). So *no source- or
bitcode-level tool available here models the hardware SIMD crypto instructions.*
To reason about code that calls them, the instruction must be **axiomatized**
(crux-mir's `cryptol_override!`, SAW's Cryptol override) — which proves the
*composition* given a correct primitive, not the primitive itself.

This is exactly why the field arithmetic is proven the way it is: a Python model
of the exact intrinsic sequence, **anchored to the captured real output** of the
running backend (`proofs/field_model.py`) and then proven equal to the spec for
all inputs (`prove_multiply.py`, basis-exhaustive). That approach reaches the
real intrinsic behavior precisely where the symbolic tools cannot.

## Status and scope

- crux-mir is a working fourth toolchain; it proves the intrinsic-free logic.
- Verifying the crate's *own* functions in place (rather than the byte-identical
  copies here) needs `cfg(crux)` exclusion of the intrinsic backends — the same
  crate-ingestibility step `proofs/hax/` documents; tracked follow-up.
- Reaching the composition (`seal`/`open`) would use `cryptol_override!` to
  axiomatize AES/GHASH, mirroring `prove_composition.py` over executed MIR — a
  larger project.

## Reproduce

`run.sh` has the full one-time setup (the key subtlety: mir-json must be the
**schema-8** commit `48d0b4b2` to match SAW 1.5.1's `crux-mir-comp`; newer
mir-json emits schema 10/11 and is rejected). Then it builds a tiny crate around
each `.rs` and runs `cargo crux-test`.
