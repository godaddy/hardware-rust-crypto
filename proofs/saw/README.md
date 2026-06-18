# SAW proofs (compiled LLVM bitcode vs Cryptol spec)

[SAW](https://github.com/GaloisInc/saw-script) (the Software Analysis Workbench,
Galois) proves that the **LLVM bitcode rustc emits** matches a
[Cryptol](https://cryptol.net) specification. It is a third, independent
verification toolchain alongside the Z3/sympy proofs (which reason about a Python
model) and Kani/CBMC (which checks the compiled Rust at the MIR/goto level): SAW
works on the optimized LLVM, with its own solvers (Z3, Yices, CVC4/5, ABC).

## What is proven

`composition.saw` proves, against the LLVM bitcode of the actual crate:

| Function | Cryptol spec | NIST reference |
| --- | --- | --- |
| `increment_counter` | big-endian `+1` on the trailing 32 bits, leading 96 bits fixed | SP 800-38D `inc_32` |
| `j0` | `IV ‖ 0x00000001` | SP 800-38D J0 (96-bit IV) |

These corroborate, on an independent toolchain, what `prove_composition.py` (Z3
model) and the `cfg(kani)` harnesses (CBMC) already establish - cross-tool
agreement reduces the "trust one prover" risk. The functions are reached through
`extern "C"` wrappers (`saw_*`) emitted only under the build-time `saw-verify`
feature (never shipped).

## Why SAW specifically

SAW is the route to the one thing hax could not reach: the **AES-calling
composition** (`seal`/`open`). At the LLVM level the AES-NI/PCLMULQDQ intrinsics
appear as intrinsic calls that SAW can in principle *axiomatize* (override with an
uninterpreted Cryptol function), so the composition could be proven equal to an
RFC-derived spec *given* a correct cipher - exactly the structure
`prove_composition.py` checks with Z3, but over the compiled code.

### Reaching through the intrinsics: attempted, blocked by a SAW limitation

`field_bilinearity.saw` is the next target: prove the GHASH/POLYVAL field multiply
(`imp::mul`, the real PCLMULQDQ code) is **GF(2)-bilinear and commutative** - the
property the basis-determination proof relies on - via the residual harnesses
`saw_field_mul_{left,right}_linear` / `saw_field_mul_commutes` (built under
`saw-verify`). Each harness computes a residual that is identically zero iff the
property holds; SAW need only prove the output is always zero, *no Cryptol spec
required*.

It is **blocked by SAW 1.5, not by the maths or the setup**: SAW's crucible-llvm
backend aborts with `Attempting to evaluate poison value` on the LLVM `poison`
values rustc emits when lowering the 128-bit SIMD carryless-multiply intrinsics.
This reproduces at every optimization level (`-O0` … `-O3`, with `-Zub-checks=no`
to clear the debug-build precondition checks) and with `enable_experimental`. The
intrinsic-free composition (`composition.saw`) is unaffected and verifies. The
harnesses and `field_bilinearity.saw` are committed as the ready proof target for
a SAW release that handles `poison`, or a `crux-mir` path with carryless-multiply
models (`crux-mir-comp` ships in the SAW bundle but needs the `mir-json`
toolchain, not bundled). Note that bilinearity is *already* proven for all inputs
by `proofs/prove_multiply.py` (basis-exhaustive); SAW here would be independent
corroboration over the compiled intrinsic, not the sole evidence.

## Reproduce

```sh
# Install SAW with bundled solvers (pick your platform asset):
curl -L -o saw.tgz \
  https://github.com/GaloisInc/saw-script/releases/download/v1.5.1/saw-1.5.1-<platform>-with-solvers.tar.gz
tar xzf saw.tgz
export PATH="$PWD/saw-1.5.1-<platform>-with-solvers/bin:$PATH"

./proofs/saw/run.sh        # builds the bitcode and runs composition.saw; exits 0 on success
```
