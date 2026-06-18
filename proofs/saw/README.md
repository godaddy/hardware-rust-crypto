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
appear as intrinsic calls that SAW can *axiomatize* (override with an
uninterpreted Cryptol function), so the composition can be proven equal to an
RFC-derived spec *given* a correct cipher - exactly the structure
`prove_composition.py` checks with Z3, but over the compiled code. Extending the
SAW proofs to `seal`/`open` (with the AES round and GHASH multiply axiomatized)
is the tracked next step.

## Reproduce

```sh
# Install SAW with bundled solvers (pick your platform asset):
curl -L -o saw.tgz \
  https://github.com/GaloisInc/saw-script/releases/download/v1.5.1/saw-1.5.1-<platform>-with-solvers.tar.gz
tar xzf saw.tgz
export PATH="$PWD/saw-1.5.1-<platform>-with-solvers/bin:$PATH"

./proofs/saw/run.sh        # builds the bitcode and runs composition.saw; exits 0 on success
```
