# Asherah Integration Plan

## Goal

Add `hardware-rust-crypto` to `asherah-ffi` behind a feature flag so we can
benchmark and validate it against the current `ring` implementation before
making any default change.

## Feature Flags

Proposed Asherah features:

- `crypto-ring`
  - Current default.
  - Uses `ring::aead::LessSafeKey`.
- `crypto-hardware-rust`
  - Uses `hardware-aes-gcm`.
  - Requires hardware AES support.
  - Enables key-state storage placement hooks.

The two backend features should be mutually exclusive at compile time:

```rust
#[cfg(all(feature = "crypto-ring", feature = "crypto-hardware-rust"))]
compile_error!("choose exactly one crypto backend");
```

Initial rollout:

- Keep `crypto-ring` as default.
- Add CI/test leg for `--no-default-features --features crypto-hardware-rust`
  once the candidate backend is wired into `asherah-ffi`.
- Add benchmark jobs/manual commands for both features.

## Asherah Code Shape

Introduce an internal backend abstraction for only the operations Asherah needs:

```rust
trait Aes256GcmBackend {
    type KeyState;

    fn expand_key(raw_key: &[u8], placement: KeyStatePlacement<'_>) -> Result<Self::KeyState>;
    fn encrypt_with_key_state(
        key: &Self::KeyState,
        plaintext: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>>;
    fn decrypt_with_key_state(
        key: &Self::KeyState,
        ciphertext_tag: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>>;
}
```

`CryptoKey` should stop naming `LessSafeKey` directly. It should cache a backend
key-state enum/type alias selected by feature.

## Storage Placement

Asherah needs to control:

- Raw 32-byte key storage.
- Expanded key-equivalent state.
- DRK key state.
- IK/SK key state.
- Wipe behavior on drop.
- Whether specific key states live in the guarded slab or normal locked memory.

The hardware backend should support caller-owned placement without exposing the
initialized key-state bytes:

```rust
let layout = HardwareAes256Gcm::key_state_layout();
let slot = slab.reserve(layout)?;
let key_state = HardwareAes256Gcm::new_in(raw_key, slot)?;
```

Rules:

- The backend reports exact size and alignment before accepting key material.
- Caller provides storage with the required size and alignment.
- Backend initializes the key state in caller storage.
- Backend returns only an opaque key-state handle.
- Backend zeroizes key-equivalent state before release.
- Backend never copies key-equivalent state into hidden heap allocation.
- Backend also has an owned convenience type for non-Asherah callers, and that
  owned state zeroizes on drop.
- Backend does not expose `AsRef<[u8]>`, clone, copy, or debug output for
  initialized key state.

The primitive crate now exposes owned and caller-placed key-state APIs. The
Asherah integration still needs to route DRK/IK/SK placement policy into those
hooks.

## Benchmark Commands

Primitive repo:

```sh
cargo bench --bench aes_gcm
cargo bench --bench random
```

Asherah before/after:

```sh
cargo test -p asherah --no-default-features --features crypto-ring
cargo test -p asherah --no-default-features --features crypto-hardware-rust
scripts/benchmark.sh --rust-only --memory
```

Run the benchmark script at least twice per backend on Apple Silicon in High
Performance mode and on target Linux hardware where possible.

## Merge Gate

Do not flip Asherah's default backend until:

- Interop tests prove AES-256-GCM byte compatibility with `ring` and RustCrypto.
- Asherah unit/lint/interop suites pass with the hardware backend.
- `scripts/benchmark.sh --rust-only --memory` shows no unacceptable regression.
- Key-state size and alignment are measured.
- Key-state placement into the guarded slab is tested.
- Drop/release zeroization is tested.
- Primitive CI passes on Linux x64 and macOS aarch64.
