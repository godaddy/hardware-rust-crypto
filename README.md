# hardware-rust-crypto

Hardware-only cryptographic primitive workstream for Asherah.

This repository is intentionally design-first. The current code provides:

- `hardware-aes-gcm`: hardware-only AES-256-GCM with compact reusable key state
  and caller-provided storage hooks.
- `hardware-random`: fallible ChaCha20 and hardware-only AES-CTR key/nonce
  generators with OS reseeding, fork detection, and zeroized state.
- Interoperability tests against stock RustCrypto `aes-gcm` and `ring`.
- Criterion benchmark harnesses for AES-GCM and random byte generation.
- CI coverage for Linux x64 and macOS aarch64 runners.

The AES-GCM and AES-CTR candidate state types do not include software AES
fallback state. `ring` remains in the repository as an interop and benchmark
baseline.

## Commands

```sh
cargo test --workspace --all-targets
cargo bench --bench aes_gcm
cargo bench --bench random
```

See [docs/design.md](docs/design.md) for the implementation plan.
See [docs/asherah-integration.md](docs/asherah-integration.md) for the
`asherah-ffi` feature-flag rollout plan.
