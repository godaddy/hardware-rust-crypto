# Mutation testing

Proofs and tests show the code is *correct*; mutation testing shows the **tests
have teeth** - that they would actually fail if the code were wrong. It answers
the question a reviewer asks of any "we tested it thoroughly" claim: *how do you
know a real bug wouldn't slip past the suite?*

[`cargo-mutants`](https://github.com/sourcefrog/cargo-mutants) rewrites the source
one change at a time (flip a comparison, swap an operator, replace a function
body with a constant) and runs the whole test suite against each mutant. A mutant
that the tests **catch** (some test fails) confirms that line is guarded; a mutant
that **survives** (all tests still pass) is a gap - either untested code, or a
test that exercises the code without checking its result.

## Reproduce

```sh
cargo install --locked cargo-mutants
# The GCM composition control logic and the nonce generator:
cargo mutants --file src/aes_gcm/mod.rs --file src/aes_gcm/nonce.rs \
  --exclude-re 'kani_proofs|tests::|ct_verify' -j 8
```

It is run on demand (each file takes minutes), not in the per-PR CI; the
`heavy-assurance` workflow includes it.

## Results and what they found

The first run over `src/aes_gcm/mod.rs` + `src/aes_gcm/nonce.rs` (the GCM
composition entry points, auth/length/counter logic, and the unique-nonce
generator) was **319 mutants: 239 caught, 61 survived, 19 unviable**. The
survivors fell into clear groups, and the **real test gaps were closed**:

| Survivor group | Real gap? | Action |
| --- | --- | --- |
| The `HardwareAes256GcmIn` explicit-buffer / nonce-appended methods (28) could be replaced with `Ok(vec![])` | **Yes** - the delegations were *called* but their output never verified | New `caller_placed_in_buffer_methods_round_trip`: round-trips every method and byte-cross-validates the explicit-nonce paths against `HardwareAes256Gcm`. |
| `os_salt` → constant, and `&`→`\|` (a constant salt) | **Yes** - would break nonce uniqueness *across* instances | New `distinct_instances_draw_distinct_salts`: two generators must produce different nonces. |
| `HardwareAes256GcmKeyState::encrypt_to` → `Ok(0)` | **Yes** - another unverified delegation | New `owned_key_state_encrypt_to_round_trips`. |
| `validate_gcm_lengths` `\|\|`→`&&` | **Yes** - would accept an input over a single limit | New `gcm_length_validation_rejects_each_over_limit` (uses length *values*, no allocation). |

After these tests, the targeted mutants are caught (re-run confirmed). The
remaining survivors are **accepted, with reason** - not silent gaps:

| Accepted survivor | Why it is not closed |
| --- | --- |
| `Debug` / `Display` `fmt` impls → default | Formatting output is not a correctness or security property; asserting on it has no value. |
| `hardware_available` → `true`, `&&`→`\|\|` | The CI/test host always has AES; distinguishing requires running on non-AES hardware. The fallible path is exercised at construction on real targets. |
| `MAX_GCM_DATA_LEN` constant formula (`*`→`/` etc.) | The actual limit is `2^36` bytes; exercising it needs that much memory. The limit's *use* is now pinned by `gcm_length_validation_rejects_each_over_limit`. |
| `NonceGen` fork-handling (`delete !`, `resalt`→`()`, wrap `==`→`!=`) | Requires an actual `fork()` or `2^64` calls to observe; both are out of reach of a unit test. The arithmetic the fork path protects is Kani-proven. |
| `nonce_value` / `os_salt` `&`→`^` (mask complement) | Security-equivalent: XOR-with-mask is still a bijection, so the nonce stays *unique* in the counter - the actual security property, which `nonce_value_is_injective_in_counter` (Kani) proves for all inputs. Only the nonce *values* change, not their uniqueness. |
| A few capacity `reserve_exact` amounts | Performance hints; the subsequent write succeeds regardless, and the round-trip (incl. an under-capacity `Vec`) is asserted. |

## Scope and honesty

This run covered the **GCM composition and the nonce generator** - the most
security-critical control logic. The same methodology applies to `src/aes_gcm/siv.rs`
(SIV composition) and `src/aes_gcm/ghash.rs`/`aes.rs` (the intrinsic backends,
where many mutants are unviable or equivalent and the differential KATs are the
real guard); extending it there is tracked follow-up. The point is established
where it matters most: the test suite was *measured*, the genuine gaps were
*closed*, and the residual survivors are individually accounted for rather than
ignored.
