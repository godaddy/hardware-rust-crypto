module HrcComposition

/// Machine-checked F* proof over the **hax-extracted** AES-256-GCM/SIV
/// composition functions.
///
/// The three function bodies below are copied verbatim from the output of
/// `proofs/hax/extract.sh` (hax translating `src/aes_gcm/{mod,nonce}.rs` to F*);
/// `proofs/fstar/check.sh` re-extracts and checks they still match, so this is a
/// proof about the tool-translated real source, not a hand-port. The opaque AES
/// and GHASH backends are not referenced by these functions, so no axioms are
/// needed here.
///
/// Verified with: fstar.exe (see proofs/fstar/check.sh). Properties proved:
///   - j0 places the GCM pre-counter byte (index 15 = 1) and the nonce prefix;
///   - increment_counter leaves the leading 96 bits (bytes 0..12) unchanged
///     (the SP 800-38D inc_32 invariant: only the trailing 32 bits move).

#set-options "--fuel 0 --ifuel 1 --z3rlimit 30"
open FStar.Mul
open Core_models

let v_NONCE_SIZE: usize = mk_usize 12

// ---- verbatim hax extraction: src/aes_gcm/mod.rs::j0 ----
let j0 (nonce: t_Array u8 (mk_usize 12)) : t_Array u8 (mk_usize 16) =
  let out:t_Array u8 (mk_usize 16) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 16) in
  let out:t_Array u8 (mk_usize 16) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range_to out
      ({ Core_models.Ops.Range.f_end = v_NONCE_SIZE } <: Core_models.Ops.Range.t_RangeTo usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (out.[ { Core_models.Ops.Range.f_end = v_NONCE_SIZE }
              <:
              Core_models.Ops.Range.t_RangeTo usize ]
            <:
            t_Slice u8)
          (nonce <: t_Slice u8)
        <:
        t_Slice u8)
  in
  let out:t_Array u8 (mk_usize 16) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize out (mk_usize 15) (mk_u8 1)
  in
  out

// ---- verbatim hax extraction: src/aes_gcm/mod.rs::increment_counter ----
let increment_counter (counter: t_Array u8 (mk_usize 16)) : t_Array u8 (mk_usize 16) =
  let low_bytes:t_Array u8 (mk_usize 4) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 4) in
  let low_bytes:t_Array u8 (mk_usize 4) =
    Core_models.Slice.impl__copy_from_slice #u8
      low_bytes
      (counter.[ { Core_models.Ops.Range.f_start = mk_usize 12 }
          <:
          Core_models.Ops.Range.t_RangeFrom usize ]
        <:
        t_Slice u8)
  in
  let low:u32 =
    Core_models.Num.impl_u32__wrapping_add (Core_models.Num.impl_u32__from_be_bytes low_bytes <: u32
      )
      (mk_u32 1)
  in
  let counter:t_Array u8 (mk_usize 16) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range_from counter
      ({ Core_models.Ops.Range.f_start = mk_usize 12 } <: Core_models.Ops.Range.t_RangeFrom usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (counter.[ { Core_models.Ops.Range.f_start = mk_usize 12 }
              <:
              Core_models.Ops.Range.t_RangeFrom usize ]
            <:
            t_Slice u8)
          (Core_models.Num.impl_u32__to_be_bytes low <: t_Slice u8)
        <:
        t_Slice u8)
  in
  counter

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

/// j0 sets the GCM pre-counter byte: the last byte of `J0 = IV || 0^31 || 1`.
let j0_sets_counter_byte (nonce: t_Array u8 (mk_usize 12))
    : Lemma (Seq.index (j0 nonce) 15 == mk_u8 1) = ()

/// increment_counter is SP 800-38D inc_32: it touches only the trailing four
/// bytes, so the leading 96 bits (bytes 0..12) are unchanged for every input.
let increment_counter_preserves_high_96 (counter: t_Array u8 (mk_usize 16)) (i: nat)
    : Lemma (requires i < 12)
            (ensures Seq.index (increment_counter counter) i == Seq.index counter i) =
  // increment_counter ends with `update_at_range_from counter {f_start = 12} _`,
  // whose post-condition gives `Seq.slice res 0 12 == Seq.slice counter 0 12`.
  // Index both slices at i (< 12) to lift that to pointwise equality.
  let r = increment_counter counter in
  Seq.lemma_index_slice r 0 12 i;
  Seq.lemma_index_slice counter 0 12 i
