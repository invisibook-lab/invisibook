//! C ABI for proving R3.2's balance statement from Go.
//!
//! Field elements cross the boundary as 32-byte blocks of eight little-endian
//! u32 words — the bytes a budget cell stores and `consensus.PaymentCommit`
//! renders as hex — so the Go side never handles field arithmetic.

use std::{panic::catch_unwind, slice};

use budget_stark::{
    hash::{Random, digest_to_bytes},
    prove,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;

/// Success.
pub const BUDGET_OK: i32 = 0;
/// Malformed input: null pointers, a non-canonical blinding word.
pub const BUDGET_BAD_INPUT: i32 = 1;
/// No proof could be made (empty or oversized table, overflowing total, ...).
pub const BUDGET_FAILED: i32 = 2;
/// The Rust side panicked.
pub const BUDGET_PANIC: i32 = 3;
/// `proof_cap` is too small; `*proof_len` holds the size needed.
pub const BUDGET_BUFFER_TOO_SMALL: i32 = 4;

/// Copies `msg` (NUL-terminated, truncated to fit) into the caller's error
/// buffer. `err`/`err_cap` may be null/0 when no message is wanted.
fn write_err(err: *mut u8, err_cap: usize, msg: &str) {
    if err.is_null() || err_cap == 0 {
        return;
    }
    let out = unsafe { slice::from_raw_parts_mut(err, err_cap) };
    let n = msg.len().min(err_cap - 1);
    out[..n].copy_from_slice(&msg.as_bytes()[..n]);
    out[n] = 0;
}

/// Decodes one 32-byte blinding factor, or `None` if a word is not below the
/// field order. Refused rather than reduced, as the Go side does.
fn decode_random(bytes: &[u8]) -> Option<Random> {
    let mut out = [KoalaBear::ZERO; 8];
    for (slot, word) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        let raw = u32::from_le_bytes(word.try_into().ok()?);
        if raw >= KoalaBear::ORDER_U32 {
            return None;
        }
        *slot = KoalaBear::from_u32(raw);
    }
    Some(out)
}

/// Proves that an allocation table of `n` entries adds up to its total.
///
/// - `amounts`: `n` amounts in shannon, in table order.
/// - `randoms`: `n` blinding factors, 32 bytes each.
/// - `commitments_out`: receives `n` commitments, 32 bytes each — what the
///   budget cell stores.
/// - `proof_out`/`proof_cap`: buffer for the proof; `*proof_len` receives its
///   length (or the length needed, with BUDGET_BUFFER_TOO_SMALL).
/// - `prepaid_out`: receives `Σ amounts`, the total the proof is for.
/// - `err`/`err_cap`: optional buffer for a NUL-terminated message.
///
/// # Safety
/// Every non-null pointer must reference valid memory of the stated size for
/// the duration of the call; `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn budget_stark_prove(
    amounts: *const u64,
    randoms: *const u8,
    n: usize,
    commitments_out: *mut u8,
    proof_out: *mut u8,
    proof_cap: usize,
    proof_len: *mut usize,
    prepaid_out: *mut u64,
    err: *mut u8,
    err_cap: usize,
) -> i32 {
    if amounts.is_null()
        || randoms.is_null()
        || commitments_out.is_null()
        || proof_out.is_null()
        || proof_len.is_null()
        || prepaid_out.is_null()
    {
        write_err(err, err_cap, "null input pointer");
        return BUDGET_BAD_INPUT;
    }
    let amounts = unsafe { slice::from_raw_parts(amounts, n) };
    let random_bytes = unsafe { slice::from_raw_parts(randoms, 32 * n) };
    let mut parsed = Vec::with_capacity(n);
    for (i, chunk) in random_bytes.chunks_exact(32).enumerate() {
        match decode_random(chunk) {
            Some(r) => parsed.push(r),
            None => {
                write_err(
                    err,
                    err_cap,
                    &format!("random {i} has a word not below the field order"),
                );
                return BUDGET_BAD_INPUT;
            }
        }
    }

    // Never unwind across the FFI boundary: Go's runtime aborts the process.
    let (prepaid, commitments, proof) = match catch_unwind(|| prove(amounts, &parsed)) {
        Ok(Ok(done)) => done,
        Ok(Err(e)) => {
            write_err(err, err_cap, &format!("{e:?}"));
            return BUDGET_FAILED;
        }
        Err(_) => {
            write_err(err, err_cap, "prover panicked");
            return BUDGET_PANIC;
        }
    };

    unsafe { *proof_len = proof.len() };
    if proof.len() > proof_cap {
        write_err(err, err_cap, "proof buffer too small");
        return BUDGET_BUFFER_TOO_SMALL;
    }
    let commitments_dst = unsafe { slice::from_raw_parts_mut(commitments_out, 32 * n) };
    for (dst, c) in commitments_dst.chunks_exact_mut(32).zip(&commitments) {
        dst.copy_from_slice(&digest_to_bytes(c));
    }
    unsafe {
        slice::from_raw_parts_mut(proof_out, proof.len()).copy_from_slice(&proof);
        *prepaid_out = prepaid;
    }
    BUDGET_OK
}
