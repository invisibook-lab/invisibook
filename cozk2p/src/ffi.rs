//! C ABI for the chain-side (Go/cgo) PLONK verifier bridge.
//!
//! The chain rebuilds the public statement from on-chain state as the SAME
//! `SettlePublic` JSON both traders agreed on, and passes it here together
//! with the ark-compressed proof and verifying key bytes. Reusing the serde
//! layer (instead of a hand-rolled binary layout) keeps the Go side free of
//! field-element encoding concerns and reuses `SettlePublic::to_vec`'s
//! canonical ordering — the single source of truth for the 5 signals.
//!
//! Build as a staticlib (`cargo build --release --lib`) and link from Go
//! with `-tags cozk2p` (see `chain/core/plonkverify_cgo.go`).

use std::{panic::catch_unwind, slice};

use ark_bn254::Bn254;
use ark_serialize::CanonicalDeserialize;
use mpc_plonk::proof_system::structs::{Proof, VerifyingKey};

use crate::{
    proof_share::{combine_compare_proof_shares, deserialize_compare_proof_share},
    prove::verify_settle,
    relation::SettlePublic,
};

/// Return codes of [`cozk2p_verify_settle`].
pub const VERIFY_OK: i32 = 0;
pub const VERIFY_BAD_INPUT: i32 = 1;
pub const VERIFY_REJECTED: i32 = 2;
pub const VERIFY_PANIC: i32 = 3;

/// Copy `msg` (NUL-terminated, truncated to fit) into the caller's error
/// buffer. `err_ptr`/`err_cap` may be null/0 when the caller wants no message.
fn write_err(err_ptr: *mut u8, err_cap: usize, msg: &str) {
    if err_ptr.is_null() || err_cap == 0 {
        return;
    }
    let out = unsafe { slice::from_raw_parts_mut(err_ptr, err_cap) };
    let n = msg.len().min(err_cap - 1);
    out[..n].copy_from_slice(&msg.as_bytes()[..n]);
    out[n] = 0;
}

/// Verify a 2-party collaborative settlement proof.
///
/// Inputs:
/// - `vk_ptr/vk_len`: ark-compressed `VerifyingKey<Bn254>` bytes (the
///   `settle_cozk2p_vk.bin` artifact).
/// - `public_json_ptr/public_json_len`: UTF-8 `SettlePublic` JSON.
/// - `proof_ptr/proof_len`: ark-compressed `Proof<Bn254>` bytes.
/// - `err_ptr/err_cap`: optional buffer receiving a NUL-terminated error
///   message on any non-zero return.
///
/// Returns `VERIFY_OK` (0) when the proof verifies, `VERIFY_BAD_INPUT` (1)
/// on malformed inputs, `VERIFY_REJECTED` (2) when verification fails, and
/// `VERIFY_PANIC` (3) if the verifier panicked internally.
///
/// # Safety
/// All pointers must reference valid readable (writable for `err_ptr`)
/// memory of the stated lengths for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cozk2p_verify_settle(
    vk_ptr: *const u8,
    vk_len: usize,
    public_json_ptr: *const u8,
    public_json_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    err_ptr: *mut u8,
    err_cap: usize,
) -> i32 {
    if vk_ptr.is_null() || public_json_ptr.is_null() || proof_ptr.is_null() {
        write_err(err_ptr, err_cap, "null input pointer");
        return VERIFY_BAD_INPUT;
    }
    let vk_bytes = unsafe { slice::from_raw_parts(vk_ptr, vk_len) };
    let public_bytes = unsafe { slice::from_raw_parts(public_json_ptr, public_json_len) };
    let proof_bytes = unsafe { slice::from_raw_parts(proof_ptr, proof_len) };

    // Never unwind across the FFI boundary — Go's linker aborts the process.
    let result = catch_unwind(|| {
        let vk = match VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes) {
            Ok(vk) => vk,
            Err(e) => return (VERIFY_BAD_INPUT, format!("parsing verifying key: {e}")),
        };
        let public: SettlePublic = match serde_json::from_slice(public_bytes) {
            Ok(p) => p,
            Err(e) => return (VERIFY_BAD_INPUT, format!("parsing public statement: {e}")),
        };
        let proof = match Proof::<Bn254>::deserialize_compressed(proof_bytes) {
            Ok(p) => p,
            Err(e) => return (VERIFY_BAD_INPUT, format!("parsing proof: {e}")),
        };
        match verify_settle(&vk, &public, &proof) {
            Ok(()) => (VERIFY_OK, String::new()),
            Err(e) => (VERIFY_REJECTED, e.to_string()),
        }
    });
    match result {
        Ok((code, msg)) => {
            if code != VERIFY_OK {
                write_err(err_ptr, err_cap, &msg);
            }
            code
        }
        Err(_) => {
            write_err(err_ptr, err_cap, "verifier panicked");
            VERIFY_PANIC
        }
    }
}

/// Reconstruct and verify a standard collaborative proof from the two owners'
/// canonical native proof-share payloads.
///
/// The first share must identify PARTY0/order A and the second PARTY1/order B.
/// Their already-open Fiat--Shamir components must match exactly; only the two
/// final KZG G1 values are combined, using curve-group addition.
///
/// # Safety
/// All pointers must reference valid readable (writable for `err_ptr`) memory
/// of the stated lengths for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cozk2p_verify_settle_shares(
    vk_ptr: *const u8,
    vk_len: usize,
    public_json_ptr: *const u8,
    public_json_len: usize,
    share_a_ptr: *const u8,
    share_a_len: usize,
    share_b_ptr: *const u8,
    share_b_len: usize,
    err_ptr: *mut u8,
    err_cap: usize,
) -> i32 {
    if vk_ptr.is_null()
        || public_json_ptr.is_null()
        || share_a_ptr.is_null()
        || share_b_ptr.is_null()
    {
        write_err(err_ptr, err_cap, "null input pointer");
        return VERIFY_BAD_INPUT;
    }
    let vk_bytes = unsafe { slice::from_raw_parts(vk_ptr, vk_len) };
    let public_bytes = unsafe { slice::from_raw_parts(public_json_ptr, public_json_len) };
    let share_a_bytes = unsafe { slice::from_raw_parts(share_a_ptr, share_a_len) };
    let share_b_bytes = unsafe { slice::from_raw_parts(share_b_ptr, share_b_len) };

    let result = catch_unwind(|| {
        let vk = match VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes) {
            Ok(vk) => vk,
            Err(e) => return (VERIFY_BAD_INPUT, format!("parsing verifying key: {e}")),
        };
        let public: SettlePublic = match serde_json::from_slice(public_bytes) {
            Ok(p) => p,
            Err(e) => return (VERIFY_BAD_INPUT, format!("parsing public statement: {e}")),
        };
        let share_a = match deserialize_compare_proof_share(share_a_bytes) {
            Ok(share) => share,
            Err(e) => return (VERIFY_BAD_INPUT, format!("parsing PARTY0 proof share: {e}")),
        };
        let share_b = match deserialize_compare_proof_share(share_b_bytes) {
            Ok(share) => share,
            Err(e) => return (VERIFY_BAD_INPUT, format!("parsing PARTY1 proof share: {e}")),
        };
        let proof = match combine_compare_proof_shares(&share_a, &share_b) {
            Ok(proof) => proof,
            Err(e) => return (VERIFY_BAD_INPUT, format!("combining proof shares: {e}")),
        };
        match verify_settle(&vk, &public, &proof) {
            Ok(()) => (VERIFY_OK, String::new()),
            Err(e) => (VERIFY_REJECTED, e.to_string()),
        }
    });
    match result {
        Ok((code, msg)) => {
            if code != VERIFY_OK {
                write_err(err_ptr, err_cap, &msg);
            }
            code
        }
        Err(_) => {
            write_err(err_ptr, err_cap, "verifier panicked");
            VERIFY_PANIC
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Affine};
    use ark_serialize::CanonicalSerialize;

    use super::*;
    use crate::{
        proof_share::{CompareProofShare, serialize_compare_proof_share},
        prove::prove_single,
        relation::compute_public,
        setup::{default_cache_dir, dev_keys, sample_trade},
    };

    /// Drive the C ABI exactly as the Go bridge does: serialized vk/proof
    /// bytes in, JSON statement in, return code out.
    #[test]
    fn ffi_roundtrip_accepts_and_rejects() {
        let (a, b, price_a, price_b, a_is_seller) = sample_trade();
        let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();
        let (pk, vk) = dev_keys(&default_cache_dir()).unwrap();
        let proof = prove_single(&a, &b, &public, &pk).unwrap();

        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let public_json = serde_json::to_vec(&public).unwrap();

        let mut err = [0u8; 256];
        let call = |public_json: &[u8], proof_bytes: &[u8], err: &mut [u8]| unsafe {
            cozk2p_verify_settle(
                vk_bytes.as_ptr(),
                vk_bytes.len(),
                public_json.as_ptr(),
                public_json.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };

        assert_eq!(call(&public_json, &proof_bytes, &mut err), VERIFY_OK);

        // Tampered public statement (flip cmp) must be rejected.
        let mut tampered = public.clone();
        tampered.cmp = -tampered.cmp;
        let tampered_json = serde_json::to_vec(&tampered).unwrap();
        assert_eq!(
            call(&tampered_json, &proof_bytes, &mut err),
            VERIFY_REJECTED
        );

        // Truncated proof bytes are a parse error, not a crash.
        assert_eq!(
            call(
                &public_json,
                &proof_bytes[..proof_bytes.len() / 2],
                &mut err
            ),
            VERIFY_BAD_INPUT
        );
    }

    #[test]
    fn ffi_native_shares_reconstruct_accept_and_reject() {
        let (a, b, price_a, price_b, a_is_seller) = sample_trade();
        let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();
        let (pk, vk) = dev_keys(&default_cache_dir()).unwrap();
        let proof = prove_single(&a, &b, &public, &pk).unwrap();

        // A zero/full split exercises the exact group reconstruction logic
        // without requiring an MPC network inside this synchronous FFI test.
        let mut proof_a = proof.clone();
        proof_a.opening_proof.0 = G1Affine::default();
        proof_a.shifted_opening_proof.0 = G1Affine::default();
        let share_a = CompareProofShare::new(0, proof_a).unwrap();
        let share_b = CompareProofShare::new(1, proof.clone()).unwrap();
        let share_a_bytes = serialize_compare_proof_share(&share_a).unwrap();
        let share_b_bytes = serialize_compare_proof_share(&share_b).unwrap();

        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        let public_json = serde_json::to_vec(&public).unwrap();
        let mut err = [0u8; 256];
        let call = |public_json: &[u8], a: &[u8], b: &[u8], err: &mut [u8]| unsafe {
            cozk2p_verify_settle_shares(
                vk_bytes.as_ptr(),
                vk_bytes.len(),
                public_json.as_ptr(),
                public_json.len(),
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };

        assert_eq!(
            call(&public_json, &share_a_bytes, &share_b_bytes, &mut err),
            VERIFY_OK
        );

        let mut tampered_public = public.clone();
        tampered_public.cmp = -tampered_public.cmp;
        let tampered_public_json = serde_json::to_vec(&tampered_public).unwrap();
        assert_eq!(
            call(
                &tampered_public_json,
                &share_a_bytes,
                &share_b_bytes,
                &mut err
            ),
            VERIFY_REJECTED
        );

        assert_eq!(
            call(
                &public_json,
                &share_a_bytes,
                &share_b_bytes[..share_b_bytes.len() / 2],
                &mut err
            ),
            VERIFY_BAD_INPUT
        );
        assert_eq!(
            call(&public_json, &share_b_bytes, &share_a_bytes, &mut err),
            VERIFY_BAD_INPUT,
            "party ordering is part of the canonical share wire"
        );

        let mut mismatched_common = share_b.clone();
        mismatched_common.proof.poly_evals.wires_evals[0] += Fr::from(1u64);
        let mismatched_common_bytes = serialize_compare_proof_share(&mismatched_common).unwrap();
        assert_eq!(
            call(
                &public_json,
                &share_a_bytes,
                &mismatched_common_bytes,
                &mut err
            ),
            VERIFY_BAD_INPUT,
            "the already-open proof components must match exactly"
        );

        // Structurally valid shares whose final group sum is not a proof are
        // parsed successfully and rejected by PLONK verification.
        let mut bad_b = share_b.clone();
        bad_b.proof.opening_proof.0 = G1Affine::default();
        let bad_b_bytes = serialize_compare_proof_share(&bad_b).unwrap();
        assert_eq!(
            call(&public_json, &share_a_bytes, &bad_b_bytes, &mut err),
            VERIFY_REJECTED
        );
    }
}
