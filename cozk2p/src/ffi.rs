//! C ABI for the chain-side (Go/cgo) PLONK verifier bridge.
//!
//! The chain rebuilds the public statement from on-chain state as the SAME
//! `SettlePublic` JSON both traders agreed on, and passes it here together
//! with the ark-compressed proof and verifying key bytes. Reusing the serde
//! layer (instead of a hand-rolled binary layout) keeps the Go side free of
//! field-element encoding concerns and reuses `SettlePublic::to_vec`'s
//! canonical ordering — the single source of truth for the 15 signals.
//!
//! Build as a staticlib (`cargo build --release --lib`) and link from Go
//! with `-tags cozk2p` (see `chain/core/plonkverify_cgo.go`).

use std::{panic::catch_unwind, slice};

use ark_bn254::Bn254;
use ark_serialize::CanonicalDeserialize;
use mpc_plonk::proof_system::structs::{Proof, VerifyingKey};

use crate::{prove::verify_settle, relation::SettlePublic};

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

#[cfg(test)]
mod tests {
    use ark_serialize::CanonicalSerialize;

    use super::*;
    use crate::{
        prove::prove_single,
        relation::compute_public,
        setup::{default_cache_dir, dev_keys, sample_trade},
    };

    /// Drive the C ABI exactly as the Go bridge does: serialized vk/proof
    /// bytes in, JSON statement in, return code out.
    #[test]
    fn ffi_roundtrip_accepts_and_rejects() {
        let (a, b, price, a_is_seller) = sample_trade();
        let public = compute_public(&a, &b, price, a_is_seller).unwrap();
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
}
