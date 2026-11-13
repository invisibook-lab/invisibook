//! How a proof is laid out across a transaction's witnesses.
//!
//! A proof (~110 KB) cannot sit in one witness. The standard
//! secp256k1_blake160_sighash_all lock reads every witness it signs over into
//! a 32 KB buffer and refuses the transaction (error -22) if one is larger —
//! and it signs over all witnesses past the inputs, and every witness of its
//! own input group. So the proof is cut into chunks, one per witness, in
//! `WitnessArgs.output_type`, starting at the budget cell's own output index
//! and running on through consecutive witnesses:
//!
//! ```text
//!   witness[i]      output_type = total length (u32 LE) ‖ first bytes
//!   witness[i + 1]  output_type = next CHUNK_PAYLOAD bytes
//!   ...
//! ```
//!
//! `chain/ckb/budget.go` writes this layout; the budget script reads it.

use alloc::vec::Vec;

/// Largest witness the sighash lock accepts.
pub const MAX_WITNESS_SIZE: usize = 32 * 1024;
/// Proof bytes per witness: MAX_WITNESS_SIZE less a WitnessArgs envelope
/// (16-byte table header, 4-byte length of `output_type`) with room to spare.
pub const CHUNK_PAYLOAD: usize = MAX_WITNESS_SIZE - 64;
/// The total length heading the first chunk.
const LEN_PREFIX: usize = 4;
/// Largest proof accepted; a table at MAX_ENTRIES proves in ~150 KB. Bounds
/// what a script allocates on a length it has not yet checked.
pub const MAX_PROOF_LEN: usize = 512 * 1024;

/// Cuts `proof` into witness chunks. `proof` must be at most MAX_PROOF_LEN.
pub fn split(proof: &[u8]) -> Vec<Vec<u8>> {
    let mut prefixed = Vec::with_capacity(LEN_PREFIX + proof.len());
    prefixed.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    prefixed.extend_from_slice(proof);
    prefixed.chunks(CHUNK_PAYLOAD).map(|c| c.to_vec()).collect()
}

/// Reassembles a proof from chunks drawn in order by `next`, which is called
/// with 0, 1, 2, ... and returns that chunk's bytes, or `None` if it is
/// missing. Returns `None` for any layout this module would not produce.
pub fn join(mut next: impl FnMut(usize) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
    let first = next(0)?;
    let len_bytes: [u8; LEN_PREFIX] = first.get(..LEN_PREFIX)?.try_into().ok()?;
    let total = u32::from_le_bytes(len_bytes) as usize;
    if total > MAX_PROOF_LEN {
        return None;
    }
    let mut proof = Vec::with_capacity(total);
    proof.extend_from_slice(&first[LEN_PREFIX..]);
    let mut index = 1;
    while proof.len() < total {
        proof.extend_from_slice(&next(index)?);
        index += 1;
    }
    (proof.len() == total).then_some(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_fits_the_lock() {
        for len in [0, 1, CHUNK_PAYLOAD - LEN_PREFIX, CHUNK_PAYLOAD, 110_000, 150_000] {
            let proof: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let chunks = split(&proof);
            assert!(chunks.iter().all(|c| c.len() <= CHUNK_PAYLOAD));
            let joined = join(|i| chunks.get(i).cloned());
            assert_eq!(joined.as_deref(), Some(proof.as_slice()), "len {len}");
        }
    }

    #[test]
    fn refuses_truncated_or_padded_layouts() {
        let chunks = split(&[7u8; 100_000]);
        // A chunk missing.
        assert!(join(|i| if i < 2 { chunks.get(i).cloned() } else { None }).is_none());
        // One chunk too long: the total no longer matches.
        let mut long = chunks.clone();
        long.last_mut().unwrap().push(0);
        assert!(join(|i| long.get(i).cloned()).is_none());
        // A length past the cap.
        let huge = ((MAX_PROOF_LEN + 1) as u32).to_le_bytes().to_vec();
        assert!(join(|i| (i == 0).then(|| huge.clone())).is_none());
    }
}
