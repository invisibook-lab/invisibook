//! Native (plaintext) circom-compatible Poseidon over BN254 Fr.
//!
//! Mirrors `light_poseidon::Poseidon::new_circom(2)` exactly (state width
//! t=3, domain tag 0, 8 full + 57 partial rounds, x^5 S-box), which is the
//! commitment hash used across the chain (collateral and note commitments).
//! Golden vector: `hash2(0, 0)` — see the unit test below.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};

use crate::constants::{FULL_ROUNDS, PARTIAL_ROUNDS, T, ark, mds};

/// Poseidon permutation on a `[Fr; 3]` state, returning the full final state.
/// Matches the circom `poseidon.circom` template used by the Groth16 circuits.
fn permute(mut state: [Fr; T]) -> [Fr; T] {
    let ark = ark();
    let mds = mds();
    let half = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;

    for r in 0..total {
        // AddRoundConstants
        for (i, s) in state.iter_mut().enumerate() {
            *s += ark[r * T + i];
        }
        // S-box: all lanes in full rounds, lane 0 only in partial rounds
        let full = r < half || r >= half + PARTIAL_ROUNDS;
        let lanes = if full { T } else { 1 };
        for s in state.iter_mut().take(lanes) {
            let s2 = s.square();
            let s4 = s2.square();
            *s = s4 * *s;
        }
        // MDS mix
        let mut next = [Fr::from(0u64); T];
        for (i, row) in mds.iter().enumerate() {
            for (j, m) in row.iter().enumerate() {
                next[i] += *m * state[j];
            }
        }
        state = next;
    }
    state
}

/// Poseidon hash of two field elements with circom domain tag 0:
/// `hash2(a, b) = permute([0, a, b])[0]`.
pub fn hash2(a: Fr, b: Fr) -> Fr {
    permute([Fr::from(0u64), a, b])[0]
}

/// Commitment to a hidden `amount` under 32-byte blinding `random`,
/// identical to `lib/zk`'s `poseidon_commit`: the random bytes are reduced
/// big-endian into Fr.
pub fn commit(amount: u64, random: &[u8; 32]) -> Fr {
    hash2(Fr::from(amount), Fr::from_be_bytes_mod_order(random))
}

/// Render an Fr as the 64-char lowercase big-endian hex string the chain
/// stores (`Cash.Amount` format). Mirrors `lib/zk`'s `fr_to_hex`.
pub fn fr_to_hex(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    let mut s = hex::encode(bytes);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector of the circom parameterization: `Poseidon(2)([0, 0])`.
    /// Proves this implementation matches light-poseidon/circom exactly.
    #[test]
    fn zero_commitment_matches_chain_constant() {
        let zero = hash2(Fr::from(0u64), Fr::from(0u64));
        assert_eq!(
            fr_to_hex(&zero),
            "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"
        );
    }
}

// ────────────────────── Shielded-pool note helpers ──────────────────────

/// Domain tag of the note commitment chain (spec/golden.json).
pub const TAG_CM: u64 = 3;

/// assetID of a token symbol: its UTF-8 bytes read big-endian into Fr.
/// The chain validates symbols are 1..=31 bytes; mirror that here.
pub fn asset_fr(token: &str) -> anyhow::Result<Fr> {
    use ark_ff::PrimeField;
    let bytes = token.as_bytes();
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= 31,
        "token symbol must be 1..=31 bytes, got {}",
        bytes.len()
    );
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

/// The pool's note commitment as the tagged nested 2-input chain
/// `P2(P2(P2(P2(TAG_CM, npk), asset), v), r)` — byte-identical to
/// `lib/chain/src/note.rs::note_commit` and `note.circom`'s NoteCommit.
pub fn note_commit(npk: Fr, asset: Fr, v: u64, r: &[u8; 32]) -> Fr {
    use ark_ff::PrimeField;
    let c = hash2(Fr::from(TAG_CM), npk);
    let c = hash2(c, asset);
    let c = hash2(c, Fr::from(v));
    hash2(c, Fr::from_be_bytes_mod_order(r))
}
