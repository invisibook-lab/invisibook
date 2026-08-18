//! Wallet-facing helpers: the shared Poseidon commitment/2-input hash and
//! the settle_cozk single-prover fixture wrapper.
//!
//! Callers (`lib/chain`, app) should use these instead of building circom
//! JSON inputs by hand — keeps Poseidon parameters, BN254 byte order, and
//! padding conventions in one place. The note-model circuit provers live in
//! `invisibook-lib::note_prover`.

use std::path::Path;

use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde_json::{Value, json};

use crate::{
    circom_bridge::fr_to_decimal_string, prover::run_rapidsnark, test_circuit::TestCircuitHandle,
};

/// Compute `Poseidon(2)([amount, r])` — the canonical commitment shape used by
/// every wallet circuit. `random` is interpreted as a 32-byte big-endian field
/// element and reduced mod the BN254 scalar field if it overflows.
///
/// This must stay byte-identical to circom's `Poseidon(2)([amount, r])` and to
/// `lib/chain/src/orderbook.rs::encrypt_with_random`, otherwise commitments on
/// the wallet, on the chain, and inside circuits would not align.
pub fn poseidon_commit(amount: u64, random: &[u8; 32]) -> Fr {
    let amount_fr = Fr::from(amount);
    let random_fr = Fr::from_be_bytes_mod_order(random);
    poseidon2(amount_fr, random_fr)
}

/// The bare 2-input circomlib Poseidon over BN254 — the `P2(a, b)` every
/// shielded-pool derivation (note commitments, Merkle nodes, nullifiers) is
/// built from. Must stay byte-identical to circom's `Poseidon(2)` and to the
/// chain's go-iden3 Poseidon.
pub fn poseidon2(a: Fr, b: Fr) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("circom(2) Poseidon params must build");
    hasher
        .hash(&[a, b])
        .expect("Poseidon hash must not fail on two field elements")
}

/// Render a BN254 Fr as the lowercase 64-char big-endian hex string the chain
/// stores in `Cash.Amount` (and as `bridge_commitment` in deposit). Pads with
/// leading zeros so the length is always 64.
pub fn fr_to_hex(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    // bytes is at most 32 bytes for BN254; pad-left to 64 hex chars
    let mut out = String::with_capacity(64);
    for _ in 0..(32 - bytes.len()) {
        out.push_str("00");
    }
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_commit_matches_circom_circuit() {
        // Reuse the same (amount, r) pair as the circom-side tests would and
        // confirm we land on the same field element.
        let r = [0x42u8; 32];
        let h = poseidon_commit(100, &r);
        // Stable invariant: hashing the same inputs twice must give the same Fr.
        let h2 = poseidon_commit(100, &r);
        assert_eq!(h, h2);
        // And different amount under same r yields different commitment.
        let h3 = poseidon_commit(101, &r);
        assert_ne!(h, h3);
    }

    #[test]
    fn fr_to_hex_pads_to_64_chars() {
        let zero = Fr::from(0u64);
        assert_eq!(fr_to_hex(&zero).len(), 64);
        assert!(fr_to_hex(&zero).chars().all(|c| c == '0'));
    }
}

// ────────────────────── Settle comparison (co-zk π_cmp) ──────────────────────

/// The collateral a side must have locked under the locked-only model:
/// q for a seller, q·price for a buyer — the settle circuits' shared
/// side-dependent equation `needed(q, s) = q·price + s·(q − q·price)`.
pub fn needed_collateral(q: u64, price: u64, is_seller: bool) -> u64 {
    if is_seller { q } else { q * price }
}

/// Witness for `settle_cozk.circom` — the single-prover twin of the
/// collaborative comparison (locked-only model): both hidden quantities,
/// both collateral blindings, plus the public price and A's side. A and B
/// are on opposite sides.
/// (Used by tests and fixtures; production runs the cozk2p MPC prover.)
pub struct SettleCmpWitness {
    pub a: u64,
    pub r_a: [u8; 32],
    pub b: u64,
    pub r_b: [u8; 32],
    pub price_a: u64,
    pub price_b: u64,
    pub a_is_seller: bool,
}

impl SettleCmpWitness {
    /// The comparison result this witness yields.
    pub fn cmp(&self) -> i8 {
        match self.a.cmp(&self.b) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// A's collateral commitment `P2(needed(a, s_a), r_a)`.
    pub fn locked_a(&self) -> Fr {
        poseidon_commit(
            needed_collateral(self.a, self.price_a, self.a_is_seller),
            &self.r_a,
        )
    }

    /// B's collateral commitment — B is on the OPPOSITE side.
    pub fn locked_b(&self) -> Fr {
        poseidon_commit(
            needed_collateral(self.b, self.price_b, !self.a_is_seller),
            &self.r_b,
        )
    }
}

/// Output of [`prove_settle_cmp`]. `public_json` is
/// `[cmp, locked_a, locked_b, price_a, price_b, a_is_seller]` in decimal.
pub struct SettleCmpProof {
    pub cmp: i8,
    pub locked_a_hex: String,
    pub locked_b_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `settle_cozk` (comparison-only) witness, run rapidsnark, and
/// return the proof.
pub fn prove_settle_cmp(
    w: &SettleCmpWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SettleCmpProof> {
    let locked_a = w.locked_a();
    let locked_b = w.locked_b();
    let cmp = w.cmp();
    let input = json!({
        "cmp": fr_to_decimal_string(&settle_cmp_fr(cmp)),
        "locked_a": fr_to_decimal_string(&locked_a),
        "locked_b": fr_to_decimal_string(&locked_b),
        "price_a": w.price_a.to_string(),
        "price_b": w.price_b.to_string(),
        "a_is_seller": if w.a_is_seller { "1" } else { "0" },
        "q_a": w.a.to_string(),
        "r_a": fr_to_decimal_string(&Fr::from_be_bytes_mod_order(&w.r_a)),
        "q_b": w.b.to_string(),
        "r_b": fr_to_decimal_string(&Fr::from_be_bytes_mod_order(&w.r_b)),
    });
    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;
    Ok(SettleCmpProof {
        cmp,
        locked_a_hex: fr_to_hex(&locked_a),
        locked_b_hex: fr_to_hex(&locked_b),
        proof_json,
        public_json,
    })
}

/// Encode a three-way comparison as the field element the circuits carry
/// (-1 becomes p-1). `cmp` must be -1, 0, or 1.
pub fn settle_cmp_fr(cmp: i8) -> Fr {
    match cmp {
        -1 => -Fr::from(1u64),
        0 => Fr::from(0u64),
        1 => Fr::from(1u64),
        _ => panic!("cmp must be -1, 0, or 1"),
    }
}

/// Decode a 64-char lowercase hex string into a BN254 Fr.
pub fn hex_to_fr(s: &str) -> Result<Fr> {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}
