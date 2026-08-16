//! The 2-party comparison relation — the paper's π_cmp (§VI-A), expressed
//! as a jellyfish PLONK circuit. Same 3-public statement as the
//! single-prover `settle_cozk.circom`:
//!
//! ```text
//!  0 cmp       sign(a - b) in {-1, 0, 1} (as Fr: p-1, 0, 1)
//!  1 order_a   on-chain order A amount commitment Poseidon(a, r_a)
//!  2 order_b   on-chain order B amount commitment Poseidon(b, r_b)
//! ```
//!
//! Everything after the comparison — payouts, residual re-commitments — is
//! single-party work (`settle_small.circom` / `settle_large.circom`): once
//! cmp is public and the smaller side reveals its opening over the
//! settlement channel, each party holds its complete witness alone. The
//! MPC layer therefore never touches notes, collateral, or the pool.
//!
//! Private inputs: trader A owns side-a signals, trader B side-b. Amounts
//! enter as 64 little-endian bits each (the owner bit-decomposes locally),
//! so the collaborative witness computation is pure share arithmetic.

use ark_bn254::Fr;
use ark_ff::Zero;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    gadgets::{AMOUNT_BITS, cmp_from_bits, enforce_bits, le_bits_to_field, poseidon_hash2},
    poseidon,
};

/// One trader's private comparison inputs. `r_order` is the 32-byte
/// blinding factor, big-endian reduced into Fr (wallet convention).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidePrivate {
    /// Hidden order amount (token1 quantity).
    pub order_amount: u64,
    /// Blinding of the current on-chain order commitment.
    pub r_order: [u8; 32],
}

/// Serde adapter: Fr as the chain's 64-char big-endian hex string.
mod fr_hex {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(f: &Fr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::poseidon::fr_to_hex(f))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Fr, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Ok(Fr::from_be_bytes_mod_order(&bytes))
    }
}

/// Deserialize `cmp` and reject anything outside {-1, 0, 1} at the trust
/// boundary (the JSON may come from the counterparty).
fn de_cmp<'de, D: serde::Deserializer<'de>>(d: D) -> Result<i8, D::Error> {
    let v = i8::deserialize(d)?;
    if matches!(v, -1 | 0 | 1) {
        Ok(v)
    } else {
        Err(serde::de::Error::custom(format!(
            "cmp must be -1, 0 or 1, got {v}"
        )))
    }
}

/// The public statement both traders agree on and the chain verifies.
/// Commitments serialize as the chain's 64-char hex strings; field names
/// stay in lockstep with Go's `settle2pPublic`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlePublic {
    #[serde(deserialize_with = "de_cmp")]
    pub cmp: i8,
    #[serde(with = "fr_hex")]
    pub order_a: Fr,
    #[serde(with = "fr_hex")]
    pub order_b: Fr,
}

impl SettlePublic {
    /// Flatten to the canonical 3-element public-input vector.
    pub fn to_vec(&self) -> Vec<Fr> {
        let cmp_fr = match self.cmp {
            1 => Fr::from(1u64),
            0 => Fr::zero(),
            -1 => -Fr::from(1u64),
            _ => unreachable!("cmp is always in {{-1,0,1}}"),
        };
        vec![cmp_fr, self.order_a, self.order_b]
    }

    /// Poseidon-fold fingerprint of the canonical public vector. Used to
    /// cross-check that both traders loaded the identical statement before
    /// any shared computation (a mismatch would otherwise surface as an
    /// undiagnosable SPDZ MAC failure deep inside proving).
    pub fn fingerprint(&self) -> Fr {
        let vec = self.to_vec();
        let mut h = Fr::from(vec.len() as u64);
        for v in vec {
            h = poseidon::hash2(h, v);
        }
        h
    }
}

/// Fr of a 32-byte blinding, wallet convention (big-endian reduction).
fn rand_fr(r: &[u8; 32]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(r)
}

/// Compute the public statement from both sides' plaintext inputs — the
/// native mirror of the circuit; the collaborative flow computes the same
/// values under MPC.
pub fn compute_public(a: &SidePrivate, b: &SidePrivate) -> SettlePublic {
    let (av, bv) = (a.order_amount, b.order_amount);
    let cmp: i8 = match av.cmp(&bv) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    SettlePublic {
        cmp,
        order_a: poseidon::commit(av, &a.r_order),
        order_b: poseidon::commit(bv, &b.r_order),
    }
}

/// Wire indices of the 3 public inputs, in canonical order.
pub struct PublicWires {
    pub cmp: Variable,
    pub order_a: Variable,
    pub order_b: Variable,
}

/// Wire indices of one side's private inputs: the amount's 64-bit LE
/// decomposition plus the order blinding.
pub struct SideWires {
    pub amount_bits: Vec<Variable>,
    pub r_order: Variable,
}

/// The plaintext values of one side's private wires, in allocation order.
/// Order MUST match `SideWires` allocation in the circuit builders and be
/// identical between the single-prover and MPC flows.
pub fn side_private_values(side: &SidePrivate) -> Vec<Fr> {
    let mut vals = Vec::with_capacity(SIDE_PRIVATE_LEN);
    for i in 0..AMOUNT_BITS {
        vals.push(Fr::from((side.order_amount >> i) & 1));
    }
    vals.push(rand_fr(&side.r_order));
    vals
}

/// Number of private wires per side.
pub const SIDE_PRIVATE_LEN: usize = AMOUNT_BITS + 1;

/// Rebuild `SideWires` from `SIDE_PRIVATE_LEN` freshly created variables,
/// in the same order `side_private_values` emits them.
pub fn side_wires_from_vars(vars: &[Variable]) -> SideWires {
    assert_eq!(vars.len(), SIDE_PRIVATE_LEN);
    let mut it = vars.iter().copied();
    let amount_bits: Vec<Variable> = (&mut it).take(AMOUNT_BITS).collect();
    let r_order = it.next().unwrap();
    assert!(it.next().is_none());
    SideWires {
        amount_bits,
        r_order,
    }
}

/// A record of the relation's satisfiability checks, sufficient to test the
/// joint witness for validity outside the proof: `eq_pairs` are the variable
/// pairs an `enforce_equal` requires to be equal, `bool_vars` the variables an
/// `enforce_bool` requires to be in `{0, 1}`. The MPC prover uses this to abort
/// on an invalid witness BEFORE any proof element is opened (see
/// `check_witness_valid` in `prove.rs`) — a proof over an invalid witness is
/// outside the zk-SNARK's zero-knowledge guarantee (eprint 2025/1026).
#[derive(Clone, Debug, Default)]
pub struct SatisfiabilityWitness {
    pub eq_pairs: Vec<(Variable, Variable)>,
    pub bool_vars: Vec<Variable>,
}

/// Encode the comparison constraints over already-allocated wires. Works on
/// any `Circuit<Fr>` implementation (single-prover or MPC).
pub fn build_settle_relation<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    public: &PublicWires,
    a: &SideWires,
    b: &SideWires,
) -> Result<(), CircuitError> {
    let mut sat = SatisfiabilityWitness::default();
    settle_relation_impl(cs, public, a, b, &mut sat)
}

/// [`build_settle_relation`] that also returns the [`SatisfiabilityWitness`]
/// so the collaborative prover can validity-check the joint witness before
/// revealing a proof.
pub fn build_settle_relation_collecting<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    public: &PublicWires,
    a: &SideWires,
    b: &SideWires,
) -> Result<SatisfiabilityWitness, CircuitError> {
    let mut sat = SatisfiabilityWitness::default();
    settle_relation_impl(cs, public, a, b, &mut sat)?;
    Ok(sat)
}

/// Shared body of the two builders. Every `enforce_equal`/`enforce_bool` is
/// mirrored into `sat` so the exact set of checks that make the circuit
/// satisfiable can be re-tested on the witness shares.
fn settle_relation_impl<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    public: &PublicWires,
    a: &SideWires,
    b: &SideWires,
    sat: &mut SatisfiabilityWitness,
) -> Result<(), CircuitError> {
    // 1. Booleanity of every amount bit (both sides) — this is also the
    //    64-bit range check that makes the comparison an integer one.
    for side in [a, b] {
        enforce_bits(cs, &side.amount_bits)?;
        sat.bool_vars.extend_from_slice(&side.amount_bits);
    }

    let mut eq = |cs: &mut Cs, x: Variable, y: Variable| -> Result<(), CircuitError> {
        cs.enforce_equal(x, y)?;
        sat.eq_pairs.push((x, y));
        Ok(())
    };

    // 2. Reconstruct amounts from bits.
    let a_amt = le_bits_to_field(cs, &a.amount_bits)?;
    let b_amt = le_bits_to_field(cs, &b.amount_bits)?;

    // 3. The compared values open the on-chain order commitments
    //    (paper Property 1(i): input legitimacy).
    let order_a_hash = poseidon_hash2(cs, a_amt, a.r_order)?;
    eq(cs, order_a_hash, public.order_a)?;
    let order_b_hash = poseidon_hash2(cs, b_amt, b.r_order)?;
    eq(cs, order_b_hash, public.order_b)?;

    // 4. cmp = (a > b) - (a < b) must equal the public claim.
    let (lt, eq_flag) = cmp_from_bits(cs, &a.amount_bits, &b.amount_bits)?;
    let one_var = cs.one();
    let zero = cs.zero();
    // gt = 1 - lt - eq
    let gt = cs.lc(
        &[one_var, lt, eq_flag, zero],
        &[
            Fr::from(1u64),
            -Fr::from(1u64),
            -Fr::from(1u64),
            Fr::from(0u64),
        ],
    )?;
    let cmp_expected = cs.sub(gt, lt)?;
    eq(cs, cmp_expected, public.cmp)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::sample_trade;

    #[test]
    fn compute_public_sample() {
        let (a, b, _price, _a_is_seller) = sample_trade();
        let p = compute_public(&a, &b);
        assert_eq!(p.cmp, 1); // a=80 > b=60
        assert_eq!(p.to_vec().len(), 3);
    }

    #[test]
    fn serde_round_trip_and_cmp_bounds() {
        let (a, b, _price, _a_is_seller) = sample_trade();
        let p = compute_public(&a, &b);
        let json = serde_json::to_string(&p).unwrap();
        let back: SettlePublic = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_vec(), p.to_vec());

        // Out-of-range cmp is rejected at the deserialization boundary.
        let bad = json.replace("\"cmp\":1", "\"cmp\":2");
        assert!(serde_json::from_str::<SettlePublic>(&bad).is_err());
    }
}
