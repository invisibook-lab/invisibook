//! The 2-party comparison relation — the paper's π_cmp (§VI-A), expressed
//! as a jellyfish PLONK circuit. Same 5-public statement as the
//! single-prover `settle_cozk.circom`:
//!
//! ```text
//!  0 cmp          sign(q_a - q_b) in {-1, 0, 1} (as Fr: p-1, 0, 1)
//!  1 locked_a     on-chain order A collateral commitment P2(needed_a, r_a)
//!  2 locked_b     on-chain order B collateral commitment P2(needed_b, r_b)
//!  3 price        the shared execution price (equal-price matching)
//!  4 a_is_seller  1 when A sells token1; B is always the opposite side
//! ```
//!
//! LOCKED-ONLY MODEL: orders commit ONLY their collateral
//! `locked = P2(needed, r_locked)` with the side-dependent equation
//! `needed(q, s) = q·price + s·(q − q·price)` (a seller locks q, a buyer
//! q·price). The equation is injective in q for price > 0, so opening each
//! collateral against its in-circuit `needed` pins the compared quantities
//! (input legitimacy); price and a_is_seller therefore enter the statement.
//!
//! Everything after the comparison — payouts, residual re-commitments — is
//! single-party work (`settle_small.circom` / `settle_large.circom`): once
//! cmp is public and the smaller side reveals its opening over the
//! settlement channel, each party holds its complete witness alone. The
//! MPC layer therefore never touches notes or the pool.
//!
//! Private inputs: trader A owns side-a signals, trader B side-b.
//! Quantities enter as 64 little-endian bits each (the owner bit-decomposes
//! locally), so the collaborative witness computation is pure share
//! arithmetic. `price` and `a_is_seller` are PUBLIC wires used as they are:
//! a prover cannot lie about a public input and the chain builds both from
//! the order rows (a u64 price, a 0-1 flag), so neither is re-checked
//! in-circuit — the same policy the statement applies to cmp's encoding.

use anyhow::{Result, anyhow};
use ark_bn254::Fr;
use ark_ff::Zero;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    gadgets::{AMOUNT_BITS, cmp_from_bits, enforce_bits, le_bits_to_field, poseidon_hash2},
    poseidon::{commit, hash2},
};

/// One trader's private comparison inputs. `r_locked` is the 32-byte
/// blinding factor of its on-chain collateral commitment, big-endian
/// reduced into Fr (wallet convention).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidePrivate {
    /// Hidden order quantity (token1 units) backing the collateral.
    pub order_amount: u64,
    /// Blinding of the current on-chain collateral commitment.
    pub r_locked: [u8; 32],
}

/// Serde adapter: Fr as the chain's 64-char big-endian hex string.
pub(crate) mod fr_hex {
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
pub(crate) fn de_cmp<'de, D: serde::Deserializer<'de>>(d: D) -> Result<i8, D::Error> {
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
/// AND their order stay in lockstep with Go's `settle2pPublic`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlePublic {
    #[serde(deserialize_with = "de_cmp")]
    pub cmp: i8,
    #[serde(with = "fr_hex")]
    pub locked_a: Fr,
    #[serde(with = "fr_hex")]
    pub locked_b: Fr,
    pub price: u64,
    pub a_is_seller: bool,
}

impl SettlePublic {
    /// Flatten to the canonical 5-element public-input vector.
    pub fn to_vec(&self) -> Vec<Fr> {
        let cmp_fr = match self.cmp {
            1 => Fr::from(1u64),
            0 => Fr::zero(),
            -1 => -Fr::from(1u64),
            _ => unreachable!("cmp is always in {{-1,0,1}}"),
        };
        vec![
            cmp_fr,
            self.locked_a,
            self.locked_b,
            Fr::from(self.price),
            Fr::from(self.a_is_seller as u64),
        ]
    }

    /// Poseidon-fold fingerprint of the canonical public vector. Used to
    /// cross-check that both traders loaded the identical statement before
    /// any shared computation (a mismatch would otherwise surface as an
    /// undiagnosable SPDZ MAC failure deep inside proving).
    pub fn fingerprint(&self) -> Fr {
        let vec = self.to_vec();
        let mut h = Fr::from(vec.len() as u64);
        for v in vec {
            h = hash2(h, v);
        }
        h
    }
}

/// Fr of a 32-byte blinding, wallet convention (big-endian reduction).
pub(crate) fn rand_fr(r: &[u8; 32]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(r)
}

/// The collateral equation `needed(q, s) = q·price + s·(q − q·price)`: a
/// seller locks (or moves) `q` token1, a buyer `q·price` token2. THE one
/// native mirror of the in-circuit chain — the session's own checks and the
/// benches call it too. Computed over u128 and rejected above u64, because
/// every settle circuit is 64-bit and a wider value could never settle.
pub fn needed_collateral(q: u64, price: u64, is_seller: bool) -> Result<u64> {
    let v: u128 = if is_seller {
        q as u128
    } else {
        q as u128 * price as u128
    };
    u64::try_from(v).map_err(|_| anyhow!("collateral value {v} exceeds 64 bits"))
}

/// Compute the public statement from both sides' plaintext inputs — the
/// native mirror of the circuit; the collaborative flow computes the same
/// values under MPC. A's side flag is `a_is_seller`; B is the opposite.
/// Fails when either side's collateral does not fit 64 bits.
pub fn compute_public(
    a: &SidePrivate,
    b: &SidePrivate,
    price: u64,
    a_is_seller: bool,
) -> Result<SettlePublic> {
    let (av, bv) = (a.order_amount, b.order_amount);
    let cmp: i8 = match av.cmp(&bv) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    Ok(SettlePublic {
        cmp,
        locked_a: commit(needed_collateral(av, price, a_is_seller)?, &a.r_locked),
        locked_b: commit(needed_collateral(bv, price, !a_is_seller)?, &b.r_locked),
        price,
        a_is_seller,
    })
}

/// Wire indices of the 5 public inputs, in canonical order.
pub struct PublicWires {
    pub cmp: Variable,
    pub locked_a: Variable,
    pub locked_b: Variable,
    pub price: Variable,
    pub a_is_seller: Variable,
}

/// Wire indices of one side's private inputs: the quantity's 64-bit LE
/// decomposition plus the collateral blinding.
pub struct SideWires {
    pub amount_bits: Vec<Variable>,
    pub r_locked: Variable,
}

/// The plaintext values of one side's private wires, in allocation order.
/// Order MUST match `SideWires` allocation in the circuit builders and be
/// identical between the single-prover and MPC flows.
pub fn side_private_values(side: &SidePrivate) -> Vec<Fr> {
    let mut vals = Vec::with_capacity(SIDE_PRIVATE_LEN);
    for i in 0..AMOUNT_BITS {
        vals.push(Fr::from((side.order_amount >> i) & 1));
    }
    vals.push(rand_fr(&side.r_locked));
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
    let r_locked = it.next().unwrap();
    assert!(it.next().is_none());
    SideWires {
        amount_bits,
        r_locked,
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
    // 1. Booleanity of every quantity bit (both sides) — these ARE secret
    //    witnesses, and their 64-bit ranges keep the comparison an integer
    //    one and the collateral products integer-exact. The public `price`
    //    and `a_is_seller` wires need no such check (see the module docs).
    for bits in [&a.amount_bits[..], &b.amount_bits[..]] {
        enforce_bits(cs, bits)?;
        sat.bool_vars.extend_from_slice(bits);
    }

    let mut eq = |cs: &mut Cs, x: Variable, y: Variable| -> Result<(), CircuitError> {
        cs.enforce_equal(x, y)?;
        sat.eq_pairs.push((x, y));
        Ok(())
    };

    // 2. Reconstruct the quantities from their bits.
    let q_a = le_bits_to_field(cs, &a.amount_bits)?;
    let q_b = le_bits_to_field(cs, &b.amount_bits)?;

    // 3. The compared quantities back the on-chain collateral commitments
    //    (paper Property 1(i): input legitimacy). Per side s in {0, 1}:
    //    needed = q·price + s·(q − q·price); then P2(needed, r) == locked.
    //    A's side flag IS the public a_is_seller wire; B's is 1 − s_a.
    let s_a = public.a_is_seller;
    let one_var = cs.one();
    let zero = cs.zero();
    let s_b = cs.sub(one_var, s_a)?;
    let needed = |cs: &mut Cs, q: Variable, s: Variable| -> Result<Variable, CircuitError> {
        let q_price = cs.mul(q, public.price)?;
        let diff = cs.sub(q, q_price)?;
        let term = cs.mul(s, diff)?;
        cs.add(q_price, term)
    };
    let needed_a = needed(cs, q_a, s_a)?;
    let needed_b = needed(cs, q_b, s_b)?;
    let locked_a_hash = poseidon_hash2(cs, needed_a, a.r_locked)?;
    eq(cs, locked_a_hash, public.locked_a)?;
    let locked_b_hash = poseidon_hash2(cs, needed_b, b.r_locked)?;
    eq(cs, locked_b_hash, public.locked_b)?;

    // 4. cmp = (q_a > q_b) - (q_a < q_b) must equal the public claim.
    let (lt, eq_flag) = cmp_from_bits(cs, &a.amount_bits, &b.amount_bits)?;
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

    /// The one collateral equation: a seller locks q, a buyer q·price, and
    /// anything wider than u64 is rejected (the circuits are 64-bit).
    #[test]
    fn needed_collateral_scales_and_bounds() {
        assert_eq!(needed_collateral(60, 3, true).unwrap(), 60);
        assert_eq!(needed_collateral(60, 3, false).unwrap(), 180);
        assert!(needed_collateral(u64::MAX, 2, false).is_err());
    }

    #[test]
    fn compute_public_sample() {
        let (a, b, price, a_is_seller) = sample_trade();
        let p = compute_public(&a, &b, price, a_is_seller).unwrap();
        assert_eq!(p.cmp, 1); // a=80 > b=60
        assert_eq!(p.to_vec().len(), 5);
        // The commitments open with needed(q, side): A sells 80 (locks 80),
        // B buys 60 at price 3 (locks 180).
        assert_eq!(p.locked_a, commit(80, &a.r_locked));
        assert_eq!(p.locked_b, commit(180, &b.r_locked));
    }

    #[test]
    fn serde_round_trip_and_cmp_bounds() {
        let (a, b, price, a_is_seller) = sample_trade();
        let p = compute_public(&a, &b, price, a_is_seller).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: SettlePublic = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_vec(), p.to_vec());

        // The serde field ORDER is normative (Go mirrors it): cmp, locked_a,
        // locked_b, price, a_is_seller.
        let keys = [
            "\"cmp\"",
            "\"locked_a\"",
            "\"locked_b\"",
            "\"price\"",
            "\"a_is_seller\"",
        ];
        let mut last = 0;
        for key in keys {
            let idx = json.find(key).expect("field must serialize");
            assert!(idx >= last, "field {key} out of order in {json}");
            last = idx;
        }

        // Out-of-range cmp is rejected at the deserialization boundary.
        let bad = json.replace("\"cmp\":1", "\"cmp\":2");
        assert!(serde_json::from_str::<SettlePublic>(&bad).is_err());
    }
}
