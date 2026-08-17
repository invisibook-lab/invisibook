//! The merged 2-party settlement relation: ONE collaborative proof that
//! covers the comparison AND both settlement legs of a matched pair — the
//! benchmark counterpart of the split flow (pi_cmp + settle_small +
//! settle_large). Nothing after this proof needs a reveal of either
//! trader's quantity: the fill, both payout notes, and both residual
//! commitments are computed inside the MPC.
//!
//! Public statement (15 signals, canonical order — the chain rebuilds
//! signals 7..15 from its own order rows and takes 0..7 from the request):
//!
//! ```text
//!  0 cmp              sign(q_a - q_b) in {-1, 0, 1} (as Fr: p-1, 0, 1)
//!  1 cm_note_out_a    payout note minted TO trader A (B pays it)
//!  2 cm_note_out_b    payout note minted TO trader B (A pays it)
//!  3 cm_q_res_a       A's residual quantity commitment  (chain uses iff cmp = +1)
//!  4 cm_locked_res_a  A's residual collateral commitment
//!  5 cm_q_res_b       B's residual quantity commitment  (chain uses iff cmp = -1)
//!  6 cm_locked_res_b  B's residual collateral commitment
//!  7 cm_q_a           on-chain order A quantity commitment P2(q_a, r_q_a)
//!  8 cm_q_b           on-chain order B quantity commitment
//!  9 locked_a         order A's collateral commitment (Order.LockedCommitment)
//! 10 locked_b         order B's collateral commitment
//! 11 price            execution price (equal-price rule; chain-validated u64)
//! 12 a_is_seller      1 when A sells token1
//! 13 asset_recv_a     assetID of the token A receives (= B's lock token)
//! 14 asset_recv_b     assetID of the token B receives (= A's lock token)
//! ```
//!
//! Collateral pad slots (`P2(0,0)`) are NOT part of this statement: the
//! merged relation opens `Order.LockedCommitment` directly against the
//! amount the collateral equation requires, so the 2-slot padding of the
//! Groth16 settle circuits has nothing to add here.
//!
//! Range-safety: every derived amount is bounded by 64-bit-checked
//! inputs, so all arithmetic is integer-exact in Fr —
//! `fill = min(q_a, q_b) < 2^64`; the buyer-side collateral equation
//! forces `q_buyer * price` to equal the opened admission-time collateral
//! (64-bit-checked by send_order), hence `fill * price` and every residual
//! collateral are `< 2^64` too. `price < 2^64` is re-checked in-circuit
//! from owner-supplied bits.

use ark_bn254::Fr;
use ark_ff::Zero;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    gadgets::{AMOUNT_BITS, cmp_from_bits, enforce_bits, le_bits_to_field, poseidon_hash2},
    poseidon,
    relation::{SatisfiabilityWitness, de_cmp, fr_hex, rand_fr},
};

/// One trader's private inputs to the merged relation. All blindings are
/// 32-byte big-endian values reduced into Fr (wallet convention).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairSidePrivate {
    /// Hidden order quantity (token1 denomination).
    pub order_amount: u64,
    /// Blinding of the on-chain order quantity commitment.
    pub r_order: [u8; 32],
    /// Blinding of the on-chain collateral commitment (locked slot 0).
    pub r_locked: [u8; 32],
    /// Fresh blinding for this side's residual quantity commitment.
    pub r_q_res: [u8; 32],
    /// Fresh blinding for this side's residual collateral commitment.
    pub r_locked_res: [u8; 32],
    /// This side's receiving key for its incoming payout note.
    #[serde(with = "fr_hex")]
    pub recv_npk: Fr,
    /// Fresh blinding for this side's incoming payout note.
    pub r_note: [u8; 32],
}

/// The public statement both traders agree on and the chain verifies.
/// Commitments and asset ids serialize as the chain's 64-char hex; field
/// names stay in lockstep with Go's `settlePair2pPublic`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairPublic {
    #[serde(deserialize_with = "de_cmp")]
    pub cmp: i8,
    #[serde(with = "fr_hex")]
    pub cm_note_out_a: Fr,
    #[serde(with = "fr_hex")]
    pub cm_note_out_b: Fr,
    #[serde(with = "fr_hex")]
    pub cm_q_res_a: Fr,
    #[serde(with = "fr_hex")]
    pub cm_locked_res_a: Fr,
    #[serde(with = "fr_hex")]
    pub cm_q_res_b: Fr,
    #[serde(with = "fr_hex")]
    pub cm_locked_res_b: Fr,
    #[serde(with = "fr_hex")]
    pub cm_q_a: Fr,
    #[serde(with = "fr_hex")]
    pub cm_q_b: Fr,
    #[serde(with = "fr_hex")]
    pub locked_a: Fr,
    #[serde(with = "fr_hex")]
    pub locked_b: Fr,
    pub price: u64,
    pub a_is_seller: bool,
    #[serde(with = "fr_hex")]
    pub asset_recv_a: Fr,
    #[serde(with = "fr_hex")]
    pub asset_recv_b: Fr,
}

/// Number of public signals in the merged statement.
pub const PAIR_PUBLIC_LEN: usize = 15;

impl PairPublic {
    /// Flatten to the canonical 15-element public-input vector.
    pub fn to_vec(&self) -> Vec<Fr> {
        let cmp_fr = match self.cmp {
            1 => Fr::from(1u64),
            0 => Fr::zero(),
            -1 => -Fr::from(1u64),
            _ => unreachable!("cmp is always in {{-1,0,1}}"),
        };
        let v = vec![
            cmp_fr,
            self.cm_note_out_a,
            self.cm_note_out_b,
            self.cm_q_res_a,
            self.cm_locked_res_a,
            self.cm_q_res_b,
            self.cm_locked_res_b,
            self.cm_q_a,
            self.cm_q_b,
            self.locked_a,
            self.locked_b,
            Fr::from(self.price),
            Fr::from(self.a_is_seller as u64),
            self.asset_recv_a,
            self.asset_recv_b,
        ];
        debug_assert_eq!(v.len(), PAIR_PUBLIC_LEN);
        v
    }

    /// Poseidon-fold fingerprint of the canonical public vector (same
    /// construction as `SettlePublic::fingerprint`).
    pub fn fingerprint(&self) -> Fr {
        let vec = self.to_vec();
        let mut h = Fr::from(vec.len() as u64);
        for v in vec {
            h = poseidon::hash2(h, v);
        }
        h
    }
}

/// The trade parameters both parties read from chain state before the
/// session: everything in the statement that is NOT an MPC output.
#[derive(Clone, Debug)]
pub struct PairStatementInputs {
    pub price: u64,
    pub a_is_seller: bool,
    pub asset_recv_a: Fr,
    pub asset_recv_b: Fr,
}

/// Plaintext mirror of the in-circuit settlement arithmetic. Returns the
/// full public statement from both sides' secrets — used by keygen, tests,
/// fixtures, and the single-prover baseline; the collaborative flow
/// computes the same values over shares.
pub fn compute_pair_public(
    a: &PairSidePrivate,
    b: &PairSidePrivate,
    inputs: &PairStatementInputs,
) -> PairPublic {
    let (qa, qb) = (a.order_amount, b.order_amount);
    let cmp: i8 = match qa.cmp(&qb) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    let fill = qa.min(qb);
    let (q_res_a, q_res_b) = (qa - fill, qb - fill);
    // Collateral / payout denominations: a seller locks and pays token1
    // quantities; a buyer locks and pays token2 = quantity * price.
    let locked_needed =
        |q: u64, is_seller: bool| -> u64 { if is_seller { q } else { q * inputs.price } };
    let recv = |is_seller: bool| -> u64 {
        // The seller receives the token2 leg, the buyer the token1 leg.
        if is_seller { fill * inputs.price } else { fill }
    };
    PairPublic {
        cmp,
        cm_note_out_a: poseidon::note_commit(
            a.recv_npk,
            inputs.asset_recv_a,
            recv(inputs.a_is_seller),
            &a.r_note,
        ),
        cm_note_out_b: poseidon::note_commit(
            b.recv_npk,
            inputs.asset_recv_b,
            recv(!inputs.a_is_seller),
            &b.r_note,
        ),
        cm_q_res_a: poseidon::hash2(Fr::from(q_res_a), rand_fr(&a.r_q_res)),
        cm_locked_res_a: poseidon::hash2(
            Fr::from(locked_needed(q_res_a, inputs.a_is_seller)),
            rand_fr(&a.r_locked_res),
        ),
        cm_q_res_b: poseidon::hash2(Fr::from(q_res_b), rand_fr(&b.r_q_res)),
        cm_locked_res_b: poseidon::hash2(
            Fr::from(locked_needed(q_res_b, !inputs.a_is_seller)),
            rand_fr(&b.r_locked_res),
        ),
        cm_q_a: poseidon::commit(qa, &a.r_order),
        cm_q_b: poseidon::commit(qb, &b.r_order),
        locked_a: poseidon::hash2(
            Fr::from(locked_needed(qa, inputs.a_is_seller)),
            rand_fr(&a.r_locked),
        ),
        locked_b: poseidon::hash2(
            Fr::from(locked_needed(qb, !inputs.a_is_seller)),
            rand_fr(&b.r_locked),
        ),
        price: inputs.price,
        a_is_seller: inputs.a_is_seller,
        asset_recv_a: inputs.asset_recv_a,
        asset_recv_b: inputs.asset_recv_b,
    }
}

/// Wire indices of the 15 public inputs, in canonical order.
pub struct PairPublicWires {
    pub cmp: Variable,
    pub cm_note_out_a: Variable,
    pub cm_note_out_b: Variable,
    pub cm_q_res_a: Variable,
    pub cm_locked_res_a: Variable,
    pub cm_q_res_b: Variable,
    pub cm_locked_res_b: Variable,
    pub cm_q_a: Variable,
    pub cm_q_b: Variable,
    pub locked_a: Variable,
    pub locked_b: Variable,
    pub price: Variable,
    pub a_is_seller: Variable,
    pub asset_recv_a: Variable,
    pub asset_recv_b: Variable,
}

/// Group the 15 canonical public wires. `vars` must be the public
/// variables in canonical order.
pub fn pair_public_wires_from_vars(vars: &[Variable]) -> PairPublicWires {
    assert_eq!(vars.len(), PAIR_PUBLIC_LEN);
    PairPublicWires {
        cmp: vars[0],
        cm_note_out_a: vars[1],
        cm_note_out_b: vars[2],
        cm_q_res_a: vars[3],
        cm_locked_res_a: vars[4],
        cm_q_res_b: vars[5],
        cm_locked_res_b: vars[6],
        cm_q_a: vars[7],
        cm_q_b: vars[8],
        locked_a: vars[9],
        locked_b: vars[10],
        price: vars[11],
        a_is_seller: vars[12],
        asset_recv_a: vars[13],
        asset_recv_b: vars[14],
    }
}

/// Wire indices of one side's private inputs: the quantity's 64-bit LE
/// decomposition plus the five blindings and the receiving key.
pub struct PairSideWires {
    pub amount_bits: Vec<Variable>,
    pub r_order: Variable,
    pub r_locked: Variable,
    pub r_q_res: Variable,
    pub r_locked_res: Variable,
    pub recv_npk: Variable,
    pub r_note: Variable,
}

/// Number of private wires per side.
pub const PAIR_SIDE_PRIVATE_LEN: usize = AMOUNT_BITS + 6;

/// Number of extra shared wires: the price's 64-bit LE decomposition,
/// supplied by trader A (both know the price; the recomposition equality
/// against the public price wire makes a wrong supply unsatisfiable).
pub const PAIR_EXTRA_LEN: usize = AMOUNT_BITS;

/// The plaintext values of one side's private wires, in allocation order.
/// Order MUST match `pair_side_wires_from_vars` and be identical between
/// the single-prover and MPC flows.
pub fn pair_side_private_values(side: &PairSidePrivate) -> Vec<Fr> {
    let mut vals = Vec::with_capacity(PAIR_SIDE_PRIVATE_LEN);
    for i in 0..AMOUNT_BITS {
        vals.push(Fr::from((side.order_amount >> i) & 1));
    }
    vals.push(rand_fr(&side.r_order));
    vals.push(rand_fr(&side.r_locked));
    vals.push(rand_fr(&side.r_q_res));
    vals.push(rand_fr(&side.r_locked_res));
    vals.push(side.recv_npk);
    vals.push(rand_fr(&side.r_note));
    vals
}

/// The plaintext values of the extra wires (price bits, LE).
pub fn pair_extra_values(price: u64) -> Vec<Fr> {
    (0..AMOUNT_BITS)
        .map(|i| Fr::from((price >> i) & 1))
        .collect()
}

/// Rebuild `PairSideWires` from `PAIR_SIDE_PRIVATE_LEN` freshly created
/// variables, in the same order `pair_side_private_values` emits them.
pub fn pair_side_wires_from_vars(vars: &[Variable]) -> PairSideWires {
    assert_eq!(vars.len(), PAIR_SIDE_PRIVATE_LEN);
    let mut it = vars.iter().copied();
    let amount_bits: Vec<Variable> = (&mut it).take(AMOUNT_BITS).collect();
    let r_order = it.next().unwrap();
    let r_locked = it.next().unwrap();
    let r_q_res = it.next().unwrap();
    let r_locked_res = it.next().unwrap();
    let recv_npk = it.next().unwrap();
    let r_note = it.next().unwrap();
    assert!(it.next().is_none());
    PairSideWires {
        amount_bits,
        r_order,
        r_locked,
        r_q_res,
        r_locked_res,
        recv_npk,
        r_note,
    }
}

/// Encode the merged settlement constraints over already-allocated wires.
/// Works on any `Circuit<Fr>` implementation (single-prover or MPC).
/// `price_bits` are the `PAIR_EXTRA_LEN` extra wires.
pub fn build_pair_relation<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    public: &PairPublicWires,
    a: &PairSideWires,
    b: &PairSideWires,
    price_bits: &[Variable],
) -> Result<(), CircuitError> {
    let mut sat = SatisfiabilityWitness::default();
    pair_relation_impl(cs, public, a, b, price_bits, &mut sat)
}

/// [`build_pair_relation`] that also returns the [`SatisfiabilityWitness`]
/// so the collaborative prover can validity-check the joint witness before
/// revealing a proof.
pub fn build_pair_relation_collecting<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    public: &PairPublicWires,
    a: &PairSideWires,
    b: &PairSideWires,
    price_bits: &[Variable],
) -> Result<SatisfiabilityWitness, CircuitError> {
    let mut sat = SatisfiabilityWitness::default();
    pair_relation_impl(cs, public, a, b, price_bits, &mut sat)?;
    Ok(sat)
}

/// Shared body of the two builders. Every `enforce_equal`/`enforce_bool`
/// is mirrored into `sat` so the exact set of checks that make the circuit
/// satisfiable can be re-tested on the witness shares.
fn pair_relation_impl<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    public: &PairPublicWires,
    a: &PairSideWires,
    b: &PairSideWires,
    price_bits: &[Variable],
    sat: &mut SatisfiabilityWitness,
) -> Result<(), CircuitError> {
    assert_eq!(price_bits.len(), PAIR_EXTRA_LEN);
    let one_var = cs.one();
    let zero = cs.zero();

    // 1. Booleanity: both quantities' bits, the price bits, and the public
    //    side flag. These are also the 64-bit range checks that make every
    //    product below integer-exact.
    for bits in [&a.amount_bits, &b.amount_bits] {
        enforce_bits(cs, bits)?;
        sat.bool_vars.extend_from_slice(bits);
    }
    enforce_bits(cs, price_bits)?;
    sat.bool_vars.extend_from_slice(price_bits);
    cs.enforce_bool(public.a_is_seller)?;
    sat.bool_vars.push(public.a_is_seller);

    let mut eq = |cs: &mut Cs, x: Variable, y: Variable| -> Result<(), CircuitError> {
        cs.enforce_equal(x, y)?;
        sat.eq_pairs.push((x, y));
        Ok(())
    };

    // 2. Reconstruct the amounts; the price recomposition must equal the
    //    public price wire (so A cannot supply wrong bits).
    let q_a = le_bits_to_field(cs, &a.amount_bits)?;
    let q_b = le_bits_to_field(cs, &b.amount_bits)?;
    let price_v = le_bits_to_field(cs, price_bits)?;
    eq(cs, price_v, public.price)?;

    // 3. Open both on-chain order quantity commitments.
    let h_qa = poseidon_hash2(cs, q_a, a.r_order)?;
    eq(cs, h_qa, public.cm_q_a)?;
    let h_qb = poseidon_hash2(cs, q_b, b.r_order)?;
    eq(cs, h_qb, public.cm_q_b)?;

    // s_a = a_is_seller, s_b = 1 - s_a.
    let s_a = public.a_is_seller;
    let s_b = cs.lc(
        &[one_var, s_a, zero, zero],
        &[
            Fr::from(1u64),
            -Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ],
    )?;

    // Side-dependent collateral denomination:
    // needed = q*price + s*(q - q*price)  (seller locks q, buyer q*price).
    let needed = |cs: &mut Cs, q: Variable, s: Variable| -> Result<Variable, CircuitError> {
        let qp = cs.mul(q, price_v)?;
        let d = cs.sub(q, qp)?;
        let m = cs.mul(s, d)?;
        cs.add(qp, m)
    };

    // 4. Open both collateral commitments against the amount the
    //    admission-time equation requires. There is no separate collateral
    //    witness: Poseidon collision resistance pins `needed` to the value
    //    send_order range-checked to 64 bits, which also bounds every
    //    product derived from it below 2^64.
    let needed_a = needed(cs, q_a, s_a)?;
    let h_la = poseidon_hash2(cs, needed_a, a.r_locked)?;
    eq(cs, h_la, public.locked_a)?;
    let needed_b = needed(cs, q_b, s_b)?;
    let h_lb = poseidon_hash2(cs, needed_b, b.r_locked)?;
    eq(cs, h_lb, public.locked_b)?;

    // 5. cmp = (q_a > q_b) - (q_a < q_b) must equal the public claim.
    let (lt, eq_flag) = cmp_from_bits(cs, &a.amount_bits, &b.amount_bits)?;
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

    // 6. Fill and residual quantities: fill = min(q_a, q_b).
    let d_ab = cs.sub(q_a, q_b)?;
    let m_lt = cs.mul(lt, d_ab)?;
    let fill = cs.add(q_b, m_lt)?;
    let q_res_a = cs.sub(q_a, fill)?;
    let q_res_b = cs.sub(q_b, fill)?;
    let h_qra = poseidon_hash2(cs, q_res_a, a.r_q_res)?;
    eq(cs, h_qra, public.cm_q_res_a)?;
    let h_qrb = poseidon_hash2(cs, q_res_b, b.r_q_res)?;
    eq(cs, h_qrb, public.cm_q_res_b)?;

    // 7. Residual collateral, re-committed under fresh blindings.
    let locked_res_a = needed(cs, q_res_a, s_a)?;
    let h_lra = poseidon_hash2(cs, locked_res_a, a.r_locked_res)?;
    eq(cs, h_lra, public.cm_locked_res_a)?;
    let locked_res_b = needed(cs, q_res_b, s_b)?;
    let h_lrb = poseidon_hash2(cs, locked_res_b, b.r_locked_res)?;
    eq(cs, h_lrb, public.cm_locked_res_b)?;

    // 8. Payout notes: the seller receives the token2 leg (fill*price),
    //    the buyer the token1 leg (fill). recv = fill + s*(fill*price - fill).
    let fill_t2 = cs.mul(fill, price_v)?;
    let d_fill = cs.sub(fill_t2, fill)?;
    let ra = cs.mul(s_a, d_fill)?;
    let recv_a = cs.add(fill, ra)?;
    let rb = cs.mul(s_b, d_fill)?;
    let recv_b = cs.add(fill, rb)?;

    // NoteCommit chain: P2(P2(P2(P2(TAG_CM=3, npk), asset), v), r).
    let tag_cm = cs.add_constant(zero, &Fr::from(crate::poseidon::TAG_CM))?;
    let note_commit = |cs: &mut Cs,
                       npk: Variable,
                       asset: Variable,
                       v: Variable,
                       r: Variable|
     -> Result<Variable, CircuitError> {
        let c1 = poseidon_hash2(cs, tag_cm, npk)?;
        let c2 = poseidon_hash2(cs, c1, asset)?;
        let c3 = poseidon_hash2(cs, c2, v)?;
        poseidon_hash2(cs, c3, r)
    };
    let note_a = note_commit(cs, a.recv_npk, public.asset_recv_a, recv_a, a.r_note)?;
    eq(cs, note_a, public.cm_note_out_a)?;
    let note_b = note_commit(cs, b.recv_npk, public.asset_recv_b, recv_b, b.r_note)?;
    eq(cs, note_b, public.cm_note_out_b)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::sample_pair_trade;

    #[test]
    fn compute_pair_public_sample() {
        let (a, b, inputs) = sample_pair_trade();
        let p = compute_pair_public(&a, &b, &inputs);
        assert_eq!(p.cmp, 1); // a=80 > b=60
        assert_eq!(p.to_vec().len(), PAIR_PUBLIC_LEN);
        // a sells 80 ETH, locked 80; b buys 60, locked 180 at price 3.
        // fill = 60: a receives 180 (token2), b receives 60 (token1).
        let expect_note_a = poseidon::note_commit(a.recv_npk, inputs.asset_recv_a, 180, &a.r_note);
        assert_eq!(p.cm_note_out_a, expect_note_a);
        let expect_note_b = poseidon::note_commit(b.recv_npk, inputs.asset_recv_b, 60, &b.r_note);
        assert_eq!(p.cm_note_out_b, expect_note_b);
        // Residuals: a keeps 20 (locked 20), b keeps 0 (locked 0).
        assert_eq!(
            p.cm_q_res_a,
            poseidon::hash2(Fr::from(20u64), rand_fr(&a.r_q_res))
        );
        assert_eq!(
            p.cm_locked_res_b,
            poseidon::hash2(Fr::from(0u64), rand_fr(&b.r_locked_res))
        );
    }

    #[test]
    fn serde_round_trip_and_cmp_bounds() {
        let (a, b, inputs) = sample_pair_trade();
        let p = compute_pair_public(&a, &b, &inputs);
        let json = serde_json::to_string(&p).unwrap();
        let back: PairPublic = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_vec(), p.to_vec());

        // Out-of-range cmp is rejected at the deserialization boundary.
        let bad = json.replace("\"cmp\":1", "\"cmp\":2");
        assert!(serde_json::from_str::<PairPublic>(&bad).is_err());
    }

    #[test]
    fn equal_quantities_have_zero_residuals() {
        let (mut a, mut b, inputs) = sample_pair_trade();
        a.order_amount = 60;
        b.order_amount = 60;
        let p = compute_pair_public(&a, &b, &inputs);
        assert_eq!(p.cmp, 0);
        assert_eq!(
            p.cm_q_res_a,
            poseidon::hash2(Fr::from(0u64), rand_fr(&a.r_q_res))
        );
        assert_eq!(
            p.cm_q_res_b,
            poseidon::hash2(Fr::from(0u64), rand_fr(&b.r_q_res))
        );
    }
}
