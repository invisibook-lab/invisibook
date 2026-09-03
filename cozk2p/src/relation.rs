//! The 2-party settlement relation: same statement as the 3-party
//! `settle_cozk.circom` circuit (see `docs/cozk_design.md` §3), expressed as
//! a jellyfish PLONK circuit.
//!
//! Public signals — 15, in the SAME canonical order the chain rebuilds for
//! the Groth16 path (outputs first, then inputs):
//!
//! ```text
//!  0 cmp            sign(a - b) in {-1, 0, 1} (as Fr: p-1, 0, 1)
//!  1 new_order_a    Poseidon(a', r_order_new_a),  a' = a - min(a,b)
//!  2 new_order_b    Poseidon(b', r_order_new_b),  b' = b - min(a,b)
//!  3 new_locked_a   Poseidon(a_locked', r_locked_new_a)
//!  4 new_locked_b   Poseidon(b_locked', r_locked_new_b)
//!  5 recv_a         Poseidon(recv_a_amt, r_recv_a)
//!  6 recv_b         Poseidon(recv_b_amt, r_recv_b)
//!  7 order_a        on-chain order A amount commitment
//!  8 order_b        on-chain order B amount commitment
//!  9 price          plaintext execution price
//! 10 a_is_seller    1 if A sells token1
//! 11 locked_a[0]    on-chain locked cash commitments of A (zero-pad slot 2)
//! 12 locked_a[1]
//! 13 locked_b[0]    same for B
//! 14 locked_b[1]
//! ```
//!
//! Private inputs: trader A owns side-a signals, trader B side-b. Amounts
//! enter as 64 little-endian bits each (the owner bit-decomposes locally),
//! so the collaborative witness computation is pure share arithmetic.

use anyhow::{Result as AnyResult, ensure};
use ark_bn254::Fr;
use ark_ff::Zero;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    gadgets::{
        AMOUNT_BITS, as_bool_unchecked, cmp_from_bits, enforce_bits, le_bits_to_field,
        poseidon_hash2,
    },
    poseidon,
};

/// Maximum locked cashes per side (matches the Groth16 circuits' N=2).
pub const MAX_LOCKED: usize = 2;

/// One trader's private settlement inputs. `random` values are the 32-byte
/// blinding factors, big-endian reduced into Fr (wallet convention).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidePrivate {
    /// Hidden order amount (token1 quantity).
    pub order_amount: u64,
    /// Blinding of the current on-chain order commitment.
    pub r_order: [u8; 32],
    /// Blinding of the updated order commitment.
    pub r_order_new: [u8; 32],
    /// Locked collateral cashes: `(amount, blinding)`, at most [`MAX_LOCKED`];
    /// missing slots are the zero cash `(0, [0; 32])`.
    pub locked: Vec<(u64, [u8; 32])>,
    /// Blinding of the updated (remainder) locked commitment.
    pub r_locked_new: [u8; 32],
    /// Blinding of the receive-cash commitment.
    pub r_recv: [u8; 32],
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

/// Serde adapter for `[Fr; 2]` in the same hex form.
mod fr_hex_pair {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    pub fn serialize<S: Serializer>(f: &[Fr; 2], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(2))?;
        for x in f {
            seq.serialize_element(&crate::poseidon::fr_to_hex(x))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[Fr; 2], D::Error> {
        let v = <[String; 2]>::deserialize(d)?;
        let parse = |s: &String| -> Result<Fr, D::Error> {
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            Ok(Fr::from_be_bytes_mod_order(&bytes))
        };
        Ok([parse(&v[0])?, parse(&v[1])?])
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
/// Commitments serialize as the chain's 64-char hex strings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlePublic {
    #[serde(deserialize_with = "de_cmp")]
    pub cmp: i8,
    #[serde(with = "fr_hex")]
    pub new_order_a: Fr,
    #[serde(with = "fr_hex")]
    pub new_order_b: Fr,
    #[serde(with = "fr_hex")]
    pub new_locked_a: Fr,
    #[serde(with = "fr_hex")]
    pub new_locked_b: Fr,
    #[serde(with = "fr_hex")]
    pub recv_a: Fr,
    #[serde(with = "fr_hex")]
    pub recv_b: Fr,
    #[serde(with = "fr_hex")]
    pub order_a: Fr,
    #[serde(with = "fr_hex")]
    pub order_b: Fr,
    pub price: u64,
    pub a_is_seller: bool,
    #[serde(with = "fr_hex_pair")]
    pub locked_a: [Fr; 2],
    #[serde(with = "fr_hex_pair")]
    pub locked_b: [Fr; 2],
}

impl SettlePublic {
    /// Flatten to the canonical 15-element public-input vector (the order
    /// documented above) for the PLONK verifier.
    pub fn to_vec(&self) -> Vec<Fr> {
        let cmp_fr = match self.cmp {
            1 => Fr::from(1u64),
            0 => Fr::zero(),
            -1 => -Fr::from(1u64),
            _ => unreachable!("cmp is always in {{-1,0,1}}"),
        };
        vec![
            cmp_fr,
            self.new_order_a,
            self.new_order_b,
            self.new_locked_a,
            self.new_locked_b,
            self.recv_a,
            self.recv_b,
            self.order_a,
            self.order_b,
            Fr::from(self.price),
            Fr::from(self.a_is_seller as u64),
            self.locked_a[0],
            self.locked_a[1],
            self.locked_b[0],
            self.locked_b[1],
        ]
    }
}

impl SettlePublic {
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

/// Locked amount at slot `i` (0 for the zero-pad slot).
fn locked_amount(side: &SidePrivate, i: usize) -> u64 {
    side.locked.get(i).map(|(a, _)| *a).unwrap_or(0)
}

/// Locked blinding at slot `i` ([0; 32] for the zero-pad slot).
fn locked_rand(side: &SidePrivate, i: usize) -> [u8; 32] {
    side.locked.get(i).map(|(_, r)| *r).unwrap_or([0u8; 32])
}

/// Compute the full public statement from both sides' plaintext inputs.
/// This is the native mirror of the circuit; the collaborative flow computes
/// the same values under MPC. Checks the same well-formedness the circuit
/// enforces (collateral backing, locked-slot count).
pub fn compute_public(
    a: &SidePrivate,
    b: &SidePrivate,
    price: u64,
    a_is_seller: bool,
) -> AnyResult<SettlePublic> {
    ensure!(
        a.locked.len() <= MAX_LOCKED,
        "side A has too many locked cashes"
    );
    ensure!(
        b.locked.len() <= MAX_LOCKED,
        "side B has too many locked cashes"
    );

    // Collateral each side must have locked: seller locks token1 = amount,
    // buyer locks token2 = amount * price (equal-price limitation as in the
    // 3-party path).
    let needed = |amount: u64, is_seller: bool| -> u128 {
        if is_seller {
            amount as u128
        } else {
            amount as u128 * price as u128
        }
    };
    let sum_locked = |s: &SidePrivate| -> u128 { s.locked.iter().map(|(v, _)| *v as u128).sum() };
    ensure!(
        sum_locked(a) == needed(a.order_amount, a_is_seller),
        "side A collateral does not back its order at the execution price"
    );
    ensure!(
        sum_locked(b) == needed(b.order_amount, !a_is_seller),
        "side B collateral does not back its order at the execution price"
    );

    let (av, bv) = (a.order_amount, b.order_amount);
    let cmp: i8 = if av < bv {
        -1
    } else if av == bv {
        0
    } else {
        1
    };
    let fill = av.min(bv);
    let (a_new, b_new) = (av - fill, bv - fill);

    // Remainder collateral and receive amounts, denominated per side's
    // token. Computed in u128 (u64 products can reach ~2^65 within the
    // collateral bound), then required to fit u64 so every minted
    // commitment stays spendable by the 64-bit downstream circuits.
    let scale = |amount: u64, by_price: bool| -> u128 {
        if by_price {
            amount as u128 * price as u128
        } else {
            amount as u128
        }
    };
    let a_locked_new = scale(a_new, !a_is_seller);
    let b_locked_new = scale(b_new, a_is_seller);
    let recv_a_amt = scale(fill, a_is_seller);
    let recv_b_amt = scale(fill, !a_is_seller);
    for (name, v) in [
        ("new locked A", a_locked_new),
        ("new locked B", b_locked_new),
        ("recv A", recv_a_amt),
        ("recv B", recv_b_amt),
    ] {
        ensure!(
            v <= u64::MAX as u128,
            "{name} amount {v} exceeds 64 bits and would be unspendable"
        );
    }
    let (a_locked_new, b_locked_new) = (a_locked_new as u64, b_locked_new as u64);
    let (recv_a_amt, recv_b_amt) = (recv_a_amt as u64, recv_b_amt as u64);

    Ok(SettlePublic {
        cmp,
        new_order_a: poseidon::hash2(Fr::from(a_new), rand_fr(&a.r_order_new)),
        new_order_b: poseidon::hash2(Fr::from(b_new), rand_fr(&b.r_order_new)),
        new_locked_a: poseidon::hash2(Fr::from(a_locked_new), rand_fr(&a.r_locked_new)),
        new_locked_b: poseidon::hash2(Fr::from(b_locked_new), rand_fr(&b.r_locked_new)),
        recv_a: poseidon::hash2(Fr::from(recv_a_amt), rand_fr(&a.r_recv)),
        recv_b: poseidon::hash2(Fr::from(recv_b_amt), rand_fr(&b.r_recv)),
        order_a: poseidon::commit(av, &a.r_order),
        order_b: poseidon::commit(bv, &b.r_order),
        price,
        a_is_seller,
        locked_a: [
            poseidon::commit(locked_amount(a, 0), &locked_rand(a, 0)),
            poseidon::commit(locked_amount(a, 1), &locked_rand(a, 1)),
        ],
        locked_b: [
            poseidon::commit(locked_amount(b, 0), &locked_rand(b, 0)),
            poseidon::commit(locked_amount(b, 1), &locked_rand(b, 1)),
        ],
    })
}

/// Wire indices of the 15 public inputs, in canonical order.
pub struct PublicWires {
    pub cmp: Variable,
    pub new_order_a: Variable,
    pub new_order_b: Variable,
    pub new_locked_a: Variable,
    pub new_locked_b: Variable,
    pub recv_a: Variable,
    pub recv_b: Variable,
    pub order_a: Variable,
    pub order_b: Variable,
    pub price: Variable,
    pub a_is_seller: Variable,
    pub locked_a: [Variable; 2],
    pub locked_b: [Variable; 2],
}

/// Wire indices of one side's private inputs. Amounts are little-endian
/// 64-bit decompositions; randoms are single field wires.
pub struct SideWires {
    pub amount_bits: Vec<Variable>,
    pub r_order: Variable,
    pub r_order_new: Variable,
    pub locked_bits: [Vec<Variable>; 2],
    pub locked_rand: [Variable; 2],
    pub r_locked_new: Variable,
    pub r_recv: Variable,
}

/// The plaintext values of one side's private wires, in allocation order.
/// Order MUST match `SideWires` allocation in the circuit builders and be
/// identical between the single-prover and MPC flows.
pub fn side_private_values(side: &SidePrivate) -> Vec<Fr> {
    let mut vals = Vec::with_capacity(AMOUNT_BITS * 3 + 6);
    for i in 0..AMOUNT_BITS {
        vals.push(Fr::from((side.order_amount >> i) & 1));
    }
    vals.push(rand_fr(&side.r_order));
    vals.push(rand_fr(&side.r_order_new));
    for slot in 0..MAX_LOCKED {
        let amt = locked_amount(side, slot);
        for i in 0..AMOUNT_BITS {
            vals.push(Fr::from((amt >> i) & 1));
        }
    }
    for slot in 0..MAX_LOCKED {
        vals.push(rand_fr(&locked_rand(side, slot)));
    }
    vals.push(rand_fr(&side.r_locked_new));
    vals.push(rand_fr(&side.r_recv));
    vals
}

/// Number of private wires per side.
pub const SIDE_PRIVATE_LEN: usize = AMOUNT_BITS * 3 + 6;

/// Rebuild `SideWires` from `SIDE_PRIVATE_LEN` freshly created variables,
/// in the same order `side_private_values` emits them.
pub fn side_wires_from_vars(vars: &[Variable]) -> SideWires {
    assert_eq!(vars.len(), SIDE_PRIVATE_LEN);
    let mut it = vars.iter().copied();
    let amount_bits: Vec<Variable> = (&mut it).take(AMOUNT_BITS).collect();
    let r_order = it.next().unwrap();
    let r_order_new = it.next().unwrap();
    let locked0: Vec<Variable> = (&mut it).take(AMOUNT_BITS).collect();
    let locked1: Vec<Variable> = (&mut it).take(AMOUNT_BITS).collect();
    let locked_rand = [it.next().unwrap(), it.next().unwrap()];
    let r_locked_new = it.next().unwrap();
    let r_recv = it.next().unwrap();
    assert!(it.next().is_none());
    SideWires {
        amount_bits,
        r_order,
        r_order_new,
        locked_bits: [locked0, locked1],
        locked_rand,
        r_locked_new,
        r_recv,
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

/// Encode the settlement constraints over already-allocated wires. Works on
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
/// (the enforced equalities and booleanity variables) so the collaborative
/// prover can validity-check the joint witness before revealing a proof.
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
/// satisfiable can be re-tested on the witness shares. `sat` collection is the
/// only addition over the plain relation; the emitted constraints are
/// identical.
fn settle_relation_impl<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    public: &PublicWires,
    a: &SideWires,
    b: &SideWires,
    sat: &mut SatisfiabilityWitness,
) -> Result<(), CircuitError> {
    // 1. Booleanity of every amount bit (both sides).
    for side in [a, b] {
        enforce_bits(cs, &side.amount_bits)?;
        enforce_bits(cs, &side.locked_bits[0])?;
        enforce_bits(cs, &side.locked_bits[1])?;
        sat.bool_vars.extend_from_slice(&side.amount_bits);
        sat.bool_vars.extend_from_slice(&side.locked_bits[0]);
        sat.bool_vars.extend_from_slice(&side.locked_bits[1]);
    }
    // a_is_seller is chain-provided but constrain it anyway; its complement
    // selects B's role.
    cs.enforce_bool(public.a_is_seller)?;
    sat.bool_vars.push(public.a_is_seller);
    let a_seller = as_bool_unchecked(public.a_is_seller);
    let b_seller = cs.logic_neg(a_seller)?;

    // Enforce `x == y` and record the pair for the validity gate. Defined
    // after the booleanity block so it does not hold a borrow of `sat` while
    // `bool_vars` is still being filled above.
    let mut eq = |cs: &mut Cs, x: Variable, y: Variable| -> Result<(), CircuitError> {
        cs.enforce_equal(x, y)?;
        sat.eq_pairs.push((x, y));
        Ok(())
    };

    // 2. Reconstruct amounts from bits (guarantees 64-bit range).
    let a_amt = le_bits_to_field(cs, &a.amount_bits)?;
    let b_amt = le_bits_to_field(cs, &b.amount_bits)?;

    // 3. Open the on-chain order commitments.
    let order_a_hash = poseidon_hash2(cs, a_amt, a.r_order)?;
    eq(cs, order_a_hash, public.order_a)?;
    let order_b_hash = poseidon_hash2(cs, b_amt, b.r_order)?;
    eq(cs, order_b_hash, public.order_b)?;

    // 4. Open the locked collateral commitments and sum each side.
    let mut locked_sum = [cs.zero(); 2];
    for (idx, side) in [a, b].into_iter().enumerate() {
        let pub_hashes = if idx == 0 {
            &public.locked_a
        } else {
            &public.locked_b
        };
        let mut sum = cs.zero();
        for slot in 0..MAX_LOCKED {
            let amt = le_bits_to_field(cs, &side.locked_bits[slot])?;
            let h = poseidon_hash2(cs, amt, side.locked_rand[slot])?;
            eq(cs, h, pub_hashes[slot])?;
            sum = cs.add(sum, amt)?;
        }
        locked_sum[idx] = sum;
    }

    // 5. Collateral backing at the execution price (strict equality; the
    //    equal-price limitation documented for the 3-party path applies).
    //    SOUNDNESS ASSUMPTION: `price` is a public input the CHAIN provides
    //    and guarantees < 2^64 (it is a u64 on-chain). Under that bound all
    //    products here are < 2^128 < r, so field arithmetic is
    //    integer-exact. The circuit does not re-range-check price.
    let a_times_price = cs.mul(a_amt, public.price)?;
    let a_needed = cs.mux(a_seller, a_amt, a_times_price)?;
    eq(cs, locked_sum[0], a_needed)?;
    let b_times_price = cs.mul(b_amt, public.price)?;
    let b_needed = cs.mux(b_seller, b_amt, b_times_price)?;
    eq(cs, locked_sum[1], b_needed)?;

    // 6. Comparison: cmp = (a > b) - (a < b) must equal the public claim.
    let (lt, eq_flag) = cmp_from_bits(cs, &a.amount_bits, &b.amount_bits)?;
    // gt = 1 - lt - eq
    let one_var = cs.one();
    let zero = cs.zero();
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

    // 7. fill = min(a, b) = b + lt * (a - b); remainders a' , b'.
    let diff = cs.sub(a_amt, b_amt)?;
    let lt_diff = cs.mul(lt, diff)?;
    let fill = cs.add(b_amt, lt_diff)?;
    let a_new = cs.sub(a_amt, fill)?;
    let b_new = cs.sub(b_amt, fill)?;

    // 8. Updated order commitments.
    let new_order_a = poseidon_hash2(cs, a_new, a.r_order_new)?;
    eq(cs, new_order_a, public.new_order_a)?;
    let new_order_b = poseidon_hash2(cs, b_new, b.r_order_new)?;
    eq(cs, new_order_b, public.new_order_b)?;

    // 9. Updated locked collateral commitments (remainder, per side token).
    let a_new_price = cs.mul(a_new, public.price)?;
    let a_locked_new = cs.mux(a_seller, a_new, a_new_price)?;
    let h = poseidon_hash2(cs, a_locked_new, a.r_locked_new)?;
    eq(cs, h, public.new_locked_a)?;
    let b_new_price = cs.mul(b_new, public.price)?;
    let b_locked_new = cs.mux(b_seller, b_new, b_new_price)?;
    let h = poseidon_hash2(cs, b_locked_new, b.r_locked_new)?;
    eq(cs, h, public.new_locked_b)?;

    // 10. Receive commitments: a seller of token1 receives fill*price
    //     token2; a buyer receives fill token1.
    let fill_price = cs.mul(fill, public.price)?;
    let recv_a_amt = cs.mux(a_seller, fill_price, fill)?;
    let h = poseidon_hash2(cs, recv_a_amt, a.r_recv)?;
    eq(cs, h, public.recv_a)?;
    let recv_b_amt = cs.mux(b_seller, fill_price, fill)?;
    let h = poseidon_hash2(cs, recv_b_amt, b.r_recv)?;
    eq(cs, h, public.recv_b)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::sample_trade;

    #[test]
    fn compute_public_sample() {
        let (a, b, price, a_is_seller) = sample_trade();
        let p = compute_public(&a, &b, price, a_is_seller).unwrap();
        assert_eq!(p.cmp, 1); // a=80 > b=60
        assert_eq!(p.to_vec().len(), 15);
        // Zero-pad slots must equal the chain's zero commitment.
        assert_eq!(
            crate::poseidon::fr_to_hex(&p.locked_a[1]),
            "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"
        );
    }

    #[test]
    fn compute_public_rejects_bad_collateral() {
        let (mut a, b, price, a_is_seller) = sample_trade();
        a.locked = vec![(79, [0xA3; 32])];
        assert!(compute_public(&a, &b, price, a_is_seller).is_err());
    }
}
