//! Circuit gadgets for the 2-party settlement relation, written against the
//! generic `mpc_relation::traits::Circuit<F>` trait so the SAME code builds
//! both the single-prover `PlonkCircuit` (key generation, baselines) and the
//! `MpcPlonkCircuit` (collaborative proving). Trait-default gate methods
//! compute witness values through the associated `Wire` type, so on the MPC
//! circuit every operation transparently runs on SPDZ shares.
//!
//! Design note: the MPC circuit has NO range/comparison/hash gadgets and no
//! way to bit-decompose a shared value (that would need a dedicated MPC
//! protocol). All amounts therefore enter the circuit as *bits supplied by
//! the party that knows them in plaintext*; everything downstream (value
//! reconstruction, comparison, Poseidon) is pure arithmetic on wires.

use ark_bn254::Fr;
use ark_ff::Field;
use mpc_relation::{BoolVar, Variable, errors::CircuitError, traits::Circuit};

use crate::constants::{FULL_ROUNDS, PARTIAL_ROUNDS, T, ark, mds};

/// Bit width of every amount in the system (matches the Groth16 circuits'
/// `Num2Bits(64)` range checks).
pub const AMOUNT_BITS: usize = 64;

/// Allocate the little-endian bits of `value` as bool-constrained wires.
/// The caller must ensure `wires` were created from actual bits; this
/// enforces booleanity so a lying prover cannot satisfy the circuit.
pub fn enforce_bits<Cs: Circuit<Fr>>(cs: &mut Cs, wires: &[Variable]) -> Result<(), CircuitError> {
    for &w in wires {
        cs.enforce_bool(w)?;
    }
    Ok(())
}

/// Reconstruct the field value of little-endian `bits` (bool-constrained by
/// the caller): `sum_i bits[i] * 2^i`. Uses chained 4-term linear
/// combinations (3 bits folded per gate).
pub fn le_bits_to_field<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    bits: &[Variable],
) -> Result<Variable, CircuitError> {
    let zero = cs.zero();
    let mut acc = zero;
    let mut power = Fr::from(1u64);
    for chunk in bits.chunks(3) {
        let mut wires = [acc, zero, zero, zero];
        let mut coeffs = [
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];
        for (j, &b) in chunk.iter().enumerate() {
            wires[j + 1] = b;
            coeffs[j + 1] = power;
            power.double_in_place();
        }
        acc = cs.lc(&wires, &coeffs)?;
    }
    Ok(acc)
}

/// Compare two bit-decomposed values (little-endian, equal length, bits
/// bool-constrained). Returns `(lt, eq)` wires with
/// `lt = (a < b) ? 1 : 0` and `eq = (a == b) ? 1 : 0`, via an MSB-first
/// scan: `lt += eq_prefix * (1 - a_i) * b_i`, `eq_prefix *= XNOR(a_i, b_i)`.
pub fn cmp_from_bits<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    a_bits: &[Variable],
    b_bits: &[Variable],
) -> Result<(Variable, Variable), CircuitError> {
    assert_eq!(a_bits.len(), b_bits.len(), "bit widths must match");
    let zero = cs.zero();
    let one_var = cs.one();
    let mut eq_prefix = one_var;
    let mut lt = zero;
    for (&a_i, &b_i) in a_bits.iter().zip(b_bits.iter()).rev() {
        // m = a_i * b_i
        let m = cs.mul(a_i, b_i)?;
        // xnor = 1 - a_i - b_i + 2*m
        let xnor = cs.lc(
            &[one_var, a_i, b_i, m],
            &[
                Fr::from(1u64),
                -Fr::from(1u64),
                -Fr::from(1u64),
                Fr::from(2u64),
            ],
        )?;
        // strict-less at this bit: (1 - a_i) * b_i = b_i - m
        let t = cs.sub(b_i, m)?;
        // lt += eq_prefix * t
        let term = cs.mul(eq_prefix, t)?;
        lt = cs.add(lt, term)?;
        // eq_prefix *= xnor
        eq_prefix = cs.mul(eq_prefix, xnor)?;
    }
    Ok((lt, eq_prefix))
}

/// Circom-compatible Poseidon(t=3) permutation over wires; returns the full
/// final state. Round constants/MDS come from [`crate::constants`], the same
/// parameters as `light-poseidon::new_circom(2)` and the on-chain circuits.
fn poseidon_permute<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    mut state: [Variable; T],
) -> Result<[Variable; T], CircuitError> {
    let ark = ark();
    let mds = mds();
    let zero = cs.zero();
    let half = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;

    for r in 0..total {
        // AddRoundConstants
        for (i, s) in state.iter_mut().enumerate() {
            *s = cs.add_constant(*s, &ark[r * T + i])?;
        }
        // S-box (x^5): all lanes in full rounds, lane 0 in partial rounds
        let full = r < half || r >= half + PARTIAL_ROUNDS;
        let lanes = if full { T } else { 1 };
        for s in state.iter_mut().take(lanes) {
            *s = cs.pow5(*s)?;
        }
        // MDS mix: each lane is a 3-term linear combination
        let mut next = state;
        for (i, row) in mds.iter().enumerate() {
            next[i] = cs.lc(
                &[state[0], state[1], state[2], zero],
                &[row[0], row[1], row[2], Fr::from(0u64)],
            )?;
        }
        state = next;
    }
    Ok(state)
}

/// Poseidon hash of two wires with circom domain tag 0:
/// `hash2(a, b) = permute([0, a, b])[0]`. Must agree with
/// [`crate::poseidon::hash2`] on every input.
pub fn poseidon_hash2<Cs: Circuit<Fr>>(
    cs: &mut Cs,
    a: Variable,
    b: Variable,
) -> Result<Variable, CircuitError> {
    let zero = cs.zero();
    let state = poseidon_permute(cs, [zero, a, b])?;
    Ok(state[0])
}

/// Wrap an already bool-enforced wire as a `BoolVar` (for `mux`/logic
/// gadgets). `w` must have been passed through `enforce_bool`.
pub fn as_bool_unchecked(w: Variable) -> BoolVar {
    BoolVar::new_unchecked(w)
}
