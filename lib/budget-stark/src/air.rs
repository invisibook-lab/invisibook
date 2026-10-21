//! The R3.2 balance AIR: one row per allocation-table entry.
//!
//! Public values (12):
//!
//! ```text
//!   0..8    chain digest over every row's commitment (see hash::chain_digest)
//!   8..12   prepaid as four 16-bit little-endian limbs
//! ```
//!
//! Row layout:
//!
//! ```text
//!   COMMIT   Poseidon2 trace of the commitment   H(limbs, random, 0000)
//!   CHAIN    Poseidon2 trace of the chain step    H(acc_prev, commitment)
//!   BITS     64 bits of the amount
//!   SUM      running per-limb sums T_0..T_3, left unnormalised
//!   CARRY    3 × 11 carry bits, used on the last row only
//! ```
//!
//! What each part buys:
//!
//! * The bits make every limb a genuine 16-bit value, so an amount is a u64
//!   and nothing wraps around the 31-bit field.
//! * The chain ties row i's commitment to the i-th commitment the verifier
//!   holds, with eight public values instead of eight per entry.
//! * Limb sums are carried unnormalised down the table — at most 1024 rows of
//!   16-bit limbs stay below 2^26 — and normalised once on the last row
//!   against `prepaid`, with carries bounded to 11 bits so none of those
//!   equations can wrap either.

use core::{borrow::Borrow, ops::Range};

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL,
    KOALABEAR_S_BOX_DEGREE, KoalaBear,
};
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants, num_cols};
use p3_uni_stark::SubAirBuilder;

use crate::hash::{DIGEST_LEN, LIMB_BITS, LIMBS, RANDOM_LEN, WIDTH};

/// S-box helper registers. Zero keeps the x^3 S-box a single degree-3
/// constraint and the row narrow.
pub const SBOX_REGISTERS: usize = 0;
pub const HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
pub const PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;

/// The Poseidon2 sub-AIR, one permutation per row.
pub type PermAir = Poseidon2Air<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    WIDTH,
    KOALABEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;
/// Columns of one permutation.
pub type PermCols<T> = Poseidon2Cols<
    T,
    WIDTH,
    KOALABEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;
/// Round constants in the sub-AIR's layout.
pub type PermConstants = RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

/// Width of one permutation's columns.
pub const PERM_WIDTH: usize =
    num_cols::<WIDTH, KOALABEAR_S_BOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
/// Amount bits per row.
pub const AMOUNT_BITS: usize = LIMBS * LIMB_BITS;
/// Bits per normalisation carry.
pub const CARRY_BITS: usize = 11;
/// Carries between the four limbs.
pub const CARRIES: usize = LIMBS - 1;

pub const COMMIT: Range<usize> = 0..PERM_WIDTH;
pub const CHAIN: Range<usize> = PERM_WIDTH..2 * PERM_WIDTH;
pub const BITS: Range<usize> = CHAIN.end..CHAIN.end + AMOUNT_BITS;
pub const SUM: Range<usize> = BITS.end..BITS.end + LIMBS;
pub const CARRY: Range<usize> = SUM.end..SUM.end + CARRIES * CARRY_BITS;
/// Total trace width.
pub const TRACE_WIDTH: usize = CARRY.end;

/// Public values: chain digest, then prepaid limbs.
pub const NUM_PUBLIC_VALUES: usize = DIGEST_LEN + LIMBS;

/// Most rows a table may have. Keeps every unnormalised limb sum below 2^26,
/// which is what CARRY_BITS and the no-wrap argument rely on.
pub const MAX_ROWS: usize = 1 << 10;

/// Returns the sub-AIR's round constants: the same ones the native
/// permutation uses.
pub fn perm_constants() -> PermConstants {
    RoundConstants::new(
        KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        KOALABEAR_POSEIDON2_RC_16_INTERNAL,
        KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

/// The balance AIR.
pub struct BudgetAir {
    perm: PermAir,
}

impl BudgetAir {
    /// Builds the AIR with the standard KoalaBear Poseidon2 constants.
    pub fn new() -> Self {
        BudgetAir {
            perm: PermAir::new(perm_constants()),
        }
    }
}

impl Default for BudgetAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<KoalaBear> for BudgetAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    /// Exactly the columns `eval` reads on the next row: the next commitment's
    /// limbs, the next chain input's accumulator half, and the next sums.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (COMMIT.start..COMMIT.start + LIMBS)
            .chain(CHAIN.start..CHAIN.start + DIGEST_LEN)
            .chain(SUM)
            .collect()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

/// The output state of a permutation laid out in `cols`: the post-state of
/// its last full round.
fn perm_output<T: Copy>(cols: &PermCols<T>) -> &[T; WIDTH] {
    &cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
}

/// `Σ bits[k] · 2^k` over `bits`, little-endian.
fn from_bits<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter().enumerate().fold(AB::Expr::ZERO, |acc, (k, b)| {
        acc + (*b).into() * AB::F::from_u32(1 << k)
    })
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for BudgetAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|&p| p.into()).collect();

        let commit: &PermCols<AB::Var> = local[COMMIT].borrow();
        let chain: &PermCols<AB::Var> = local[CHAIN].borrow();
        let bits = &local[BITS];
        let sum = &local[SUM];
        let carry = &local[CARRY];
        let commitment = perm_output(commit);
        let acc = perm_output(chain);

        // Both permutations are checked by the stock Poseidon2 AIR, each over
        // its own slice of the row.
        self.perm
            .eval(&mut SubAirBuilder::<AB, PermAir, AB::Var>::new(
                builder, COMMIT,
            ));
        self.perm
            .eval(&mut SubAirBuilder::<AB, PermAir, AB::Var>::new(
                builder, CHAIN,
            ));

        for &b in bits.iter().chain(carry) {
            builder.assert_bool(b);
        }

        // Commitment input: 16-bit limbs from the bits, blinding, zero tail.
        for j in 0..LIMBS {
            let limb = from_bits::<AB>(&bits[LIMB_BITS * j..LIMB_BITS * (j + 1)]);
            builder.assert_eq(commit.inputs[j], limb);
        }
        for &x in &commit.inputs[LIMBS + RANDOM_LEN..] {
            builder.assert_zero(x);
        }

        // Chain input: this row's commitment in the second half.
        for k in 0..DIGEST_LEN {
            builder.assert_eq(chain.inputs[DIGEST_LEN + k], commitment[k]);
        }

        // First row: the chain starts from zero, the sums from this amount.
        {
            let mut first = builder.when_first_row();
            for k in 0..DIGEST_LEN {
                first.assert_zero(chain.inputs[k]);
            }
            for j in 0..LIMBS {
                first.assert_eq(sum[j], commit.inputs[j]);
            }
        }

        // Every later row continues the chain and adds its amount.
        {
            let next_commit_limbs = &next[COMMIT.start..COMMIT.start + LIMBS];
            let next_chain_acc = &next[CHAIN.start..CHAIN.start + DIGEST_LEN];
            let next_sum = &next[SUM];
            let mut step = builder.when_transition();
            for k in 0..DIGEST_LEN {
                step.assert_eq(next_chain_acc[k], acc[k]);
            }
            for j in 0..LIMBS {
                step.assert_eq(next_sum[j], sum[j] + next_commit_limbs[j]);
            }
        }

        // Last row: the chain ends at the verifier's digest, and the sums
        // normalise to prepaid. With P_j the prepaid limbs and c_j the carries:
        //   T_0         = P_0 + 2^16 c_0
        //   T_1 + c_0   = P_1 + 2^16 c_1
        //   T_2 + c_1   = P_2 + 2^16 c_2
        //   T_3 + c_2   = P_3
        let carries: Vec<AB::Expr> = (0..CARRIES)
            .map(|j| from_bits::<AB>(&carry[CARRY_BITS * j..CARRY_BITS * (j + 1)]))
            .collect();
        let base = AB::F::from_u32(1 << LIMB_BITS);
        let mut last = builder.when_last_row();
        for k in 0..DIGEST_LEN {
            last.assert_eq(acc[k], pis[k].clone());
        }
        for j in 0..LIMBS {
            let carry_in = if j == 0 {
                AB::Expr::ZERO
            } else {
                carries[j - 1].clone()
            };
            let carry_out = if j == CARRIES {
                AB::Expr::ZERO
            } else {
                carries[j].clone() * base
            };
            last.assert_eq(sum[j] + carry_in, pis[DIGEST_LEN + j].clone() + carry_out);
        }
    }
}
