//! EdaBits-style secure comparison of two `u64` values.
//!
//! # Setting
//! Party P0 holds a secret `x: u64`; Party P1 holds a secret `y: u64`.
//! Neither party reveals their value.  The protocol computes XOR shares of
//! the comparison result `(x > y)`.
//!
//! # Protocol overview
//!
//! ## 1. Input sharing (bit decomposition)
//! Each 64-bit value is decomposed into 64 XOR-shared bits.  For P0's value x:
//!   - For each bit i, P0 samples random mask `r_i`, keeps `x_share0[i] = x_bit[i] ⊕ r_i`,
//!     and "sends" `x_share1[i] = r_i` to P1.
//! Similarly P1 decomposes y.
//!
//! ## 2. Preprocessing (Beaver AND triples)
//! The comparison circuit uses 3 AND gates per bit position, so 3×64 = 192 triples
//! are generated via OT (see `beaver` module).
//!
//! ## 3. Online: comparison circuit
//! Process bits from MSB (63) to LSB (0), maintaining shares of:
//!   - `gt`  = "x > y considering bits 63..i+1 only" (initially 0)
//!   - `eq`  = "x and y are equal on bits 63..i+1"   (initially 1)
//!
//! Each round (one bit `i`):
//!   ```text
//!   d          = x[i] XOR y[i]                    (free: XOR shares)
//!   x_and_d    = AND(x[i], d)                     (AND gate #1)
//!                 = 1 iff x[i]=1 ∧ y[i]=0  →  "x wins at bit i"
//!   contrib    = AND(eq, x_and_d)                 (AND gate #2)
//!                 = 1 iff equal so far ∧ x wins here
//!   gt         = gt XOR contrib                   (free)
//!   eq         = AND(eq, NOT d)  = AND(eq, 1⊕d)  (AND gate #3)
//!   ```
//!
//! ## 4. Output
//! `gt_share0 XOR gt_share1 = 1` iff `x > y`.
//! The public function `compare_uint64` returns the final boolean for convenience.

use crate::beaver::{beaver_and, generate_triples, AndTriple0, AndTriple1};
use rand::{rngs::OsRng, Rng};

// Number of AND gates per bit step in the comparison circuit.
const ANDS_PER_BIT: usize = 3;
const BITS: usize = 64;
const TOTAL_TRIPLES: usize = BITS * ANDS_PER_BIT;

/// P0's private state during the comparison protocol.
pub struct CompareParty0 {
    /// P0's share of each bit of x (x = x_shares0[i] ⊕ x_shares1[i]).
    x_shares: [bool; BITS],
    /// P0's share of each bit of y.
    y_shares: [bool; BITS],
    triples: Vec<AndTriple0>,
}

/// P1's private state during the comparison protocol.
pub struct CompareParty1 {
    x_shares: [bool; BITS],
    y_shares: [bool; BITS],
    triples: Vec<AndTriple1>,
}

/// Decompose a `u64` into XOR shares for both parties.
/// Returns `(shares_for_p0, shares_for_p1)` such that `s0[i] ⊕ s1[i] = bit i of v`.
fn share_u64(v: u64) -> ([bool; BITS], [bool; BITS]) {
    let mut rng = OsRng;
    let mut s0 = [false; BITS];
    let mut s1 = [false; BITS];
    for i in 0..BITS {
        let bit = (v >> i) & 1 == 1;
        let mask: bool = rng.gen();
        s0[i] = bit ^ mask;
        s1[i] = mask;
    }
    (s0, s1)
}

/// Set up both parties for the comparison protocol.
fn setup(x: u64, y: u64) -> (CompareParty0, CompareParty1) {
    let (x_s0, x_s1) = share_u64(x);
    let (y_s0, y_s1) = share_u64(y);
    let (triples0, triples1) = generate_triples(TOTAL_TRIPLES);

    let p0 = CompareParty0 { x_shares: x_s0, y_shares: y_s0, triples: triples0 };
    let p1 = CompareParty1 { x_shares: x_s1, y_shares: y_s1, triples: triples1 };
    (p0, p1)
}

/// Evaluate the comparison circuit.
/// Returns XOR shares `(gt0, gt1)` where `gt0 ⊕ gt1 = (x > y) ? 1 : 0`.
fn evaluate(p0: &CompareParty0, p1: &CompareParty1) -> (bool, bool) {
    // gt = 0: shares (false, false)
    let mut gt0 = false;
    let mut gt1 = false;
    // eq = 1: shares (true, false) so that true ⊕ false = true = 1
    let mut eq0 = true;
    let mut eq1 = false;

    let mut triple_idx = 0;

    for i in (0..BITS).rev() {
        // d = x[i] XOR y[i]  (free, local XOR of shares)
        let d0 = p0.x_shares[i] ^ p0.y_shares[i];
        let d1 = p1.x_shares[i] ^ p1.y_shares[i];

        // AND gate #1: x_and_d = x[i] AND d
        let (xd0, xd1) = beaver_and(
            p0.x_shares[i], p1.x_shares[i],
            d0, d1,
            &p0.triples[triple_idx],
            &p1.triples[triple_idx],
        );
        triple_idx += 1;

        // AND gate #2: contrib = eq AND x_and_d
        let (c0, c1) = beaver_and(eq0, eq1, xd0, xd1, &p0.triples[triple_idx], &p1.triples[triple_idx]);
        triple_idx += 1;

        // gt = gt XOR contrib  (free)
        gt0 ^= c0;
        gt1 ^= c1;

        // NOT(d) as shares: flip P0's share  →  (1⊕d0, d1)
        let not_d0 = !d0;
        let not_d1 = d1;

        // AND gate #3: eq = eq AND NOT(d)
        let (new_eq0, new_eq1) = beaver_and(eq0, eq1, not_d0, not_d1, &p0.triples[triple_idx], &p1.triples[triple_idx]);
        triple_idx += 1;

        eq0 = new_eq0;
        eq1 = new_eq1;
    }

    (gt0, gt1)
}

// ── public API ────────────────────────────────────────────────────────────────

/// Securely compare two `u64` values.
///
/// P0 provides `x`, P1 provides `y`.  The function simulates the 2-party
/// protocol and returns `true` if `x > y`, `false` otherwise.
///
/// In a real deployment, P0 and P1 would run on separate machines; this
/// function merges both sides for testing and demonstration purposes.
pub fn compare_uint64(x: u64, y: u64) -> bool {
    let (p0, p1) = setup(x, y);
    let (gt0, gt1) = evaluate(&p0, &p1);
    gt0 ^ gt1
}

/// Same as `compare_uint64`, but returns the raw XOR shares so that each party
/// can hold their half without learning the result.
pub fn compare_uint64_shares(x: u64, y: u64) -> (bool, bool) {
    let (p0, p1) = setup(x, y);
    evaluate(&p0, &p1)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_basic() {
        assert!(compare_uint64(10, 5));
        assert!(!compare_uint64(5, 10));
        assert!(!compare_uint64(7, 7));
    }

    #[test]
    fn compare_zero() {
        assert!(compare_uint64(1, 0));
        assert!(!compare_uint64(0, 1));
        assert!(!compare_uint64(0, 0));
    }

    #[test]
    fn compare_max() {
        assert!(compare_uint64(u64::MAX, u64::MAX - 1));
        assert!(!compare_uint64(u64::MAX - 1, u64::MAX));
        assert!(!compare_uint64(u64::MAX, u64::MAX));
    }

    #[test]
    fn compare_powers_of_two() {
        for shift in 0..63u32 {
            let a = 1u64 << (shift + 1);
            let b = 1u64 << shift;
            assert!(compare_uint64(a, b), "{a} > {b} should be true");
            assert!(!compare_uint64(b, a), "{b} > {a} should be false");
        }
    }

    #[test]
    fn shares_xor_to_result() {
        let cases = [(100u64, 50u64, true), (50, 100, false), (42, 42, false)];
        for (x, y, expected) in cases {
            let (s0, s1) = compare_uint64_shares(x, y);
            assert_eq!(s0 ^ s1, expected, "shares mismatch for ({x}, {y})");
        }
    }
}
