//! Beaver AND triple generation using Oblivious Transfer.
//!
//! A Beaver AND triple is a tuple (a, b, c) in GF(2) with c = a AND b,
//! represented as additive XOR shares between two parties P0 and P1:
//!   a = a0 ⊕ a1,  b = b0 ⊕ b1,  c = c0 ⊕ c1,  c0 ⊕ c1 = (a0⊕a1) AND (b0⊕b1)
//!
//! Generation (2 OT calls per triple):
//!   Both parties pick random bits for their (a_i, b_i).
//!   Cross terms a0·b1 and a1·b0 are computed via OT:
//!
//!   • a0·b1: P0 is OT-Sender with msgs (r01, r01⊕a0), P1 is OT-Receiver with choice b1.
//!            P0's share = r01;  P1's share = r01 ⊕ (a0·b1).
//!
//!   • a1·b0: P1 is OT-Sender with msgs (r10, r10⊕a1), P0 is OT-Receiver with choice b0.
//!            P1's share = r10;  P0's share = r10 ⊕ (a1·b0).
//!
//!   Final:
//!     c0 = a0·b0 ⊕ r01 ⊕ (r10 ⊕ a1·b0)
//!     c1 = a1·b1 ⊕ (r01 ⊕ a0·b1) ⊕ r10
//!
//! Online AND gate (Beaver protocol):
//!   Given shares [x] = (x0,x1) and [y] = (y0,y1) and a pre-computed triple:
//!     Reveal: d = x ⊕ a  (both parties open their d_i)
//!             e = y ⊕ b
//!     P0 computes: z0 = c0 ⊕ (d·b0) ⊕ (e·a0) ⊕ (d·e)
//!     P1 computes: z1 = c1 ⊕ (d·b1) ⊕ (e·a1)
//!   Result: z0 ⊕ z1 = x AND y

use crate::ot::simulate_bit_ot;
use rand::{rngs::OsRng, Rng};

/// P0's share of a Beaver AND triple.
#[derive(Clone, Debug)]
pub struct AndTriple0 {
    pub a: bool,
    pub b: bool,
    pub c: bool,
}

/// P1's share of a Beaver AND triple.
#[derive(Clone, Debug)]
pub struct AndTriple1 {
    pub a: bool,
    pub b: bool,
    pub c: bool,
}

/// Generate one Beaver AND triple via two OT calls.
/// Returns `(P0's share, P1's share)`.
pub fn generate_and_triple() -> (AndTriple0, AndTriple1) {
    let mut rng = OsRng;

    let a0: bool = rng.gen();
    let b0: bool = rng.gen();
    let a1: bool = rng.gen();
    let b1: bool = rng.gen();

    // Local products
    let c_local0 = a0 & b0;
    let c_local1 = a1 & b1;

    // Cross term a0·b1: P0 sends (r01, r01⊕a0); P1 chooses with b1.
    let r01: bool = rng.gen();
    let p1_share_01 = simulate_bit_ot(r01, r01 ^ a0, b1);
    // p1_share_01 = r01 ⊕ (a0 AND b1); P0's share = r01.

    // Cross term a1·b0: P1 sends (r10, r10⊕a1); P0 chooses with b0.
    let r10: bool = rng.gen();
    let p0_share_10 = simulate_bit_ot(r10, r10 ^ a1, b0);
    // p0_share_10 = r10 ⊕ (a1 AND b0); P1's share = r10.

    let c0 = c_local0 ^ r01 ^ p0_share_10;
    let c1 = c_local1 ^ p1_share_01 ^ r10;

    (
        AndTriple0 { a: a0, b: b0, c: c0 },
        AndTriple1 { a: a1, b: b1, c: c1 },
    )
}

/// Generate `n` Beaver AND triples.
pub fn generate_triples(n: usize) -> (Vec<AndTriple0>, Vec<AndTriple1>) {
    let mut t0 = Vec::with_capacity(n);
    let mut t1 = Vec::with_capacity(n);
    for _ in 0..n {
        let (a, b) = generate_and_triple();
        t0.push(a);
        t1.push(b);
    }
    (t0, t1)
}

/// Evaluate one AND gate using a pre-computed Beaver triple (simulation).
///
/// Arguments are the XOR shares of the two input bits and the triple.
/// Returns XOR shares of `(x0⊕x1) AND (y0⊕y1)`.
pub fn beaver_and(
    x0: bool,
    x1: bool,
    y0: bool,
    y1: bool,
    t0: &AndTriple0,
    t1: &AndTriple1,
) -> (bool, bool) {
    // Reveal d = x ⊕ a and e = y ⊕ b (both parties XOR their local shares and open).
    let d = (x0 ^ t0.a) ^ (x1 ^ t1.a);
    let e = (y0 ^ t0.b) ^ (y1 ^ t1.b);

    // Local output shares.
    let z0 = t0.c ^ (d & t0.b) ^ (e & t0.a) ^ (d & e);
    let z1 = t1.c ^ (d & t1.b) ^ (e & t1.a);

    (z0, z1)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_bit(a: bool, b: bool) -> bool {
        a ^ b
    }

    #[test]
    fn triple_invariant() {
        for _ in 0..50 {
            let (t0, t1) = generate_and_triple();
            let a = xor_bit(t0.a, t1.a);
            let b = xor_bit(t0.b, t1.b);
            let c = xor_bit(t0.c, t1.c);
            assert_eq!(c, a & b, "triple invariant c = a AND b violated");
        }
    }

    #[test]
    fn beaver_and_all_cases() {
        for x0 in [false, true] {
            for x1 in [false, true] {
                for y0 in [false, true] {
                    for y1 in [false, true] {
                        let x = x0 ^ x1;
                        let y = y0 ^ y1;
                        let expected = x & y;

                        let (t0, t1) = generate_and_triple();
                        let (z0, z1) = beaver_and(x0, x1, y0, y1, &t0, &t1);
                        assert_eq!(
                            z0 ^ z1,
                            expected,
                            "beaver_and({},{},{},{}) = {} but got {}",
                            x0,
                            x1,
                            y0,
                            y1,
                            expected,
                            z0 ^ z1
                        );
                    }
                }
            }
        }
    }
}
