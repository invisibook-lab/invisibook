//! Cross-validate our Poseidon constants against light-poseidon crate.
//!
//! This test computes a cleartext Poseidon hash using light-poseidon
//! and verifies that our embedded constants (from settle.mpc) produce
//! the same result when used in a reference implementation.

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};
use mpc::constants::{self, FULL_ROUNDS, PARTIAL_ROUNDS, T, fr_from_decimal};

/// Reference cleartext Poseidon using our constants (same algorithm as MPC version).
fn poseidon_cleartext(a: Fr, b: Fr) -> Fr {
    let ark = constants::ark();
    let mds = constants::mds();

    let mut state = [Fr::from(0u64), a, b];

    let half = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;

    // First half full rounds
    for r in 0..half {
        for i in 0..T {
            state[i] += ark[r * T + i];
        }
        for i in 0..T {
            let x2 = state[i] * state[i];
            let x4 = x2 * x2;
            state[i] = x4 * state[i]; // x^5
        }
        let mut new = [Fr::from(0u64); 3];
        for i in 0..T {
            for j in 0..T {
                new[i] += state[j] * mds[i][j];
            }
        }
        state = new;
    }

    // Partial rounds
    for r in half..(half + PARTIAL_ROUNDS) {
        for i in 0..T {
            state[i] += ark[r * T + i];
        }
        let x2 = state[0] * state[0];
        let x4 = x2 * x2;
        state[0] = x4 * state[0];
        let mut new = [Fr::from(0u64); 3];
        for i in 0..T {
            for j in 0..T {
                new[i] += state[j] * mds[i][j];
            }
        }
        state = new;
    }

    // Second half full rounds
    for r in (half + PARTIAL_ROUNDS)..total {
        for i in 0..T {
            state[i] += ark[r * T + i];
        }
        for i in 0..T {
            let x2 = state[i] * state[i];
            let x4 = x2 * x2;
            state[i] = x4 * state[i];
        }
        let mut new = [Fr::from(0u64); 3];
        for i in 0..T {
            for j in 0..T {
                new[i] += state[j] * mds[i][j];
            }
        }
        state = new;
    }

    state[0]
}

#[test]
fn test_poseidon_matches_light_poseidon() {
    // Test with known inputs
    let a = Fr::from(42u64);
    let b = Fr::from(123u64);

    // Compute with our constants
    let our_hash = poseidon_cleartext(a, b);

    // Compute with light-poseidon
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let lp_hash = hasher.hash(&[a, b]).unwrap();

    assert_eq!(
        our_hash, lp_hash,
        "Poseidon hash mismatch!\n  ours:  {:?}\n  light: {:?}",
        our_hash, lp_hash
    );
}

#[test]
fn test_poseidon_zero_inputs() {
    let a = Fr::from(0u64);
    let b = Fr::from(0u64);

    let our_hash = poseidon_cleartext(a, b);

    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let lp_hash = hasher.hash(&[a, b]).unwrap();

    assert_eq!(our_hash, lp_hash);
}

#[test]
fn test_poseidon_large_values() {
    // Use a large value parsed from decimal
    let a = fr_from_decimal("12345678901234567890");
    let b = fr_from_decimal("98765432109876543210");

    let our_hash = poseidon_cleartext(a, b);

    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let lp_hash = hasher.hash(&[a, b]).unwrap();

    assert_eq!(our_hash, lp_hash);
}

#[test]
fn test_fr_from_decimal_roundtrip() {
    // Parse a known value and verify it matches ark_bn254's From<u64>
    let fr = fr_from_decimal("42");
    assert_eq!(fr, Fr::from(42u64));

    let fr = fr_from_decimal("0");
    assert_eq!(fr, Fr::from(0u64));

    let fr = fr_from_decimal("18446744073709551615"); // u64::MAX
    assert_eq!(fr, Fr::from(u64::MAX));
}
