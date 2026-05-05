//! Poseidon hash over MPC secret-shared BN254 field elements.
//!
//! Implements the same permutation as `light-poseidon::Poseidon::new_circom(2)`:
//! - State width t=3, domain_tag=0
//! - 4 full rounds + 57 partial rounds + 4 full rounds
//! - S-box: x^5 (via `pow(5)`)
//! - ARK + MDS from [`constants`](crate::constants)

use ark_bn254::g1::Config as BnConfig;
use ark_ec::short_weierstrass::Projective;
use ark_mpc::algebra::{AuthenticatedScalarResult, Scalar};

use crate::constants::{self, FULL_ROUNDS, PARTIAL_ROUNDS, T};

type Curve = Projective<BnConfig>;

/// Compute Poseidon hash of two secret-shared field elements.
///
/// State: `[0, a, b]` (domain_tag = 0 for circom compatibility).
/// Returns `state[0]` after the full permutation.
pub fn poseidon_hash(
    a: &AuthenticatedScalarResult<Curve>,
    b: &AuthenticatedScalarResult<Curve>,
) -> AuthenticatedScalarResult<Curve> {
    let ark = constants::ark();
    let mds = constants::mds();

    let fabric = a.fabric();
    let zero = fabric.zero_authenticated();

    let mut state: [AuthenticatedScalarResult<Curve>; 3] = [zero, a.clone(), b.clone()];

    let half = FULL_ROUNDS / 2; // 4
    let total = FULL_ROUNDS + PARTIAL_ROUNDS; // 65

    // --- First half full rounds (rounds 0..3) ---
    for r in 0..half {
        // AddRoundConstants (public scalar addition, free)
        for i in 0..T {
            let c = Scalar::<Curve>::new(ark[r * T + i]);
            state[i] = &state[i] + &c;
        }
        // Full S-box
        for i in 0..T {
            state[i] = state[i].pow(5);
        }
        // MDS mix
        state = mds_mix(&state, mds);
    }

    // --- Partial rounds (rounds 4..60) ---
    for r in half..(half + PARTIAL_ROUNDS) {
        // AddRoundConstants
        for i in 0..T {
            let c = Scalar::<Curve>::new(ark[r * T + i]);
            state[i] = &state[i] + &c;
        }
        // Partial S-box (only state[0])
        state[0] = state[0].pow(5);
        // MDS mix
        state = mds_mix(&state, mds);
    }

    // --- Second half full rounds (rounds 61..64) ---
    for r in (half + PARTIAL_ROUNDS)..total {
        // AddRoundConstants
        for i in 0..T {
            let c = Scalar::<Curve>::new(ark[r * T + i]);
            state[i] = &state[i] + &c;
        }
        // Full S-box
        for i in 0..T {
            state[i] = state[i].pow(5);
        }
        // MDS mix
        state = mds_mix(&state, mds);
    }

    state[0].clone()
}

/// MDS matrix multiplication: new[i] = sum_j(state[j] * MDS[i][j])
///
/// Since MDS entries are public constants, this is a scalar-by-public multiplication
/// which does not consume Beaver triples.
fn mds_mix(
    state: &[AuthenticatedScalarResult<Curve>; 3],
    mds: &[[ark_bn254::Fr; 3]; 3],
) -> [AuthenticatedScalarResult<Curve>; 3] {
    let mut result: [Option<AuthenticatedScalarResult<Curve>>; 3] = [None, None, None];

    for i in 0..3 {
        let mut acc = &state[0] * &Scalar::<Curve>::new(mds[i][0]);
        acc = &acc + &(&state[1] * &Scalar::<Curve>::new(mds[i][1]));
        acc = &acc + &(&state[2] * &Scalar::<Curve>::new(mds[i][2]));
        result[i] = Some(acc);
    }

    [
        result[0].take().unwrap(),
        result[1].take().unwrap(),
        result[2].take().unwrap(),
    ]
}
