//! Poseidon hash over SPDZ secret-shared BN254 field elements.
//!
//! Port of `lib/mpc/src/poseidon.rs` onto the pinned ark-mpc fork: the same
//! circom-compatible permutation as [`crate::poseidon`] (t=3, domain tag 0,
//! 8 full + 57 partial rounds, x^5 S-box), evaluated on
//! `AuthenticatedScalarResult` wires so a commitment `C = Poseidon(v, r)`
//! can be verified inside the MPC without opening `v` or `r`.
//!
//! Cost note: ARK addition and MDS mixing use only public constants (no
//! Beaver triples); the x^5 S-box is the only triple-consuming operation.

use ark_bn254::G1Projective;
use ark_mpc::{
    MpcFabric,
    algebra::{AuthenticatedScalarResult, Scalar},
};

use crate::constants::{FULL_ROUNDS, PARTIAL_ROUNDS, T, ark, mds};

/// Poseidon hash of two shared field elements with circom domain tag 0:
/// state starts as `[0, a, b]` and the hash is `state[0]` after the full
/// permutation. Must agree with [`crate::poseidon::hash2`] on every input.
/// `a` and `b` must belong to `fabric`.
pub fn poseidon_hash(
    fabric: &MpcFabric<G1Projective>,
    a: &AuthenticatedScalarResult<G1Projective>,
    b: &AuthenticatedScalarResult<G1Projective>,
) -> AuthenticatedScalarResult<G1Projective> {
    let ark = ark();
    let mds = mds();
    let zero = fabric.zero_authenticated();

    let mut state: [AuthenticatedScalarResult<G1Projective>; T] = [zero, a.clone(), b.clone()];

    let half = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;

    for r in 0..total {
        // AddRoundConstants: public scalar addition, free of triples.
        for (i, s) in state.iter_mut().enumerate() {
            let c = Scalar::new(ark[r * T + i]);
            *s = &*s + &c;
        }
        // S-box (x^5): all lanes in full rounds, lane 0 in partial rounds.
        let full = r < half || r >= half + PARTIAL_ROUNDS;
        let lanes = if full { T } else { 1 };
        for s in state.iter_mut().take(lanes) {
            *s = s.pow(5);
        }
        // MDS mix: scalar-by-public multiplication, free of triples.
        state = mds_mix(&state, mds);
    }

    state[0].clone()
}

/// MDS matrix multiplication `new[i] = sum_j(state[j] * MDS[i][j])` over
/// shared wires with public matrix entries.
fn mds_mix(
    state: &[AuthenticatedScalarResult<G1Projective>; T],
    mds: &[[ark_bn254::Fr; T]; T],
) -> [AuthenticatedScalarResult<G1Projective>; T] {
    let mut result: [Option<AuthenticatedScalarResult<G1Projective>>; T] = [None, None, None];
    for (i, row) in mds.iter().enumerate() {
        let mut acc = &state[0] * &Scalar::new(row[0]);
        acc = &acc + &(&state[1] * &Scalar::new(row[1]));
        acc = &acc + &(&state[2] * &Scalar::new(row[2]));
        result[i] = Some(acc);
    }
    [
        result[0].take().unwrap(),
        result[1].take().unwrap(),
        result[2].take().unwrap(),
    ]
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_mpc::{PARTY0, PARTY1, algebra::Scalar, test_helpers::execute_mock_mpc};

    use super::poseidon_hash;
    use crate::poseidon::hash2;

    /// The shared-wire Poseidon must agree with the native permutation,
    /// including on the zero commitment the chain hardcodes.
    #[tokio::test(flavor = "multi_thread")]
    async fn mpc_poseidon_matches_native() {
        for (a, b) in [
            (Fr::from(0u64), Fr::from(0u64)),
            (Fr::from(80u64), Fr::from(12345u64)),
            (Fr::from(u64::MAX), Fr::from(1u64)),
        ] {
            let expected = hash2(a, b);
            let (r0, r1) = execute_mock_mpc(move |fabric| async move {
                let va = fabric.share_scalar(Scalar::new(a), PARTY0);
                let vb = fabric.share_scalar(Scalar::new(b), PARTY1);
                let h = poseidon_hash(&fabric, &va, &vb);
                h.open_authenticated()
                    .await
                    .expect("MAC check must pass on honest execution")
            })
            .await;
            assert_eq!(r0, Scalar::new(expected));
            assert_eq!(r1, Scalar::new(expected));
        }
    }
}
