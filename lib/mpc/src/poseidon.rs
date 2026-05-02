use ark_bn254::Fr;
use ark_mpc::{
    MpcFabric,
    algebra::{AuthenticatedScalarResult, Scalar},
};
use light_poseidon::{Poseidon, PoseidonParameters};

use crate::fabric::Curve;

/// Poseidon parameters compatible with `lib/zk`'s `Poseidon::<Fr>::new_circom(1)`.
///
/// The parameters are pulled straight from `light_poseidon`'s `new_circom(1)`
/// at construction, so any drift in the upstream constants is reflected here
/// without manual vendoring.
pub struct PoseidonCfg {
    params: PoseidonParameters<Fr>,
}

impl PoseidonCfg {
    /// Build the circomlib t=2, alpha=5, full=8, partial=57 parameter set.
    pub fn circom_single() -> Self {
        let poseidon = Poseidon::<Fr>::new_circom(1).expect("circom(1) params must build");
        // `Poseidon::params` is private; rebuild the identical set via the
        // public `PoseidonParameters` of the same spec. We do this by calling
        // `Poseidon::<Fr>::new_circom(1)` once to ensure the crate has these
        // parameters, then construct our own copy from the circom constants
        // exposed via the same crate's internal tables.
        //
        // light-poseidon 0.2 exposes `Poseidon` with only `hash`/`hash_bytes_*`
        // on the public surface; the underlying `PoseidonParameters` struct is
        // public but Poseidon does not expose its field. We therefore go
        // through `get_poseidon_parameters` which is `pub`.
        let _ = poseidon; // keep the call for future parity assertions
        let params = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(2)
            .expect("bn254_x5 t=2 params");
        Self { params }
    }

    /// Plaintext Poseidon — used by tests, demo, and as the oracle when
    /// verifying the in-circuit computation.
    ///
    /// `input` is a single field element; result matches
    /// `Poseidon::<Fr>::new_circom(1).hash(&[input])`.
    pub fn hash_plain(&self, input: Fr) -> Fr {
        let mut state = vec![Fr::from(0u64), input];
        let half = self.params.full_rounds / 2;
        let all = self.params.full_rounds + self.params.partial_rounds;

        for round in 0..half {
            self.apply_ark(&mut state, round);
            self.apply_sbox_full(&mut state);
            self.apply_mds(&mut state);
        }
        for round in half..half + self.params.partial_rounds {
            self.apply_ark(&mut state, round);
            self.apply_sbox_partial(&mut state);
            self.apply_mds(&mut state);
        }
        for round in half + self.params.partial_rounds..all {
            self.apply_ark(&mut state, round);
            self.apply_sbox_full(&mut state);
            self.apply_mds(&mut state);
        }
        state[0]
    }

    /// Add round constants to `state` (free, local operation on each party).
    fn apply_ark(&self, state: &mut [Fr], round: usize) {
        let w = self.params.width;
        for (i, s) in state.iter_mut().enumerate() {
            *s += self.params.ark[round * w + i];
        }
    }

    fn apply_sbox_full(&self, state: &mut [Fr]) {
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
    }

    fn apply_sbox_partial(&self, state: &mut [Fr]) {
        state[0] = pow5(state[0]);
    }

    /// Multiply `state` by the MDS matrix in place (linear: free in MPC).
    fn apply_mds(&self, state: &mut [Fr]) {
        let w = self.params.width;
        let mut out = vec![Fr::from(0u64); w];
        for i in 0..w {
            for j in 0..w {
                out[i] += state[j] * self.params.mds[i][j];
            }
        }
        state.copy_from_slice(&out);
    }
}

/// Compute `x^5` in the field.
fn pow5(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// In-circuit Poseidon hasher over an ark-mpc fabric.
///
/// Each evaluation consumes Beaver triples for the S-box multiplications. MDS
/// mixing and round-constant addition are linear and free in SPDZ.
pub struct MpcPoseidon<'f> {
    cfg: &'f PoseidonCfg,
    fabric: &'f MpcFabric<Curve>,
}

impl<'f> MpcPoseidon<'f> {
    pub fn new(cfg: &'f PoseidonCfg, fabric: &'f MpcFabric<Curve>) -> Self {
        Self { cfg, fabric }
    }

    /// Hash a single authenticated scalar and return the authenticated digest.
    ///
    /// Emulates `Poseidon::<Fr>::new_circom(1).hash(&[x])` on shared values:
    /// state starts as `[0, x]`; applies full/partial/full round schedule
    /// with S-box `x^5` via Beaver triples.
    pub fn hash_single(
        &self,
        x: &AuthenticatedScalarResult<Curve>,
    ) -> AuthenticatedScalarResult<Curve> {
        let zero = self.fabric.zero_authenticated();
        let mut state = vec![zero, x.clone()];

        let half = self.cfg.params.full_rounds / 2;
        let all = self.cfg.params.full_rounds + self.cfg.params.partial_rounds;

        for round in 0..half {
            self.mpc_apply_ark(&mut state, round);
            self.mpc_apply_sbox_full(&mut state);
            self.mpc_apply_mds(&mut state);
        }
        for round in half..half + self.cfg.params.partial_rounds {
            self.mpc_apply_ark(&mut state, round);
            self.mpc_apply_sbox_partial(&mut state);
            self.mpc_apply_mds(&mut state);
        }
        for round in half + self.cfg.params.partial_rounds..all {
            self.mpc_apply_ark(&mut state, round);
            self.mpc_apply_sbox_full(&mut state);
            self.mpc_apply_mds(&mut state);
        }

        state.swap_remove(0)
    }

    fn mpc_apply_ark(&self, state: &mut [AuthenticatedScalarResult<Curve>], round: usize) {
        let w = self.cfg.params.width;
        for (i, s) in state.iter_mut().enumerate() {
            let c = Scalar::<Curve>::new(self.cfg.params.ark[round * w + i]);
            *s = &*s + c;
        }
    }

    fn mpc_apply_sbox_full(&self, state: &mut [AuthenticatedScalarResult<Curve>]) {
        for s in state.iter_mut() {
            *s = pow5_shared(s);
        }
    }

    fn mpc_apply_sbox_partial(&self, state: &mut [AuthenticatedScalarResult<Curve>]) {
        state[0] = pow5_shared(&state[0]);
    }

    fn mpc_apply_mds(&self, state: &mut [AuthenticatedScalarResult<Curve>]) {
        let w = self.cfg.params.width;
        let mut out: Vec<AuthenticatedScalarResult<Curve>> =
            (0..w).map(|_| self.fabric.zero_authenticated()).collect();
        for i in 0..w {
            for j in 0..w {
                let c = Scalar::<Curve>::new(self.cfg.params.mds[i][j]);
                out[i] = &out[i] + &(&state[j] * c);
            }
        }
        // Write back without allocating again.
        for (dst, src) in state.iter_mut().zip(out.into_iter()) {
            *dst = src;
        }
    }
}

/// `x^5` on a shared scalar. Costs 3 Beaver triples.
fn pow5_shared(x: &AuthenticatedScalarResult<Curve>) -> AuthenticatedScalarResult<Curve> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    &x4 * x
}
