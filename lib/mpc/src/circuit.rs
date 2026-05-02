use ark_bn254::Fr;
use ark_mpc::{MpcFabric, PARTY0, PARTY1, algebra::Scalar};

use crate::{
    compare::{CompareStrategy, LtInputs, less_than_by},
    error::MpcError,
    fabric::Curve,
    poseidon::{MpcPoseidon, PoseidonCfg},
};

/// One end of the 2PC circuit.
///
/// Takes this party's plaintext `amount` plus the public Poseidon hashes
/// agreed up-front (`hash_a` for party 0, `hash_b` for party 1), verifies
/// both hashes in-circuit against the parties' shared inputs, and finally
/// computes `a < b` and opens the authenticated answer.
///
/// Errors if either Poseidon check fails, or if the MAC check on any opened
/// value fails (indicating a malicious counterparty).
pub async fn run_party(
    party_id: u64,
    amount: u64,
    hash_a: Fr,
    hash_b: Fr,
    strategy: CompareStrategy,
    fabric: &MpcFabric<Curve>,
) -> Result<bool, MpcError> {
    // Each side shares its own amount; the counterparty's `amount` arg is
    // irrelevant to the non-sender side of `share_scalar`.
    let my_scalar = Scalar::<Curve>::from(amount);
    let a = fabric.share_scalar(my_scalar, PARTY0);
    let b = fabric.share_scalar(my_scalar, PARTY1);

    // In-circuit Poseidon evaluation on shared a, b.
    let cfg = PoseidonCfg::circom_single();
    let hasher = MpcPoseidon::new(&cfg, fabric);
    let shared_h_a = hasher.hash_single(&a);
    let shared_h_b = hasher.hash_single(&b);

    // MAC-checked open of both hashes.
    let h_a = shared_h_a
        .open_authenticated()
        .await
        .map_err(|_| MpcError::Auth)?;
    let h_b = shared_h_b
        .open_authenticated()
        .await
        .map_err(|_| MpcError::Auth)?;

    if h_a.inner() != hash_a {
        return Err(MpcError::HashMismatch(PARTY0));
    }
    if h_b.inner() != hash_b {
        return Err(MpcError::HashMismatch(PARTY1));
    }

    // Less-than over the shared scalars using the selected strategy.
    let lt_shared = less_than_by(
        strategy,
        &LtInputs {
            a: &a,
            b: &b,
            party_id,
            amount,
        },
        fabric,
    )
    .await;

    let lt = lt_shared
        .open_authenticated()
        .await
        .map_err(|_| MpcError::Auth)?;
    // The answer is a field element in {0, 1}; treat anything non-zero as
    // `a < b` but flag unexpected values as protocol errors.
    let one = Scalar::<Curve>::from(1u64);
    let zero = Scalar::<Curve>::from(0u64);
    if lt == one {
        Ok(true)
    } else if lt == zero {
        Ok(false)
    } else {
        Err(MpcError::Protocol("LT output not in {0,1}".to_string()))
    }
}
