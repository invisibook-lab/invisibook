//! MPC (Multi-Party Computation) library for Invisibook.
//!
//! Maliciously-secure two-party comparison of private `u64` amounts, built on
//! top of ark-mpc's SPDZ implementation over BN254. Each party also proves,
//! in-circuit, that its input matches a public Poseidon commitment, so the
//! circuit as a whole computes
//!
//! ```text
//! assert poseidon(a) == hash_a
//! assert poseidon(b) == hash_b
//! output  a < b
//! ```
//!
//! Three SPDZ-compatible less-than strategies are provided — see
//! [`CompareStrategy`] for the tradeoffs.
//!
//! # Field compatibility
//!
//! Uses `ark_bn254::Fr` so Poseidon outputs match lib/zk's
//! `Poseidon::<Fr>::new_circom(1)`. ark-mpc is on arkworks 0.4 while lib/zk
//! is on 0.5: the prime field is the same and hashes are byte-identical,
//! but the Rust `Fr` type must be converted at the boundary.

pub mod compare;
pub mod error;
pub mod fabric;
pub mod poseidon;

mod circuit;

pub use ark_bn254::Fr;
pub use compare::{CompareStrategy, LtInputs};
pub use error::MpcError;
pub use fabric::{Curve, run_two_party};
pub use poseidon::{MpcPoseidon, PoseidonCfg};

use ark_mpc::PARTY0;

/// Run the full 2PC circuit with both parties executed as in-process tokio
/// tasks over an unbounded duplex channel.
///
/// `amount_p0` and `amount_p1` are the private inputs; `hash_a`, `hash_b` are
/// the public Poseidon commitments each side published in advance. Returns
/// `a < b` on success. Panics if the two parties disagree (which cannot
/// happen in the honest-execution model).
pub async fn run_inprocess(
    amount_p0: u64,
    amount_p1: u64,
    hash_a: Fr,
    hash_b: Fr,
    strategy: CompareStrategy,
) -> Result<bool, MpcError> {
    let (r0, r1) = run_two_party(move |fabric| {
        let pid = fabric.party_id();
        let amount = if pid == PARTY0 { amount_p0 } else { amount_p1 };
        async move { circuit::run_party(pid, amount, hash_a, hash_b, strategy, &fabric).await }
    })
    .await;

    match (r0, r1) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "parties disagreed on LT outcome");
            Ok(a)
        }
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
    }
}

/// Convenience sync wrapper around [`run_inprocess`] that builds a fresh
/// multi-thread tokio runtime. Callers already inside a runtime should call
/// the async function directly.
pub fn compare_amounts(
    amount_p0: u64,
    amount_p1: u64,
    hash_a: Fr,
    hash_b: Fr,
    strategy: CompareStrategy,
) -> Result<bool, MpcError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| MpcError::Protocol(format!("tokio runtime: {e}")))?;
    rt.block_on(run_inprocess(
        amount_p0, amount_p1, hash_a, hash_b, strategy,
    ))
}
