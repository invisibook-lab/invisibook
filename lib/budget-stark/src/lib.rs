//! Transparent STARK for PoB's R3.2: a budget cell's allocation table adds up
//! exactly to its prepaid total (Plonky3, KoalaBear, Poseidon2 commitments).
//!
//! The statement and why each constraint is there are in `air.rs`; the
//! commitment and the chain that binds the table in `hash.rs`; the STARK
//! parameters in `config.rs`. `verify` is no_std and is what the CKB script
//! runs; `prove` needs the `prover` feature.

#![no_std]

extern crate alloc;

pub mod air;
pub mod config;
pub mod hash;
#[cfg(feature = "prover")]
pub mod prove;
pub mod witness;

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{Proof, verify as stark_verify};
use postcard::from_bytes;

use crate::{
    air::{BudgetAir, MAX_ROWS, NUM_PUBLIC_VALUES},
    config::{BudgetConfig, config},
    hash::{Digest, chain_digest, limbs},
};

#[cfg(feature = "prover")]
pub use crate::prove::prove;

/// Fewest trace rows a proof uses; shorter tables are padded up to it.
///
/// The hiding PCS only stays zero-knowledge while the trace height covers
/// everything a proof discloses about it: `2 · (4 · points + queries)`
/// evaluations, with two opening points (ζ and ζ·g) and NUM_QUERIES = 24,
/// i.e. 64. 128 leaves room to raise the query count without touching this.
pub const MIN_ROWS: usize = 128;
/// Most entries one proof covers.
pub const MAX_ENTRIES: usize = MAX_ROWS;

/// Why a proof could not be made or was not accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The table has no entries.
    Empty,
    /// The table has more than MAX_ENTRIES entries.
    TooLarge,
    /// Amounts and blinding factors differ in number.
    LengthMismatch,
    /// The amounts add up to more than a u64.
    Overflow,
    /// The proof bytes do not decode.
    Malformed,
    /// The proof does not verify against this prepayment and table.
    Rejected,
    /// The prover failed on a well-formed table.
    Prover,
    /// No entropy for the hiding randomness.
    Entropy,
}

/// Trace height for a table of `entries` rows.
/// `entries` must be between 1 and MAX_ENTRIES.
pub fn rows_for(entries: usize) -> usize {
    entries.next_power_of_two().max(MIN_ROWS)
}

/// Rejects table sizes no proof is made for.
fn check_size(entries: usize) -> Result<(), Error> {
    match entries {
        0 => Err(Error::Empty),
        n if n > MAX_ENTRIES => Err(Error::TooLarge),
        _ => Ok(()),
    }
}

/// The public values for `prepaid` and a table of `commitments`.
/// `commitments` must be non-empty and at most MAX_ENTRIES long.
pub fn public_values(prepaid: u64, commitments: &[Digest]) -> Vec<KoalaBear> {
    let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
    out.extend_from_slice(&chain_digest(commitments, rows_for(commitments.len())));
    out.extend(limbs(prepaid).map(KoalaBear::from_u32));
    out
}

/// Verifies `proof` (postcard-encoded) against the plaintext total `prepaid`
/// and the table's `commitments`, in table order.
pub fn verify(prepaid: u64, commitments: &[Digest], proof: &[u8]) -> Result<(), Error> {
    check_size(commitments.len())?;
    let proof: Proof<BudgetConfig> = from_bytes(proof).map_err(|_| Error::Malformed)?;
    let public = public_values(prepaid, commitments);
    // The seed only feeds prover-side hiding randomness.
    let config = config([0u8; 32]);
    stark_verify(&config, &BudgetAir::new(), &proof, &public).map_err(|_| Error::Rejected)
}
