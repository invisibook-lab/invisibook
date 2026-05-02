//! Less-than strategies for two authenticated shared scalars.
//!
//! ark-mpc is SPDZ-only (arithmetic secret sharing). None of the strategies
//! below fall back to garbled circuits or oblivious transfer — they are three
//! different *arithmetic* constructions, included so that round count,
//! multiplication count and randomness consumption can be compared.
//!
//! All strategies return an authenticated shared bit `lt ∈ {0, 1}` with
//! `lt = 1 ⇔ a < b`, assuming `a, b ∈ [0, 2^64)`.

use ark_mpc::{MpcFabric, algebra::AuthenticatedScalarResult};
use async_trait::async_trait;

use crate::fabric::Curve;

pub mod bit_direct;
pub mod prefix_or;
pub mod sign_bit;

/// Tag selecting a comparison strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompareStrategy {
    /// Each party locally splits its input into bits, shares each bit, and the
    /// comparison runs entirely in the boolean domain via a scan comparator.
    BitDirect,
    /// Inputs are shared as field elements; the sign bit of `a - b + 2^k` is
    /// extracted via masked reveal + sequential borrow propagation.
    SignBit,
    /// Same masked-reveal setup as `SignBit`, but the borrow propagation is
    /// replaced by a prefix-OR scan built on ark-mpc's `prefix_product`.
    PrefixOr,
}

/// Inputs consumed by a less-than strategy.
///
/// Arithmetic strategies (`SignBit`, `PrefixOr`) only need `a` and `b`. The
/// bit-input strategy (`BitDirect`) also needs the caller's `party_id` and
/// the local plaintext `amount`, because it re-shares the input as individual
/// bits rather than as one field element.
pub struct LtInputs<'a> {
    pub a: &'a AuthenticatedScalarResult<Curve>,
    pub b: &'a AuthenticatedScalarResult<Curve>,
    pub party_id: u64,
    pub amount: u64,
}

/// Contract implemented by each less-than strategy.
#[async_trait]
pub trait LessThan: Send + Sync {
    /// Return a shared authenticated bit that equals 1 iff `a < b`.
    ///
    /// `inputs.a` and `inputs.b` must represent values in `[0, 2^64)`; the
    /// fabric must have enough preprocessing material (triples, shared bits)
    /// to cover the strategy's consumption.
    async fn less_than(
        &self,
        inputs: &LtInputs<'_>,
        fabric: &MpcFabric<Curve>,
    ) -> AuthenticatedScalarResult<Curve>;
}

/// Plaintext input bit-width.
pub const K: usize = 64;
/// Statistical security parameter used by masked-reveal strategies.
pub const KAPPA: usize = 40;

/// Dispatch helper so callers don't have to instantiate strategy structs.
pub async fn less_than_by(
    strategy: CompareStrategy,
    inputs: &LtInputs<'_>,
    fabric: &MpcFabric<Curve>,
) -> AuthenticatedScalarResult<Curve> {
    match strategy {
        CompareStrategy::BitDirect => bit_direct::BitDirect.less_than(inputs, fabric).await,
        CompareStrategy::SignBit => sign_bit::SignBit.less_than(inputs, fabric).await,
        CompareStrategy::PrefixOr => prefix_or::PrefixOr.less_than(inputs, fabric).await,
    }
}
