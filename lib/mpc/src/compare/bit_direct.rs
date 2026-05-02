use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    algebra::{AuthenticatedScalarResult, Scalar},
};
use async_trait::async_trait;

use crate::{
    compare::{K, LessThan, LtInputs},
    fabric::Curve,
};

/// Bit-input less-than.
///
/// Each party locally decomposes its `u64` amount into 64 bits and shares
/// each bit as a separate scalar in `{0, 1}`. The comparator then runs a
/// boolean-like scan in the shared-bit domain.
///
/// Round depth: O(k) sequential multiplications for the scan.
/// Triples used: roughly `3k` (one eq multiply + one accumulate multiply per
/// bit + prefix product updates).
pub struct BitDirect;

#[async_trait]
impl LessThan for BitDirect {
    async fn less_than(
        &self,
        inputs: &LtInputs<'_>,
        fabric: &MpcFabric<Curve>,
    ) -> AuthenticatedScalarResult<Curve> {
        // Each party shares its own 64 bits; the counterparty simply provides
        // placeholder zero-values that are ignored by ark-mpc's `share_scalar`
        // (only the declared sender's value is consumed).
        let a_bits = share_bits(fabric, inputs.party_id, inputs.amount, PARTY0);
        let b_bits = share_bits(fabric, inputs.party_id, inputs.amount, PARTY1);

        // Boolean scan from MSB to LSB:
        //   result = OR over i (eq_above_i AND NOT a_i AND b_i)
        // implemented sequentially with an `eq_above` accumulator equal to
        // 1 as long as all prior (higher-index) bits are equal.
        let one = fabric.one_authenticated();
        let mut eq_above = one.clone();
        let mut lt = fabric.zero_authenticated();

        for i in (0..K).rev() {
            let a_i = &a_bits[i];
            let b_i = &b_bits[i];

            // `lt_i = (1 - a_i) * b_i` : at position i, a_i=0 and b_i=1.
            let one_minus_a = &one - a_i;
            let lt_i = &one_minus_a * b_i;

            // `contrib_i = eq_above * lt_i` — active only if all higher-order
            // bits matched so far.
            let contrib = &eq_above * &lt_i;
            lt = &lt + &contrib;

            // Update `eq_above` for the next (lower) bit:
            //   eq_i = 1 - (a_i - b_i)^2   (equals 1 iff a_i == b_i)
            //   eq_above *= eq_i
            let diff = a_i - b_i;
            let diff_sq = &diff * &diff;
            let eq_i = &one - &diff_sq;
            eq_above = &eq_above * &eq_i;
        }

        lt
    }
}

/// Share the 64 bits of a `u64` input coming from `sender`.
///
/// The caller's `party_id` is needed because ark-mpc's `share_scalar` uses
/// whichever side is the sender for the true value; the other side supplies
/// a placeholder that is discarded.
fn share_bits(
    fabric: &MpcFabric<Curve>,
    party_id: u64,
    amount: u64,
    sender: u64,
) -> Vec<AuthenticatedScalarResult<Curve>> {
    // Local plaintext bits of the sender's amount; the non-sender passes
    // zeros and they are ignored by the sharing protocol.
    let local = if party_id == sender { amount } else { 0 };
    (0..K)
        .map(|i| {
            let bit = (local >> i) & 1;
            fabric.share_scalar(Scalar::<Curve>::from(bit), sender)
        })
        .collect()
}
