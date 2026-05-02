use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    algebra::{AuthenticatedScalarResult, Scalar},
    gadgets::prefix_product,
};
use async_trait::async_trait;

use crate::{
    compare::{K, LessThan, LtInputs},
    fabric::Curve,
};

/// Bit-input less-than with a parallel prefix scan.
///
/// Structurally matches `BitDirect` (each party shares 64 input bits) but the
/// sequential "all higher bits are equal" accumulator is replaced with
/// ark-mpc's `prefix_product` gadget so the depth drops from `O(k)` to
/// `O(log k)` at the cost of extra randomness (inverse pairs) consumed by
/// the prefix product.
pub struct PrefixOr;

#[async_trait]
impl LessThan for PrefixOr {
    async fn less_than(
        &self,
        inputs: &LtInputs<'_>,
        fabric: &MpcFabric<Curve>,
    ) -> AuthenticatedScalarResult<Curve> {
        let a_bits = share_bits(fabric, inputs.party_id, inputs.amount, PARTY0);
        let b_bits = share_bits(fabric, inputs.party_id, inputs.amount, PARTY1);

        let one = fabric.one_authenticated();

        // Per-bit equality and bit-lt indicators, MSB first.
        // eq_i    = 1 - (a_i - b_i)^2
        // lt_i    = (1 - a_i) · b_i
        // Both require one multiplication per bit.
        let mut eq: Vec<AuthenticatedScalarResult<Curve>> = Vec::with_capacity(K);
        let mut lt_bits: Vec<AuthenticatedScalarResult<Curve>> = Vec::with_capacity(K);
        for i in (0..K).rev() {
            let a_i = &a_bits[i];
            let b_i = &b_bits[i];

            let diff = a_i - b_i;
            let diff_sq = &diff * &diff;
            eq.push(&one - &diff_sq);

            let not_a = &one - a_i;
            lt_bits.push(&not_a * b_i);
        }

        // Prefix product of eq values (MSB-first). `prefix_eq[i]` equals 1
        // iff bits MSB..=MSB-i of a and b all matched. Depth O(log K).
        let prefix_eq = prefix_product(&eq, fabric);

        // At bit position j (0-indexed from MSB), the contribution to LT is
        //     lt_bits[j] · prefix_eq[j-1]    for j >= 1
        //     lt_bits[0]                      for j = 0
        // and at most one position contributes (positions are mutually
        // exclusive because prefix_eq[j-1] forces equality in all higher
        // bits while lt_bits[j] forces a != b at j).
        let mut acc = lt_bits[0].clone();
        for j in 1..K {
            let term = &lt_bits[j] * &prefix_eq[j - 1];
            acc = &acc + &term;
        }

        acc
    }
}

/// Share the 64 bits of `amount` on behalf of `sender`.
fn share_bits(
    fabric: &MpcFabric<Curve>,
    party_id: u64,
    amount: u64,
    sender: u64,
) -> Vec<AuthenticatedScalarResult<Curve>> {
    let local = if party_id == sender { amount } else { 0 };
    (0..K)
        .map(|i| {
            let bit = (local >> i) & 1;
            fabric.share_scalar(Scalar::<Curve>::from(bit), sender)
        })
        .collect()
}
