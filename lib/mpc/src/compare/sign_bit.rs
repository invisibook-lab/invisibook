use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_mpc::{
    MpcFabric,
    algebra::{AuthenticatedScalarResult, Scalar},
};
use async_trait::async_trait;
use num_bigint::BigUint;

use crate::{
    compare::{K, KAPPA, LessThan, LtInputs},
    fabric::Curve,
};

/// Sign-bit-of-difference less-than.
///
/// Given shared `a`, `b ∈ [0, 2^K)`, build `x = a − b + 2^K` (so
/// `x ∈ [1, 2^{K+1})`); the bit at position `K` of `x` equals 1 iff
/// `a ≥ b`. We bit-decompose `x` with the masked-reveal trick — reveal
/// `c = x + r` for a random shared-bit scalar `r = Σ 2^i r_i`, then recover
/// the low bits of `x = c − r` from public bits of `c` and shared bits of
/// `r` via a sequential borrow chain.
///
/// The final answer is `1 − x_K`.
pub struct SignBit;

#[async_trait]
impl LessThan for SignBit {
    async fn less_than(
        &self,
        inputs: &LtInputs<'_>,
        fabric: &MpcFabric<Curve>,
    ) -> AuthenticatedScalarResult<Curve> {
        // `l = K + 1 + KAPPA` random bits for statistical masking of x
        // (x ∈ [0, 2^{K+1})). The masked reveal c = x + r fits comfortably
        // inside BN254's ~254-bit field.
        let l = K + 1 + KAPPA;

        // x = a - b + 2^K  (shared, non-negative in [1, 2^{K+1})).
        let two_k = Scalar::<Curve>::new(pow2_fr(K));
        let x = &(inputs.a - inputs.b) + two_k;

        // Mask: r = Σ 2^i r_i with fresh authenticated shared bits.
        let r_bits = fabric.random_shared_bits(l);
        let mut r_scalar = fabric.zero_authenticated();
        for (i, r_i) in r_bits.iter().enumerate() {
            let pow = Scalar::<Curve>::new(pow2_fr(i));
            r_scalar = &r_scalar + &(r_i * pow);
        }

        // Reveal c = x + r. c < 2^{l+1} < p, so reading as integer is safe.
        let c_auth = &x + &r_scalar;
        let c_scalar = c_auth
            .open_authenticated()
            .await
            .expect("authenticated open of masked value must succeed");
        let c_bits = field_to_low_bits(c_scalar.inner(), l + 1);

        // Subtraction chain for x = c - r. Only the first K+1 bits matter
        // because we only need x_K (the sign bit). Each iteration uses one
        // Beaver multiplication (s_i · borrow).
        let one = fabric.one_authenticated();
        let two = Scalar::<Curve>::from(2u64);
        let one_s = Scalar::<Curve>::from(1u64);

        let mut borrow = fabric.zero_authenticated();
        let mut x_k = fabric.zero_authenticated();

        for i in 0..=K {
            let r_i = &r_bits[i];
            let c_i = Scalar::<Curve>::from(c_bits[i] as u64);

            // s_i = c_i XOR r_i  = c_i + r_i − 2·c_i·r_i  (c_i public, free).
            let two_ci = &two * c_i;
            let s_i = &(r_i + c_i) - &(r_i * two_ci);

            // x_i = s_i XOR borrow  = s_i + borrow − 2·s_i·borrow.
            let cross = &s_i * &borrow; // Beaver mult
            let x_i = &(&s_i + &borrow) - &(&cross * &two);

            if i == K {
                x_k = x_i;
                break;
            }

            // borrow_{i+1} = (1 − c_i)·r_i + borrow − s_i·borrow
            //               = (NOT c_i)·r_i + borrow·(1 − s_i)
            let not_ci = one_s - c_i;
            let not_ci_r = r_i * not_ci;
            borrow = &(&not_ci_r + &borrow) - &cross;
        }

        // lt = 1 − x_K.
        &one - &x_k
    }
}

/// `2^i` as a BN254 `Fr`. `i` must be < 254.
fn pow2_fr(i: usize) -> Fr {
    let mut acc = BigUint::from(1u8);
    acc <<= i;
    Fr::from_le_bytes_mod_order(&acc.to_bytes_le())
}

/// Extract the least-significant `n` bits of `x` as booleans.
///
/// `x` must fit in the first `n` bits (callers ensure this by construction).
fn field_to_low_bits(x: Fr, n: usize) -> Vec<bool> {
    let bytes = x.into_bigint().to_bytes_le();
    (0..n)
        .map(|i| {
            let byte = bytes.get(i / 8).copied().unwrap_or(0);
            (byte >> (i % 8)) & 1 == 1
        })
        .collect()
}
