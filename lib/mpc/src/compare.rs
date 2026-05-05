//! Zero-leakage u64 comparison over secret-shared BN254 field elements.
//!
//! Uses masked bit decomposition to determine if `v1 >= v2` without
//! revealing anything other than the single comparison bit.
//!
//! Algorithm:
//! 1. Compute `[d] = [v1] - [v2] + 2^64` (shift to range [1, 2^65))
//! 2. Generate 105 random shared bits (65 + κ=40) → compose mask `[r]`
//! 3. Open `c = [d] + [r]` — statistically hides d (2^-40 advantage)
//! 4. Borrow-propagation circuit: extract bit 64 of `d = c - r` using
//!    public c_bits and shared r_bits
//! 5. Return shared comparison bit (1 = v1 >= v2)
//!
//! Only reveals: the masked value `c` (indistinguishable from random)
//! and the final 1-bit comparison result. Never reveals v1 - v2.

use ark_bn254::g1::Config as BnConfig;
use ark_bn254::Fr;
use ark_ec::short_weierstrass::Projective;
use ark_ff::PrimeField;
use ark_mpc::algebra::{AuthenticatedScalarResult, Scalar};

use crate::error::MpcError;

type Curve = Projective<BnConfig>;

/// Statistical security parameter (extra masking bits).
const KAPPA: usize = 40;
/// Number of bits needed for comparison (65 for u64 + offset bit).
const CMP_BITS: usize = 65;
/// Total random bits: CMP_BITS + KAPPA = 105.
const TOTAL_BITS: usize = CMP_BITS + KAPPA;

/// Compare two secret-shared u64 values with zero leakage.
///
/// Returns a shared bit (as `AuthenticatedScalarResult`):
/// - 1 if v1 >= v2
/// - 0 if v1 < v2
///
/// The only values opened during this protocol are:
/// - `c = d + r` where r has 105 random bits (statistically hides d)
/// - The final 1-bit result
///
/// Cost: ~65 Beaver triples for borrow propagation + 1 opening round.
pub async fn compare_geq(
    v1: &AuthenticatedScalarResult<Curve>,
    v2: &AuthenticatedScalarResult<Curve>,
) -> Result<AuthenticatedScalarResult<Curve>, MpcError> {
    let fabric = v1.fabric();

    // --- Phase 1: Mask and open ---

    // d = v1 - v2 + 2^64
    // If v1 >= v2: d in [2^64, 2^65), bit 64 = 1
    // If v1 < v2:  d in [1, 2^64),   bit 64 = 0
    let offset = Scalar::<Curve>::new(Fr::from(1u64 << 63) * Fr::from(2u64)); // 2^64
    let d = v1 - v2 + &offset;

    // Generate 105 random shared bits
    let r_bits: Vec<AuthenticatedScalarResult<Curve>> =
        (0..TOTAL_BITS).map(|_| fabric.random_shared_bit()).collect();

    // Compose [r] = Σ r_i * 2^i
    let mut r = fabric.zero_authenticated();
    let mut power = Fr::from(1u64);
    let two = Fr::from(2u64);
    for bit in &r_bits {
        r = &r + &(bit * &Scalar::<Curve>::new(power));
        power *= two;
    }

    // Open c = d + r (safe: r has 40 extra bits of statistical masking)
    let c_shared = &d + &r;
    let c_open = c_shared
        .open_authenticated()
        .await
        .map_err(|e| MpcError::Auth(format!("masked comparison open failed: {e}")))?;

    // --- Phase 2: Borrow-propagation circuit ---

    // Extract public bits of c
    let c_fr = c_open.inner();
    let c_bits = extract_bits(&c_fr, CMP_BITS + 1); // need bits 0..64 inclusive

    // Compute bit 64 of d = c - r via ripple-carry subtraction:
    //   d_i = c_i XOR r_i XOR borrow_i
    //   borrow_{i+1} depends on c_i (public):
    //     if c_i = 0: borrow_{i+1} = [r_i] + [borrow] - [r_i] * [borrow]
    //     if c_i = 1: borrow_{i+1} = [r_i] * [borrow]
    let mut borrow = fabric.zero_authenticated();

    for i in 0..CMP_BITS {
        if c_bits[i] {
            // c_i = 1: borrow_{i+1} = r_i AND borrow = r_i * borrow
            borrow = &r_bits[i] * &borrow;
        } else {
            // c_i = 0: borrow_{i+1} = r_i OR borrow = r_i + borrow - r_i * borrow
            let prod = &r_bits[i] * &borrow;
            borrow = &(&r_bits[i] + &borrow) - &prod;
        }
    }

    // d_64 = c_64 XOR r_64 XOR borrow_64
    // Since c_64 is public, we compute:
    let cmp_bit = if c_bits[CMP_BITS - 1] {
        // c_64 = 1: d_64 = 1 XOR r_64 XOR borrow = NOT(r_64 XOR borrow)
        //         = 1 - (r_64 + borrow - 2 * r_64 * borrow)
        let xor = xor_shared(&r_bits[CMP_BITS - 1], &borrow);
        let one = Scalar::<Curve>::from(1u64);
        &one - &xor
    } else {
        // c_64 = 0: d_64 = 0 XOR r_64 XOR borrow = r_64 XOR borrow
        xor_shared(&r_bits[CMP_BITS - 1], &borrow)
    };

    Ok(cmp_bit)
}

/// XOR of two shared bits: a XOR b = a + b - 2*a*b
fn xor_shared(
    a: &AuthenticatedScalarResult<Curve>,
    b: &AuthenticatedScalarResult<Curve>,
) -> AuthenticatedScalarResult<Curve> {
    let prod = a * b;
    let two = Scalar::<Curve>::from(2u64);
    &(a + b) - &(&prod * &two)
}

/// Extract the first `n` bits of a field element (little-endian).
fn extract_bits(fr: &Fr, n: usize) -> Vec<bool> {
    let bigint = fr.into_bigint();
    let limbs = bigint.as_ref(); // &[u64; 4]
    let mut bits = Vec::with_capacity(n);
    for i in 0..n {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        if limb_idx < limbs.len() {
            bits.push((limbs[limb_idx] >> bit_idx) & 1 == 1);
        } else {
            bits.push(false);
        }
    }
    bits
}
