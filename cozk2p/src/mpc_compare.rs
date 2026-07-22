//! Zero-leakage u64 comparison over SPDZ secret-shared BN254 field elements.
//!
//! Port of `lib/mpc/src/compare.rs` onto the pinned ark-mpc fork, plus the
//! three-way comparison the settlement session needs.
//!
//! `compare_geq` algorithm (masked bit decomposition):
//! 1. `[d] = [v1] - [v2] + 2^64` (shift into `[1, 2^65)`; bit 64 of `d` IS
//!    the comparison result)
//! 2. Draw 105 random shared bits (65 + kappa=40) and compose the mask `[r]`
//! 3. Open `c = [d] + [r]` — the 40 extra bits statistically hide `d`
//!    (2^-40 advantage)
//! 4. Ripple-carry borrow circuit on public `c` bits and shared `r` bits
//!    extracts bit 64 of `d = c - r` (~65 Beaver multiplications)
//!
//! Only `c` (statistically masked) and whatever the caller later opens are
//! revealed; `v1 - v2` never is.

use anyhow::{Result, bail};
use ark_bn254::{Fr, G1Projective};
use ark_ff::PrimeField;
use ark_mpc::{
    MpcFabric,
    algebra::{AuthenticatedScalarResult, Scalar},
};

/// Statistical security parameter (extra masking bits).
const KAPPA: usize = 40;
/// Bits needed for the comparison (64 for u64 values + 1 offset bit).
const CMP_BITS: usize = 65;
/// Total random mask bits.
const TOTAL_BITS: usize = CMP_BITS + KAPPA;

/// Compare two secret-shared u64 values with zero leakage, returning a
/// shared bit: 1 iff `v1 >= v2`. Both inputs must belong to `fabric` and
/// must be < 2^64 (guaranteed upstream by the commitment openings the
/// session performs before comparing).
pub fn compare_geq(
    fabric: &MpcFabric<G1Projective>,
    v1: &AuthenticatedScalarResult<G1Projective>,
    v2: &AuthenticatedScalarResult<G1Projective>,
) -> CompareGeq {
    // d = v1 - v2 + 2^64: bit 64 is 1 iff v1 >= v2.
    let offset = Scalar::<G1Projective>::new(Fr::from(1u64 << 63) * Fr::from(2u64));
    let d = v1 - v2 + &offset;

    let r_bits = fabric.random_shared_bits(TOTAL_BITS);

    // Compose [r] = sum_i r_i * 2^i.
    let mut r = fabric.zero_authenticated();
    let mut power = Fr::from(1u64);
    let two = Fr::from(2u64);
    for bit in &r_bits {
        r = &r + &(bit * &Scalar::new(power));
        power *= two;
    }

    // c = d + r is safe to open: 40 extra bits of statistical masking.
    let c_shared = &d + &r;
    CompareGeq {
        c_open: c_shared.open_authenticated(),
        r_bits,
        fabric: fabric.clone(),
    }
}

/// The in-flight state of one `compare_geq` call: the masked opening plus
/// the mask bits needed to finish the borrow circuit once `c` is known.
pub struct CompareGeq {
    c_open: ark_mpc::algebra::AuthenticatedScalarOpenResult<G1Projective>,
    r_bits: Vec<AuthenticatedScalarResult<G1Projective>>,
    fabric: MpcFabric<G1Projective>,
}

impl CompareGeq {
    /// Await the masked opening and run the borrow-propagation circuit,
    /// yielding the shared comparison bit (1 iff `v1 >= v2`).
    pub async fn finish(self) -> Result<AuthenticatedScalarResult<G1Projective>> {
        let c = self
            .c_open
            .await
            .map_err(|e| anyhow::anyhow!("masked comparison open failed (MAC): {e:?}"))?;
        let c_bits = extract_bits(&c.inner(), CMP_BITS + 1);

        // Ripple-carry subtraction d = c - r with public c bits:
        //   c_i = 1: borrow' = r_i AND borrow = r_i * borrow
        //   c_i = 0: borrow' = r_i OR borrow = r_i + borrow - r_i * borrow
        // Process bits 0..CMP_BITS-1 to accumulate the borrow INTO the top
        // bit; the top bit itself is combined in `cmp_bit` below. (Looping
        // through CMP_BITS would double-count the top bit.)
        let mut borrow = self.fabric.zero_authenticated();
        for i in 0..(CMP_BITS - 1) {
            if c_bits[i] {
                borrow = &self.r_bits[i] * &borrow;
            } else {
                let prod = &self.r_bits[i] * &borrow;
                borrow = &(&self.r_bits[i] + &borrow) - &prod;
            }
        }

        // d_64 = c_64 XOR r_64 XOR borrow. `one_authenticated` (not a bare
        // public scalar) keeps the SPDZ public modifier at zero.
        let cmp_bit = if c_bits[CMP_BITS - 1] {
            let xor = xor_shared(&self.r_bits[CMP_BITS - 1], &borrow);
            let one = self.fabric.one_authenticated();
            &one - &xor
        } else {
            xor_shared(&self.r_bits[CMP_BITS - 1], &borrow)
        };
        Ok(cmp_bit)
    }
}

/// Three-way comparison of two shared u64 amounts, opened to BOTH parties:
/// returns `sign(v_a - v_b)` in `{-1, 0, 1}`.
///
/// Runs `compare_geq` in both directions and opens both bits — in the
/// honest domain `cmp` determines both bits, so this leaks nothing beyond
/// `cmp` itself. Any opened value outside `{0, 1}`, or the impossible
/// `(0, 0)` pair (a broken compare or active tampering), aborts instead of
/// being silently mapped onto a valid result.
pub async fn compare_three_way(
    fabric: &MpcFabric<G1Projective>,
    v_a: &AuthenticatedScalarResult<G1Projective>,
    v_b: &AuthenticatedScalarResult<G1Projective>,
) -> Result<i8> {
    // Run each direction to completion sequentially — this is exactly how
    // the standalone `compare_geq` is used and keeps the two borrow circuits
    // from interleaving on the shared fabric.
    let g_ab = compare_geq(fabric, v_a, v_b).finish().await?;
    let g_ba = compare_geq(fabric, v_b, v_a).finish().await?;

    let g_ab = g_ab
        .open_authenticated()
        .await
        .map_err(|e| anyhow::anyhow!("opening geq(a,b) failed (MAC): {e:?}"))?;
    let g_ba = g_ba
        .open_authenticated()
        .await
        .map_err(|e| anyhow::anyhow!("opening geq(b,a) failed (MAC): {e:?}"))?;

    let bit = |s: Scalar<G1Projective>, name: &str| -> Result<bool> {
        if s == Scalar::from(1u64) {
            Ok(true)
        } else if s == Scalar::from(0u64) {
            Ok(false)
        } else {
            bail!("comparison bit {name} opened to a non-bit value");
        }
    };
    match (bit(g_ab, "geq(a,b)")?, bit(g_ba, "geq(b,a)")?) {
        (true, true) => Ok(0),
        (true, false) => Ok(1),
        (false, true) => Ok(-1),
        (false, false) => bail!("impossible comparison state (0,0) — aborting"),
    }
}

/// XOR of two shared bits: `a + b - 2ab`.
fn xor_shared(
    a: &AuthenticatedScalarResult<G1Projective>,
    b: &AuthenticatedScalarResult<G1Projective>,
) -> AuthenticatedScalarResult<G1Projective> {
    let prod = a * b;
    let two = Scalar::<G1Projective>::from(2u64);
    &(a + b) - &(&prod * &two)
}

/// Extract the low `n` bits of a field element, little-endian. `n` must not
/// exceed 256.
fn extract_bits(fr: &Fr, n: usize) -> Vec<bool> {
    let bigint = fr.into_bigint();
    let limbs = bigint.as_ref();
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

#[cfg(test)]
mod tests {
    use ark_mpc::{PARTY0, PARTY1, algebra::Scalar, test_helpers::execute_mock_mpc};

    use super::compare_three_way;

    /// Every branch and the u64 edges must map to the right sign.
    #[tokio::test(flavor = "multi_thread")]
    async fn three_way_branches() {
        for (a, b, expected) in [
            (80u64, 60u64, 1i8),
            (60, 80, -1),
            (60, 60, 0),
            (0, 0, 0),
            (0, 1, -1),
            (u64::MAX, u64::MAX - 1, 1),
            (u64::MAX, u64::MAX, 0),
        ] {
            let (r0, r1) = execute_mock_mpc(move |fabric| async move {
                let va = fabric.share_scalar(Scalar::from(a), PARTY0);
                let vb = fabric.share_scalar(Scalar::from(b), PARTY1);
                compare_three_way(&fabric, &va, &vb)
                    .await
                    .expect("comparison must succeed on honest inputs")
            })
            .await;
            assert_eq!(r0, expected, "a={a} b={b}");
            assert_eq!(r1, expected, "a={a} b={b}");
        }
    }
}
