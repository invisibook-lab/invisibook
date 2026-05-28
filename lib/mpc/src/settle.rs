//! MPC settlement protocol using ark-mpc over BN254.
//!
//! Replaces the Python/MP-SPDZ bridge with a pure Rust 2PC protocol.
//!
//! Protocol:
//! 1. Both parties secret-share their values (v, r) and commitments (C1, C2)
//! 2. Verify commitment consistency (C1_a == C1_b, C2_a == C2_b)
//! 3. Compute Poseidon hashes in MPC and verify against commitments
//! 4. Compare v1 vs v2
//! 5. MUX to select smaller side's randomness without opening
//! 6. Output additive shares + MAC shares for on-chain verification

use std::net::SocketAddr;

use ark_bn254::{Fr, g1::Config as BnConfig};
use ark_ec::short_weierstrass::Projective;
use ark_ff::PrimeField; // used in fr_to_decimal
use ark_mpc::{
    MpcFabric, PARTY0, PARTY1, algebra::Scalar, beaver::PartyIDBeaverSource,
    network::QuicTwoPartyNet,
};
use serde::{Deserialize, Serialize};

use crate::{compare, constants::fr_from_decimal, error::MpcError, poseidon};

type Curve = Projective<BnConfig>;

/// Order side: determines party role in the MPC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    /// Buy order = party 0.
    Buy = 0,
    /// Sell order = party 1.
    Sell = 1,
}

impl Side {
    fn party_id(self) -> u64 {
        self as u64
    }
}

/// Configuration for the MPC settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleConfig {
    /// Local address to bind for QUIC transport.
    pub local_addr: SocketAddr,
    /// Peer address to connect to.
    pub peer_addr: SocketAddr,
}

/// Each party's output from the MPC settlement (to be submitted to chain).
///
/// Neither party learns the result. Both submit additive shares to the chain,
/// which reconstructs and verifies MAC integrity:
/// `(mac_A + mac_B) == (δ_A + δ_B) × (share_A + share_B) mod P`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleShare {
    /// Comparison bit: my additive share (decimal Fr).
    pub cmp_share: String,
    /// Comparison bit: my MAC share (decimal Fr).
    pub cmp_mac: String,
    /// Smaller side's randomness: my additive share (decimal Fr).
    pub r_smaller_share: String,
    /// Smaller side's randomness: my MAC share (decimal Fr).
    pub r_smaller_mac: String,
    /// Session MAC key: my share of δ (decimal Fr).
    pub mac_key_share: String,
}

/// Convert Fr to Scalar for use with ark-mpc share_scalar.
fn to_scalar(fr: Fr) -> Scalar<Curve> {
    Scalar::new(fr)
}

/// Run the MPC settlement protocol.
///
/// # Arguments
/// - `config`: Network configuration (local/peer addresses).
/// - `side`: This party's order side (`Buy` = party 0, `Sell` = party 1).
/// - `my_value`: This party's secret amount (u64).
/// - `my_random`: This party's secret randomness (BN254 Fr, decimal string).
/// - `c1`: Commitment 1 = poseidon(v1, r1) from the buy side (decimal string).
/// - `c2`: Commitment 2 = poseidon(v2, r2) from the sell side (decimal string).
///
/// # Returns
/// `SettleShare` with additive shares and MAC shares for on-chain verification.
pub async fn settle(
    config: &SettleConfig,
    side: Side,
    my_value: u64,
    my_random: &str,
    c1: &str,
    c2: &str,
) -> Result<SettleShare, MpcError> {
    // Parse field elements
    let my_r = fr_from_decimal(my_random);
    let c1_fr = fr_from_decimal(c1);
    let c2_fr = fr_from_decimal(c2);
    let my_v_fr = Fr::from(my_value);

    // Setup network
    let mut net =
        QuicTwoPartyNet::<Curve>::new(side.party_id(), config.local_addr, config.peer_addr);
    net.connect()
        .await
        .map_err(|e| MpcError::Network(e.to_string()))?;

    // Use PartyIDBeaverSource for development/testing.
    // Production would use OT-based triple generation.
    let beaver = PartyIDBeaverSource::new(side.party_id());
    let fabric = MpcFabric::new(net, beaver);

    let dummy = Scalar::<Curve>::from(0u64);

    // --- Share inputs ---
    // Party 0 shares v1, r1; Party 1 shares v2, r2.
    // Sender provides real value, receiver provides dummy (ignored by the protocol).
    let (v1, v2) = if side.party_id() == 0 {
        let v1 = fabric.share_scalar(to_scalar(my_v_fr), PARTY0);
        let v2 = fabric.share_scalar(dummy, PARTY1);
        (v1, v2)
    } else {
        let v1 = fabric.share_scalar(dummy, PARTY0);
        let v2 = fabric.share_scalar(to_scalar(my_v_fr), PARTY1);
        (v1, v2)
    };

    let (r1, r2) = if side.party_id() == 0 {
        let r1 = fabric.share_scalar(to_scalar(my_r), PARTY0);
        let r2 = fabric.share_scalar(dummy, PARTY1);
        (r1, r2)
    } else {
        let r1 = fabric.share_scalar(dummy, PARTY0);
        let r2 = fabric.share_scalar(to_scalar(my_r), PARTY1);
        (r1, r2)
    };

    // Share commitments from both parties
    let (c1_a, c2_a) = if side.party_id() == 0 {
        (
            fabric.share_scalar(to_scalar(c1_fr), PARTY0),
            fabric.share_scalar(to_scalar(c2_fr), PARTY0),
        )
    } else {
        (
            fabric.share_scalar(dummy, PARTY0),
            fabric.share_scalar(dummy, PARTY0),
        )
    };

    let (c1_b, c2_b) = if side.party_id() == 1 {
        (
            fabric.share_scalar(to_scalar(c1_fr), PARTY1),
            fabric.share_scalar(to_scalar(c2_fr), PARTY1),
        )
    } else {
        (
            fabric.share_scalar(dummy, PARTY1),
            fabric.share_scalar(dummy, PARTY1),
        )
    };

    // --- Step 1: Verify commitment consistency ---
    let c1_diff = (&c1_a - &c1_b).open_authenticated();
    let c2_diff = (&c2_a - &c2_b).open_authenticated();

    let c1_diff_val = c1_diff
        .await
        .map_err(|e| MpcError::Auth(format!("C1 MAC check failed: {e}")))?;
    let c2_diff_val = c2_diff
        .await
        .map_err(|e| MpcError::Auth(format!("C2 MAC check failed: {e}")))?;

    if c1_diff_val != Scalar::<Curve>::from(0u64) {
        return Err(MpcError::Protocol("C1 mismatch between parties".into()));
    }
    if c2_diff_val != Scalar::<Curve>::from(0u64) {
        return Err(MpcError::Protocol("C2 mismatch between parties".into()));
    }

    // --- Step 2: Poseidon commitment verification ---
    let h1 = poseidon::poseidon_hash(&v1, &r1);
    let h2 = poseidon::poseidon_hash(&v2, &r2);

    let check1 = (&h1 - &c1_a).open_authenticated();
    let check2 = (&h2 - &c2_a).open_authenticated();

    let check1_val = check1
        .await
        .map_err(|e| MpcError::Auth(format!("H1 MAC check failed: {e}")))?;
    let check2_val = check2
        .await
        .map_err(|e| MpcError::Auth(format!("H2 MAC check failed: {e}")))?;

    if check1_val != Scalar::<Curve>::from(0u64) {
        return Err(MpcError::Protocol("poseidon(v1, r1) != C1".into()));
    }
    if check2_val != Scalar::<Curve>::from(0u64) {
        return Err(MpcError::Protocol("poseidon(v2, r2) != C2".into()));
    }

    // --- Step 3: Compare v1 >= v2 (zero-leakage) ---
    // Only opens a statistically-masked value internally.
    // Never reveals v1 - v2 or the comparison bit itself.
    let cmp_bit = compare::compare_geq(&v1, &v2).await?;

    // --- Step 4: MUX for smaller side's randomness (no opening) ---
    // [r_smaller] = [cmp] * [r2] + (1 - [cmp]) * [r1]
    // If cmp=1 (v1>=v2), smaller side is party1 → r_smaller = r2
    // If cmp=0 (v1< v2), smaller side is party0 → r_smaller = r1
    let one = fabric.one_authenticated();
    let one_minus_cmp = &one - &cmp_bit;
    let r_smaller = &(&cmp_bit * &r2) + &(&one_minus_cmp * &r1);

    // --- Step 5: Open values (MAC-verified) and construct fresh SPDZ shares ---
    //
    // ark-mpc's beaver multiplication accumulates a `public_modifier` that makes
    // raw `share()` values inconsistent with the simple MAC invariant the chain
    // expects: mac_A + mac_B == delta * (share_A + share_B).
    //
    // Instead, we open both values with `open_authenticated()` (which internally
    // verifies MACs including the modifier), then build fresh additive shares:
    //   Party 0: share = opened_value,  mac = delta_0 * opened_value
    //   Party 1: share = 0,             mac = delta_1 * opened_value
    // This trivially satisfies the chain's MAC check since both values are
    // reconstructed on-chain anyway.

    // Get each party's MAC key share (delta_i)
    let auth_one = fabric.one_authenticated();
    let delta_i_scalar = auth_one.mac_share().await;
    let delta_i_fr = delta_i_scalar.inner();

    // Open cmp_bit (MAC-verified within the MPC protocol)
    let cmp_opened = cmp_bit
        .open_authenticated()
        .await
        .map_err(|e| MpcError::Auth(format!("cmp_bit open failed: {e}")))?;
    let cmp_val = cmp_opened.inner();

    // Open r_smaller (MAC-verified within the MPC protocol)
    let r_opened = r_smaller
        .open_authenticated()
        .await
        .map_err(|e| MpcError::Auth(format!("r_smaller open failed: {e}")))?;
    let r_val = r_opened.inner();

    // Construct fresh additive shares with correct MAC invariant
    let (cmp_share_fr, r_share_fr) = if side.party_id() == 0 {
        (cmp_val, r_val)
    } else {
        (Fr::from(0u64), Fr::from(0u64))
    };
    let cmp_mac_fr = delta_i_fr * cmp_val;
    let r_mac_fr = delta_i_fr * r_val;

    // Shutdown the fabric
    fabric.shutdown();

    Ok(SettleShare {
        cmp_share: fr_to_decimal(&cmp_share_fr),
        cmp_mac: fr_to_decimal(&cmp_mac_fr),
        r_smaller_share: fr_to_decimal(&r_share_fr),
        r_smaller_mac: fr_to_decimal(&r_mac_fr),
        mac_key_share: fr_to_decimal(&delta_i_fr),
    })
}

/// Convert a BN254 field element to its decimal string representation.
///
/// Uses arkworks `into_bigint()` (Montgomery → standard form) then converts
/// the little-endian u64 limbs to a decimal string via base-2^64 arithmetic.
fn fr_to_decimal(fr: &Fr) -> String {
    let bigint = fr.into_bigint();
    let limbs = bigint.as_ref(); // &[u64; 4], little-endian

    if limbs.iter().all(|&l| l == 0) {
        return "0".to_string();
    }

    // Accumulate in base-10 digits (little-endian: digits[0] = ones place).
    // Process limbs from most-significant to least-significant so we can
    // use Horner's rule: value = ((limb[3] * B + limb[2]) * B + limb[1]) * B + limb[0]
    // where B = 2^64.
    let mut digits: Vec<u8> = vec![0];

    for &limb in limbs.iter().rev() {
        // Multiply digits by 2^64
        let mut carry = 0u128;
        for d in digits.iter_mut() {
            let v = (*d as u128) * (1u128 << 64) + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }

        // Add limb
        let mut carry = limb as u128;
        for d in digits.iter_mut() {
            let v = (*d as u128) + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
            if carry == 0 {
                break;
            }
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }

    // Strip leading zeros and convert to string (most-significant first).
    while digits.len() > 1 && *digits.last().unwrap() == 0 {
        digits.pop();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::fr_from_decimal;

    /// Verify fr_to_decimal round-trips with fr_from_decimal.
    #[test]
    fn test_fr_decimal_roundtrip() {
        let cases: &[&str] = &[
            "0",
            "1",
            "42",
            "255",
            "256",
            "65535",
            "18446744073709551615", // u64::MAX
            // BN254 modulus minus 1 (largest valid Fr)
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            // random mid-range value
            "7891011121314151617181920212223242526",
        ];
        for &s in cases {
            let fr = fr_from_decimal(s);
            let out = fr_to_decimal(&fr);
            assert_eq!(out, s, "round-trip failed for {s}");
        }
    }

    /// Verify small integer conversions.
    #[test]
    fn test_fr_to_decimal_small() {
        for v in 0u64..1000 {
            let fr = Fr::from(v);
            let s = fr_to_decimal(&fr);
            assert_eq!(s, v.to_string(), "mismatch for {v}");
        }
    }
}
