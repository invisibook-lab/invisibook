//! MPC settlement protocol using ark-mpc over BN254.
//!
//! Replaces the Python/MP-SPDZ bridge with a pure Rust 2PC protocol.
//!
//! Protocol:
//! 1. Both parties secret-share their values (v, r) and commitments (C1, C2)
//! 2. Verify commitment consistency (C1_a == C1_b, C2_a == C2_b)
//! 3. Compute Poseidon hashes in MPC and verify against commitments
//! 4. Compare v1 vs v2
//! 5. Reveal loser's randomness

use std::net::SocketAddr;

use ark_bn254::g1::Config as BnConfig;
use ark_bn254::Fr;
use ark_ec::short_weierstrass::Projective;
use ark_ff::PrimeField; // used in fr_to_decimal
use ark_mpc::{
    algebra::Scalar, beaver::PartyIDBeaverSource, network::QuicTwoPartyNet, MpcFabric, PARTY0,
    PARTY1,
};
use serde::{Deserialize, Serialize};

use crate::compare;
use crate::constants::fr_from_decimal;
use crate::error::MpcError;
use crate::poseidon;

type Curve = Projective<BnConfig>;

/// Configuration for the MPC settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleConfig {
    /// Party ID: 0 for Alice, 1 for Bob.
    pub party_id: u64,
    /// Local address to bind for QUIC transport.
    pub local_addr: SocketAddr,
    /// Peer address to connect to.
    pub peer_addr: SocketAddr,
}

/// Result of the MPC settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleResult {
    /// `true` if party 0's value >= party 1's value.
    pub cmp: bool,
    /// The loser's randomness (decimal string of BN254 field element).
    pub revealed_r: String,
}

/// Convert Fr to Scalar for use with ark-mpc share_scalar.
fn to_scalar(fr: Fr) -> Scalar<Curve> {
    Scalar::new(fr)
}

/// Run the MPC settlement protocol.
///
/// # Arguments
/// - `config`: Network and party configuration.
/// - `my_value`: This party's secret amount (u64).
/// - `my_random`: This party's secret randomness (BN254 Fr, decimal string).
/// - `c1`: Commitment 1 = poseidon(v1, r1) (decimal string).
/// - `c2`: Commitment 2 = poseidon(v2, r2) (decimal string).
///
/// # Returns
/// `SettleResult` with comparison outcome and the loser's revealed randomness.
pub async fn settle(
    config: &SettleConfig,
    my_value: u64,
    my_random: &str,
    c1: &str,
    c2: &str,
) -> Result<SettleResult, MpcError> {
    // Parse field elements
    let my_r = fr_from_decimal(my_random);
    let c1_fr = fr_from_decimal(c1);
    let c2_fr = fr_from_decimal(c2);
    let my_v_fr = Fr::from(my_value);

    // Setup network
    let mut net =
        QuicTwoPartyNet::<Curve>::new(config.party_id, config.local_addr, config.peer_addr);
    net.connect()
        .await
        .map_err(|e| MpcError::Network(e.to_string()))?;

    // Use PartyIDBeaverSource for development/testing.
    // Production would use OT-based triple generation.
    let beaver = PartyIDBeaverSource::new(config.party_id);
    let fabric = MpcFabric::new(net, beaver);

    let dummy = Scalar::<Curve>::from(0u64);

    // --- Share inputs ---
    // Party 0 shares v1, r1; Party 1 shares v2, r2.
    // Sender provides real value, receiver provides dummy (ignored by the protocol).
    let (v1, v2) = if config.party_id == 0 {
        let v1 = fabric.share_scalar(to_scalar(my_v_fr), PARTY0);
        let v2 = fabric.share_scalar(dummy, PARTY1);
        (v1, v2)
    } else {
        let v1 = fabric.share_scalar(dummy, PARTY0);
        let v2 = fabric.share_scalar(to_scalar(my_v_fr), PARTY1);
        (v1, v2)
    };

    let (r1, r2) = if config.party_id == 0 {
        let r1 = fabric.share_scalar(to_scalar(my_r), PARTY0);
        let r2 = fabric.share_scalar(dummy, PARTY1);
        (r1, r2)
    } else {
        let r1 = fabric.share_scalar(dummy, PARTY0);
        let r2 = fabric.share_scalar(to_scalar(my_r), PARTY1);
        (r1, r2)
    };

    // Share commitments from both parties
    let (c1_a, c2_a) = if config.party_id == 0 {
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

    let (c1_b, c2_b) = if config.party_id == 1 {
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
    // Only opens a statistically-masked value and the 1-bit result.
    // Never reveals v1 - v2.
    let cmp_bit = compare::compare_geq(&v1, &v2).await?;
    let cmp_open = cmp_bit
        .open_authenticated()
        .await
        .map_err(|e| MpcError::Auth(format!("comparison bit MAC failed: {e}")))?;
    let cmp = cmp_open.inner() == Fr::from(1u64);

    // --- Step 4: Reveal loser's randomness ---
    let revealed_r = if cmp {
        // v1 >= v2: Bob loses, reveal r2
        let r2_open = r2.open_authenticated();
        let r2_val = r2_open
            .await
            .map_err(|e| MpcError::Auth(format!("r2 reveal MAC failed: {e}")))?;
        fr_to_decimal(&r2_val.inner())
    } else {
        // v1 < v2: Alice loses, reveal r1
        let r1_open = r1.open_authenticated();
        let r1_val = r1_open
            .await
            .map_err(|e| MpcError::Auth(format!("r1 reveal MAC failed: {e}")))?;
        fr_to_decimal(&r1_val.inner())
    };

    // Shutdown the fabric
    fabric.shutdown();

    Ok(SettleResult { cmp, revealed_r })
}

/// Convert a BN254 field element to its decimal string representation.
fn fr_to_decimal(fr: &Fr) -> String {
    let bigint = fr.into_bigint();
    let limbs = bigint.as_ref(); // &[u64; 4]

    if limbs.iter().all(|&l| l == 0) {
        return "0".to_string();
    }

    // Convert big-endian byte representation to decimal
    let mut bytes: Vec<u8> = Vec::new();
    for &limb in limbs.iter().rev() {
        for i in (0..8).rev() {
            bytes.push(((limb >> (i * 8)) & 0xff) as u8);
        }
    }

    let mut decimal_digits: Vec<u8> = vec![0];
    for byte in &bytes {
        // Multiply decimal_digits by 256
        let mut carry = 0u16;
        for d in decimal_digits.iter_mut() {
            let v = (*d as u16) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            decimal_digits.push((carry % 10) as u8);
            carry /= 10;
        }
        // Add byte
        let mut carry = *byte as u16;
        for d in decimal_digits.iter_mut() {
            let v = (*d as u16) + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
            if carry == 0 {
                break;
            }
        }
        while carry > 0 {
            decimal_digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }

    // decimal_digits is little-endian. Reverse and convert to string.
    while decimal_digits.len() > 1 && *decimal_digits.last().unwrap() == 0 {
        decimal_digits.pop();
    }
    decimal_digits
        .iter()
        .rev()
        .map(|d| (b'0' + d) as char)
        .collect()
}
