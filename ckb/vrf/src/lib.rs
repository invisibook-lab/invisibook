//! ECVRF verification for the CKB contract, byte-compatible with the L2 side.
//!
//! The L2 chain proves with `vechain/go-ecvrf`'s `Secp256k1Sha256Tai` suite
//! (draft-irtf-cfrg-vrf-06). Anything this module hashes, encodes or truncates
//! must match that implementation exactly, or a proof the L2 accepts will be
//! rejected on chain and the two layers will disagree about who won a height.
//!
//! Suite parameters: secp256k1, SHA-256, suite string `0xFE`, cofactor 1,
//! try-and-increment hash-to-curve.

#![cfg_attr(not(test), no_std)]

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// Suite string of Secp256k1_SHA256_TAI.
const SUITE: u8 = 0xFE;

/// Length of a compressed secp256k1 point.
const POINT_LEN: usize = 33;
/// Length of the challenge `c`, which the suite truncates to half a field
/// element rounded up: `((256 + 1) / 2 + 7) / 8` = 16 bytes.
const C_LEN: usize = 16;
/// Length of the scalar `s`, a full group element.
const S_LEN: usize = 32;
/// Length of a proof: gamma || c || s.
pub const PROOF_LEN: usize = POINT_LEN + C_LEN + S_LEN;
/// Length of the VRF output `beta`.
pub const BETA_LEN: usize = 32;

/// Why a proof was rejected. The contract only needs to know that it was.
#[derive(Debug, PartialEq, Eq)]
pub enum VrfError {
    /// `pi` was not `PROOF_LEN` bytes.
    ProofLength,
    /// The public key or gamma was not a point on the curve.
    InvalidPoint,
    /// `c` or `s` was zero, or `s` was not below the group order.
    InvalidScalar,
    /// No valid curve point was found in 256 try-and-increment rounds.
    HashToCurveFailed,
    /// The recomputed challenge did not match the one in the proof.
    ChallengeMismatch,
}

/// Verifies `pi` over `alpha` under `pubkey`, returning the VRF output `beta`.
///
/// `pubkey` is a compressed secp256k1 point; `alpha` is the exact byte string
/// the prover hashed, domain tag included; `pi` is the 81-byte proof.
pub fn verify(
    pubkey: &[u8; POINT_LEN],
    alpha: &[u8],
    pi: &[u8],
) -> Result<[u8; BETA_LEN], VrfError> {
    if pi.len() != PROOF_LEN {
        return Err(VrfError::ProofLength);
    }

    let y = decompress(pubkey).ok_or(VrfError::InvalidPoint)?;

    // Step 1: decode the proof into (gamma, c, s).
    let gamma_bytes: [u8; POINT_LEN] = pi[..POINT_LEN].try_into().unwrap();
    let gamma = decompress(&gamma_bytes).ok_or(VrfError::InvalidPoint)?;
    let c = scalar_from_challenge(&pi[POINT_LEN..POINT_LEN + C_LEN])?;
    let s = scalar_from_full(&pi[POINT_LEN + C_LEN..])?;

    // Step 2: H = hash_to_curve(pubkey, alpha).
    let h = hash_to_curve_tai(pubkey, alpha)?;

    // Step 3: U = s*B - c*Y, V = s*H - c*Gamma.
    let u = ProjectivePoint::GENERATOR * s - ProjectivePoint::from(y) * c;
    let v = h * s - gamma_proj(&gamma) * c;

    // Step 4: the challenge recomputed from the four points must match.
    let derived = hash_points(&[
        compress(&h),
        compress_affine(&gamma),
        compress(&u),
        compress(&v),
    ]);
    if derived != pi[POINT_LEN..POINT_LEN + C_LEN] {
        return Err(VrfError::ChallengeMismatch);
    }

    Ok(gamma_to_hash(&gamma))
}

/// Derives `beta` from gamma. Split out because a verifier that already trusts
/// a proof may want the output without repeating the checks.
/// The cofactor is 1, so gamma is hashed as-is.
pub fn gamma_to_hash(gamma: &AffinePoint) -> [u8; BETA_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([SUITE, 0x03]);
    hasher.update(compress_affine(gamma));
    hasher.finalize().into()
}

/// Maps `alpha` onto the curve by try-and-increment.
///
/// Each round hashes `suite || 0x01 || pubkey || alpha || ctr` and reads the
/// digest as the x coordinate of an even-y compressed point. Most counters
/// yield an x with no square root, so the loop runs until one does.
fn hash_to_curve_tai(pubkey: &[u8; POINT_LEN], alpha: &[u8]) -> Result<ProjectivePoint, VrfError> {
    let mut candidate = [0u8; POINT_LEN];
    candidate[0] = 0x02; // compressed, even y

    for ctr in 0u16..256 {
        let mut hasher = Sha256::new();
        hasher.update([SUITE, 0x01]);
        hasher.update(pubkey);
        hasher.update(alpha);
        hasher.update([ctr as u8]);
        candidate[1..].copy_from_slice(&hasher.finalize());

        if let Some(point) = decompress(&candidate) {
            return Ok(ProjectivePoint::from(point));
        }
    }
    Err(VrfError::HashToCurveFailed)
}

/// Hashes the four points into the challenge: `suite || 0x02 || p1 .. p4`,
/// truncated to the leftmost `C_LEN` bytes.
///
/// The truncation is `bits2int` from RFC 6979: the digest is 256 bits and the
/// challenge is 128, so the top half is kept — which for a byte-aligned width
/// is simply the leading bytes.
fn hash_points(points: &[[u8; POINT_LEN]]) -> [u8; C_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([SUITE, 0x02]);
    for point in points {
        hasher.update(point);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; C_LEN];
    out.copy_from_slice(&digest[..C_LEN]);
    out
}

/// Reads the challenge as a scalar. It is `C_LEN` bytes, so it is always below
/// the group order; only zero is rejected.
fn scalar_from_challenge(bytes: &[u8]) -> Result<Scalar, VrfError> {
    let mut padded = [0u8; S_LEN];
    padded[S_LEN - C_LEN..].copy_from_slice(bytes);
    let scalar = Scalar::from_repr(padded.into());
    let scalar: Option<Scalar> = scalar.into();
    match scalar {
        Some(s) if s != Scalar::ZERO => Ok(s),
        _ => Err(VrfError::InvalidScalar),
    }
}

/// Reads `s` as a scalar, rejecting zero and anything at or above the order.
fn scalar_from_full(bytes: &[u8]) -> Result<Scalar, VrfError> {
    let repr: [u8; S_LEN] = bytes.try_into().map_err(|_| VrfError::InvalidScalar)?;
    let scalar: Option<Scalar> = Scalar::from_repr(repr.into()).into();
    match scalar {
        Some(s) if s != Scalar::ZERO => Ok(s),
        _ => Err(VrfError::InvalidScalar),
    }
}

/// Decompresses a 33-byte SEC1 point.
fn decompress(bytes: &[u8; POINT_LEN]) -> Option<AffinePoint> {
    let encoded = EncodedPoint::from_bytes(bytes).ok()?;
    Option::from(AffinePoint::from_encoded_point(&encoded))
}

/// Compresses a projective point to 33 bytes.
fn compress(point: &ProjectivePoint) -> [u8; POINT_LEN] {
    compress_affine(&point.to_affine())
}

/// Compresses an affine point to 33 bytes.
fn compress_affine(point: &AffinePoint) -> [u8; POINT_LEN] {
    let encoded = point.to_encoded_point(true);
    let mut out = [0u8; POINT_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// Lifts gamma into projective form for the arithmetic above.
fn gamma_proj(gamma: &AffinePoint) -> ProjectivePoint {
    ProjectivePoint::from(*gamma)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tuple produced by the L2 chain's prover
    /// (`chain/consensus/vrf_vector_test.go`). It is the whole point of this
    /// module: if the contract and the chain ever disagree byte for byte, a
    /// proof one side accepts the other rejects, and the two layers settle on
    /// different winners.
    const PUBKEY: &str = "0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0";
    const ALPHA: &str = "696e76697369626f6f6b2d7672662d696e7075743a706172656e742d626c6f636b2d686173682d7374616e642d696e2d2d2d2d2d2d";
    const PI: &str = "0265a9303778fdb8309477b76c5055ab169fec67c539c57e0b08ce3c1c0383a84a1132a9c33331312c3a5612617357cef5bf0a356b9e2183068e606187ec214f8b554862268b261576087b3374fa49bd2d";
    const BETA: &str = "5cba6b0d039d18b7acb2be6f1759da78e69fc8df38747e205e4a617cb06b1bbe";

    fn pubkey() -> [u8; POINT_LEN] {
        hex::decode(PUBKEY).unwrap().try_into().unwrap()
    }

    #[test]
    fn accepts_a_proof_from_the_l2_prover() {
        let beta = verify(
            &pubkey(),
            &hex::decode(ALPHA).unwrap(),
            &hex::decode(PI).unwrap(),
        )
        .expect("the chain's own proof must verify here");
        assert_eq!(
            hex::encode(beta),
            BETA,
            "beta must match the chain's output"
        );
    }

    #[test]
    fn rejects_a_proof_over_a_different_input() {
        let mut alpha = hex::decode(ALPHA).unwrap();
        alpha[0] ^= 0x01;
        assert_eq!(
            verify(&pubkey(), &alpha, &hex::decode(PI).unwrap()),
            Err(VrfError::ChallengeMismatch)
        );
    }

    #[test]
    fn rejects_a_tampered_proof() {
        let mut pi = hex::decode(PI).unwrap();
        // Flip a bit of s: the challenge no longer reproduces.
        let last = pi.len() - 1;
        pi[last] ^= 0x01;
        assert_eq!(
            verify(&pubkey(), &hex::decode(ALPHA).unwrap(), &pi),
            Err(VrfError::ChallengeMismatch)
        );
    }

    #[test]
    fn rejects_a_proof_under_another_key() {
        let mut other = pubkey();
        other[0] = if other[0] == 0x02 { 0x03 } else { 0x02 };
        let result = verify(
            &other,
            &hex::decode(ALPHA).unwrap(),
            &hex::decode(PI).unwrap(),
        );
        assert!(
            result.is_err(),
            "a proof must not verify under a different key"
        );
    }

    #[test]
    fn rejects_a_malformed_proof_length() {
        assert_eq!(
            verify(&pubkey(), &hex::decode(ALPHA).unwrap(), &[0u8; 10]),
            Err(VrfError::ProofLength)
        );
    }
}
