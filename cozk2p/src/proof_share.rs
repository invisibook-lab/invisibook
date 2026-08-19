//! Canonical wire format for one party's native collaborative-PLONK output.
//!
//! Fiat--Shamir requires the wire, permutation, quotient commitments and
//! polynomial evaluations to be opened while the collaborative prover is
//! running.  Those components are consequently identical in both parties'
//! payloads.  The two final KZG opening commitments remain additively shared;
//! each payload stores only the local value component of the corresponding
//! `PointShare` in those two `Proof` fields.

use anyhow::{Result, anyhow, ensure};
use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_plonk::proof_system::structs::Proof;

/// Version of the canonical comparison-proof-share wire format.
pub const COMPARE_PROOF_SHARE_VERSION: u8 = 1;

/// One MPC party's native share of a collaborative comparison proof.
///
/// `proof.opening_proof` and `proof.shifted_opening_proof` are G1 additive
/// shares, not complete KZG commitments.  Every other `Proof` component is
/// public by the time the Fiat--Shamir transcript reaches the final round and
/// must be byte-for-byte identical between PARTY0 and PARTY1.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompareProofShare {
    pub version: u8,
    pub party_id: u8,
    pub proof: Proof<Bn254>,
}

impl CompareProofShare {
    /// Construct a v1 share for PARTY0 or PARTY1.
    pub fn new(party_id: u64, proof: Proof<Bn254>) -> Result<Self> {
        ensure!(
            party_id <= 1,
            "comparison proof share party_id must be 0 or 1"
        );
        Ok(Self {
            version: COMPARE_PROOF_SHARE_VERSION,
            party_id: party_id as u8,
            proof,
        })
    }

    fn validate_header(&self) -> Result<()> {
        ensure!(
            self.version == COMPARE_PROOF_SHARE_VERSION,
            "unsupported comparison proof share version {}",
            self.version
        );
        ensure!(
            self.party_id <= 1,
            "comparison proof share party_id must be 0 or 1"
        );
        Ok(())
    }
}

/// Serialize a proof share using arkworks' compressed canonical encoding.
pub fn serialize_compare_proof_share(share: &CompareProofShare) -> Result<Vec<u8>> {
    share.validate_header()?;
    let mut bytes = Vec::with_capacity(share.compressed_size());
    share
        .serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("serializing comparison proof share: {e}"))?;
    Ok(bytes)
}

/// Deserialize one canonical proof share, rejecting trailing bytes and unknown
/// versions/party identifiers.
pub fn deserialize_compare_proof_share(bytes: &[u8]) -> Result<CompareProofShare> {
    let mut reader = bytes;
    let share = CompareProofShare::deserialize_compressed(&mut reader)
        .map_err(|e| anyhow!("parsing comparison proof share: {e}"))?;
    ensure!(
        reader.is_empty(),
        "comparison proof share has trailing bytes"
    );
    share.validate_header()?;
    Ok(share)
}

/// Encode one canonical proof share as chain-facing lowercase hex.
pub fn encode_compare_proof_share_hex(share: &CompareProofShare) -> Result<String> {
    Ok(hex::encode(serialize_compare_proof_share(share)?))
}

/// Decode one chain-facing hexadecimal proof share.
pub fn decode_compare_proof_share_hex(value: &str) -> Result<CompareProofShare> {
    let bytes =
        hex::decode(value).map_err(|e| anyhow!("comparison proof share is not hex: {e}"))?;
    deserialize_compare_proof_share(&bytes)
}

/// Check the proof components that were already opened for the Fiat--Shamir
/// transcript.  The final two KZG commitments are deliberately excluded: they
/// are the additive values reconstructed below.
fn common_components_match(a: &Proof<Bn254>, b: &Proof<Bn254>) -> bool {
    a.wires_poly_comms == b.wires_poly_comms
        && a.prod_perm_poly_comm == b.prod_perm_poly_comm
        && a.split_quot_poly_comms == b.split_quot_poly_comms
        && a.poly_evals == b.poly_evals
        && a.plookup_proof == b.plookup_proof
}

/// Reconstruct a standard PLONK proof from PARTY0's and PARTY1's native output
/// shares.  G1 group addition is used for the two final commitments; no byte or
/// coordinate-wise operation is valid here.
pub fn combine_compare_proof_shares(
    party0: &CompareProofShare,
    party1: &CompareProofShare,
) -> Result<Proof<Bn254>> {
    party0.validate_header()?;
    party1.validate_header()?;
    ensure!(
        party0.party_id == 0,
        "first comparison proof share is not PARTY0"
    );
    ensure!(
        party1.party_id == 1,
        "second comparison proof share is not PARTY1"
    );
    ensure!(
        party0.version == party1.version,
        "comparison proof share versions differ"
    );
    ensure!(
        common_components_match(&party0.proof, &party1.proof),
        "comparison proof share common components differ"
    );

    let mut proof = party0.proof.clone();
    proof.opening_proof.0 = (party0.proof.opening_proof.0.into_group()
        + party1.proof.opening_proof.0.into_group())
    .into_affine();
    proof.shifted_opening_proof.0 = (party0.proof.shifted_opening_proof.0.into_group()
        + party1.proof.shifted_opening_proof.0.into_group())
    .into_affine();
    Ok(proof)
}
