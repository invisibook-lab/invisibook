//! Circuit builders and the collaborative proving driver for the MERGED
//! settlement relation (`relation_pair`): one proof covering the
//! comparison and both settlement legs. Mirrors `prove.rs`, which drives
//! the compare-only relation; both share the witness-validity gate.

use anyhow::{Result, anyhow};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_mpc::{MpcFabric, PARTY0, PARTY1, algebra::Scalar};
use mpc_plonk::{
    multiprover::proof_system::{MpcPlonkCircuit, MultiproverPlonkKzgSnark},
    proof_system::{
        PlonkKzgSnark,
        structs::{Proof, ProvingKey, VerifyingKey},
    },
    transcript::SolidityTranscript,
};
use mpc_relation::{PlonkCircuit, Variable, traits::Circuit};

use crate::{
    prove::{ProveTimings, check_witness_valid},
    relation::SatisfiabilityWitness,
    relation_pair::{
        PAIR_SIDE_PRIVATE_LEN, PairPublic, PairSidePrivate, build_pair_relation,
        build_pair_relation_collecting, pair_public_wires_from_vars, pair_side_private_values,
        pair_side_wires_from_vars,
    },
};

/// Build the single-prover circuit (key generation, satisfiability tests,
/// baselines). Witness = both sides in plaintext.
pub fn build_pair_single_prover_circuit(
    a: &PairSidePrivate,
    b: &PairSidePrivate,
    public: &PairPublic,
) -> Result<PlonkCircuit<Fr>> {
    let mut cs = PlonkCircuit::<Fr>::new_turbo_plonk();

    let pub_vars = public
        .to_vec()
        .into_iter()
        .map(|v| cs.create_public_variable(v))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("allocating public inputs: {e}"))?;
    let pw = pair_public_wires_from_vars(&pub_vars);

    let mut alloc = |values: Vec<Fr>| -> Result<Vec<Variable>> {
        values
            .into_iter()
            .map(|v| cs.create_variable(v))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("allocating private inputs: {e}"))
    };
    let a_vars = alloc(pair_side_private_values(a))?;
    let b_vars = alloc(pair_side_private_values(b))?;
    let aw = pair_side_wires_from_vars(&a_vars);
    let bw = pair_side_wires_from_vars(&b_vars);

    build_pair_relation(&mut cs, &pw, &aw, &bw).map_err(|e| anyhow!("building relation: {e}"))?;
    cs.finalize_for_arithmetization()
        .map_err(|e| anyhow!("finalizing circuit: {e}"))?;
    Ok(cs)
}

/// Build the collaborative circuit on an `MpcFabric`. `my_side` is this
/// party's plaintext inputs; the counterparty's arrive as SPDZ shares.
/// Both parties MUST call this with the same `public`.
pub fn build_pair_mpc_circuit(
    fabric: &MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &PairSidePrivate,
    public: &PairPublic,
) -> Result<MpcPlonkCircuit<G1Projective>> {
    build_pair_mpc_circuit_sat(fabric, my_party, my_side, public).map(|(cs, _)| cs)
}

/// [`build_pair_mpc_circuit`] that also returns the
/// [`SatisfiabilityWitness`] for the pre-proof validity gate.
fn build_pair_mpc_circuit_sat(
    fabric: &MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &PairSidePrivate,
    public: &PairPublic,
) -> Result<(MpcPlonkCircuit<G1Projective>, SatisfiabilityWitness)> {
    let mut cs = MpcPlonkCircuit::new(fabric.clone());

    let one = fabric.one_authenticated();
    let pub_vars = public
        .to_vec()
        .into_iter()
        .map(|v| cs.create_public_variable(Scalar::new(v) * &one))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("allocating public inputs: {e}"))?;
    let pw = pair_public_wires_from_vars(&pub_vars);

    // Shared wire groups, in fixed allocation order (op-id alignment):
    // side A (PARTY0), then side B (PARTY1).
    let mut alloc_group = |owner: u64, values: Vec<Fr>, len: usize| -> Result<Vec<Variable>> {
        debug_assert_eq!(values.len(), len);
        values
            .into_iter()
            .map(|v| {
                let shared = fabric.share_scalar(Scalar::new(v), owner);
                cs.create_variable(shared)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("allocating shared inputs: {e}"))
    };
    let side_values = |owner: u64| -> Vec<Fr> {
        if my_party == owner {
            pair_side_private_values(my_side)
        } else {
            vec![Fr::from(0u64); PAIR_SIDE_PRIVATE_LEN]
        }
    };
    let a_vars = alloc_group(PARTY0, side_values(PARTY0), PAIR_SIDE_PRIVATE_LEN)?;
    let b_vars = alloc_group(PARTY1, side_values(PARTY1), PAIR_SIDE_PRIVATE_LEN)?;
    let aw = pair_side_wires_from_vars(&a_vars);
    let bw = pair_side_wires_from_vars(&b_vars);

    let sat = build_pair_relation_collecting(&mut cs, &pw, &aw, &bw)
        .map_err(|e| anyhow!("building relation: {e}"))?;
    cs.finalize_for_arithmetization()
        .map_err(|e| anyhow!("finalizing circuit: {e}"))?;
    Ok((cs, sat))
}

/// Run the collaborative proof of the merged relation and reveal the
/// standard single-prover PLONK proof. Same protocol as
/// `prove_collaborative`: statement-fingerprint preamble, witness-validity
/// gate, prove, MAC-checked open.
pub async fn prove_pair_collaborative(
    fabric: MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &PairSidePrivate,
    public: &PairPublic,
    pk: &ProvingKey<Bn254>,
) -> Result<Proof<Bn254>> {
    let (proof, _t) = prove_pair_collaborative_timed(fabric, my_party, my_side, public, pk).await?;
    Ok(proof)
}

/// [`prove_pair_collaborative`] with per-phase wall-clock timings.
pub async fn prove_pair_collaborative_timed(
    fabric: MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &PairSidePrivate,
    public: &PairPublic,
    pk: &ProvingKey<Bn254>,
) -> Result<(Proof<Bn254>, ProveTimings)> {
    use std::time::Instant;
    let t0 = Instant::now();

    // Fail fast on divergent public statements (canonical party order —
    // both parties must enqueue identical fabric ops).
    let fp = Scalar::new(public.fingerprint());
    let fp_a = fabric.share_plaintext(fp, PARTY0);
    let fp_b = fabric.share_plaintext(fp, PARTY1);
    let (fp_a, fp_b) = (fp_a.await, fp_b.await);
    anyhow::ensure!(
        fp_a == fp_b,
        "the two traders loaded different public statements — refusing to prove"
    );

    let (circuit, sat) = build_pair_mpc_circuit_sat(&fabric, my_party, my_side, public)?;
    // Refuse to prove (and reveal) on an invalid joint witness.
    check_witness_valid(&fabric, &circuit, &sat).await?;
    let t1 = Instant::now();
    let collab = MultiproverPlonkKzgSnark::<Bn254>::prove(&circuit, pk, fabric)
        .map_err(|e| anyhow!("collaborative prove: {e}"))?;
    let t2 = Instant::now();
    let proof = collab
        .open_authenticated()
        .await
        .map_err(|e| anyhow!("opening collaborative proof (MAC check): {e}"))?;
    let t3 = Instant::now();
    let timings = ProveTimings {
        build_ms: (t1 - t0).as_secs_f64() * 1e3,
        prove_ms: (t2 - t1).as_secs_f64() * 1e3,
        open_ms: (t3 - t2).as_secs_f64() * 1e3,
    };
    Ok((proof, timings))
}

/// Verify a merged settlement proof against the canonical public vector —
/// the same check the chain runs through the FFI.
pub fn verify_settle_pair(
    vk: &VerifyingKey<Bn254>,
    public: &PairPublic,
    proof: &Proof<Bn254>,
) -> Result<()> {
    let pub_vec = public.to_vec();
    PlonkKzgSnark::<Bn254>::batch_verify::<SolidityTranscript>(
        &[vk],
        &[&pub_vec],
        &[proof],
        &[None],
    )
    .map_err(|e| anyhow!("proof verification failed: {e}"))
}

/// Single-prover baseline proof over the merged relation and keys (what a
/// trusted prover holding BOTH sides' secrets would produce).
pub fn prove_pair_single(
    a: &PairSidePrivate,
    b: &PairSidePrivate,
    public: &PairPublic,
    pk: &ProvingKey<Bn254>,
) -> Result<Proof<Bn254>> {
    use rand::{SeedableRng, rngs::StdRng};
    let circuit = build_pair_single_prover_circuit(a, b, public)?;
    let mut rng = StdRng::from_entropy();
    let (proof, _hint) = PlonkKzgSnark::<Bn254>::prove_with_link_hint::<_, _, SolidityTranscript>(
        &mut rng, &circuit, pk,
    )
    .map_err(|e| anyhow!("single prove: {e}"))?;
    Ok(proof)
}
