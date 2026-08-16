//! Circuit builders and the 2-party collaborative proving driver.
//!
//! Roles: trader A = `PARTY0`, trader B = `PARTY1` (SPDZ two-party). Each
//! trader contributes its private side of the witness via
//! `fabric.share_scalar(value, owner)`; the non-owner passes zero
//! placeholders in the identical allocation order, so both parties build
//! the exact same circuit over the same shared wires.

use anyhow::{Result, anyhow};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    algebra::{AuthenticatedScalarResult, Scalar},
};
use mpc_plonk::{
    multiprover::proof_system::{MpcPlonkCircuit, MultiproverPlonkKzgSnark},
    proof_system::{
        PlonkKzgSnark,
        structs::{Proof, ProvingKey, VerifyingKey},
    },
    transcript::SolidityTranscript,
};
use mpc_relation::{PlonkCircuit, Variable, traits::Circuit};

use crate::relation::{
    PublicWires, SIDE_PRIVATE_LEN, SatisfiabilityWitness, SettlePublic, SidePrivate,
    build_settle_relation, build_settle_relation_collecting, side_private_values,
    side_wires_from_vars,
};

/// Group the 3 canonical public wires ([cmp, order_a, order_b]).
/// `vars` must be the public variables in canonical order.
fn public_wires_from_vars(vars: &[Variable]) -> PublicWires {
    assert_eq!(vars.len(), 3);
    PublicWires {
        cmp: vars[0],
        order_a: vars[1],
        order_b: vars[2],
    }
}

/// Build the single-prover circuit (key generation, satisfiability tests,
/// and the single-prover baseline in benches). Witness = both sides in
/// plaintext.
pub fn build_single_prover_circuit(
    a: &SidePrivate,
    b: &SidePrivate,
    public: &SettlePublic,
) -> Result<PlonkCircuit<Fr>> {
    let mut cs = PlonkCircuit::<Fr>::new_turbo_plonk();

    let pub_vars = public
        .to_vec()
        .into_iter()
        .map(|v| cs.create_public_variable(v))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("allocating public inputs: {e}"))?;
    let pw = public_wires_from_vars(&pub_vars);

    let mut alloc_side = |side: &SidePrivate| -> Result<Vec<Variable>> {
        side_private_values(side)
            .into_iter()
            .map(|v| cs.create_variable(v))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("allocating private inputs: {e}"))
    };
    let a_vars = alloc_side(a)?;
    let b_vars = alloc_side(b)?;
    let aw = side_wires_from_vars(&a_vars);
    let bw = side_wires_from_vars(&b_vars);

    build_settle_relation(&mut cs, &pw, &aw, &bw).map_err(|e| anyhow!("building relation: {e}"))?;
    cs.finalize_for_arithmetization()
        .map_err(|e| anyhow!("finalizing circuit: {e}"))?;
    Ok(cs)
}

/// Build the collaborative circuit on an `MpcFabric`. `my_side` is this
/// party's plaintext inputs; the counterparty's inputs arrive as SPDZ
/// shares through the fabric (`share_scalar` with the respective owner).
/// Both parties MUST call this with the same `public`.
pub fn build_mpc_circuit(
    fabric: &MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &SidePrivate,
    public: &SettlePublic,
) -> Result<MpcPlonkCircuit<G1Projective>> {
    build_mpc_circuit_sat(fabric, my_party, my_side, public).map(|(cs, _)| cs)
}

/// [`build_mpc_circuit`] that also returns the [`SatisfiabilityWitness`] so the
/// prover can validity-check the joint witness before opening a proof.
fn build_mpc_circuit_sat(
    fabric: &MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &SidePrivate,
    public: &SettlePublic,
) -> Result<(MpcPlonkCircuit<G1Projective>, SatisfiabilityWitness)> {
    let mut cs = MpcPlonkCircuit::new(fabric.clone());

    // Public inputs: known to both parties in plaintext; lift them into the
    // fabric by scaling the shared representation of one.
    let one = fabric.one_authenticated();
    let pub_vars = public
        .to_vec()
        .into_iter()
        .map(|v| cs.create_public_variable(Scalar::new(v) * &one))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("allocating public inputs: {e}"))?;
    let pw = public_wires_from_vars(&pub_vars);

    // Private inputs: `owner` supplies real values, the counterparty zeros
    // (ignored by `share_scalar` — only the sender's value matters).
    let mut alloc_side = |owner: u64| -> Result<Vec<Variable>> {
        let values: Vec<Fr> = if my_party == owner {
            side_private_values(my_side)
        } else {
            vec![Fr::from(0u64); SIDE_PRIVATE_LEN]
        };
        values
            .into_iter()
            .map(|v| {
                let shared = fabric.share_scalar(Scalar::new(v), owner);
                cs.create_variable(shared)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("allocating side inputs: {e}"))
    };
    let a_vars = alloc_side(PARTY0)?;
    let b_vars = alloc_side(PARTY1)?;
    let aw = side_wires_from_vars(&a_vars);
    let bw = side_wires_from_vars(&b_vars);

    let sat = build_settle_relation_collecting(&mut cs, &pw, &aw, &bw)
        .map_err(|e| anyhow!("building relation: {e}"))?;
    cs.finalize_for_arithmetization()
        .map_err(|e| anyhow!("finalizing circuit: {e}"))?;
    Ok((cs, sat))
}

/// Witness-validity gate. Before any proof element is revealed, the two
/// parties jointly test that the shared witness actually satisfies the
/// settlement relation, aborting if it does not. SPDZ MACs only guarantee
/// correct-or-abort computation on the *given* shares — they do not stop a
/// party from *inputting* shares that make the joint witness unsatisfiable,
/// and a proof over an invalid witness falls outside the zk-SNARK's
/// zero-knowledge guarantee, leaking the honest party's inputs (eprint
/// 2025/1026, Pitfall 1). The counterparty receives the opened proof at
/// `open_authenticated`, so a purely local post-hoc verify does not protect
/// it; this check must run first.
///
/// Construction (a standard MPC zero-test, reveals only one bit — "valid" vs
/// "invalid"): let `r_i` be the residuals of every enforced constraint
/// (`lhs - rhs` for each equality; `b^2 - b` for each booleanity, batched into
/// one multiplication). Draw a fresh MAC-opened random `gamma` (unbiasable and
/// unpredictable *after* inputs are committed) and form `S = sum_i gamma^i
/// r_i`; then open `S * m` for a fresh shared random mask `m`. If every
/// `r_i = 0` the product is `0`; otherwise it is `0` with only negligible
/// probability (Schwartz–Zippel), and the mask hides `S`'s actual value so a
/// rejection leaks nothing beyond "invalid".
async fn check_witness_valid(
    fabric: &MpcFabric<G1Projective>,
    circuit: &MpcPlonkCircuit<G1Projective>,
    sat: &SatisfiabilityWitness,
) -> Result<()> {
    let witness = |v: Variable| -> Result<AuthenticatedScalarResult<G1Projective>> {
        circuit
            .witness(v)
            .map_err(|e| anyhow!("reading witness share: {e}"))
    };

    // Equality residuals: lhs - rhs (local subtraction on shares).
    let mut residuals: Vec<AuthenticatedScalarResult<G1Projective>> =
        Vec::with_capacity(sat.eq_pairs.len() + sat.bool_vars.len());
    for &(x, y) in &sat.eq_pairs {
        residuals.push(&witness(x)? - &witness(y)?);
    }
    // Booleanity residuals: b^2 - b, with all squarings in one batched round.
    if !sat.bool_vars.is_empty() {
        let bits = sat
            .bool_vars
            .iter()
            .map(|&v| witness(v))
            .collect::<Result<Vec<_>>>()?;
        let squares = AuthenticatedScalarResult::batch_mul(&bits, &bits);
        for (sq, b) in squares.iter().zip(bits.iter()) {
            residuals.push(sq - b);
        }
    }
    if residuals.is_empty() {
        return Ok(());
    }

    // Fresh MAC-opened challenge: sampled after inputs are committed, so a
    // party cannot pick residuals that cancel under a known combination, and
    // MAC-checked so it cannot be biased during the open.
    let gamma = fabric.random_shared_scalars(1)[0]
        .open_authenticated()
        .await
        .map_err(|e| anyhow!("opening validity challenge: {e}"))?;

    // S = sum_i gamma^i * r_i (powers are public; each term is local).
    let mut acc = fabric.zero_authenticated();
    let mut power = Scalar::new(Fr::from(1u64));
    for r in &residuals {
        acc = &acc + &(r * &power);
        power = &power * &gamma;
    }

    // Mask so a nonzero S reveals nothing beyond "invalid", then open once.
    let mask = fabric.random_shared_scalars(1);
    let masked = &acc * &mask[0];
    let value = masked
        .open_authenticated()
        .await
        .map_err(|e| anyhow!("opening validity residual: {e}"))?;
    if value != Scalar::new(Fr::from(0u64)) {
        return Err(anyhow!(
            "witness-validity gate failed: the joint witness does not satisfy \
             the settlement relation; aborting before revealing any proof element"
        ));
    }
    Ok(())
}

/// Wall-clock phase timings of one collaborative proving run, in ms.
/// `build` covers MPC circuit construction (the witness-extension analog:
/// every gate output share is computed here); `prove` the PLONK rounds on
/// shares; `open` the reveal + SPDZ MAC check of the proof elements.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ProveTimings {
    pub build_ms: f64,
    pub prove_ms: f64,
    pub open_ms: f64,
}

/// Run the collaborative proof on an established fabric and reveal the
/// standard single-prover PLONK proof. Consumes one round of SPDZ opening
/// for the proof elements; the MAC check aborts on any tampering.
pub async fn prove_collaborative(
    fabric: MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &SidePrivate,
    public: &SettlePublic,
    pk: &ProvingKey<Bn254>,
) -> Result<Proof<Bn254>> {
    let (proof, _t) = prove_collaborative_timed(fabric, my_party, my_side, public, pk).await?;
    Ok(proof)
}

/// [`prove_collaborative`] with per-phase wall-clock timings.
/// Note: the fabric evaluates lazily, so `build`/`prove` mostly enqueue the
/// dataflow graph and `open` includes draining it; the split is still
/// useful to see where wall time goes end to end.
pub async fn prove_collaborative_timed(
    fabric: MpcFabric<G1Projective>,
    my_party: u64,
    my_side: &SidePrivate,
    public: &SettlePublic,
    pk: &ProvingKey<Bn254>,
) -> Result<(Proof<Bn254>, ProveTimings)> {
    use std::time::Instant;
    let t0 = Instant::now();

    // Fail fast (with a diagnosable error) if the parties disagree on the
    // public statement: each broadcasts a fingerprint of its copy in
    // plaintext and both compare. Without this, divergent publics would
    // abort much later as an opaque SPDZ MAC failure.
    // IMPORTANT: both parties must enqueue fabric operations in the
    // IDENTICAL order (dataflow op-ids must align), so the exchange is in
    // canonical party order — A's fingerprint first, then B's — with each
    // party passing its own value (ignored when it is not the sender).
    let fp = Scalar::new(public.fingerprint());
    let fp_a = fabric.share_plaintext(fp, PARTY0);
    let fp_b = fabric.share_plaintext(fp, PARTY1);
    let (fp_a, fp_b) = (fp_a.await, fp_b.await);
    anyhow::ensure!(
        fp_a == fp_b,
        "the two traders loaded different public statements — refusing to prove"
    );

    let (circuit, sat) = build_mpc_circuit_sat(&fabric, my_party, my_side, public)?;
    // Refuse to prove (and reveal) on an invalid joint witness — see
    // `check_witness_valid`. Runs before the proof so an unsatisfiable witness
    // never reaches the counterparty's `open_authenticated`.
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

/// Verify a settlement proof against the canonical public vector — the same
/// check the chain would run.
pub fn verify_settle(
    vk: &VerifyingKey<Bn254>,
    public: &SettlePublic,
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

/// Single-prover baseline proof over the same relation and keys (what a
/// trusted prover holding BOTH sides' secrets would produce).
pub fn prove_single(
    a: &SidePrivate,
    b: &SidePrivate,
    public: &SettlePublic,
    pk: &ProvingKey<Bn254>,
) -> Result<Proof<Bn254>> {
    use rand::{SeedableRng, rngs::StdRng};
    let circuit = build_single_prover_circuit(a, b, public)?;
    let mut rng = StdRng::from_entropy();
    // This fork exposes `prove_with_link_hint` (no plain `prove`); the
    // linking hint is irrelevant here and dropped.
    let (proof, _hint) = PlonkKzgSnark::<Bn254>::prove_with_link_hint::<_, _, SolidityTranscript>(
        &mut rng, &circuit, pk,
    )
    .map_err(|e| anyhow!("single prove: {e}"))?;
    Ok(proof)
}
