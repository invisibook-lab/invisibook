//! End-to-end tests of the MERGED settlement relation: satisfiability on
//! all comparison branches, single-prover round-trip with per-signal
//! tampering, the 2-party collaborative flow over mock MPC, and the
//! witness-validity abort.

use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use cozk2p::{
    PairSidePrivate, build_pair_single_prover_circuit, compute_pair_public, dev_keys_pair,
    prove_pair_collaborative, prove_pair_single, sample_pair_trade, verify_settle_pair,
};
use mpc_relation::traits::Circuit;

fn keys_dir() -> std::path::PathBuf {
    cozk2p::default_cache_dir()
}

/// The merged relation is satisfiable on the sample trade; the
/// single-prover proof round-trips; tampering with every class of public
/// signal must fail verification.
#[test]
fn pair_single_prover_roundtrip_and_tamper() {
    let (a, b, inputs) = sample_pair_trade();
    let public = compute_pair_public(&a, &b, &inputs).unwrap();

    let circuit = build_pair_single_prover_circuit(&a, &b, &public).unwrap();
    circuit
        .check_circuit_satisfiability(&public.to_vec())
        .expect("merged relation must be satisfiable on a well-formed trade");
    eprintln!("merged circuit gates: {}", circuit.num_gates());

    let (pk, vk) = dev_keys_pair(&keys_dir()).unwrap();
    let proof = prove_pair_single(&a, &b, &public, &pk).unwrap();
    verify_settle_pair(&vk, &public, &proof).expect("valid proof must verify");

    // Tamper with one signal of each class: the claim, a payout note, a
    // residual collateral commitment, an on-chain open, a trade parameter,
    // and a payout asset.
    let mut bad = public.clone();
    bad.cmp = -bad.cmp;
    assert!(verify_settle_pair(&vk, &bad, &proof).is_err(), "cmp");

    let mut bad = public.clone();
    bad.cm_note_out_a = bad.cm_note_out_b;
    assert!(verify_settle_pair(&vk, &bad, &proof).is_err(), "note A");

    let mut bad = public.clone();
    bad.cm_locked_res_a = bad.cm_locked_res_b;
    assert!(
        verify_settle_pair(&vk, &bad, &proof).is_err(),
        "residual collateral"
    );

    let mut bad = public.clone();
    bad.locked_a = bad.locked_b;
    assert!(
        verify_settle_pair(&vk, &bad, &proof).is_err(),
        "collateral open"
    );

    let mut bad = public.clone();
    bad.price += 1;
    assert!(verify_settle_pair(&vk, &bad, &proof).is_err(), "price");

    let mut bad = public.clone();
    bad.a_is_seller = !bad.a_is_seller;
    assert!(verify_settle_pair(&vk, &bad, &proof).is_err(), "side flag");

    let mut bad = public.clone();
    bad.asset_recv_a = bad.asset_recv_b;
    assert!(verify_settle_pair(&vk, &bad, &proof).is_err(), "recv asset");
}

/// All three comparison branches (and both side orientations) are
/// satisfiable with the correct fills and residuals.
#[test]
fn pair_relation_branches() {
    let (mut a, mut b, mut inputs) = sample_pair_trade();

    // a < b → cmp = -1, A fully filled, B keeps a residual.
    a.order_amount = 50;
    b.order_amount = 60;
    let public = compute_pair_public(&a, &b, &inputs).unwrap();
    assert_eq!(public.cmp, -1);
    build_pair_single_prover_circuit(&a, &b, &public)
        .unwrap()
        .check_circuit_satisfiability(&public.to_vec())
        .unwrap();

    // a == b → cmp = 0, both residual collaterals commit zero.
    a.order_amount = 60;
    let public = compute_pair_public(&a, &b, &inputs).unwrap();
    assert_eq!(public.cmp, 0);
    build_pair_single_prover_circuit(&a, &b, &public)
        .unwrap()
        .check_circuit_satisfiability(&public.to_vec())
        .unwrap();

    // Flipped orientation: A buys, B sells.
    inputs.a_is_seller = false;
    a.order_amount = 80;
    b.order_amount = 60;
    let public = compute_pair_public(&a, &b, &inputs).unwrap();
    assert_eq!(public.cmp, 1);
    build_pair_single_prover_circuit(&a, &b, &public)
        .unwrap()
        .check_circuit_satisfiability(&public.to_vec())
        .unwrap();
}

/// A wrong witness (B claims a different quantity than its on-chain
/// commitment opens) must make the circuit unsatisfiable.
#[test]
fn pair_relation_rejects_wrong_opening() {
    let (a, mut b, inputs) = sample_pair_trade();
    let public = compute_pair_public(&a, &b, &inputs).unwrap();
    b.order_amount += 1;
    let circuit = build_pair_single_prover_circuit(&a, &b, &public).unwrap();
    assert!(
        circuit
            .check_circuit_satisfiability(&public.to_vec())
            .is_err(),
        "a lying opening must not satisfy the merged relation"
    );
}

/// The full 2-party collaborative flow over the merged relation: both
/// traders jointly extend the witness on SPDZ shares, produce ONE proof
/// covering compare + both settle legs, and each verifies it locally.
#[tokio::test(flavor = "multi_thread")]
async fn pair_collaborative_prove_and_verify() {
    let (a, b, inputs) = sample_pair_trade();
    let public = compute_pair_public(&a, &b, &inputs).unwrap();
    let (pk, vk) = dev_keys_pair(&keys_dir()).unwrap();

    let (proof0, proof1) = execute_mock_mpc(|fabric| {
        let (a, b, public, pk) = (a.clone(), b.clone(), public.clone(), pk.clone());
        async move {
            let party = fabric.party_id();
            let my_side: PairSidePrivate = if party == PARTY0 { a } else { b };
            prove_pair_collaborative(fabric.clone(), party, &my_side, &public, &pk)
                .await
                .expect("collaborative proving must succeed")
        }
    })
    .await;

    verify_settle_pair(&vk, &public, &proof0).expect("party 0's proof must verify");
    verify_settle_pair(&vk, &public, &proof1).expect("party 1's proof must verify");
    assert_eq!(
        format!("{proof0:?}"),
        format!("{proof1:?}"),
        "both parties must reveal the same proof"
    );
}

/// The witness-validity gate on the merged relation: a party whose input
/// shares break the joint witness (B's amount does not open the agreed
/// commitment) must cause BOTH parties to abort before any proof element
/// is revealed.
#[tokio::test(flavor = "multi_thread")]
async fn pair_validity_gate_aborts_on_invalid_witness() {
    let (a, b, inputs) = sample_pair_trade();
    let public = compute_pair_public(&a, &b, &inputs).unwrap();
    let (pk, _vk) = dev_keys_pair(&keys_dir()).unwrap();

    let mut b_bad = b.clone();
    b_bad.order_amount = b.order_amount + 1;

    let (r0, r1) = execute_mock_mpc(|fabric| {
        let (a, b_bad, public, pk) = (a.clone(), b_bad.clone(), public.clone(), pk.clone());
        async move {
            let party = fabric.party_id();
            let my_side: PairSidePrivate = if party == PARTY0 { a } else { b_bad };
            prove_pair_collaborative(fabric.clone(), party, &my_side, &public, &pk).await
        }
    })
    .await;

    assert!(
        r0.is_err() && r1.is_err(),
        "both parties must abort on an invalid joint witness (got ok: p0={}, p1={})",
        r0.is_ok(),
        r1.is_ok()
    );
}
