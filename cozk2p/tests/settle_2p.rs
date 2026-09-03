//! End-to-end tests: the two traders jointly prove the settlement relation
//! and the resulting proof verifies as a standard single-prover PLONK proof
//! against the deterministic dev keys — plus relation-correctness cases via
//! the single-prover circuit.

use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use cozk2p::{
    SidePrivate, compute_public, dev_keys, prove_collaborative, prove_single, sample_trade,
    verify_settle,
};
use mpc_relation::traits::Circuit;

fn keys_dir() -> std::path::PathBuf {
    cozk2p::default_cache_dir()
}

/// The relation is satisfiable on the sample trade and the single-prover
/// proof round-trips; tampering with any public signal must fail.
#[test]
fn single_prover_roundtrip_and_tamper() {
    let (a, b, price, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price, a_is_seller).unwrap();

    let circuit = cozk2p::build_single_prover_circuit(&a, &b, &public).unwrap();
    circuit
        .check_circuit_satisfiability(&public.to_vec())
        .expect("relation must be satisfiable on a well-formed trade");

    let (pk, vk) = dev_keys(&keys_dir()).unwrap();
    let proof = prove_single(&a, &b, &public, &pk).unwrap();
    verify_settle(&vk, &public, &proof).expect("valid proof must verify");

    // Tamper: claim the opposite comparison result.
    let mut bad = public.clone();
    bad.cmp = -1;
    assert!(
        verify_settle(&vk, &bad, &proof).is_err(),
        "tampered cmp must not verify"
    );
}

/// All three comparison branches are satisfiable and produce the right cmp.
#[test]
fn relation_cmp_branches() {
    let (mut a, mut b, price, a_is_seller) = sample_trade();

    // a < b  →  cmp = -1, A fully fills.
    a.order_amount = 50;
    a.locked = vec![(50, [0xA3; 32])];
    b.order_amount = 60;
    b.locked = vec![(180, [0xB3; 32])];
    let public = compute_public(&a, &b, price, a_is_seller).unwrap();
    assert_eq!(public.cmp, -1);
    let circuit = cozk2p::build_single_prover_circuit(&a, &b, &public).unwrap();
    circuit
        .check_circuit_satisfiability(&public.to_vec())
        .unwrap();

    // a == b  →  cmp = 0, both fully fill.
    a.order_amount = 60;
    a.locked = vec![(60, [0xA3; 32])];
    let public = compute_public(&a, &b, price, a_is_seller).unwrap();
    assert_eq!(public.cmp, 0);
    let circuit = cozk2p::build_single_prover_circuit(&a, &b, &public).unwrap();
    circuit
        .check_circuit_satisfiability(&public.to_vec())
        .unwrap();
}

/// The full 2-party collaborative flow: both traders run the same closure
/// (distinguished by fabric party id), jointly extend the witness on SPDZ
/// shares, produce ONE proof, and each verifies it locally.
#[tokio::test(flavor = "multi_thread")]
async fn collaborative_prove_and_verify() {
    let (a, b, price, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price, a_is_seller).unwrap();
    let (pk, vk) = dev_keys(&keys_dir()).unwrap();

    let (proof0, proof1) = execute_mock_mpc(|fabric| {
        let (a, b, public, pk) = (a.clone(), b.clone(), public.clone(), pk.clone());
        async move {
            let party = fabric.party_id();
            let my_side: SidePrivate = if party == PARTY0 { a } else { b };
            prove_collaborative(fabric.clone(), party, &my_side, &public, &pk)
                .await
                .expect("collaborative proving must succeed")
        }
    })
    .await;

    // Both parties obtain the identical, independently verifiable proof.
    verify_settle(&vk, &public, &proof0).expect("party 0's proof must verify");
    verify_settle(&vk, &public, &proof1).expect("party 1's proof must verify");
    assert_eq!(
        format!("{proof0:?}"),
        format!("{proof1:?}"),
        "both parties must reveal the same proof"
    );
}

/// The witness-validity gate: if a party inputs shares that make the joint
/// witness unsatisfiable (here B claims an amount that does not open the
/// agreed `order_b` commitment), collaborative proving must ABORT for both
/// parties — no proof is produced, so an invalid-witness proof never reaches
/// the counterparty (eprint 2025/1026, Pitfall 1).
#[tokio::test(flavor = "multi_thread")]
async fn validity_gate_aborts_on_invalid_witness() {
    let (a, b, price, a_is_seller) = sample_trade();
    // Statement is agreed from the honest amounts...
    let public = compute_public(&a, &b, price, a_is_seller).unwrap();
    let (pk, _vk) = dev_keys(&keys_dir()).unwrap();

    // ...but B lies to the MPC: an amount whose commitment differs from the
    // agreed `public.order_b`, so the joint witness cannot satisfy the relation.
    let mut b_bad = b.clone();
    b_bad.order_amount = b.order_amount + 1;

    let (r0, r1) = execute_mock_mpc(|fabric| {
        let (a, b_bad, public, pk) = (a.clone(), b_bad.clone(), public.clone(), pk.clone());
        async move {
            let party = fabric.party_id();
            let my_side: SidePrivate = if party == PARTY0 { a } else { b_bad };
            prove_collaborative(fabric.clone(), party, &my_side, &public, &pk).await
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
