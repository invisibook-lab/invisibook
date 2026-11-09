//! End-to-end tests: the two traders jointly prove the settlement relation
//! and the resulting proof verifies as a standard single-prover PLONK proof
//! against the deterministic dev keys — plus relation-correctness cases via
//! the single-prover circuit. Locked-only model: the statement is
//! [cmp, locked_a, locked_b, price, a_is_seller].

use std::mem::swap;

use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use cozk2p::{
    SidePrivate, combine_compare_proof_shares, compute_public, deserialize_compare_proof_share,
    dev_keys, prove_collaborative, prove_collaborative_share_timed, prove_single, sample_trade,
    serialize_compare_proof_share, verify_settle,
};
use mpc_relation::traits::Circuit;

fn keys_dir() -> std::path::PathBuf {
    cozk2p::default_cache_dir()
}

/// The relation is satisfiable on the sample trade and the single-prover
/// proof round-trips; tampering with any public signal must fail.
#[test]
fn single_prover_roundtrip_and_tamper() {
    let (a, b, price_a, price_b, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();

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

    // Tamper: swap the two collateral commitments.
    let mut bad = public.clone();
    swap(&mut bad.locked_a, &mut bad.locked_b);
    assert!(
        verify_settle(&vk, &bad, &proof).is_err(),
        "swapped collateral commitments must not verify"
    );

    // Tamper: a different execution price.
    let mut bad = public.clone();
    bad.price_a += 1;
    assert!(
        verify_settle(&vk, &bad, &proof).is_err(),
        "tampered price must not verify"
    );

    // Tamper: the opposite side flag.
    let mut bad = public.clone();
    bad.a_is_seller = !bad.a_is_seller;
    assert!(
        verify_settle(&vk, &bad, &proof).is_err(),
        "tampered side flag must not verify"
    );
}

/// All three comparison branches are satisfiable and produce the right cmp.
#[test]
fn relation_cmp_branches() {
    let (mut a, mut b, price_a, price_b, a_is_seller) = sample_trade();

    // a < b  →  cmp = -1.
    a.order_amount = 50;
    b.order_amount = 60;
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();
    assert_eq!(public.cmp, -1);
    let circuit = cozk2p::build_single_prover_circuit(&a, &b, &public).unwrap();
    circuit
        .check_circuit_satisfiability(&public.to_vec())
        .unwrap();

    // a == b  →  cmp = 0.
    a.order_amount = 60;
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();
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
    let (a, b, price_a, price_b, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();
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

/// Native-output mode leaves the two final KZG points additively shared. Each
/// role emits a canonical, identity-bound payload; only their on-chain group
/// sum is a standard verifiable proof.
#[tokio::test(flavor = "multi_thread")]
async fn collaborative_native_shares_reconstruct_and_verify() {
    let (a, b, price_a, price_b, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();
    let (pk, vk) = dev_keys(&keys_dir()).unwrap();

    let (share0, share1) = execute_mock_mpc(|fabric| {
        let (a, b, public, pk) = (a.clone(), b.clone(), public.clone(), pk.clone());
        async move {
            let party = fabric.party_id();
            let my_side: SidePrivate = if party == PARTY0 { a } else { b };
            prove_collaborative_share_timed(fabric.clone(), party, &my_side, &public, &pk)
                .await
                .expect("native collaborative proving must succeed")
                .0
        }
    })
    .await;

    assert_eq!(share0.party_id, 0);
    assert_eq!(share1.party_id, 1);
    let encoded0 = serialize_compare_proof_share(&share0).unwrap();
    let encoded1 = serialize_compare_proof_share(&share1).unwrap();
    assert_eq!(
        encoded0.len(),
        771,
        "v1 wire is 2 header bytes + 769-byte proof"
    );
    assert_eq!(
        encoded1.len(),
        771,
        "v1 wire is 2 header bytes + 769-byte proof"
    );
    assert_ne!(encoded0, encoded1);
    let mut with_trailing_byte = encoded0.clone();
    with_trailing_byte.push(0);
    assert!(deserialize_compare_proof_share(&with_trailing_byte).is_err());
    let decoded0 = deserialize_compare_proof_share(&encoded0).unwrap();
    let decoded1 = deserialize_compare_proof_share(&encoded1).unwrap();
    let proof = combine_compare_proof_shares(&decoded0, &decoded1).unwrap();
    verify_settle(&vk, &public, &proof).expect("reconstructed native proof must verify");
}

/// The witness-validity gate: if a party inputs shares that make the joint
/// witness unsatisfiable (here B claims a quantity whose `needed(q, side)`
/// does not open the agreed `locked_b` commitment), collaborative proving
/// must ABORT for both parties — no proof is produced, so an invalid-witness
/// proof never reaches the counterparty (eprint 2025/1026, Pitfall 1).
#[tokio::test(flavor = "multi_thread")]
async fn validity_gate_aborts_on_invalid_witness() {
    let (a, b, price_a, price_b, a_is_seller) = sample_trade();
    // Statement is agreed from the honest quantities...
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller).unwrap();
    let (pk, _vk) = dev_keys(&keys_dir()).unwrap();

    // ...but B lies to the MPC: a quantity whose collateral differs from the
    // agreed `public.locked_b`, so the joint witness cannot satisfy the
    // relation.
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
