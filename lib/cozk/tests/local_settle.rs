//! End-to-end collaborative proving test: three in-process REP3 nodes prove
//! the `settle_cozk` circuit from split inputs (no node ever holds both
//! traders' secrets) and the resulting Groth16 proof verifies against the
//! snarkjs verification key — i.e. it is byte-compatible with what the chain
//! verifies via go-rapidsnark.
//!
//! Requires circom + snarkjs + node on PATH (same as the `zk` test suite).

use ark_bn254::Fr;
use cozk::{default_circuit_path, default_link_dir, load_artifacts, run_local_settle};
use zk::{
    setup::dev_setup_snarkjs,
    wallet::{
        SettleCoZkSide, SettleCoZkWitness, poseidon_commit, settle_cozk_cmp_fr,
        settle_cozk_locked_hashes, settle_cozk_outcome, settle_cozk_public_json,
        settle_cozk_side_json,
    },
};

/// A (maker) sells 80 token1 at price 3; B buys 60 → cmp = 1, A keeps 20 on
/// the book and receives 180 token2, B receives 60 token1.
fn sample_witness() -> SettleCoZkWitness {
    SettleCoZkWitness {
        a: SettleCoZkSide {
            order_amount: 80,
            r_order: [0xA1u8; 32],
            r_order_new: [0xA2u8; 32],
            locked: vec![(80, [0xA3u8; 32])],
            r_locked_new: [0xA4u8; 32],
            r_recv: [0xA5u8; 32],
        },
        b: SettleCoZkSide {
            order_amount: 60,
            r_order: [0xB1u8; 32],
            r_order_new: [0xB2u8; 32],
            locked: vec![(180, [0xB3u8; 32])],
            r_locked_new: [0xB4u8; 32],
            r_recv: [0xB5u8; 32],
        },
        price: 3,
        a_is_seller: true,
    }
}

#[test]
fn local_three_party_settle_proof_verifies() {
    let setup = dev_setup_snarkjs("settle_cozk").expect("snarkjs setup");
    let artifacts = load_artifacts(
        &default_circuit_path(),
        &default_link_dir(),
        &setup.zkey,
        &setup.vk_json,
    )
    .expect("loading artifacts");

    let w = sample_witness();
    let a_private = settle_cozk_side_json(&w.a, "a").expect("a-side json");
    let b_private = settle_cozk_side_json(&w.b, "b").expect("b-side json");
    let public = settle_cozk_public_json(
        &poseidon_commit(w.a.order_amount, &w.a.r_order),
        &poseidon_commit(w.b.order_amount, &w.b.r_order),
        w.price,
        w.a_is_seller,
        &settle_cozk_locked_hashes(&w.a),
        &settle_cozk_locked_hashes(&w.b),
    );

    let outcome = run_local_settle(&artifacts, &a_private, &b_private, &public)
        .expect("collaborative proving");

    // The public vector must match the plaintext outcome exactly — this is
    // the same 15-signal layout the chain rebuilds before verification.
    let out = settle_cozk_outcome(&w).expect("outcome");
    let expected: Vec<Fr> = vec![
        settle_cozk_cmp_fr(out.cmp),
        poseidon_commit(out.a_prime, &w.a.r_order_new),
        poseidon_commit(out.b_prime, &w.b.r_order_new),
        poseidon_commit(out.a_new_locked, &w.a.r_locked_new),
        poseidon_commit(out.b_new_locked, &w.b.r_locked_new),
        poseidon_commit(out.a_recv, &w.a.r_recv),
        poseidon_commit(out.b_recv, &w.b.r_recv),
        poseidon_commit(w.a.order_amount, &w.a.r_order),
        poseidon_commit(w.b.order_amount, &w.b.r_order),
        Fr::from(w.price),
        Fr::from(w.a_is_seller as u64),
        settle_cozk_locked_hashes(&w.a)[0],
        settle_cozk_locked_hashes(&w.a)[1],
        settle_cozk_locked_hashes(&w.b)[0],
        settle_cozk_locked_hashes(&w.b)[1],
    ];
    assert_eq!(outcome.public_inputs, expected);
    assert_eq!(out.cmp, 1);

    // Sanity on the wire formats the chain consumes.
    assert_eq!(outcome.proof_json["protocol"], "groth16");
    assert_eq!(outcome.public_json.as_array().unwrap().len(), 15);
}
