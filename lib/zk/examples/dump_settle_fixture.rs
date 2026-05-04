// Produce a paired settle fixture (one larger + one smaller) for chain Go tests.
// Output: <out_path> with shape:
//   {
//     "larger": { my_match, other_match, input_commitments, change, proof, public, vk },
//     "smaller": { match, input_commitments, proof, public, vk },
//     "shared_recv_commitments": { alice_recv, bob_recv },
//     "price": <u64>,
//   }
//
// Run with:
//   cargo run -p zk --example dump_settle_fixture -- <out_path>

use std::env;
use std::path::PathBuf;

use zk::setup::dev_setup_snarkjs;
use zk::test_circuit::TestCircuitHandle;
use zk::wallet::{
    SettleLargerWitness, SettleSmallerWitness, fr_to_hex, poseidon_commit, prove_settle_larger,
    prove_settle_smaller,
};

fn main() {
    let out_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: dump_settle_fixture <out_path>");

    // Trade: alice sells 80 ETH at price 1 USDT/ETH; bob buys 60 ETH (= locks 60 USDT).
    // Match fill = 60. alice (larger) keeps 20 ETH change; bob (smaller) has no change.
    let price: u64 = 1;
    let alice_locked: u64 = 80;
    let bob_locked: u64 = 60;
    let fill = bob_locked; // smaller side fully fills

    // Off-chain coordination: both sides agree on r_match values for the two fills.
    // alice's "my_fill" is the Token1 fill (60 ETH); bob's match for his fill (60 USDT)
    // is what alice sees as `other_match_commitment`.
    let r_alice_match = [0x01u8; 32]; // = r_my for alice's larger leg, r_other for ... no, alice is t1 sender
    let r_bob_match = [0x02u8; 32]; //   alice's other_match (= bob's match) — bob's smaller leg's match commitment uses this same r
    let alice_change_random = [0xC3u8; 32];

    // Each side picks their own recv random (their own private), then exchanges only the commitment hex.
    let alice_recv_random = [0xA0u8; 32]; // alice's USDT recv (= bob's counterparty_recv in his smaller leg)
    let bob_recv_random = [0xB0u8; 32]; //   bob's   ETH  recv (= alice's counterparty_recv in her larger leg)
    let alice_recv_commit_hex = fr_to_hex(&poseidon_commit(fill, &alice_recv_random));
    let bob_recv_commit_hex = fr_to_hex(&poseidon_commit(fill, &bob_recv_random));

    // alice locked input(s)
    let alice_in_random = [0xA1u8; 32];

    // Larger leg: alice (Token1 sender)
    let larger_setup = dev_setup_snarkjs("settle_larger").expect("snarkjs setup larger");
    let larger_handle =
        TestCircuitHandle::from_compiled(&larger_setup.circuit_dir).expect("circuit handle larger");
    let larger_witness = SettleLargerWitness {
        r_my: r_alice_match,
        other_fill: fill,
        r_other: r_bob_match,
        price,
        is_token2_sender: false,
        inputs: vec![(alice_locked, alice_in_random)],
        change_amount: alice_locked - fill,
        change_random: alice_change_random,
        counterparty_recv_commitment_hex: bob_recv_commit_hex.clone(),
    };
    let larger = prove_settle_larger(larger_witness, &larger_handle, &larger_setup.zkey)
        .expect("prove_settle_larger");

    // Smaller leg: bob (Token2 sender), no change
    let bob_in_random = [0xB1u8; 32];
    let smaller_setup = dev_setup_snarkjs("settle_smaller").expect("snarkjs setup smaller");
    let smaller_handle = TestCircuitHandle::from_compiled(&smaller_setup.circuit_dir)
        .expect("circuit handle smaller");
    let smaller_witness = SettleSmallerWitness {
        r_match: r_bob_match,
        inputs: vec![(bob_locked, bob_in_random)],
        counterparty_recv_commitment_hex: alice_recv_commit_hex.clone(),
    };
    let smaller = prove_settle_smaller(smaller_witness, &smaller_handle, &smaller_setup.zkey)
        .expect("prove_settle_smaller");

    // Sanity: larger.other_match_commitment_hex must equal smaller.match_commitment_hex —
    // this is the equality chain enforces across legs.
    assert_eq!(
        larger.other_match_commitment_hex, smaller.match_commitment_hex,
        "larger.other_match must equal smaller.match — they cover the same fill on the smaller side"
    );

    let fixture = serde_json::json!({
        "price": price,
        "larger": {
            "my_match_commitment_hex":    larger.my_match_commitment_hex,
            "other_match_commitment_hex": larger.other_match_commitment_hex,
            "input_commitments_hex":      larger.input_commitments_hex,
            "change_commitment_hex":      larger.change_commitment_hex,
            "is_token2_sender":           false,
            "proof_json":                 larger.proof_json,
            "public_json":                larger.public_json,
            "vk_path":                    larger_setup.vk_json,
        },
        "smaller": {
            "match_commitment_hex":   smaller.match_commitment_hex,
            "input_commitments_hex":  smaller.input_commitments_hex,
            "proof_json":             smaller.proof_json,
            "public_json":            smaller.public_json,
            "vk_path":                smaller_setup.vk_json,
        },
        "shared_recv_commitments": {
            "alice_recv_commitment_hex": alice_recv_commit_hex,
            "bob_recv_commitment_hex":   bob_recv_commit_hex,
        },
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("write fixture");
    println!("wrote fixture to {out_path:?}");
}
