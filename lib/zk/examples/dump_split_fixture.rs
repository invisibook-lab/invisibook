// Produce a sample split proof + public inputs file for chain Go tests.
// Output: <out_path> with shape:
//   { "input_commitments_hex": [...], "locked_commitment_hex": "...",
//     "change_commitment_hex": "...", "proof_json": <snarkjs proof>,
//     "public_json": [<decimal strings>], "vk_path": "..." }
//
// Run with:
//   cargo run -p zk --example dump_split_fixture -- <out_path>

use std::env;
use std::path::PathBuf;

use zk::setup::dev_setup_snarkjs;
use zk::test_circuit::TestCircuitHandle;
use zk::wallet::{SplitWitness, prove_split};

fn main() {
    let out_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: dump_split_fixture <out_path>");

    let setup = dev_setup_snarkjs("split").expect("snarkjs setup");
    let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
    // Spend one 100-cash, lock 60 + return 40 change — same shape as the prover
    // round-trip test so chain Go tests see a familiar layout.
    let witness = SplitWitness {
        inputs: vec![(100, [0xE5u8; 32])],
        locked_amount: 60,
        locked_random: [0xF6u8; 32],
        change_amount: 40,
        change_random: [0xC7u8; 32],
    };
    let sp = prove_split(witness, &handle, &setup.zkey).expect("prove_split");

    let fixture = serde_json::json!({
        "input_commitments_hex": sp.input_commitments_hex,
        "locked_commitment_hex": sp.locked_commitment_hex,
        "change_commitment_hex": sp.change_commitment_hex,
        "proof_json": sp.proof_json,
        "public_json": sp.public_json,
        "vk_path": setup.vk_json,
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("write fixture");
    println!("wrote fixture to {out_path:?}");
}
