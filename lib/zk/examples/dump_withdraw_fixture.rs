// Produce a sample withdraw proof + public inputs file for chain Go tests.
// Output: <out_path> with shape:
//   { "bridge_out_commitment_hex": "...", "input_commitments_hex": [...],
//     "change_commitment_hex": "...", "proof_json": <snarkjs proof>,
//     "public_json": [<decimal strings>], "vk_path": "..." }
//
// Run with:
//   cargo run -p zk --example dump_withdraw_fixture -- <out_path>

use std::env;
use std::path::PathBuf;

use zk::setup::dev_setup_snarkjs;
use zk::test_circuit::TestCircuitHandle;
use zk::wallet::{WithdrawWitness, prove_withdraw};

fn main() {
    let out_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: dump_withdraw_fixture <out_path>");

    let setup = dev_setup_snarkjs("withdraw").expect("snarkjs setup");
    let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
    // Spend two cashes (70 + 40 = 110); withdraw 100 (hidden); mint 10 as change.
    let witness = WithdrawWitness {
        withdraw_amount: 100,
        r_bridge_out: [0x11u8; 32],
        inputs: vec![(70, [0xA1u8; 32]), (40, [0xB2u8; 32])],
        change_amount: 10,
        change_random: [0xC3u8; 32],
    };
    let wp = prove_withdraw(witness, &handle, &setup.zkey).expect("prove_withdraw");

    let fixture = serde_json::json!({
        "bridge_out_commitment_hex": wp.bridge_out_commitment_hex,
        "input_commitments_hex": wp.input_commitments_hex,
        "change_commitment_hex": wp.change_commitment_hex,
        "proof_json": wp.proof_json,
        "public_json": wp.public_json,
        "vk_path": setup.vk_json,
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("write fixture");
    println!("wrote fixture to {out_path:?}");
}
