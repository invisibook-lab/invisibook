// Produce a sample deposit proof + public inputs file for chain Go tests.
// Output: <out_dir>/deposit_fixture.json with shape:
//   { "bridge_commitment_hex": "...", "output_commitment_hex": "...",
//     "proof_json": <snarkjs proof>, "public_json": [<decimal strings>] }
//
// Run with:
//   cargo run -p zk --example dump_deposit_fixture -- <out_path>

use std::{env, path::PathBuf};

use zk::{
    setup::dev_setup_snarkjs,
    test_circuit::TestCircuitHandle,
    wallet::{DepositWitness, prove_deposit},
};

fn main() {
    let out_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: dump_deposit_fixture <out_path>");

    let setup = dev_setup_snarkjs("deposit").expect("snarkjs setup");
    let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
    let witness = DepositWitness {
        deposit_amount: 150,
        r_bridge: [0x11u8; 32],
        output_amount: 150,
        output_random: [0x22u8; 32],
    };
    let dp = prove_deposit(witness, &handle, &setup.zkey).expect("prove_deposit");

    let fixture = serde_json::json!({
        "bridge_commitment_hex": dp.bridge_commitment_hex,
        "output_commitment_hex": dp.output_commitment_hex,
        "proof_json": dp.proof_json,
        "public_json": dp.public_json,
        "vk_path": setup.vk_json,
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("write fixture");
    println!("wrote fixture to {out_path:?}");
}
