// Produce a settle_cozk fixture for chain Go verifier tests. The proof is
// generated COLLABORATIVELY by three in-process REP3 nodes (no node holds
// both traders' secrets), so the Go test verifies exactly what production
// settlement submits.
//
// Run with:
//   cargo run -p cozk --example dump_settle_cozk_fixture -- <out_path>

use std::{env, path::PathBuf};

use cozk::{default_circuit_path, default_link_dir, load_artifacts, run_local_settle};
use zk::{
    setup::dev_setup_snarkjs,
    wallet::{
        SettleCoZkSide, SettleCoZkWitness, fr_to_hex, poseidon_commit, settle_cozk_locked_hashes,
        settle_cozk_outcome, settle_cozk_public_json, settle_cozk_side_json,
    },
};

fn main() {
    let out_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: dump_settle_cozk_fixture <out_path>");

    // Trade: A (maker) sells 80 token1 at price 3; B buys 60 token1 (locks
    // 180 token2). cmp = 1: B fully fills, A keeps 20 on the book.
    let w = SettleCoZkWitness {
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
    };

    let setup = dev_setup_snarkjs("settle_cozk").expect("snarkjs setup settle_cozk");
    let artifacts = load_artifacts(
        &default_circuit_path(),
        &default_link_dir(),
        &setup.zkey,
        &setup.vk_json,
    )
    .expect("loading artifacts");

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
    let outcome =
        run_local_settle(&artifacts, &a_private, &b_private, &public).expect("collaborative prove");

    let out = settle_cozk_outcome(&w).expect("outcome");
    let locked_a_hex: Vec<String> = settle_cozk_locked_hashes(&w.a)
        .iter()
        .map(fr_to_hex)
        .collect();
    let locked_b_hex: Vec<String> = settle_cozk_locked_hashes(&w.b)
        .iter()
        .map(fr_to_hex)
        .collect();

    let fixture = serde_json::json!({
        "price": w.price,
        "a_is_seller": w.a_is_seller,
        "cmp": out.cmp,
        "order_a_commitment_hex": fr_to_hex(&poseidon_commit(w.a.order_amount, &w.a.r_order)),
        "order_b_commitment_hex": fr_to_hex(&poseidon_commit(w.b.order_amount, &w.b.r_order)),
        "locked_a_hashes_hex": locked_a_hex,
        "locked_b_hashes_hex": locked_b_hex,
        "new_order_a_commitment_hex": fr_to_hex(&poseidon_commit(out.a_prime, &w.a.r_order_new)),
        "new_order_b_commitment_hex": fr_to_hex(&poseidon_commit(out.b_prime, &w.b.r_order_new)),
        "new_locked_a_commitment_hex": fr_to_hex(&poseidon_commit(out.a_new_locked, &w.a.r_locked_new)),
        "new_locked_b_commitment_hex": fr_to_hex(&poseidon_commit(out.b_new_locked, &w.b.r_locked_new)),
        "recv_a_commitment_hex": fr_to_hex(&poseidon_commit(out.a_recv, &w.a.r_recv)),
        "recv_b_commitment_hex": fr_to_hex(&poseidon_commit(out.b_recv, &w.b.r_recv)),
        "proof_json": outcome.proof_json,
        "public_json": outcome.public_json,
        "vk_path": setup.vk_json,
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("write fixture");
    println!("wrote fixture to {out_path:?}");
}
