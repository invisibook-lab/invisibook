//! Dump shielded-pool fixtures for the Go chain tests, and copy the two
//! circuits' verification keys into `chain/vk/`.
//!
//! Usage: cargo run -p invisibook-lib --example dump_pool_fixture -- \
//!            /tmp/pool_fixture.json [--copy-vk]
//!
//! The fixture holds one valid note_deposit proof and one valid
//! spend_withdraw proof over the golden 3-leaf tree (spec/golden.json), so
//! the Go side can verify real proofs and pin the public-input layouts and
//! the bind transcript lockstep. `--copy-vk` additionally refreshes
//! `chain/vk/note_deposit_vk.json` and `chain/vk/spend_withdraw_vk.json`.

use std::{env, fs, path::PathBuf};

use invisibook_lib::{
    note::{
        asset_id, fr_from_be_bytes, note_commit, note_deposit_bind, note_fr_to_hex,
        note_withdraw_bind, npk_from_sk,
    },
    note_prover::{
        NoteDepositWitness, SpendSlot, SpendWithdrawWitness, prove_note_deposit,
        prove_spend_withdraw,
    },
    note_tree::NoteTree,
};
use serde_json::json;
use zk::{setup::dev_setup_snarkjs, test_circuit::TestCircuitHandle};

const CHAIN_ID: u64 = 1926;

fn rep(b: u8) -> [u8; 32] {
    [b; 32]
}

fn main() {
    let mut args = env::args().skip(1);
    let out_path = args
        .next()
        .expect("usage: dump_pool_fixture <out.json> [--copy-vk]");
    let copy_vk = args.any(|a| a == "--copy-vk");

    // The golden 3-leaf tree (spec/golden.json) is the genesis pool.
    let sk1 = fr_from_be_bytes(&rep(0x42));
    let sk2 = fr_from_be_bytes(&rep(0x43));
    let eth = asset_id("ETH").unwrap();
    let usdt = asset_id("USDT").unwrap();
    let leaves = [
        note_commit(npk_from_sk(sk1), eth, 7, fr_from_be_bytes(&rep(0x33))),
        note_commit(
            npk_from_sk(sk2),
            usdt,
            1_000_000,
            fr_from_be_bytes(&rep(0x34)),
        ),
        note_commit(npk_from_sk(sk1), eth, 5, fr_from_be_bytes(&rep(0x35))),
    ];
    let mut tree = NoteTree::new();
    for l in leaves {
        tree.append(l);
    }
    let anchor = tree.root();

    // ── note_deposit fixture: mint 2000 ETH to sk1 ──
    let dep_setup = dev_setup_snarkjs("note_deposit").expect("setup note_deposit");
    let dep_handle = TestCircuitHandle::from_compiled(&dep_setup.circuit_dir).expect("handle");
    let dep_bridge_r = fr_from_be_bytes(&rep(0x61));
    let dep_note_r = fr_from_be_bytes(&rep(0x62));
    // Pre-compute the public hexes so bind can be derived before proving
    // (bind covers the request fields, which include both commitments).
    let dep_cm = note_commit(npk_from_sk(sk1), eth, 2_000, dep_note_r);
    let dep_bridge = zk::wallet::poseidon2(ark_bn254::Fr::from(2_000u64), dep_bridge_r);
    let dep_bind = note_deposit_bind(
        CHAIN_ID,
        "ETH",
        &note_fr_to_hex(&dep_bridge),
        &note_fr_to_hex(&dep_cm),
    );
    let dep_proof = prove_note_deposit(
        NoteDepositWitness {
            v: 2_000,
            r_bridge: dep_bridge_r,
            npk: npk_from_sk(sk1),
            r_note: dep_note_r,
            asset: eth,
            bind: dep_bind,
        },
        &dep_handle,
        &dep_setup.zkey,
    )
    .expect("prove note_deposit");

    // ── spend_withdraw fixture: sk2 spends leaf1 (1_000_000 USDT),
    //    withdraws 400_000, keeps 600_000 as change ──
    let wd_setup = dev_setup_snarkjs("spend_withdraw").expect("setup spend_withdraw");
    let wd_handle = TestCircuitHandle::from_compiled(&wd_setup.circuit_dir).expect("handle");
    let (path, bits) = tree.path(1);
    let slots = [
        SpendSlot::real(sk2, 1_000_000, fr_from_be_bytes(&rep(0x34)), path, bits),
        SpendSlot::dummy(),
    ];
    let wd_bridge_r = fr_from_be_bytes(&rep(0x51));
    let wd_change_r = fr_from_be_bytes(&rep(0x52));
    let wd_bridge = zk::wallet::poseidon2(ark_bn254::Fr::from(400_000u64), wd_bridge_r);
    let wd_change = note_commit(npk_from_sk(sk2), usdt, 600_000, wd_change_r);
    let nf0 = slots[0].nullifier(usdt);
    let nf1 = slots[1].nullifier(usdt);
    let wd_bind = note_withdraw_bind(
        CHAIN_ID,
        "USDT",
        &note_fr_to_hex(&anchor),
        &note_fr_to_hex(&nf0),
        &note_fr_to_hex(&nf1),
        &note_fr_to_hex(&wd_bridge),
        &note_fr_to_hex(&wd_change),
    );
    let wd_proof = prove_spend_withdraw(
        SpendWithdrawWitness {
            slots,
            anchor,
            asset: usdt,
            v_out: 400_000,
            r_bridge_out: wd_bridge_r,
            npk_change: npk_from_sk(sk2),
            v_change: 600_000,
            r_change: wd_change_r,
            bind: wd_bind,
        },
        &wd_handle,
        &wd_setup.zkey,
    )
    .expect("prove spend_withdraw");

    let fixture = json!({
        "chain_id": CHAIN_ID,
        "genesis_notes": leaves.iter().map(note_fr_to_hex).collect::<Vec<_>>(),
        "anchor": note_fr_to_hex(&anchor),
        "deposit": {
            "token": "ETH",
            "bridge_commitment": dep_proof.bridge_commitment_hex,
            "output_commitment": dep_proof.cm_out_hex,
            "proof_json": dep_proof.proof_json,
            "public_json": dep_proof.public_json,
            "vk_path": dep_setup.vk_json.to_string_lossy(),
        },
        "withdraw": {
            "token": "USDT",
            "anchor": note_fr_to_hex(&anchor),
            "nullifiers": [wd_proof.nf_hex[0], wd_proof.nf_hex[1]],
            "bridge_out_commitment": wd_proof.bridge_out_commitment_hex,
            "change_commitment": wd_proof.cm_change_hex,
            "proof_json": wd_proof.proof_json,
            "public_json": wd_proof.public_json,
            "vk_path": wd_setup.vk_json.to_string_lossy(),
        },
    });
    fs::write(&out_path, serde_json::to_string_pretty(&fixture).unwrap()).expect("write fixture");
    println!("wrote {out_path}");

    if copy_vk {
        let vk_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../chain/vk");
        fs::copy(&dep_setup.vk_json, vk_dir.join("note_deposit_vk.json"))
            .expect("copy note_deposit vk");
        fs::copy(&wd_setup.vk_json, vk_dir.join("spend_withdraw_vk.json"))
            .expect("copy spend_withdraw vk");
        println!("copied VKs into chain/vk/");
    }
}
