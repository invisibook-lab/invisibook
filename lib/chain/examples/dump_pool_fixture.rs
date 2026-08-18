//! Dump shielded-pool and settlement fixtures for the Go chain tests, and
//! copy their circuits' verification keys into `chain/vk/`.
//!
//! Usage: cargo run -p invisibook-lib --example dump_pool_fixture -- \
//!            /tmp/pool_fixture.json [--copy-vk]
//!
//! The fixture holds one valid note_deposit proof and one valid
//! spend_withdraw proof over the golden 3-leaf tree (spec/golden.json), so
//! the Go side can verify real proofs and pin the public-input layouts and
//! the bind transcript lockstep. `--copy-vk` additionally refreshes
//! the pool and settlement verification keys under `chain/vk/`.

use std::{env, fs, path::PathBuf};

use invisibook_lib::{
    note::{
        asset_id, fr_from_be_bytes, note_commit, note_deposit_bind, note_fr_to_hex,
        note_withdraw_bind, npk_from_sk, settle_large_bind, settle_small_bind,
    },
    note_prover::{
        NoteDepositWitness, SettleLargeWitness, SettleSmallWitness, SpendSlot,
        SpendWithdrawWitness, prove_note_deposit, prove_settle_large, prove_settle_small,
        prove_spend_withdraw,
    },
    note_tree::NoteTree,
};
use serde_json::json;
use zk::{
    setup::dev_setup_snarkjs,
    test_circuit::TestCircuitHandle,
    wallet::{SettleCmpWitness, prove_settle_cmp},
};

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

    // ── Settlement fixtures: a matched pair (A sells 80 ETH @3, B buys 60)
    //    through compare + both settle proofs, with placeholder order ids
    //    ("order-a"/"order-b") baked into the binds so the Go verify tests
    //    can rebuild the exact statements without chain state.
    //    Locked-only model: each order carries ONE collateral commitment —
    //    A locks 80 ETH under r_la, B locks 180 USDT under r_lb; the same
    //    commitments enter the compare and the settle statements. ──
    let settle_out = out_path.replace(".json", "_settle.json");
    let (r_la_bytes, r_lb_bytes) = (rep(0x83), rep(0x84));
    let (r_la, r_lb) = (fr_from_be_bytes(&r_la_bytes), fr_from_be_bytes(&r_lb_bytes));
    let (price_a, price_b, execution_price) = (3u64, 4u64, 3u64);

    let cmp_setup = dev_setup_snarkjs("settle_cozk").expect("setup settle_cozk");
    let cmp_handle = TestCircuitHandle::from_compiled(&cmp_setup.circuit_dir).expect("handle");
    let cmp_proof = prove_settle_cmp(
        &SettleCmpWitness {
            a: 80,
            r_a: r_la_bytes,
            b: 60,
            r_b: r_lb_bytes,
            price_a,
            price_b,
            a_is_seller: true,
        },
        &cmp_handle,
        &cmp_setup.zkey,
    )
    .expect("prove settle_cmp");

    // B (smaller, buyer, side = 0): pays its whole 180 USDT collateral to
    // A's fresh npk.
    let small_setup = dev_setup_snarkjs("settle_small").expect("setup settle_small");
    let small_handle = TestCircuitHandle::from_compiled(&small_setup.circuit_dir).expect("handle");
    let npk_a_fresh = npk_from_sk(fr_from_be_bytes(&rep(0x91)));
    let npk_b_fresh = npk_from_sk(fr_from_be_bytes(&rep(0x92)));
    let small_w = SettleSmallWitness {
        q: 60,
        r_locked: r_lb,
        collateral_price: price_b,
        execution_price,
        side_sell: false,
        pay_asset: asset_id("USDT").unwrap(),
        npk_ctr: npk_a_fresh,
        r_note: fr_from_be_bytes(&rep(0x93)),
        npk_refund: npk_b_fresh,
        r_refund: fr_from_be_bytes(&rep(0x94)),
        bind: fr_from_be_bytes(&[0u8; 32]), // patched below
    };
    let (small_note, small_refund) = small_w.output_cms();
    let small_bind = settle_small_bind(
        CHAIN_ID,
        "order-b",
        "order-a",
        &note_fr_to_hex(&small_note),
        &note_fr_to_hex(&small_refund),
    );
    let small_w = SettleSmallWitness {
        bind: small_bind,
        ..small_w
    };
    let small_proof =
        prove_settle_small(small_w, &small_handle, &small_setup.zkey).expect("prove settle_small");

    // A (larger, seller, side = 1): pays the 60 ETH fill to B's fresh npk,
    // relists the residual 20 under a fresh collateral commitment.
    let large_setup = dev_setup_snarkjs("settle_large").expect("setup settle_large");
    let large_handle = TestCircuitHandle::from_compiled(&large_setup.circuit_dir).expect("handle");
    let large_w = SettleLargeWitness {
        q: 80,
        r_locked: r_la,
        q_ctr: 60,
        r_locked_ctr: r_lb,
        collateral_price: price_a,
        ctr_collateral_price: price_b,
        execution_price,
        side_sell: true,
        r_locked_residual: fr_from_be_bytes(&rep(0x95)),
        pay_asset: asset_id("ETH").unwrap(),
        npk_ctr: npk_b_fresh,
        r_note: fr_from_be_bytes(&rep(0x96)),
        npk_refund: npk_a_fresh,
        r_refund: fr_from_be_bytes(&rep(0x97)),
        bind: fr_from_be_bytes(&[0u8; 32]), // patched below
    };
    let (cm_locked_res, cm_note, cm_refund) = large_w.output_cms();
    let large_bind = settle_large_bind(
        CHAIN_ID,
        "order-a",
        "order-b",
        &note_fr_to_hex(&cm_locked_res),
        &note_fr_to_hex(&cm_note),
        &note_fr_to_hex(&cm_refund),
    );
    let large_w = SettleLargeWitness {
        bind: large_bind,
        ..large_w
    };
    let large_proof =
        prove_settle_large(large_w, &large_handle, &large_setup.zkey).expect("prove settle_large");

    let settle_fixture = json!({
        "version": 2,
        "chain_id": CHAIN_ID,
        "price_a": price_a,
        "price_b": price_b,
        "execution_price": execution_price,
        "a_is_seller": true,
        "locked_a": cmp_proof.locked_a_hex,
        "locked_b": cmp_proof.locked_b_hex,
        "cmp": {
            "cmp": cmp_proof.cmp,
            "proof_json": cmp_proof.proof_json,
            "public_json": cmp_proof.public_json,
            "vk_path": cmp_setup.vk_json.to_string_lossy(),
        },
        "small": {
            "order_id": "order-b",
            "match_order_id": "order-a",
            "cm_note_out": small_proof.cm_note_out_hex,
            "cm_refund_out": small_proof.cm_refund_out_hex,
            "proof_json": small_proof.proof_json,
            "public_json": small_proof.public_json,
            "vk_path": small_setup.vk_json.to_string_lossy(),
        },
        "large": {
            "order_id": "order-a",
            "match_order_id": "order-b",
            "cm_locked_residual": large_proof.cm_locked_residual_hex,
            "cm_note_out": large_proof.cm_note_out_hex,
            "cm_refund_out": large_proof.cm_refund_out_hex,
            "proof_json": large_proof.proof_json,
            "public_json": large_proof.public_json,
            "vk_path": large_setup.vk_json.to_string_lossy(),
        },
    });
    fs::write(
        &settle_out,
        serde_json::to_string_pretty(&settle_fixture).unwrap(),
    )
    .expect("write settle fixture");
    println!("wrote {settle_out}");

    if copy_vk {
        let vk_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../chain/vk");
        fs::copy(&dep_setup.vk_json, vk_dir.join("note_deposit_vk.json"))
            .expect("copy note_deposit vk");
        fs::copy(&wd_setup.vk_json, vk_dir.join("spend_withdraw_vk.json"))
            .expect("copy spend_withdraw vk");
        fs::copy(&cmp_setup.vk_json, vk_dir.join("settle_cozk_vk.json"))
            .expect("copy settle_cozk vk");
        fs::copy(&small_setup.vk_json, vk_dir.join("settle_small_vk.json"))
            .expect("copy settle_small vk");
        fs::copy(&large_setup.vk_json, vk_dir.join("settle_large_vk.json"))
            .expect("copy settle_large vk");
        let so_setup = dev_setup_snarkjs("send_order").expect("setup send_order");
        fs::copy(&so_setup.vk_json, vk_dir.join("send_order_vk.json")).expect("copy send_order vk");
        let cf_setup = dev_setup_snarkjs("claim_fees").expect("setup claim_fees");
        fs::copy(&cf_setup.vk_json, vk_dir.join("claim_fees_vk.json")).expect("copy claim_fees vk");
        println!("copied VKs into chain/vk/");
    }
}
