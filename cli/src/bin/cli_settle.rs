//! Settle a matched pair of orders (demo mode: driver holds both parties'
//! mnemonics so it can run both `prove_settle_*` calls locally and submit a
//! single SettleOrder request).
//!
//! In production this would be split: each party proves their own leg and
//! they exchange `SettleTokenLeg` JSON over a P2P channel before either side
//! submits. Here we cut that corner so the e2e flow can be exercised by a
//! single command.
//!
//! Usage:
//!   cli-settle --orders <id1>,<id2> --alice-mnemonic <words> --bob-mnemonic <words>
//!
//! The driver figures out which order belongs to which mnemonic by comparing
//! `order.Pubkey` to each derived ed25519 pubkey.

use std::collections::HashSet;
use std::path::Path;
use std::process::ExitCode;

use invisibook_lib::cash_store::{CashRecord, CashStore};
use invisibook_lib::chain::{ChainClient, SettleTokenLegParam};
use invisibook_lib::config::ClientConfig;
use invisibook_lib::types::{
    CASH_ACTIVE, CASH_LOCKED, CASH_SPENT, Order, OrderID, OrderStatus, TokenID, TradeType,
};
use rand::RngCore;
use zk::setup::dev_setup_snarkjs;
use zk::test_circuit::TestCircuitHandle;
use zk::wallet::{
    SettleLargerWitness, SettleSmallerWitness, fr_to_hex, poseidon_commit,
    prove_settle_larger, prove_settle_smaller,
};

const POSEIDON_ZERO_COMMITMENT_HEX: &str =
    "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut order_ids: Option<(OrderID, OrderID)> = None;
    let mut alice_mnemonic: Option<String> = None;
    let mut bob_mnemonic: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--orders" if i + 1 < args.len() => {
                let parts: Vec<&str> = args[i + 1].split(',').collect();
                if parts.len() != 2 {
                    eprintln!("--orders must be <id1>,<id2>");
                    return ExitCode::from(2);
                }
                order_ids = Some((parts[0].to_string(), parts[1].to_string()));
                i += 2;
            }
            "--alice-mnemonic" if i + 1 < args.len() => {
                alice_mnemonic = Some(args[i + 1].clone());
                i += 2;
            }
            "--bob-mnemonic" if i + 1 < args.len() => {
                bob_mnemonic = Some(args[i + 1].clone());
                i += 2;
            }
            "--config" | "-c" if i + 1 < args.len() => {
                config_path = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                eprintln!("usage: cli-settle --orders <id1>,<id2> --alice-mnemonic <words> --bob-mnemonic <words> [--config <path>]");
                return ExitCode::from(2);
            }
        }
    }
    let Some((id_a, id_b)) = order_ids else {
        eprintln!("missing --orders");
        return ExitCode::from(2);
    };
    let Some(am) = alice_mnemonic else {
        eprintln!("missing --alice-mnemonic");
        return ExitCode::from(2);
    };
    let Some(bm) = bob_mnemonic else {
        eprintln!("missing --bob-mnemonic");
        return ExitCode::from(2);
    };

    let mut alice_cfg = ClientConfig::load(config_path.as_deref());
    alice_cfg.keypair.mnemonic = am;
    let mut bob_cfg = ClientConfig::load(config_path.as_deref());
    bob_cfg.keypair.mnemonic = bm;

    let alice_seed = match alice_cfg.seed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("alice seed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bob_seed = match bob_cfg.seed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bob seed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let alice = ChainClient::new(
        &alice_cfg.chain.http_url,
        &alice_cfg.chain.ws_url,
        alice_seed,
        alice_cfg.chain.chain_id,
    );
    let bob = ChainClient::new(
        &bob_cfg.chain.http_url,
        &bob_cfg.chain.ws_url,
        bob_seed,
        bob_cfg.chain.chain_id,
    );
    let alice_pubkey = alice.pubkey_hex().to_string();
    let bob_pubkey = bob.pubkey_hex().to_string();

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    // Pull both orders from chain. Either order id can map to either party — match by pubkey.
    let orders = match rt.block_on(alice.query_orders(None, None, None, None, None, Some(100), Some(0))) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("query_orders: {e}");
            return ExitCode::FAILURE;
        }
    };
    let order_a = match orders.iter().find(|o| o.id == id_a) {
        Some(o) => o.clone(),
        None => {
            eprintln!("order {id_a} not found");
            return ExitCode::FAILURE;
        }
    };
    let order_b = match orders.iter().find(|o| o.id == id_b) {
        Some(o) => o.clone(),
        None => {
            eprintln!("order {id_b} not found");
            return ExitCode::FAILURE;
        }
    };
    if order_a.status != OrderStatus::Matched || order_b.status != OrderStatus::Matched {
        eprintln!("both orders must be Matched (got {:?} / {:?})", order_a.status, order_b.status);
        return ExitCode::FAILURE;
    }
    if order_a.match_order.as_deref() != Some(&order_b.id)
        || order_b.match_order.as_deref() != Some(&order_a.id)
    {
        eprintln!("orders are not matched with each other");
        return ExitCode::FAILURE;
    }
    let price = match (order_a.price, order_b.price) {
        (Some(p), Some(q)) if p == q => p,
        _ => {
            eprintln!("orders disagree on price");
            return ExitCode::FAILURE;
        }
    };

    // Map each order to its owner (alice or bob).
    let (alice_order, bob_order) = match (order_a.pubkey == alice_pubkey, order_b.pubkey == bob_pubkey) {
        (true, true) => (order_a, order_b),
        (false, false) => {
            // Maybe ids are reversed
            if orders.iter().any(|o| o.id == id_a && o.pubkey == bob_pubkey) {
                (order_b, order_a)
            } else {
                eprintln!("could not match orders to mnemonics — pubkey mismatch");
                return ExitCode::FAILURE;
            }
        }
        _ => {
            eprintln!("could not match orders to mnemonics — pubkey mismatch");
            return ExitCode::FAILURE;
        }
    };

    // Each party loads their own CashStore. Demo mode keeps separate stores per
    // mnemonic — same path with mnemonic discriminator (not implemented; assume
    // one home dir holds the active mnemonic's records, which works in the e2e
    // because each party runs their own deposit/send_order separately before settle).
    let alice_store = CashStore::load(CashStore::default_path());
    let bob_store = CashStore::load(CashStore::default_path());

    // Determine which token each party locked. Buy locks token2 (paying side);
    // Sell locks token1 (asset side).
    let alice_lock_token = match alice_order.trade_type {
        TradeType::Buy => alice_order.subject.token2.clone(),
        TradeType::Sell => alice_order.subject.token1.clone(),
    };
    let bob_lock_token = match bob_order.trade_type {
        TradeType::Buy => bob_order.subject.token2.clone(),
        TradeType::Sell => bob_order.subject.token1.clone(),
    };

    // Pull each party's locked CashRecord(s) for their order.
    let alice_locked_recs: Vec<CashRecord> = alice_order
        .input_cash_ids
        .iter()
        .filter_map(|id| alice_store.records().iter().find(|r| &r.cash_id == id).cloned())
        .collect();
    let bob_locked_recs: Vec<CashRecord> = bob_order
        .input_cash_ids
        .iter()
        .filter_map(|id| bob_store.records().iter().find(|r| &r.cash_id == id).cloned())
        .collect();
    if alice_locked_recs.is_empty() || bob_locked_recs.is_empty() {
        eprintln!("missing local CashRecord for one of the locked inputs — driver requires both wallets' cash.json populated");
        return ExitCode::FAILURE;
    }

    let alice_locked_amount: u64 = alice_locked_recs.iter().map(|r| r.amount).sum();
    let bob_locked_amount: u64 = bob_locked_recs.iter().map(|r| r.amount).sum();

    // The fill is the smaller-side's full lock. In a Buy/Sell pair on Token1/Token2
    // at integer `price`, the matched amount in each token is:
    //   fill_t1 = min(seller's token1 lock, buyer's token1 wanted = buyer_locked_t2 / price)
    //   fill_t2 = fill_t1 * price
    let (fill_t1, fill_t2) = compute_fills(
        &alice_order,
        &bob_order,
        alice_locked_amount,
        bob_locked_amount,
        price,
    );

    eprintln!("matched: alice {alice_lock_token}={alice_locked_amount}, bob {bob_lock_token}={bob_locked_amount}, price={price}, fill_t1={fill_t1}, fill_t2={fill_t2}");

    // Decide larger / smaller per party. The party whose locked == fill_in_their_token is "smaller".
    let alice_locked_in_their_token = alice_locked_amount;
    let alice_fill = if alice_lock_token == alice_order.subject.token1 { fill_t1 } else { fill_t2 };
    let bob_fill = if bob_lock_token == bob_order.subject.token1 { fill_t1 } else { fill_t2 };
    let alice_is_smaller = alice_locked_in_their_token == alice_fill;
    let bob_is_smaller = bob_locked_amount == bob_fill;

    if alice_is_smaller && bob_is_smaller {
        // Dual-larger path (exact match) per plan: both run settle_larger.
        // This branch isn't fully demoed; bail out with a clear message.
        eprintln!("both sides fully fill (locked == fill) — dual-larger settle not implemented in demo");
        return ExitCode::FAILURE;
    }

    // Off-chain coordination secrets. Driver picks them randomly here; in
    // production both parties would derive them from a shared secret + counter.
    let mut r_match_t1 = [0u8; 32];
    let mut r_match_t2 = [0u8; 32];
    let mut alice_recv_random = [0u8; 32];
    let mut bob_recv_random = [0u8; 32];
    rand::rng().fill_bytes(&mut r_match_t1);
    rand::rng().fill_bytes(&mut r_match_t2);
    rand::rng().fill_bytes(&mut alice_recv_random);
    rand::rng().fill_bytes(&mut bob_recv_random);

    // alice receives token-not-her-own (the counterparty's token);
    // amount = fill in that token.
    let alice_recv_token = if alice_lock_token == alice_order.subject.token1 {
        alice_order.subject.token2.clone()
    } else {
        alice_order.subject.token1.clone()
    };
    let bob_recv_token = if bob_lock_token == bob_order.subject.token1 {
        bob_order.subject.token2.clone()
    } else {
        bob_order.subject.token1.clone()
    };
    let alice_recv_amount = if alice_recv_token == alice_order.subject.token1 { fill_t1 } else { fill_t2 };
    let bob_recv_amount = if bob_recv_token == bob_order.subject.token1 { fill_t1 } else { fill_t2 };
    let alice_recv_commit_hex = fr_to_hex(&poseidon_commit(alice_recv_amount, &alice_recv_random));
    let bob_recv_commit_hex = fr_to_hex(&poseidon_commit(bob_recv_amount, &bob_recv_random));

    // Compile + cache circuits once
    eprintln!("preparing settle circuits (compile + snarkjs setup, cached)...");
    let larger_setup = match dev_setup_snarkjs("settle_larger") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("settle_larger setup: {e}");
            return ExitCode::FAILURE;
        }
    };
    let smaller_setup = match dev_setup_snarkjs("settle_smaller") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("settle_smaller setup: {e}");
            return ExitCode::FAILURE;
        }
    };
    let larger_handle = TestCircuitHandle::from_compiled(&larger_setup.circuit_dir).unwrap();
    let smaller_handle = TestCircuitHandle::from_compiled(&smaller_setup.circuit_dir).unwrap();

    // Build legs
    let mut legs: Vec<SettleTokenLegParam> = Vec::new();
    if alice_is_smaller {
        // alice = smaller, bob = larger
        let leg_alice = match build_smaller_leg(
            &alice_locked_recs,
            r_match_for_token(&alice_lock_token, &alice_order, r_match_t1, r_match_t2),
            &bob_recv_commit_hex,
            bob.pubkey_hex(),
            &alice_lock_token,
            &smaller_handle,
            &smaller_setup.zkey,
        ) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("alice smaller leg: {e}");
                return ExitCode::FAILURE;
            }
        };
        let bob_change_amount = bob_locked_amount.saturating_sub(bob_fill);
        let leg_bob = match build_larger_leg(
            &bob_locked_recs,
            r_match_t1,
            r_match_t2,
            price,
            &bob_lock_token,
            &bob_order,
            bob_change_amount,
            &alice_recv_commit_hex,
            alice.pubkey_hex(),
            &larger_handle,
            &larger_setup.zkey,
        ) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("bob larger leg: {e}");
                return ExitCode::FAILURE;
            }
        };
        legs.push(leg_alice);
        legs.push(leg_bob);
    } else {
        // bob = smaller, alice = larger
        let leg_bob = match build_smaller_leg(
            &bob_locked_recs,
            r_match_for_token(&bob_lock_token, &bob_order, r_match_t1, r_match_t2),
            &alice_recv_commit_hex,
            alice.pubkey_hex(),
            &bob_lock_token,
            &smaller_handle,
            &smaller_setup.zkey,
        ) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("bob smaller leg: {e}");
                return ExitCode::FAILURE;
            }
        };
        let alice_change_amount = alice_locked_amount.saturating_sub(alice_fill);
        let leg_alice = match build_larger_leg(
            &alice_locked_recs,
            r_match_t1,
            r_match_t2,
            price,
            &alice_lock_token,
            &alice_order,
            alice_change_amount,
            &bob_recv_commit_hex,
            bob.pubkey_hex(),
            &larger_handle,
            &larger_setup.zkey,
        ) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("alice larger leg: {e}");
                return ExitCode::FAILURE;
            }
        };
        legs.push(leg_alice);
        legs.push(leg_bob);
    }

    // Submit. Either client can submit; chain doesn't gate by signer for SettleOrder.
    eprintln!("submitting settle to chain...");
    let order_ids_vec = vec![alice_order.id.clone(), bob_order.id.clone()];
    if let Err(e) = rt.block_on(alice.settle_order(order_ids_vec, legs)) {
        eprintln!("settle_order failed: {e}");
        return ExitCode::FAILURE;
    }

    // Update local CashStores: spent locked, append change + recv as ACTIVE.
    // Demo simplification: both stores share the same path; we update once.
    let mut store = CashStore::load(CashStore::default_path());
    let spent_ids: HashSet<String> = alice_order
        .input_cash_ids
        .iter()
        .chain(bob_order.input_cash_ids.iter())
        .cloned()
        .collect();
    for rec in store.records_mut().iter_mut() {
        if spent_ids.contains(&rec.cash_id) {
            rec.status = CASH_SPENT;
        }
    }
    // alice's recv (active)
    store.records_mut().push(CashRecord {
        cash_id: invisibook_lib::orderbook::compute_cash_id(&alice_pubkey, &alice_recv_token, &alice_recv_commit_hex),
        token: alice_recv_token.clone(),
        amount: alice_recv_amount,
        random: hex::encode(alice_recv_random),
        status: CASH_ACTIVE,
    });
    // bob's recv (active)
    store.records_mut().push(CashRecord {
        cash_id: invisibook_lib::orderbook::compute_cash_id(&bob_pubkey, &bob_recv_token, &bob_recv_commit_hex),
        token: bob_recv_token.clone(),
        amount: bob_recv_amount,
        random: hex::encode(bob_recv_random),
        status: CASH_ACTIVE,
    });
    // Note: change cash records aren't appended here because the local
    // CashStore would need to know each side's change_random separately —
    // omitted to keep the demo small. If you need to spend change later,
    // re-add manually or extend this binary.
    let _ = store.flush();

    println!("settle ok: orders {} / {} done; alice received {} {}; bob received {} {}",
        alice_order.id, bob_order.id, alice_recv_amount, alice_recv_token,
        bob_recv_amount, bob_recv_token);
    ExitCode::SUCCESS
}

/// Choose which `r_match_*` corresponds to the given token (Token1 vs Token2).
fn r_match_for_token(
    token: &TokenID,
    order: &Order,
    r_t1: [u8; 32],
    r_t2: [u8; 32],
) -> [u8; 32] {
    if token == &order.subject.token1 { r_t1 } else { r_t2 }
}

/// Compute (fill_t1, fill_t2) for a matched pair. fill_t1 = min(seller's
/// token1 lock, buyer's intended token1 amount = buyer's token2 lock / price).
fn compute_fills(
    order_a: &Order,
    order_b: &Order,
    locked_a: u64,
    locked_b: u64,
    price: u64,
) -> (u64, u64) {
    // Determine which is seller (locks token1) and which is buyer (locks token2).
    let (seller_lock_t1, buyer_lock_t2) = match order_a.trade_type {
        TradeType::Sell => (locked_a, locked_b),
        TradeType::Buy => (locked_b, locked_a),
    };
    let buyer_wanted_t1 = if price > 0 { buyer_lock_t2 / price } else { 0 };
    let fill_t1 = seller_lock_t1.min(buyer_wanted_t1);
    let fill_t2 = fill_t1 * price;
    (fill_t1, fill_t2)
}

#[allow(clippy::too_many_arguments)]
fn build_smaller_leg(
    inputs: &[CashRecord],
    r_match: [u8; 32],
    counterparty_recv_commit_hex: &str,
    counterparty_pubkey: &str,
    token: &TokenID,
    handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SettleTokenLegParam, String> {
    let inputs_for_witness = decode_inputs(inputs)?;
    let sp = prove_settle_smaller(
        SettleSmallerWitness {
            r_match,
            inputs: inputs_for_witness,
            counterparty_recv_commitment_hex: counterparty_recv_commit_hex.to_string(),
        },
        handle,
        zkey,
    )
    .map_err(|e| format!("prove_settle_smaller: {e}"))?;
    Ok(SettleTokenLegParam {
        side: "smaller".to_string(),
        token: token.clone(),
        my_match_commitment: None,
        other_match_commitment: None,
        price: None,
        is_token2_sender: None,
        change_commitment: None,
        change_pubkey: String::new(),
        match_commitment: Some(sp.match_commitment_hex),
        recv_commitment: counterparty_recv_commit_hex.to_string(),
        recv_pubkey: counterparty_pubkey.to_string(),
        zk_proof: serde_json::to_string(&sp.proof_json).map_err(|e| e.to_string())?,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_larger_leg(
    inputs: &[CashRecord],
    r_match_t1: [u8; 32],
    r_match_t2: [u8; 32],
    price: u64,
    token: &TokenID,
    order: &Order,
    change_amount: u64,
    counterparty_recv_commit_hex: &str,
    counterparty_pubkey: &str,
    handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SettleTokenLegParam, String> {
    let inputs_for_witness = decode_inputs(inputs)?;
    let inputs_sum: u64 = inputs.iter().map(|r| r.amount).sum();
    let my_fill = inputs_sum.checked_sub(change_amount).ok_or("change > inputs.sum")?;
    let is_token2_sender = token == &order.subject.token2;
    let (other_fill, r_my, r_other) = if is_token2_sender {
        // I send Token2; my fill is fill_t2; counterparty sends Token1 (other_fill = fill_t1)
        (my_fill / price.max(1), r_match_t2, r_match_t1)
    } else {
        // I send Token1; my fill is fill_t1; counterparty sends Token2 (other_fill = fill_t2)
        (my_fill * price, r_match_t1, r_match_t2)
    };
    let mut change_random = [0u8; 32];
    if change_amount > 0 {
        rand::rng().fill_bytes(&mut change_random);
    }
    let sp = prove_settle_larger(
        SettleLargerWitness {
            r_my,
            other_fill,
            r_other,
            price,
            is_token2_sender,
            inputs: inputs_for_witness,
            change_amount,
            change_random,
            counterparty_recv_commitment_hex: counterparty_recv_commit_hex.to_string(),
        },
        handle,
        zkey,
    )
    .map_err(|e| format!("prove_settle_larger: {e}"))?;
    let change_commitment_hex = if change_amount == 0 {
        POSEIDON_ZERO_COMMITMENT_HEX.to_string()
    } else {
        sp.change_commitment_hex.clone()
    };
    Ok(SettleTokenLegParam {
        side: "larger".to_string(),
        token: token.clone(),
        my_match_commitment: Some(sp.my_match_commitment_hex),
        other_match_commitment: Some(sp.other_match_commitment_hex),
        price: Some(price),
        is_token2_sender: Some(is_token2_sender),
        change_commitment: Some(change_commitment_hex),
        change_pubkey: String::new(),
        match_commitment: None,
        recv_commitment: counterparty_recv_commit_hex.to_string(),
        recv_pubkey: counterparty_pubkey.to_string(),
        zk_proof: serde_json::to_string(&sp.proof_json).map_err(|e| e.to_string())?,
    })
}

fn decode_inputs(inputs: &[CashRecord]) -> Result<Vec<(u64, [u8; 32])>, String> {
    let mut out = Vec::with_capacity(inputs.len());
    for rec in inputs {
        let raw = hex::decode(&rec.random).map_err(|e| format!("bad random hex: {e}"))?;
        if raw.len() != 32 {
            return Err(format!("cash {} random must be 32 bytes", rec.cash_id));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        out.push((rec.amount, arr));
    }
    Ok(out)
}

// Silence unused: kept here so the binary compiles even if `CASH_LOCKED` import
// is unused after future tweaks.
#[allow(dead_code)]
const _LOCKED: u8 = CASH_LOCKED;
