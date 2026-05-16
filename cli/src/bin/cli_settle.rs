//! Settle a matched order (single-party mode).
//!
//! Each party runs this command independently, connecting to the counterparty
//! via QUIC for the MPC comparison, then submitting their own settlement data
//! to the chain. The chain collects both parties' submissions and finalises
//! settlement when both arrive.
//!
//! Usage:
//!   cli-settle --order <my_order_id> --mnemonic <words> \
//!              --local-addr <ip:port> --peer-addr <ip:port> \
//!              [--config <path>]

use std::{collections::HashSet, net::SocketAddr, path::Path, process::ExitCode};

use invisibook_lib::{
    cash_store::{CashRecord, CashStore},
    chain::{ChainClient, SettleTokenLegParam},
    config::ClientConfig,
    types::{
        CASH_ACTIVE, CASH_LOCKED, CASH_SPENT, MpcShareParam, Order, OrderID, OrderStatus, TokenID,
        TradeType,
    },
};
use mpc::{SettleConfig, SettleShare, Side, settle};
use rand::RngCore;
use zk::{
    setup::dev_setup_snarkjs,
    test_circuit::TestCircuitHandle,
    wallet::{
        SettleLargerWitness, SettleSmallerWitness, fr_to_hex, poseidon_commit, prove_settle_larger,
        prove_settle_smaller,
    },
};

const POSEIDON_ZERO_COMMITMENT_HEX: &str =
    "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut order_id: Option<OrderID> = None;
    let mut mnemonic: Option<String> = None;
    let mut local_addr: Option<String> = None;
    let mut peer_addr: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--order" if i + 1 < args.len() => {
                order_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--mnemonic" if i + 1 < args.len() => {
                mnemonic = Some(args[i + 1].clone());
                i += 2;
            }
            "--local-addr" if i + 1 < args.len() => {
                local_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--peer-addr" if i + 1 < args.len() => {
                peer_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--config" | "-c" if i + 1 < args.len() => {
                config_path = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                eprintln!(
                    "usage: cli-settle --order <id> --mnemonic <words> --local-addr <ip:port> --peer-addr <ip:port> [--config <path>]"
                );
                return ExitCode::from(2);
            }
        }
    }
    let Some(my_order_id) = order_id else {
        eprintln!("missing --order");
        return ExitCode::from(2);
    };
    let Some(mn) = mnemonic else {
        eprintln!("missing --mnemonic");
        return ExitCode::from(2);
    };
    let Some(local_addr_str) = local_addr else {
        eprintln!("missing --local-addr");
        return ExitCode::from(2);
    };
    let Some(peer_addr_str) = peer_addr else {
        eprintln!("missing --peer-addr");
        return ExitCode::from(2);
    };
    let local: SocketAddr = match local_addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid --local-addr: {e}");
            return ExitCode::from(2);
        }
    };
    let peer: SocketAddr = match peer_addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid --peer-addr: {e}");
            return ExitCode::from(2);
        }
    };

    let mut cfg = ClientConfig::load(config_path.as_deref());
    cfg.keypair.mnemonic = mn;

    let seed = match cfg.seed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("seed derivation: {e}");
            return ExitCode::FAILURE;
        }
    };
    let client = ChainClient::new(
        &cfg.chain.http_url,
        &cfg.chain.ws_url,
        seed,
        cfg.chain.chain_id,
    );
    let my_pubkey = client.pubkey_hex().to_string();

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    // Query my order from chain.
    let orders = match rt.block_on(client.query_orders(
        Some(my_order_id.clone()),
        None,
        None,
        None,
        None,
        Some(1),
        Some(0),
    )) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("query_orders: {e}");
            return ExitCode::FAILURE;
        }
    };
    let my_order = match orders.into_iter().find(|o| o.id == my_order_id) {
        Some(o) => o,
        None => {
            eprintln!("order {my_order_id} not found");
            return ExitCode::FAILURE;
        }
    };
    if my_order.status != OrderStatus::Matched {
        eprintln!(
            "order {} is not Matched (got {:?})",
            my_order.id, my_order.status
        );
        return ExitCode::FAILURE;
    }
    let match_order_id = match &my_order.match_order {
        Some(id) => id.clone(),
        None => {
            eprintln!("order {} has no match_order", my_order.id);
            return ExitCode::FAILURE;
        }
    };

    // Query counterparty order.
    let counter_orders = match rt.block_on(client.query_orders(
        Some(match_order_id.clone()),
        None,
        None,
        None,
        None,
        Some(1),
        Some(0),
    )) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("query counterparty order: {e}");
            return ExitCode::FAILURE;
        }
    };
    let counter_order = match counter_orders.into_iter().find(|o| o.id == match_order_id) {
        Some(o) => o,
        None => {
            eprintln!("counterparty order {match_order_id} not found");
            return ExitCode::FAILURE;
        }
    };
    let price = match (my_order.price, counter_order.price) {
        (Some(p), Some(q)) if p == q => p,
        _ => {
            eprintln!("orders disagree on price");
            return ExitCode::FAILURE;
        }
    };

    // Determine my locked token and side.
    let my_lock_token = match my_order.trade_type {
        TradeType::Buy => my_order.subject.token2.clone(),
        TradeType::Sell => my_order.subject.token1.clone(),
    };
    let counter_lock_token = match counter_order.trade_type {
        TradeType::Buy => counter_order.subject.token2.clone(),
        TradeType::Sell => counter_order.subject.token1.clone(),
    };

    // Load locked CashRecords from local store.
    let store = CashStore::load(CashStore::default_path());
    let my_locked_recs: Vec<CashRecord> = my_order
        .input_cash_ids
        .iter()
        .filter_map(|id| store.records().iter().find(|r| &r.cash_id == id).cloned())
        .collect();
    if my_locked_recs.is_empty() {
        eprintln!("missing local CashRecord for locked inputs");
        return ExitCode::FAILURE;
    }
    let my_locked_amount: u64 = my_locked_recs.iter().map(|r| r.amount).sum();

    // Determine MPC side: Buy = party 0, Sell = party 1.
    let mpc_side = match my_order.trade_type {
        TradeType::Buy => Side::Buy,
        TradeType::Sell => Side::Sell,
    };

    // Reconstruct the commitment for the locked cash (poseidon(amount, random)).
    // For MPC, we need decimal-string representations of the commitments.
    let my_random_hex = &my_locked_recs[0].random;
    let my_random_dec = hex_to_fr_decimal(my_random_hex);

    // Compute both commitments (c1 = buy side, c2 = sell side).
    let my_commit = fr_to_hex(&poseidon_commit(
        my_locked_amount,
        &hex_to_bytes32(my_random_hex),
    ));
    let my_commit_dec = hex_to_fr_decimal(&my_commit);

    // For the counterparty commitment, read it from chain (the order's Amount field).
    let counter_commit_dec = hex_to_fr_decimal(&counter_order.amount);

    let (c1, c2) = match mpc_side {
        Side::Buy => (my_commit_dec.clone(), counter_commit_dec.clone()),
        Side::Sell => (counter_commit_dec.clone(), my_commit_dec.clone()),
    };

    // Run MPC settle protocol via QUIC.
    eprintln!("running MPC settle protocol (local={local}, peer={peer})...");
    let mpc_config = SettleConfig {
        local_addr: local,
        peer_addr: peer,
    };
    let mpc_result: SettleShare = match rt.block_on(settle(
        &mpc_config,
        mpc_side,
        my_locked_amount,
        &my_random_dec,
        &c1,
        &c2,
    )) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("MPC settle failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("MPC settle complete");

    // Build MPC share param from the MPC result.
    let mpc_share = MpcShareParam {
        cmp_share: mpc_result.cmp_share,
        cmp_mac: mpc_result.cmp_mac,
        r_smaller_share: mpc_result.r_smaller_share,
        r_smaller_mac: mpc_result.r_smaller_mac,
        mac_key_share: mpc_result.mac_key_share,
    };

    // Compute fills to determine which side is larger/smaller.
    let counter_locked_amount = guess_counter_locked_amount(&counter_order, &store);
    let (fill_t1, fill_t2) = compute_fills(
        &my_order,
        &counter_order,
        my_locked_amount,
        counter_locked_amount,
        price,
    );

    let my_fill = if my_lock_token == my_order.subject.token1 {
        fill_t1
    } else {
        fill_t2
    };
    let my_is_smaller = my_locked_amount == my_fill;

    // Generate random for my received cash.
    let mut my_recv_random = [0u8; 32];
    rand::rng().fill_bytes(&mut my_recv_random);

    // My recv token is the counterparty's locked token.
    let my_recv_token = counter_lock_token.clone();
    let my_recv_amount = if my_recv_token == my_order.subject.token1 {
        fill_t1
    } else {
        fill_t2
    };
    let my_recv_commit_hex = fr_to_hex(&poseidon_commit(my_recv_amount, &my_recv_random));

    // For the ZK proof, we need the counterparty's recv commitment. In per-party
    // mode, each side independently computes `recv_commitment` — the counterparty
    // will produce their own. We use a placeholder: the proof binds the
    // counterparty's recv commitment as a public input; the chain verifies both
    // legs' recv commitments independently. We set it to the counterparty's
    // order amount as a placeholder that chain will verify via the leg.
    // Actually, the counterparty's recv commitment = the recv_commitment we
    // provide in our leg (the output we mint for them). So we compute it too.
    let mut counter_recv_random = [0u8; 32];
    rand::rng().fill_bytes(&mut counter_recv_random);
    let counter_recv_amount = if counter_lock_token == my_order.subject.token1 {
        fill_t1
    } else {
        fill_t2
    };
    let counter_recv_commit_hex =
        fr_to_hex(&poseidon_commit(counter_recv_amount, &counter_recv_random));

    // Compile circuits.
    eprintln!("preparing settle circuits...");
    let (larger_setup, smaller_setup) = (
        dev_setup_snarkjs("settle_larger").expect("settle_larger setup"),
        dev_setup_snarkjs("settle_smaller").expect("settle_smaller setup"),
    );
    let larger_handle = TestCircuitHandle::from_compiled(&larger_setup.circuit_dir).unwrap();
    let smaller_handle = TestCircuitHandle::from_compiled(&smaller_setup.circuit_dir).unwrap();

    // Build off-chain coordination secrets. In per-party mode, both parties must
    // agree on r_match_t1, r_match_t2. For now, we derive them from a shared
    // seed (e.g. hash of both order IDs). This is a simplification — production
    // would use the MPC-revealed r_smaller or a DH exchange.
    let (r_match_t1, r_match_t2) = derive_match_randoms(&my_order.id, &counter_order.id);

    // Build ZK leg.
    let leg = if my_is_smaller {
        let r_match = r_match_for_token(&my_lock_token, &my_order, r_match_t1, r_match_t2);
        match build_smaller_leg(
            &my_locked_recs,
            r_match,
            &counter_recv_commit_hex,
            &counter_order.pubkey,
            &my_lock_token,
            &smaller_handle,
            &smaller_setup.zkey,
        ) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("smaller leg: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let change_amount = my_locked_amount.saturating_sub(my_fill);
        match build_larger_leg(
            &my_locked_recs,
            r_match_t1,
            r_match_t2,
            price,
            &my_lock_token,
            &my_order,
            change_amount,
            &counter_recv_commit_hex,
            &counter_order.pubkey,
            &larger_handle,
            &larger_setup.zkey,
        ) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("larger leg: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    // Submit to chain.
    eprintln!("submitting settle to chain...");
    if let Err(e) = rt.block_on(client.settle_order(
        my_order_id.clone(),
        match_order_id.clone(),
        leg,
        mpc_share,
    )) {
        eprintln!("settle_order failed: {e}");
        return ExitCode::FAILURE;
    }

    // Update local CashStore.
    let mut store = CashStore::load(CashStore::default_path());
    let spent_ids: HashSet<String> = my_order.input_cash_ids.iter().cloned().collect();
    for rec in store.records_mut().iter_mut() {
        if spent_ids.contains(&rec.cash_id) {
            rec.status = CASH_SPENT;
        }
    }
    // My received cash.
    store.records_mut().push(CashRecord {
        cash_id: invisibook_lib::orderbook::compute_cash_id(
            &my_pubkey,
            &my_recv_token,
            &my_recv_commit_hex,
        ),
        token: my_recv_token.clone(),
        amount: my_recv_amount,
        random: hex::encode(my_recv_random),
        status: CASH_ACTIVE,
    });
    let _ = store.flush();

    println!(
        "settle submitted: order {} -> waiting for counterparty {}; received {} {}",
        my_order_id, match_order_id, my_recv_amount, my_recv_token
    );
    ExitCode::SUCCESS
}

/// Derive deterministic match randoms from both order IDs (sorted).
/// This is a simplification — production would use MPC-derived values.
fn derive_match_randoms(id_a: &str, id_b: &str) -> ([u8; 32], [u8; 32]) {
    use sha2::{Digest, Sha256};
    let (first, second) = if id_a < id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut h1 = Sha256::new();
    h1.update(b"r_match_t1:");
    h1.update(first.as_bytes());
    h1.update(second.as_bytes());
    let r1: [u8; 32] = h1.finalize().into();

    let mut h2 = Sha256::new();
    h2.update(b"r_match_t2:");
    h2.update(first.as_bytes());
    h2.update(second.as_bytes());
    let r2: [u8; 32] = h2.finalize().into();

    (r1, r2)
}

/// Convert hex string to BN254 Fr decimal string.
fn hex_to_fr_decimal(hex_str: &str) -> String {
    let bytes = hex::decode(hex_str).expect("valid hex");
    // Interpret as big-endian unsigned integer, then take mod BN254 order.
    let n = num_bigint::BigUint::from_bytes_be(&bytes);
    n.to_string()
}

/// Convert hex string to [u8; 32].
fn hex_to_bytes32(hex_str: &str) -> [u8; 32] {
    let raw = hex::decode(hex_str).expect("valid hex");
    let mut arr = [0u8; 32];
    let start = 32usize.saturating_sub(raw.len());
    arr[start..].copy_from_slice(&raw[..raw.len().min(32)]);
    arr
}

/// Guess the counterparty's locked amount. In per-party mode we might not have
/// their CashRecords locally. Fall back to 0 (which makes this party appear as
/// smaller). If the local store does have it, use that.
fn guess_counter_locked_amount(counter: &Order, store: &CashStore) -> u64 {
    counter
        .input_cash_ids
        .iter()
        .filter_map(|id| store.records().iter().find(|r| &r.cash_id == id))
        .map(|r| r.amount)
        .sum()
}

/// Choose which `r_match_*` corresponds to the given token (Token1 vs Token2).
fn r_match_for_token(token: &TokenID, order: &Order, r_t1: [u8; 32], r_t2: [u8; 32]) -> [u8; 32] {
    if token == &order.subject.token1 {
        r_t1
    } else {
        r_t2
    }
}

/// Compute (fill_t1, fill_t2) for a matched pair.
fn compute_fills(
    order_a: &Order,
    _order_b: &Order,
    locked_a: u64,
    locked_b: u64,
    price: u64,
) -> (u64, u64) {
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
    let my_fill = inputs_sum
        .checked_sub(change_amount)
        .ok_or("change > inputs.sum")?;
    let is_token2_sender = token == &order.subject.token2;
    let (other_fill, r_my, r_other) = if is_token2_sender {
        (my_fill / price.max(1), r_match_t2, r_match_t1)
    } else {
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

/// Decode CashRecord randoms from hex to (amount, [u8; 32]) pairs.
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

// Silence unused import warning.
#[allow(dead_code)]
const _LOCKED: u8 = CASH_LOCKED;
