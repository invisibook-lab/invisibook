//! Standalone send-order subcommand. Selects active cashes, generates a
//! rapidsnark split proof when the inputs over-cover the order amount, sends
//! the order to chain, and updates the local CashStore (mark inputs as
//! Spent/Locked, append change + locked records).
//!
//! Usage:
//!   cli-send-order --type buy|sell --token1 ETH --token2 USDT --price 1 --amount 60
//!
//! Order amount semantics mirror the TUI:
//!   * Buy:  total_input_token2 = price * amount   (paying with token2)
//!   * Sell: total_input_token1 = amount           (selling token1)
//! Inputs are auto-selected from `~/.invisibook/cash.json`.

use std::process::ExitCode;

use invisibook_lib::{
    cash_store::{CashRecord, CashStore},
    chain::ChainClient,
    config::ClientConfig,
    orderbook::{
        self, CashSelection, compute_cash_id, compute_order_id, encrypt_amount_with_info,
        select_cash,
    },
    types::{
        CASH_ACTIVE, CASH_LOCKED, CASH_SPENT, CashChange, Order, OrderStatus, TradePair, TradeType,
    },
};
use zk::{
    setup::dev_setup_snarkjs,
    test_circuit::TestCircuitHandle,
    wallet::{SplitWitness, prove_split},
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut trade_type: Option<TradeType> = None;
    let mut token1: Option<String> = None;
    let mut token2: Option<String> = None;
    let mut price: Option<u64> = None;
    let mut amount: Option<u64> = None;
    let mut mnemonic: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--type" if i + 1 < args.len() => {
                trade_type = match args[i + 1].as_str() {
                    "buy" => Some(TradeType::Buy),
                    "sell" => Some(TradeType::Sell),
                    other => {
                        eprintln!("--type must be buy or sell, got {other}");
                        return ExitCode::from(2);
                    }
                };
                i += 2;
            }
            "--token1" if i + 1 < args.len() => {
                token1 = Some(args[i + 1].to_uppercase());
                i += 2;
            }
            "--token2" if i + 1 < args.len() => {
                token2 = Some(args[i + 1].to_uppercase());
                i += 2;
            }
            "--price" if i + 1 < args.len() => {
                price = args[i + 1].parse().ok();
                i += 2;
            }
            "--amount" if i + 1 < args.len() => {
                amount = args[i + 1].parse().ok();
                i += 2;
            }
            "--mnemonic" if i + 1 < args.len() => {
                mnemonic = Some(args[i + 1].clone());
                i += 2;
            }
            "--config" | "-c" if i + 1 < args.len() => {
                config_path = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                eprintln!(
                    "usage: cli-send-order --type buy|sell --token1 T1 --token2 T2 --price <u64> --amount <u64> [--mnemonic <words>] [--config <path>]"
                );
                return ExitCode::from(2);
            }
        }
    }
    let trade_type = trade_type.unwrap_or_else(|| {
        eprintln!("missing --type");
        std::process::exit(2)
    });
    let token1 = token1.unwrap_or_else(|| {
        eprintln!("missing --token1");
        std::process::exit(2)
    });
    let token2 = token2.unwrap_or_else(|| {
        eprintln!("missing --token2");
        std::process::exit(2)
    });
    let price = price.unwrap_or_else(|| {
        eprintln!("missing --price");
        std::process::exit(2)
    });
    let amount = amount.unwrap_or_else(|| {
        eprintln!("missing --amount");
        std::process::exit(2)
    });

    let mut cfg = ClientConfig::load(config_path.as_deref());
    if let Some(m) = mnemonic {
        cfg.keypair.mnemonic = m;
    }
    let seed = match cfg.seed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to derive ed25519 seed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let client = ChainClient::new(
        &cfg.chain.http_url,
        &cfg.chain.ws_url,
        seed,
        cfg.chain.chain_id,
    );
    let pubkey = client.pubkey_hex().to_string();

    // Determine which token's cashes the order locks: Buy spends token2 (the
    // quote/payment side), Sell spends token1 (the asset being sold).
    let (input_token, total) = match trade_type {
        TradeType::Buy => (token2.clone(), price * amount),
        TradeType::Sell => (token1.clone(), amount),
    };

    // Select inputs from the local store, capped at the N=2 split circuit limit.
    let store = CashStore::load(CashStore::default_path());
    let (input_records, change_data) = match select_cash(store.records(), &input_token, total) {
        CashSelection::Exact(ids) => (
            store
                .records()
                .iter()
                .filter(|r| ids.contains(&r.cash_id))
                .cloned()
                .collect::<Vec<_>>(),
            None,
        ),
        CashSelection::WithChange {
            cash_ids,
            change_amount,
        } => {
            let recs: Vec<CashRecord> = store
                .records()
                .iter()
                .filter(|r| cash_ids.contains(&r.cash_id))
                .cloned()
                .collect();
            let (change_cipher, _, change_random_hex) =
                encrypt_amount_with_info(&change_amount.to_string());
            let change_cash_id = compute_cash_id(&pubkey, &input_token, &change_cipher);
            (
                recs,
                Some((
                    change_cash_id,
                    change_cipher,
                    change_amount,
                    change_random_hex,
                )),
            )
        }
        CashSelection::Insufficient => {
            eprintln!("insufficient {input_token} balance for total {total}");
            return ExitCode::FAILURE;
        }
    };
    if input_records.is_empty() {
        eprintln!("internal error: cash selection returned no records");
        return ExitCode::FAILURE;
    }
    if input_records.len() > 2 {
        eprintln!(
            "split circuit caps at 2 inputs but selector picked {} — please consolidate first",
            input_records.len()
        );
        return ExitCode::FAILURE;
    }

    let input_cash_ids: Vec<String> = input_records.iter().map(|r| r.cash_id.clone()).collect();
    let order_id = compute_order_id(&input_cash_ids);

    // Build the locked-amount commitment + remember its random for the proof
    // and the local CashRecord.
    let (locked_cipher, _, locked_random_hex) = encrypt_amount_with_info(&amount.to_string());

    let order = Order {
        id: order_id.clone(),
        trade_type,
        subject: TradePair {
            token1: token1.clone(),
            token2: token2.clone(),
        },
        price: Some(price),
        amount: locked_cipher.clone(),
        pubkey: pubkey.clone(),
        input_cash_ids: input_cash_ids.clone(),
        handling_fee: vec!["0".to_string()],
        block_height: 0,
        status: OrderStatus::Pending,
        match_order: None,
        is_smaller: false,
    };

    // Generate split proof iff we have a change output.
    let (change_param, split_proof) = if let Some((
        ref change_cash_id,
        ref change_cipher,
        change_amount,
        ref change_random_hex,
    )) = change_data
    {
        eprintln!("preparing split circuit (compile + snarkjs setup, cached)...");
        let setup = match dev_setup_snarkjs("split") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("split circuit setup failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        let handle = match TestCircuitHandle::from_compiled(&setup.circuit_dir) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("loading compiled circuit: {e}");
                return ExitCode::FAILURE;
            }
        };

        let mut inputs_for_witness = Vec::with_capacity(input_records.len());
        for rec in &input_records {
            let raw = match hex::decode(&rec.random) {
                Ok(b) if b.len() == 32 => b,
                Ok(b) => {
                    eprintln!(
                        "cash {} random must be 32 bytes, got {}",
                        rec.cash_id,
                        b.len()
                    );
                    return ExitCode::FAILURE;
                }
                Err(e) => {
                    eprintln!("cash {} random hex invalid: {e}", rec.cash_id);
                    return ExitCode::FAILURE;
                }
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            inputs_for_witness.push((rec.amount, arr));
        }
        let locked_random = match decode_random(&locked_random_hex) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("locked random invalid: {e}");
                return ExitCode::FAILURE;
            }
        };
        let change_random = match decode_random(change_random_hex) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("change random invalid: {e}");
                return ExitCode::FAILURE;
            }
        };

        eprintln!("generating split proof...");
        let sp = match prove_split(
            SplitWitness {
                inputs: inputs_for_witness,
                locked_amount: amount,
                locked_random,
                change_amount,
                change_random,
            },
            &handle,
            &setup.zkey,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("prove_split: {e}");
                return ExitCode::FAILURE;
            }
        };
        let proof_str = match serde_json::to_string(&sp.proof_json) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("serialize proof: {e}");
                return ExitCode::FAILURE;
            }
        };

        (
            Some(CashChange {
                cash_id: change_cash_id.clone(),
                amount: change_cipher.clone(),
            }),
            Some(proof_str),
        )
    } else {
        (None, None)
    };

    eprintln!("submitting order to chain...");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(client.send_order(&order, change_param.as_ref(), split_proof)) {
        eprintln!("send_order failed: {e}");
        return ExitCode::FAILURE;
    }

    // Update the local CashStore: mark inputs spent/locked + record locked & change cashes.
    let mut store = store;
    let spent_or_locked_ids: std::collections::HashSet<String> =
        input_cash_ids.iter().cloned().collect();
    let split_mode = change_data.is_some();
    for rec in store.records_mut().iter_mut() {
        if spent_or_locked_ids.contains(&rec.cash_id) {
            rec.status = if split_mode { CASH_SPENT } else { CASH_LOCKED };
        }
    }
    if let Some((change_cash_id, _, change_amount, change_random_hex)) = change_data {
        store.records_mut().push(CashRecord {
            cash_id: change_cash_id,
            token: input_token.clone(),
            amount: change_amount,
            random: change_random_hex,
            status: CASH_ACTIVE,
        });
        let locked_cash_id = compute_cash_id(&pubkey, &input_token, &locked_cipher);
        store.records_mut().push(CashRecord {
            cash_id: locked_cash_id,
            token: input_token.clone(),
            amount,
            random: locked_random_hex,
            status: CASH_LOCKED,
        });
    }
    if let Err(e) = store.flush() {
        eprintln!("warning: chain succeeded but local CashStore write failed: {e}");
    }

    let _ = orderbook::short_id(&order_id); // keep import alive in non-debug builds
    println!(
        "send_order ok: id={} type={:?} {}/{} price={} amount={} (split={})",
        order_id, order.trade_type, token1, token2, price, amount, split_mode
    );
    ExitCode::SUCCESS
}

fn decode_random(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
