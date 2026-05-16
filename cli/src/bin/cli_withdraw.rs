//! Standalone withdraw subcommand. Selects active cashes from
//! `~/.invisibook/cash.json` (via the existing greedy selector), generates a
//! rapidsnark withdraw proof, sends it to chain, and updates the local store
//! (marks inputs spent + appends any change cash).
//!
//! Usage:
//!   cli-withdraw --token ETH --amount 60
//!
//! Reuses ClientConfig + load_with_args-bypass pattern from cli_deposit.

use std::process::ExitCode;

use invisibook_lib::{
    cash_store::{CashRecord, CashStore},
    chain::ChainClient,
    config::ClientConfig,
    orderbook::{CashSelection, select_cash},
    types::{CASH_ACTIVE, CASH_SPENT},
};
use zk::{setup::dev_setup_snarkjs, test_circuit::TestCircuitHandle};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut token: Option<String> = None;
    let mut amount: Option<u64> = None;
    let mut mnemonic: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--token" if i + 1 < args.len() => {
                token = Some(args[i + 1].clone());
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
                    "usage: cli-withdraw --token <T> --amount <u64> [--mnemonic <words>] [--config <path>]"
                );
                return ExitCode::from(2);
            }
        }
    }
    let Some(token) = token else {
        eprintln!("missing --token");
        return ExitCode::from(2);
    };
    let Some(amount) = amount else {
        eprintln!("missing --amount");
        return ExitCode::from(2);
    };

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

    // Select inputs from the local store. The N=2 circuit caps the number of
    // inputs per withdraw — fall back to "Insufficient" so the user knows to
    // consolidate first via Withdraw-then-Deposit (or wait for variable-N).
    let store = CashStore::load(CashStore::default_path());
    let inputs: Vec<CashRecord> = match select_cash(store.records(), &token, amount) {
        CashSelection::Exact(ids) | CashSelection::WithChange { cash_ids: ids, .. } => store
            .records()
            .iter()
            .filter(|r| ids.contains(&r.cash_id))
            .cloned()
            .collect(),
        CashSelection::Insufficient => {
            eprintln!("insufficient {token} balance for amount {amount}");
            return ExitCode::FAILURE;
        }
    };
    if inputs.is_empty() {
        eprintln!("internal error: cash selection returned no records");
        return ExitCode::FAILURE;
    }
    if inputs.len() > 2 {
        eprintln!(
            "withdraw circuit caps at 2 inputs but selector picked {} — please consolidate first",
            inputs.len()
        );
        return ExitCode::FAILURE;
    }

    eprintln!("preparing withdraw circuit (compile + snarkjs setup, cached)...");
    let setup = match dev_setup_snarkjs("withdraw") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("circuit setup failed: {e}");
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

    eprintln!("generating proof and submitting to chain...");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let change = match rt.block_on(client.withdraw(&token, amount, &inputs, &handle, &setup.zkey)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("withdraw failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Update local CashStore: mark spent inputs + append any change cash.
    let spent_ids: std::collections::HashSet<String> =
        inputs.iter().map(|r| r.cash_id.clone()).collect();
    let mut store = store; // shadow to take mut
    for rec in store.records_mut().iter_mut() {
        if spent_ids.contains(&rec.cash_id) {
            rec.status = CASH_SPENT;
        }
    }
    if let Some((change_cash_id, change_random)) = change.clone() {
        let change_amount: u64 = inputs.iter().map(|r| r.amount).sum::<u64>() - amount;
        store.records_mut().push(CashRecord {
            cash_id: change_cash_id,
            token: token.clone(),
            amount: change_amount,
            random: change_random,
            status: CASH_ACTIVE,
        });
    }
    if let Err(e) = store.flush() {
        eprintln!("warning: chain succeeded but local CashStore write failed: {e}");
    }

    match change {
        None => println!("withdraw ok: token={token} amount={amount} (no change)"),
        Some((id, _)) => println!("withdraw ok: token={token} amount={amount} change_cash_id={id}"),
    }
    ExitCode::SUCCESS
}
