//! Standalone deposit subcommand. Generates a rapidsnark deposit proof,
//! sends it to chain, and persists the resulting cash to `~/.invisibook/cash.json`.
//!
//! Usage:
//!   cli-deposit --token ETH --amount 100
//!
//! Reads chain endpoint + ed25519 seed from the same client.toml as the TUI.
//! Compiles + snarkjs-sets-up the deposit circuit on first run (artifacts
//! cached under `lib/target/circuit-build/deposit/`).

use std::process::ExitCode;

use invisibook_lib::{
    cash_store::{CashRecord, CashStore},
    chain::ChainClient,
    config::ClientConfig,
    types::CASH_ACTIVE,
};
use zk::{setup::dev_setup_snarkjs, test_circuit::TestCircuitHandle};

fn main() -> ExitCode {
    // Minimal flag parsing — bypasses ClientConfig's clap parser so we can
    // accept --token and --amount alongside the standard --mnemonic / --config.
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
                    "usage: cli-deposit --token <T> --amount <u64> [--mnemonic <words>] [--config <path>]"
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

    eprintln!("preparing deposit circuit (compile + snarkjs setup, cached)...");
    let setup = match dev_setup_snarkjs("deposit") {
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
    let (cash_id, output_random_hex) =
        match rt.block_on(client.deposit(&token, amount, &handle, &setup.zkey)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("deposit failed: {e}");
                return ExitCode::FAILURE;
            }
        };

    let mut store = CashStore::load(CashStore::default_path());
    let record = CashRecord {
        cash_id: cash_id.clone(),
        token: token.clone(),
        amount,
        random: output_random_hex,
        status: CASH_ACTIVE,
    };
    if let Err(e) = store.add(record) {
        eprintln!("warning: cash created on-chain but local CashStore write failed: {e}");
    }

    println!("deposit ok: token={token} amount={amount} cash_id={cash_id}");
    ExitCode::SUCCESS
}
