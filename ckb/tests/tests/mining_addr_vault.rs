//! Rule tests for the mining addr type script (`docs/ckb_layout.md` §4, R4.0).
//!
//! Build both scripts first:
//!
//! ```text
//! export CC_riscv64imac_unknown_none_elf=riscv64-elf-gcc
//! export AR_riscv64imac_unknown_none_elf=riscv64-elf-ar
//! for c in pob-spent pob-vault; do
//!     cargo build --manifest-path ../contracts/$c/Cargo.toml \
//!         --target riscv64imac-unknown-none-elf --release
//! done
//! ```

use std::fs;

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_error::Error as CKBError;
use ckb_testtool::ckb_types::bytes::Bytes;
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::packed::{CellInput, CellOutput, Script, Uint64};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 10_000_000;

/// Exit code the vault script returns, mirroring `contracts/pob-vault`.
const ERR_PAYOUT_NOT_MARKED: i8 = 2;

const VAULT_BIN: &str = "../contracts/pob-vault/target/riscv64imac-unknown-none-elf/release/pob-vault";
const SPENT_BIN: &str = "../contracts/pob-spent/target/riscv64imac-unknown-none-elf/release/pob-spent";

/// Loads a compiled script, failing with a usable message when it is absent.
fn script_binary(path: &str) -> Bytes {
    fs::read(path)
        .unwrap_or_else(|e| panic!("build the scripts before running tests ({path}): {e}"))
        .into()
}

/// Asserts the transaction was refused by a script with exactly `code`.
///
/// Matching the code rather than merely "some error" is what keeps the test
/// honest: a crashing script also returns `Err`.
fn assert_refused_with(result: Result<u64, CKBError>, code: i8, what: &str) {
    let err = match result {
        Ok(cycles) => panic!("{what}: accepted in {cycles} cycles, expected code {code}"),
        Err(err) => err,
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains(&format!("error code {code} ")) || rendered.contains(&format!("#{code}")),
        "{what}: expected exit code {code}, got {rendered}"
    );
}

/// The deployed setup: a vault guarding the mining addr, the mark it demands,
/// and an outsider's lock to pay into.
struct Fixture {
    vault: Script,
    mark: Script,
    mining_addr_lock: Script,
    other_lock: Script,
}

/// Deploys both scripts and ties them to each other.
fn deploy(context: &mut Context) -> Fixture {
    let vault_out_point = context.deploy_cell(script_binary(VAULT_BIN));
    let spent_out_point = context.deploy_cell(script_binary(SPENT_BIN));
    let lock_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mining_addr_lock = context
        .build_script(&lock_out_point, Bytes::from(vec![0x01]))
        .expect("mining addr lock");
    let other_lock = context
        .build_script(&lock_out_point, Bytes::from(vec![0x02]))
        .expect("other lock");

    // The mark is bound to the mining addr; the vault is bound to the mark.
    let mining_addr_hash: [u8; 32] = mining_addr_lock.calc_script_hash().unpack();
    let mark = context
        .build_script(&spent_out_point, Bytes::from(mining_addr_hash.to_vec()))
        .expect("mark script");
    let mark_hash: [u8; 32] = mark.calc_script_hash().unpack();
    let vault = context
        .build_script(&vault_out_point, Bytes::from(mark_hash.to_vec()))
        .expect("vault script");

    Fixture {
        vault,
        mark,
        mining_addr_lock,
        other_lock,
    }
}

/// Builds an output cell with the given lock and optional type script.
fn cell(lock: &Script, type_script: Option<&Script>) -> CellOutput {
    let capacity: Uint64 = 400u64.pack();
    CellOutput::new_builder()
        .capacity(capacity)
        .lock(lock.clone())
        .type_(type_script.cloned().pack())
        .build()
}

/// Creates the vault cell — the mining addr holding miners' payments — and
/// returns the input spending it.
fn vault_input(context: &mut Context, f: &Fixture) -> CellInput {
    let capacity: Uint64 = 1000u64.pack();
    let out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(capacity)
            .lock(f.mining_addr_lock.clone())
            .type_(Some(f.vault.clone()).pack())
            .build(),
        Bytes::new(),
    );
    CellInput::new_builder().previous_output(out_point).build()
}

/// Assembles a transaction from one input and a list of outputs.
fn build_tx(context: &mut Context, input: CellInput, outputs: Vec<CellOutput>) -> TransactionView {
    let data: Vec<Bytes> = outputs.iter().map(|_| Bytes::new()).collect();
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(data.pack())
        .build();
    context.complete_tx(tx)
}

// R4.0, the rule that makes the mark unavoidable: money leaving the mining
// addr must carry it.
#[test]
fn a_marked_payout_is_allowed() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = vault_input(&mut context, &f);
    let tx = build_tx(&mut context, input, vec![cell(&f.other_lock, Some(&f.mark))]);

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("a marked payout must be allowed");
    println!("mining_addr_type_script cleared a payout in {cycles} cycles");
}

// The hole this script exists to close: without it the operator signs a payout
// into a plain cell and every rule in pob-spent is bypassed.
#[test]
fn an_unmarked_payout_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = vault_input(&mut context, &f);
    let tx = build_tx(&mut context, input, vec![cell(&f.other_lock, None)]);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_PAYOUT_NOT_MARKED,
        "an unmarked payout out of the mining addr",
    );
}

// Change is the one exception: capacity that stays on the mining addr under
// the same vault script never left, so it needs no mark.
#[test]
fn change_back_to_the_mining_addr_needs_no_mark() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = vault_input(&mut context, &f);
    let tx = build_tx(
        &mut context,
        input,
        vec![
            cell(&f.other_lock, Some(&f.mark)),
            cell(&f.mining_addr_lock, Some(&f.vault)),
        ],
    );

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("marked payout plus vault change must be allowed");
}

// The change exception must not become a loophole: a cell carrying the vault
// script but locked to somebody else is a payout wearing change's clothes.
#[test]
fn vault_script_under_another_lock_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = vault_input(&mut context, &f);
    let tx = build_tx(
        &mut context,
        input,
        vec![cell(&f.other_lock, Some(&f.vault))],
    );

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_PAYOUT_NOT_MARKED,
        "a vault-script cell under someone else's lock",
    );
}

// Paying into the mining addr is unrestricted — that is miners buying block
// rights, and their money is clean.
#[test]
fn paying_into_the_mining_addr_is_unrestricted() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let capacity: Uint64 = 1000u64.pack();
    let out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(capacity)
            .lock(f.other_lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder().previous_output(out_point).build();
    let tx = build_tx(
        &mut context,
        input,
        vec![cell(&f.mining_addr_lock, Some(&f.vault))],
    );

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("a miner paying into the mining addr must be allowed");
}
