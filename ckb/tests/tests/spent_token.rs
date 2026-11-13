//! Rule tests for the spent token type script (`docs/ckb_layout.md` §4).
//!
//! Build the script first:
//!
//! ```text
//! export CC_riscv64imac_unknown_none_elf=riscv64-elf-gcc
//! export AR_riscv64imac_unknown_none_elf=riscv64-elf-ar
//! cargo build --manifest-path ../contracts/pob-spent/Cargo.toml \
//!     --target riscv64imac-unknown-none-elf --release
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

/// Exit codes the script returns, mirroring `contracts/pob-spent/src/main.rs`.
const ERR_MARK_DROPPED: i8 = 2;
const ERR_RETURNS_TO_MINING_ADDR: i8 = 3;

/// Asserts the transaction was refused by the script with exactly `code`.
///
/// Matching on the code rather than on "some error" is what keeps these tests
/// honest: a script that crashed — an unsupported instruction, a panic, an
/// allocator fault — also returns `Err`, and a laxer assertion would report
/// that as the rule working.
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
const SCRIPT_BIN: &str =
    "../contracts/pob-spent/target/riscv64imac-unknown-none-elf/release/pob-spent";

/// Loads the compiled script, failing with a usable message when it is absent.
fn script_binary() -> Bytes {
    fs::read(SCRIPT_BIN)
        .unwrap_or_else(|e| panic!("build the script before running tests ({SCRIPT_BIN}): {e}"))
        .into()
}

/// One deployed setup: the mark script bound to a mining addr, plus two locks
/// to play the mining addr and an ordinary third party.
struct Fixture {
    mark: Script,
    mining_addr_lock: Script,
    other_lock: Script,
}

/// Deploys the scripts and binds the mark to the mining addr's lock hash.
fn deploy(context: &mut Context) -> Fixture {
    let mark_out_point = context.deploy_cell(script_binary());
    let lock_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // Two distinct locks from the same always-success binary: different args
    // give different lock hashes, which is all the script compares.
    let mining_addr_lock = context
        .build_script(&lock_out_point, Bytes::from(vec![0x01]))
        .expect("mining addr lock");
    let other_lock = context
        .build_script(&lock_out_point, Bytes::from(vec![0x02]))
        .expect("other lock");

    let mining_addr_hash: [u8; 32] = mining_addr_lock.calc_script_hash().unpack();
    let mark = context
        .build_script(&mark_out_point, Bytes::from(mining_addr_hash.to_vec()))
        .expect("mark script");

    Fixture {
        mark,
        mining_addr_lock,
        other_lock,
    }
}

/// Builds a cell output with the given lock, optionally carrying the mark.
fn cell(lock: &Script, mark: Option<&Script>) -> CellOutput {
    let capacity: Uint64 = 500u64.pack();
    CellOutput::new_builder()
        .capacity(capacity)
        .lock(lock.clone())
        .type_(mark.cloned().pack())
        .build()
}

/// Creates a funding cell and returns the input spending it.
fn funding_input(context: &mut Context, lock: &Script, mark: Option<&Script>) -> CellInput {
    let capacity: Uint64 = 1000u64.pack();
    let out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(capacity)
            .lock(lock.clone())
            .type_(mark.cloned().pack())
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

// The operator spending out of the mining addr: a clean input becomes a marked
// cell. There is no marked input yet, so R4.1 does not apply.
#[test]
fn marking_tokens_on_the_way_out_is_allowed() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = funding_input(&mut context, &f.mining_addr_lock, None);
    let tx = build_tx(&mut context, input, vec![cell(&f.other_lock, Some(&f.mark))]);

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("minting a marked cell must be allowed");
    println!("spent_type_script marked a payout in {cycles} cycles");
}

// R4.1: paying a marked cell forward keeps the mark on every output.
#[test]
fn a_marked_cell_may_be_spent_when_every_output_stays_marked() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = funding_input(&mut context, &f.other_lock, Some(&f.mark));
    let tx = build_tx(
        &mut context,
        input,
        vec![
            cell(&f.other_lock, Some(&f.mark)),
            cell(&f.other_lock, Some(&f.mark)),
        ],
    );

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("paying a marked cell forward must be allowed when the mark survives");
}

// R4.1, the half that matters: the mark cannot be washed off by paying it into
// a plain cell. Without this the whole mechanism lasts exactly one hop.
#[test]
fn dropping_the_mark_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = funding_input(&mut context, &f.other_lock, Some(&f.mark));
    let tx = build_tx(&mut context, input, vec![cell(&f.other_lock, None)]);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_MARK_DROPPED,
        "an unmarked output when a marked cell is spent",
    );
}

// R4.1 is deliberately strict: one marked input taints every output in the
// transaction, change included. Capacity is fungible inside a transaction, so
// there is no way to tell which output the marked capacity flowed into —
// erring the other way would let the mark be shed by bundling a clean input.
#[test]
fn change_alongside_a_marked_input_must_also_be_marked() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = funding_input(&mut context, &f.other_lock, Some(&f.mark));
    let tx = build_tx(
        &mut context,
        input,
        vec![cell(&f.other_lock, Some(&f.mark)), cell(&f.other_lock, None)],
    );

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_MARK_DROPPED,
        "an unmarked change output",
    );
}

// R4.2: marked tokens can never be locked back to the mining addr.
#[test]
fn returning_to_the_mining_addr_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = funding_input(&mut context, &f.other_lock, Some(&f.mark));
    let tx = build_tx(
        &mut context,
        input,
        vec![cell(&f.mining_addr_lock, Some(&f.mark))],
    );

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_RETURNS_TO_MINING_ADDR,
        "a marked cell locked to the mining addr",
    );
}

// R4.2 also covers the minting path: the operator cannot create a marked cell
// that is already sitting on the mining addr.
#[test]
fn minting_a_marked_cell_onto_the_mining_addr_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let input = funding_input(&mut context, &f.mining_addr_lock, None);
    let tx = build_tx(
        &mut context,
        input,
        vec![cell(&f.mining_addr_lock, Some(&f.mark))],
    );

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_RETURNS_TO_MINING_ADDR,
        "minting a marked cell onto the mining addr",
    );
}
