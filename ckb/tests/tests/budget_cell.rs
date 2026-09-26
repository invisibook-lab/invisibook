//! Rule tests for the budget cell type script (`docs/ckb_layout.md` §3).
//!
//! Covers R3.1, R3.3, R3.4 and R3.5. R3.2 — the Groth16 proof that the
//! allocation table sums to `prepaid` — is not implemented, so nothing here
//! exercises it.
//!
//! Build the scripts first:
//!
//! ```text
//! export CC_riscv64imac_unknown_none_elf=riscv64-elf-gcc
//! export AR_riscv64imac_unknown_none_elf=riscv64-elf-ar
//! for c in pob-budget pob-spent pob-submission; do
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

/// Exit codes, mirroring `contracts/pob-budget`.
const ERR_DATA_MUTATED: i8 = 2;
const ERR_PREPAID_MISMATCH: i8 = 3;
const ERR_SPENT_TOKEN_INPUT: i8 = 4;
const ERR_BAD_LOCK: i8 = 5;

const BUDGET_BIN: &str =
    "../contracts/pob-budget/target/riscv64imac-unknown-none-elf/release/pob-budget";
const SUBMISSION_BIN: &str =
    "../contracts/pob-submission/target/riscv64imac-unknown-none-elf/release/pob-submission";

/// What the budget cell declares it was paid, and what actually moves into
/// the mining addr when the two agree.
const PREPAID: u64 = 1_000;

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

/// The deployed setup: the budget script, the mark it refuses to be funded
/// by, and the locks it tells apart.
struct Fixture {
    budget: Script,
    mark: Script,
    /// The lock the budget cell is required to use (R3.5).
    miner_lock: Script,
    /// A lock with a *different* code hash, to violate R3.5 with.
    other_lock: Script,
    mining_addr_lock: Script,
}

fn deploy(context: &mut Context) -> Fixture {
    let budget_out = context.deploy_cell(script_binary(BUDGET_BIN));
    let lock_out = context.deploy_cell(ALWAYS_SUCCESS.clone());
    // A second lock binary, needed only because every lock built from
    // ALWAYS_SUCCESS shares its code hash and R3.5 compares exactly that.
    // pob-submission serves: as a lock its GroupOutput is empty, so its loop
    // never runs and it returns 0.
    let other_lock_out = context.deploy_cell(script_binary(SUBMISSION_BIN));

    let mining_addr_lock = context
        .build_script(&lock_out, Bytes::from(vec![0x01]))
        .expect("mining addr lock");
    let miner_lock = context
        .build_script(&lock_out, Bytes::from(vec![0x02]))
        .expect("miner lock");
    let other_lock = context
        .build_script(&other_lock_out, Bytes::from(vec![0x03]))
        .expect("other lock");

    let mining_addr_hash: [u8; 32] = mining_addr_lock.calc_script_hash().unpack();
    // As far as this script is concerned the mark is one thing: a type hash
    // it refuses to be funded by. Built from ALWAYS_SUCCESS rather than the
    // real pob-spent on purpose — on a live chain R4.1 refuses such a
    // transaction first, because a marked input forces *every* output to
    // carry the mark and a budget cell carries the budget script instead.
    // R3.4 is the second line behind that, and this test is about R3.4's own
    // reaction rather than R4.1's.
    let mark = context
        .build_script(&lock_out, Bytes::from(vec![0x09]))
        .expect("mark script");
    let mark_hash: [u8; 32] = mark.calc_script_hash().unpack();
    let sighash_code: [u8; 32] = miner_lock.code_hash().unpack();

    let mut args = Vec::with_capacity(96);
    args.extend_from_slice(&mining_addr_hash);
    args.extend_from_slice(&mark_hash);
    args.extend_from_slice(&sighash_code);
    let budget = context
        .build_script(&budget_out, Bytes::from(args))
        .expect("budget script");

    Fixture {
        budget,
        mark,
        miner_lock,
        other_lock,
        mining_addr_lock,
    }
}

/// A budget cell's data: `prepaid` little-endian, then the allocation table.
/// The table is left empty — R3.2 is the rule that would read it, and it is
/// not implemented.
fn budget_data(prepaid: u64) -> Bytes {
    Bytes::from(prepaid.to_le_bytes().to_vec())
}

/// Builds a transaction creating a budget cell that declares `prepaid`, while
/// moving `paid` into the mining addr.
fn creation_tx(
    context: &mut Context,
    f: &Fixture,
    prepaid: u64,
    paid: u64,
    budget_lock: &Script,
    funding_mark: Option<&Script>,
) -> TransactionView {
    let funding_capacity: Uint64 = 100_000u64.pack();
    let funding = context.create_cell(
        CellOutput::new_builder()
            .capacity(funding_capacity)
            .lock(f.miner_lock.clone())
            .type_(funding_mark.cloned().pack())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder().previous_output(funding).build();

    let budget_capacity: Uint64 = 200u64.pack();
    let budget_cell = CellOutput::new_builder()
        .capacity(budget_capacity)
        .lock(budget_lock.clone())
        .type_(Some(f.budget.clone()).pack())
        .build();

    let paid_capacity: Uint64 = paid.pack();
    let mining_cell = CellOutput::new_builder()
        .capacity(paid_capacity)
        .lock(f.mining_addr_lock.clone())
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(vec![budget_cell, mining_cell])
        .outputs_data(vec![budget_data(prepaid), Bytes::new()].pack())
        .build();
    context.complete_tx(tx)
}

// The shape every other case departs from: a table written once, declaring
// exactly what the same transaction paid.
#[test]
fn creating_a_budget_cell_that_matches_the_payment_is_allowed() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let tx = creation_tx(&mut context, &f, PREPAID, PREPAID, &f.miner_lock, None);

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("a budget cell matching its payment must be allowed");
    println!("budget_type_script cleared a creation in {cycles} cycles");
}

// R3.3: declaring more than was paid is printing money.
#[test]
fn declaring_more_than_was_paid_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let tx = creation_tx(&mut context, &f, PREPAID * 2, PREPAID, &f.miner_lock, None);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_PREPAID_MISMATCH,
        "a budget cell declaring more than it paid",
    );
}

// R3.3 is an equality, not a ceiling: declaring less is refused too, so the
// number in the cell always says exactly what was paid.
#[test]
fn declaring_less_than_was_paid_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let tx = creation_tx(&mut context, &f, PREPAID / 2, PREPAID, &f.miner_lock, None);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_PREPAID_MISMATCH,
        "a budget cell declaring less than it paid",
    );
}

// R3.4, the rule that keeps §4's marking from being idle: without it the
// operator spends tokens out of the mining addr, has them marked, and funds
// its own budget cell with them straight away.
#[test]
fn funding_a_prepayment_with_marked_tokens_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let mark = f.mark.clone();
    let tx = creation_tx(
        &mut context,
        &f,
        PREPAID,
        PREPAID,
        &f.miner_lock,
        Some(&mark),
    );

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_SPENT_TOKEN_INPUT,
        "a prepayment funded by marked tokens",
    );
}

// R3.5: V7's first item compares a block producer's key against this cell's
// lock args, and that comparison means nothing if the lock can be any script.
#[test]
fn a_budget_cell_under_a_foreign_lock_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let other = f.other_lock.clone();
    let tx = creation_tx(&mut context, &f, PREPAID, PREPAID, &other, None);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_BAD_LOCK,
        "a budget cell locked by a non-sighash script",
    );
}

// R3.1, second legal transfer: the owner spends the cell whole to reclaim its
// capacity. Whether that is allowed is the lock's business, not this script's.
#[test]
fn spending_a_budget_cell_to_reclaim_capacity_is_allowed() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let capacity: Uint64 = 1_000u64.pack();
    let existing = context.create_cell(
        CellOutput::new_builder()
            .capacity(capacity)
            .lock(f.miner_lock.clone())
            .type_(Some(f.budget.clone()).pack())
            .build(),
        budget_data(PREPAID),
    );
    let input = CellInput::new_builder().previous_output(existing).build();

    let out_capacity: Uint64 = 900u64.pack();
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(vec![CellOutput::new_builder()
            .capacity(out_capacity)
            .lock(f.miner_lock.clone())
            .build()])
        .outputs_data(vec![Bytes::new()].pack())
        .build();
    let tx = context.complete_tx(tx);

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reclaiming the capacity must be allowed");
    println!("budget_type_script cleared a reclaim in {cycles} cycles");
}

// R3.1, the rule itself: there is no "edit". Spending a budget cell and
// creating another in the same transaction is exactly the move that would let
// a miner raise an allocation after seeing its VRF output, which is what
// whitepaper §7.3's ordering forbids.
#[test]
fn rewriting_a_budget_cell_in_place_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let capacity: Uint64 = 100_000u64.pack();
    let existing = context.create_cell(
        CellOutput::new_builder()
            .capacity(capacity)
            .lock(f.miner_lock.clone())
            .type_(Some(f.budget.clone()).pack())
            .build(),
        budget_data(PREPAID),
    );
    let input = CellInput::new_builder().previous_output(existing).build();

    let budget_capacity: Uint64 = 200u64.pack();
    let paid_capacity: Uint64 = PREPAID.pack();
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(vec![
            CellOutput::new_builder()
                .capacity(budget_capacity)
                .lock(f.miner_lock.clone())
                .type_(Some(f.budget.clone()).pack())
                .build(),
            CellOutput::new_builder()
                .capacity(paid_capacity)
                .lock(f.mining_addr_lock.clone())
                .build(),
        ])
        .outputs_data(vec![budget_data(PREPAID), Bytes::new()].pack())
        .build();
    let tx = context.complete_tx(tx);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_DATA_MUTATED,
        "rewriting a budget cell in place",
    );
}
