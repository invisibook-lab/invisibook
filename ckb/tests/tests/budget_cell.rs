//! Rule tests for the budget cell type script (`docs/ckb_layout.md` §3).
//!
//! Covers R3.1 to R3.5. R3.2's proofs are made here with `budget-stark`'s
//! prover, the same code `pob-miner` links.
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

use budget_stark::hash::{Digest, Random, digest_to_bytes};
use budget_stark::prove;
use budget_stark::witness::{MAX_WITNESS_SIZE, split};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_error::Error as CKBError;
use ckb_testtool::ckb_types::bytes::Bytes;
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::packed::{CellInput, CellOutput, Script, Uint64, WitnessArgs};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

/// A whole block's cycle budget: R3.2's proof alone takes ~50M.
const MAX_CYCLES: u64 = 3_500_000_000;

/// Exit codes, mirroring `contracts/pob-budget`.
const ERR_DATA_MUTATED: i8 = 2;
const ERR_PREPAID_MISMATCH: i8 = 3;
const ERR_SPENT_TOKEN_INPUT: i8 = 4;
const ERR_BAD_LOCK: i8 = 5;
const ERR_BAD_TABLE: i8 = 8;
const ERR_UNBALANCED: i8 = 9;

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

/// A budget cell's data with no table. Only for cells that already exist:
/// creating one requires a balanced table (R3.2).
fn budget_data(prepaid: u64) -> Bytes {
    Bytes::from(prepaid.to_le_bytes().to_vec())
}

/// A budget cell's data: `prepaid`, then (height, commitment) entries.
fn table_data(prepaid: u64, commitments: &[Digest]) -> Bytes {
    let mut out = prepaid.to_le_bytes().to_vec();
    out.extend_from_slice(&(commitments.len() as u32).to_le_bytes());
    for (i, c) in commitments.iter().enumerate() {
        out.extend_from_slice(&(i as u32 + 1).to_le_bytes());
        out.extend_from_slice(&digest_to_bytes(c));
    }
    out.into()
}

/// Deterministic blinding factors; these tests are about the rules, not
/// about hiding.
fn randoms(n: usize) -> Vec<Random> {
    (0..n)
        .map(|i| core::array::from_fn(|k| KoalaBear::from_u32((i * 8 + k) as u32 + 7)))
        .collect()
}

/// Proves a table of `amounts`: its data (declaring their sum) and the proof.
fn proven_table(amounts: &[u64]) -> (u64, Vec<Digest>, Bytes) {
    let (prepaid, commitments, proof) = prove(amounts, &randoms(amounts.len())).unwrap();
    (prepaid, commitments, proof.into())
}

/// A balanced two-entry table for `prepaid`, and its proof.
fn balanced_table(prepaid: u64) -> (Bytes, Bytes) {
    let (total, commitments, proof) = proven_table(&[prepaid / 2, prepaid - prepaid / 2]);
    (table_data(total, &commitments), proof)
}

/// Builds a transaction creating a budget cell that declares `prepaid` with a
/// balanced table and its proof, while moving `paid` into the mining addr.
fn creation_tx(
    context: &mut Context,
    f: &Fixture,
    prepaid: u64,
    paid: u64,
    budget_lock: &Script,
    funding_mark: Option<&Script>,
) -> TransactionView {
    let (data, proof) = balanced_table(prepaid);
    creation_tx_with(
        context,
        f,
        data,
        Some(proof),
        paid,
        budget_lock,
        funding_mark,
    )
}

/// Builds a transaction creating a budget cell holding `data`, with `proof`
/// (if any) cut across the witnesses from the budget cell's index on, while
/// moving `paid` into the mining addr.
fn creation_tx_with(
    context: &mut Context,
    f: &Fixture,
    data: Bytes,
    proof: Option<Bytes>,
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

    // The budget cell is output 0, so its proof starts in witness 0. Each
    // chunk has to fit the sighash lock's 32 KB witness buffer, which these
    // tests' always-success lock would not notice on its own.
    let witnesses: Vec<Bytes> = proof
        .map(|p| split(&p))
        .unwrap_or_default()
        .into_iter()
        .map(|chunk| {
            let args = WitnessArgs::new_builder()
                .output_type(Some(Bytes::from(chunk)).pack())
                .build();
            assert!(args.as_slice().len() <= MAX_WITNESS_SIZE);
            args.as_bytes()
        })
        .collect();
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(vec![budget_cell, mining_cell])
        .outputs_data(vec![data, Bytes::new()].pack())
        .witnesses(witnesses.pack())
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
        .outputs(vec![
            CellOutput::new_builder()
                .capacity(out_capacity)
                .lock(f.miner_lock.clone())
                .build(),
        ])
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

// R3.2: a proof made for a different total does not carry over. Here the
// table adds up to one more than the cell declares — the extra shannon is
// money that was never paid.
#[test]
fn a_table_that_does_not_add_up_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let (_, commitments, proof) = proven_table(&[PREPAID / 2, PREPAID - PREPAID / 2 + 1]);
    let data = table_data(PREPAID, &commitments);
    let lock = f.miner_lock.clone();
    let tx = creation_tx_with(&mut context, &f, data, Some(proof), PREPAID, &lock, None);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_UNBALANCED,
        "a table adding up to more than prepaid",
    );
}

// R3.2: the proof binds the table entry by entry, in order.
#[test]
fn a_reordered_table_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let (total, mut commitments, proof) = proven_table(&[100, PREPAID - 100]);
    commitments.swap(0, 1);
    let data = table_data(total, &commitments);
    let lock = f.miner_lock.clone();
    let tx = creation_tx_with(&mut context, &f, data, Some(proof), PREPAID, &lock, None);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_UNBALANCED,
        "a table whose entries were reordered after proving",
    );
}

// A proof cut short — its last witness dropped — does not reassemble.
#[test]
fn a_truncated_proof_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let (data, proof) = balanced_table(PREPAID);
    let tx = creation_tx_with(&mut context, &f, data, Some(proof), PREPAID, &f.miner_lock.clone(), None);
    let witnesses: Vec<Bytes> = tx.witnesses().into_iter().map(|w| w.raw_data()).collect();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(witnesses[..witnesses.len() - 1].iter().map(|w| w.pack()).collect())
        .build();

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_UNBALANCED,
        "a proof missing its last chunk",
    );
}

#[test]
fn a_table_without_a_proof_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let (data, _) = balanced_table(PREPAID);
    let lock = f.miner_lock.clone();
    let tx = creation_tx_with(&mut context, &f, data, None, PREPAID, &lock, None);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_UNBALANCED,
        "a budget cell with no balance proof",
    );
}

// An empty table divides nothing, so it cannot account for a positive total.
#[test]
fn an_empty_table_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);

    let (_, proof) = balanced_table(PREPAID);
    let data = table_data(PREPAID, &[]);
    let lock = f.miner_lock.clone();
    let tx = creation_tx_with(&mut context, &f, data, Some(proof), PREPAID, &lock, None);

    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_UNBALANCED,
        "a budget cell whose table is empty",
    );
}

#[test]
fn a_malformed_table_is_refused() {
    let mut context = Context::default();
    let f = deploy(&mut context);
    let lock = f.miner_lock.clone();

    // The count claims one entry more than the bytes hold.
    let (_, commitments, proof) = proven_table(&[PREPAID / 2, PREPAID - PREPAID / 2]);
    let mut short = table_data(PREPAID, &commitments).to_vec();
    short[8..12].copy_from_slice(&3u32.to_le_bytes());
    let tx = creation_tx_with(
        &mut context,
        &f,
        short.into(),
        Some(proof.clone()),
        PREPAID,
        &lock,
        None,
    );
    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_BAD_TABLE,
        "a table whose count disagrees with its length",
    );

    // A word at the field order is not a hash output, so not a commitment.
    let mut non_canonical = table_data(PREPAID, &commitments).to_vec();
    non_canonical[16..20].copy_from_slice(&0x7f00_0001u32.to_le_bytes());
    let tx = creation_tx_with(
        &mut context,
        &f,
        non_canonical.into(),
        Some(proof),
        PREPAID,
        &lock,
        None,
    );
    assert_refused_with(
        context.verify_tx(&tx, MAX_CYCLES),
        ERR_BAD_TABLE,
        "a table holding a non-canonical commitment",
    );
}

// What R3.2 costs on chain, by table size. Up to 128 entries the trace is
// padded to 128 rows (the hiding PCS needs them), so cost is flat there.
#[test]
fn balance_proof_cycles_by_table_size() {
    for n in [1usize, 50, 100, 128, 512, 1024] {
        let amounts: Vec<u64> = (0..n as u64).map(|i| 1_000 + i).collect();
        let (total, commitments, proof) = proven_table(&amounts);
        let proof_len = proof.len();

        let mut context = Context::default();
        let f = deploy(&mut context);
        let lock = f.miner_lock.clone();
        let data = table_data(total, &commitments);
        let tx = creation_tx_with(&mut context, &f, data, Some(proof), total, &lock, None);
        let cycles = context
            .verify_tx(&tx, MAX_CYCLES)
            .unwrap_or_else(|e| panic!("n={n}: a balanced table was refused: {e}"));
        println!(
            "R3.2 n={n:>5}  proof={proof_len:>7} B  cycles={cycles:>11}  ({:.1}% of a block)",
            cycles as f64 / MAX_CYCLES as f64 * 100.0
        );
    }
}
