//! Rule tests for the commit cell type script.
//!
//! These build real transactions and run the compiled script against them.
//! Running the binary with no transaction context proves only that it loads —
//! the guarded-output loop never executes, so it returns success no matter
//! what the rule says. Everything below therefore goes through `Context`.
//!
//! Build the script first:
//!
//! ```text
//! export CC_riscv64imac_unknown_none_elf=riscv64-elf-gcc
//! export AR_riscv64imac_unknown_none_elf=riscv64-elf-ar
//! cargo build --manifest-path ../contracts/pob-submission/Cargo.toml \
//!     --target riscv64imac-unknown-none-elf --release
//! ```

use std::fs;

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_error::Error as CKBError;
use ckb_testtool::ckb_types::bytes::Bytes;
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::packed::{CellInput, CellOutput, Uint64};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 10_000_000;
const SCRIPT_BIN: &str =
    "../contracts/pob-submission/target/riscv64imac-unknown-none-elf/release/pob-submission";

/// Exit code the script returns, mirroring `contracts/pob-submission`.
const ERR_BAD_COMMITMENT_LEN: i8 = 1;

/// Asserts the transaction was refused by the script with exactly `code`.
///
/// Matching the code rather than merely "some error" is what keeps the test
/// honest: a script that crashed also returns `Err`, and a laxer assertion
/// would report that as the rule working.
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

/// Loads the compiled script, failing with a usable message when it is absent.
fn script_binary() -> Bytes {
    fs::read(SCRIPT_BIN)
        .unwrap_or_else(|e| panic!("build the script before running tests ({SCRIPT_BIN}): {e}"))
        .into()
}

/// Builds a transaction creating one commit cell whose data is `data`.
///
/// The cell carries the script under test as its type script and an
/// always-success lock, so whatever the verification reports comes from the
/// rule being tested and nothing else.
fn tx_creating_commit_cell(context: &mut Context, data: Bytes) -> TransactionView {
    let script_out_point = context.deploy_cell(script_binary());
    let lock_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&lock_out_point, Bytes::new())
        .expect("lock script");
    let type_script = context
        .build_script(&script_out_point, Bytes::new())
        .expect("type script");

    // An input to fund the output; its own cell carries no type script.
    // `u64` packs into both Uint64 and BeUint64, so the target type is named
    // through the binding rather than left to inference.
    let input_capacity: Uint64 = 1000u64.pack();
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(input_capacity)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output_capacity: Uint64 = 500u64.pack();
    let output = CellOutput::new_builder()
        .capacity(output_capacity)
        .lock(lock_script)
        .type_(Some(type_script).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(data.pack())
        .build();
    context.complete_tx(tx)
}

// R5.1: a commit cell carries exactly 32 bytes.
//
// The cycle count is reported rather than discarded: on CKB it is the figure
// that decides whether a script is affordable at all, and `verify_tx` hands it
// over for free. Run with `--nocapture` to read it.
#[test]
fn accepts_a_32_byte_commitment() {
    let mut context = Context::default();
    let tx = tx_creating_commit_cell(&mut context, Bytes::from(vec![0xab; 32]));

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("a 32-byte commitment must be accepted");
    println!("commit_type_script accepted a commitment in {cycles} cycles");
}

// The other half of R5.1, and the half that matters: anything that is not a
// commitment has to be refused. A script that returned success unconditionally
// would pass the test above and fail every one of these.
#[test]
fn rejects_a_commitment_of_the_wrong_length() {
    for len in [0usize, 1, 31, 33, 64] {
        let mut context = Context::default();
        let tx = tx_creating_commit_cell(&mut context, Bytes::from(vec![0xab; len]));

        assert_refused_with(
            context.verify_tx(&tx, MAX_CYCLES),
            ERR_BAD_COMMITMENT_LEN,
            &format!("data of {len} bytes"),
        );
    }
}
