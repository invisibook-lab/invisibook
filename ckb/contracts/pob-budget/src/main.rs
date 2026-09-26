//! Budget cell type script.
//!
//! The miner's prepayment and its allocation table — `docs/ckb_layout.md` §3.
//! This is the one place on chain with substantive rules, because the whole
//! cost model of whitepaper §7 rests on it.
//!
//! Four of the five rules live here:
//!
//! * **R3.1** — once created, the data never changes. A budget cell has only
//!   two legal transfers: being created, or being spent whole by its owner to
//!   reclaim the capacity. There is no "edit" in between. This is what makes
//!   §7.3's ordering enforceable: a miner that could raise an allocation after
//!   seeing its VRF output would have no reason to commit first.
//! * **R3.3** — `prepaid` must equal the capacity this same transaction moves
//!   into the mining addr. Writing a larger number than was actually paid
//!   would be printing money.
//! * **R3.4** — no input may carry `spent_type_script`. Without this, §4's
//!   whole marking scheme is idle: the operator would spend tokens out of the
//!   mining addr, have them marked, and turn straight around to fund its own
//!   budget cell with them.
//! * **R3.5** — the lock must be the standard secp256k1_blake160 sighash
//!   lock. V7's first item compares the block producer's key against this
//!   cell's lock args, and that comparison has no meaning if the lock could
//!   be any script at all.
//!
//! **R3.2 (`Σ amount == prepaid`, in zero knowledge) is not implemented.**
//! The circuit does not exist yet, so nothing here constrains the allocation
//! table against the total: a miner can write a table that spends its
//! prepayment many times over and this script will accept it. That hole
//! closes when the Groth16 verification lands.
//!
//! The three hashes the rules need — mining addr lock, spent script, and the
//! sighash lock's code hash — arrive as `args` rather than being hardcoded,
//! so one deployed binary can serve several L2 chains. As with §4's scripts,
//! the price is that the args can never change afterwards.

#![no_std]
#![cfg_attr(not(test), no_main)]

// Under `entry!` the ckb-std macro declares `extern crate alloc` itself, so
// this one is only needed when that macro is compiled out.
#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!();

use ckb_std::ckb_constants::{CellField, Source};
use ckb_std::ckb_types::packed::ScriptReader;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{load_cell_capacity, load_cell_data, load_cell_lock_hash,
                          load_cell_type_hash, QueryIter};
use ckb_std::syscalls;

/// Length of a CKB script hash.
const HASH_LEN: usize = 32;
/// `args` is three hashes: mining addr lock, spent script, sighash code.
const ARGS_LEN: usize = HASH_LEN * 3;
/// `prepaid` is the first 8 bytes of the cell's data, little-endian.
const PREPAID_LEN: usize = 8;

/// The script's `args` is not three 32-byte hashes.
const ERR_BAD_ARGS: i8 = 1;
/// A budget cell was spent and re-created in one transaction (R3.1).
const ERR_DATA_MUTATED: i8 = 2;
/// `prepaid` does not match the capacity moved to the mining addr (R3.3).
const ERR_PREPAID_MISMATCH: i8 = 3;
/// A marked token funded the prepayment (R3.4).
const ERR_SPENT_TOKEN_INPUT: i8 = 4;
/// The cell's lock is not the standard sighash lock (R3.5).
const ERR_BAD_LOCK: i8 = 5;
/// The cell's data is too short to hold `prepaid`.
const ERR_BAD_DATA: i8 = 6;
/// A cell could not be read.
const ERR_LOAD: i8 = 7;

/// The three hashes carried in `args`.
struct Args {
    mining_addr: [u8; HASH_LEN],
    spent_script: [u8; HASH_LEN],
    sighash_code: [u8; HASH_LEN],
}

/// Entry point: enforces R3.1, R3.3, R3.4 and R3.5.
pub fn program_entry() -> i8 {
    let creating = group_len(Source::GroupOutput) > 0;
    let spending = group_len(Source::GroupInput) > 0;

    // Reclaiming the capacity: the cell goes away and nothing takes its
    // place. Whether that is allowed is the lock's business, not this
    // script's (R3.1's second legal transfer).
    if spending && !creating {
        return 0;
    }
    // Spending one and creating another in the same transaction is exactly
    // the "edit" R3.1 exists to forbid. Refused without looking at what
    // changed: the point is that a budget cell's data is fixed for its life,
    // not that this particular edit was harmless.
    if spending && creating {
        return ERR_DATA_MUTATED;
    }
    if !creating {
        return 0;
    }

    let args = match parse_args() {
        Ok(args) => args,
        Err(code) => return code,
    };

    // R3.4 — checked once for the whole transaction: a marked input taints
    // the prepayment no matter which budget cell it ends up funding.
    for type_hash in QueryIter::new(load_cell_type_hash, Source::Input) {
        if type_hash == Some(args.spent_script) {
            return ERR_SPENT_TOKEN_INPUT;
        }
    }

    let paid = match capacity_to(&args.mining_addr) {
        Ok(total) => total,
        Err(code) => return code,
    };

    let mut declared: u64 = 0;
    for index in 0.. {
        let data = match load_cell_data(index, Source::GroupOutput) {
            Ok(data) => data,
            Err(_) => break,
        };

        // R3.5 — the lock has to be the one V7's first item knows how to read.
        match lock_code_hash(index, Source::GroupOutput) {
            Ok(code) if code == args.sighash_code => {}
            Ok(_) => return ERR_BAD_LOCK,
            Err(code) => return code,
        }

        let prepaid = match read_prepaid(&data) {
            Ok(value) => value,
            Err(code) => return code,
        };
        declared = match declared.checked_add(prepaid) {
            Some(total) => total,
            // An overflow here would wrap around into a small number and let
            // the comparison below pass on money that was never paid.
            None => return ERR_PREPAID_MISMATCH,
        };
    }

    // R3.3 — summed over the group, so a transaction creating several budget
    // cells is held to the same total rather than letting each one claim the
    // whole payment.
    if declared != paid {
        return ERR_PREPAID_MISMATCH;
    }
    0
}

/// Counts the cells this script guards on one side of the transaction.
fn group_len(source: Source) -> usize {
    QueryIter::new(load_cell_capacity, source).count()
}

/// Sums the capacity this transaction sends to `mining_addr`.
fn capacity_to(mining_addr: &[u8; HASH_LEN]) -> Result<u64, i8> {
    let mut total: u64 = 0;
    for index in 0.. {
        let lock_hash = match load_cell_lock_hash(index, Source::Output) {
            Ok(hash) => hash,
            Err(_) => break,
        };
        if &lock_hash != mining_addr {
            continue;
        }
        let capacity = load_cell_capacity(index, Source::Output).map_err(|_| ERR_LOAD)?;
        total = total.checked_add(capacity).ok_or(ERR_PREPAID_MISMATCH)?;
    }
    Ok(total)
}

/// Reads `prepaid` from the head of a budget cell's data.
fn read_prepaid(data: &[u8]) -> Result<u64, i8> {
    let head = data.get(..PREPAID_LEN).ok_or(ERR_BAD_DATA)?;
    let mut bytes = [0u8; PREPAID_LEN];
    bytes.copy_from_slice(head);
    Ok(u64::from_le_bytes(bytes))
}

/// Reads the `code_hash` of a cell's lock.
///
/// Goes through the raw syscall and a borrowing `ScriptReader` rather than
/// `high_level::load_cell_lock`: that helper yields an owned molecule
/// `Script` whose clone compiles down to `lr.d`/`sc.d`, RISC-V atomics CKB-VM
/// refuses to execute.
fn lock_code_hash(index: usize, source: Source) -> Result<[u8; HASH_LEN], i8> {
    let mut buf = [0u8; 256];
    let len = syscalls::load_cell_by_field(&mut buf, 0, index, source, CellField::Lock)
        .map_err(|_| ERR_LOAD)?;
    let raw = buf.get(..len).ok_or(ERR_LOAD)?;

    let reader = ScriptReader::from_slice(raw).map_err(|_| ERR_LOAD)?;
    let code = reader.code_hash().raw_data();
    let code = code.get(..HASH_LEN).ok_or(ERR_LOAD)?;

    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(code);
    Ok(out)
}

/// Reads the three hashes out of this script's `args`.
fn parse_args() -> Result<Args, i8> {
    let mut buf = [0u8; 256];
    let len = syscalls::load_script(&mut buf, 0).map_err(|_| ERR_LOAD)?;
    let raw = buf.get(..len).ok_or(ERR_LOAD)?;

    let reader = ScriptReader::from_slice(raw).map_err(|_| ERR_LOAD)?;
    let args = reader.args().raw_data();
    if args.len() != ARGS_LEN {
        return Err(ERR_BAD_ARGS);
    }

    let mut out = Args {
        mining_addr: [0u8; HASH_LEN],
        spent_script: [0u8; HASH_LEN],
        sighash_code: [0u8; HASH_LEN],
    };
    out.mining_addr.copy_from_slice(&args[..HASH_LEN]);
    out.spent_script.copy_from_slice(&args[HASH_LEN..HASH_LEN * 2]);
    out.sighash_code.copy_from_slice(&args[HASH_LEN * 2..]);
    Ok(out)
}
