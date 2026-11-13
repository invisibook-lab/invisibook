//! Mining addr type script — the half of `docs/ckb_layout.md` §4 that makes
//! the mark unavoidable.
//!
//! `pob-spent` only governs tokens that already carry the mark: it keeps the
//! mark from being washed off and keeps marked tokens away from the mining
//! addr. Neither rule forces anyone to apply the mark in the first place. With
//! the mining addr under a plain lock, the operator could sign a payout into
//! an unmarked cell and never touch those rules at all — the whole defence of
//! whitepaper §9.4 would be one signature away from being bypassed.
//!
//! This script closes that hole. It guards the cell holding the mining addr's
//! balance, and its one rule (R4.0) is:
//!
//! > when this cell is spent, every output either carries `spent_type_script`
//! > or is the mining addr itself.
//!
//! The second case is change — capacity that never left. Everything else is a
//! payout, and a payout must be marked.
//!
//! The `spent_type_script` hash comes in as `args` rather than hardcoded, for
//! the same reason the mining addr does in `pob-spent`: one deployed binary
//! serves several L2 chains. And for the same reason it can never change,
//! since a different args is a different vault guarding a different mark.

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

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::packed::ScriptReader;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_lock_hash, load_cell_type_hash, load_script_hash, QueryIter,
};
use ckb_std::syscalls;

/// Length of a CKB script hash.
const HASH_LEN: usize = 32;

/// The script's `args` is not a 32-byte spent-script hash.
const ERR_BAD_ARGS: i8 = 1;
/// A payout left the mining addr without carrying the mark (R4.0).
const ERR_PAYOUT_NOT_MARKED: i8 = 2;
/// A cell could not be read.
const ERR_LOAD: i8 = 4;

/// Entry point: enforces R4.0.
pub fn program_entry() -> i8 {
    // Creating or topping up the vault is unrestricted — that is miners paying
    // in, and their money is clean. The rule bites only on the way out.
    if !spends_the_vault() {
        return 0;
    }

    let spent_script = match spent_script_hash() {
        Ok(hash) => hash,
        Err(code) => return code,
    };
    let vault_script = match load_script_hash() {
        Ok(hash) => hash,
        Err(_) => return ERR_LOAD,
    };
    // The mining addr is identified by the lock of the cell being spent, so
    // the script needs no second argument to recognise its own change.
    let mining_addr = match load_cell_lock_hash(0, Source::GroupInput) {
        Ok(hash) => hash,
        Err(_) => return ERR_LOAD,
    };

    for index in 0.. {
        let type_hash = match load_cell_type_hash(index, Source::Output) {
            Ok(hash) => hash,
            Err(_) => break,
        };

        // A payout: must be marked.
        if type_hash == Some(spent_script) {
            continue;
        }

        // Change: capacity staying under the same lock and the same vault
        // script never left the mining addr, so it needs no mark.
        if type_hash == Some(vault_script) {
            match load_cell_lock_hash(index, Source::Output) {
                Ok(lock_hash) if lock_hash == mining_addr => continue,
                Ok(_) => return ERR_PAYOUT_NOT_MARKED,
                Err(_) => return ERR_LOAD,
            }
        }

        return ERR_PAYOUT_NOT_MARKED;
    }

    0
}

/// Reads the `spent_type_script` hash out of this script's `args`.
///
/// Goes through the raw syscall and a borrowing `ScriptReader` rather than
/// `high_level::load_script`: that helper yields an owned molecule `Bytes`
/// whose clone compiles down to `lr.d`/`sc.d`, RISC-V atomics CKB-VM refuses
/// to execute.
fn spent_script_hash() -> Result<[u8; HASH_LEN], i8> {
    let mut buf = [0u8; 256];
    let len = syscalls::load_script(&mut buf, 0).map_err(|_| ERR_LOAD)?;
    let raw = buf.get(..len).ok_or(ERR_LOAD)?;

    let reader = ScriptReader::from_slice(raw).map_err(|_| ERR_LOAD)?;
    let args = reader.args().raw_data();
    if args.len() != HASH_LEN {
        return Err(ERR_BAD_ARGS);
    }

    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(args);
    Ok(hash)
}

/// Reports whether this transaction spends a cell carrying this script.
fn spends_the_vault() -> bool {
    QueryIter::new(load_cell_capacity, Source::GroupInput)
        .next()
        .is_some()
}
