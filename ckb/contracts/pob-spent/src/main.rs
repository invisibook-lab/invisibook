//! Spent token type script.
//!
//! The mark that makes `docs/ckb_layout.md` §4 work. Tokens miners pay into
//! the mining addr are clean; the moment the operator spends them out again
//! they are wrapped in this script, and from then on they can never reach the
//! mining addr — which is what stops the operator from mining its own chain
//! for free and diluting honest miners (whitepaper §9.4).
//!
//! Two rules, both from §4:
//!
//! * **R4.1** — if any input carries this script, every output must carry it
//!   too, so the mark cannot be washed off by paying it forward.
//! * **R4.2** — no cell carrying this script may be locked to the mining addr.
//!
//! R4.3 (marked tokens cannot fund a prepayment) is enforced on the budget
//! cell's side by R3.4: that script already walks its own inputs, so checking
//! there is far cheaper than tracing capacity backwards from here.
//!
//! The mining addr is passed in as the script's `args` — a 32-byte lock hash —
//! rather than hardcoded, so one deployed binary can serve several L2 chains.
//! The price is that the args can never change: a different args is a
//! different script and a different mark, and the old mark would not constrain
//! the new address.

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

/// The script's `args` is not a 32-byte mining addr lock hash.
const ERR_BAD_ARGS: i8 = 1;
/// A marked input was spent but some output does not carry the mark (R4.1).
const ERR_MARK_DROPPED: i8 = 2;
/// A marked cell is locked to the mining addr (R4.2).
const ERR_RETURNS_TO_MINING_ADDR: i8 = 3;
/// A cell could not be read.
const ERR_LOAD: i8 = 4;

/// Entry point: enforces R4.1 and R4.2.
pub fn program_entry() -> i8 {
    let mining_addr = match mining_addr_lock_hash() {
        Ok(hash) => hash,
        Err(code) => return code,
    };
    let this_script = match load_script_hash() {
        Ok(hash) => hash,
        Err(_) => return ERR_LOAD,
    };

    // R4.2 first: it applies to every marked cell, including the ones minted
    // in this very transaction when the operator first spends out of the
    // mining addr. Checking the group's own outputs is enough — R4.1 forces
    // every other output into this group anyway.
    for index in 0.. {
        match load_cell_lock_hash(index, Source::GroupOutput) {
            Ok(lock_hash) => {
                if lock_hash == mining_addr {
                    return ERR_RETURNS_TO_MINING_ADDR;
                }
            }
            Err(_) => break,
        }
    }

    // R4.1 applies only when a marked cell is being spent. Creating the first
    // marked cell is what the operator does on the way out of the mining addr,
    // and that transaction has no marked input to propagate from.
    if !spends_a_marked_cell() {
        return 0;
    }

    for type_hash in QueryIter::new(load_cell_type_hash, Source::Output) {
        match type_hash {
            Some(hash) if hash == this_script => {}
            // An output with no type script, or with someone else's, would
            // carry capacity out from under the mark.
            _ => return ERR_MARK_DROPPED,
        }
    }

    0
}

/// Reads the mining addr's lock hash out of this script's `args`.
///
/// Deliberately goes through the raw syscall and a borrowing `ScriptReader`
/// rather than `high_level::load_script`. That helper hands back a molecule
/// `Script` whose `args()` yields an owned `Bytes`, and cloning one compiles
/// down to `lr.d`/`sc.d` — RISC-V atomics that CKB-VM refuses to execute. A
/// stack buffer plus a reader touches no refcount and no allocator at all.
fn mining_addr_lock_hash() -> Result<[u8; HASH_LEN], i8> {
    // A Script holding a 32-byte args serialises well under 256 bytes; the
    // syscall reports the real length, so a short read is caught below.
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
///
/// `GroupInput` holds exactly those, so its being non-empty is the question.
fn spends_a_marked_cell() -> bool {
    QueryIter::new(load_cell_capacity, Source::GroupInput)
        .next()
        .is_some()
}
